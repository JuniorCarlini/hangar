package auth

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// The team: the owner invites people with a role and, for operators and
// viewers, a list of projects. A user limited to some projects sees only
// those: the rest of the panel (other projects and server-wide pages) is out
// of reach (docs/17 § 1.3). Owners and admins always see every project:
// their pages (domains, backups, alerts...) span the whole server.

// InviteTTL is how long an invitation link works.
const InviteTTL = 24 * time.Hour

// Team errors the handlers translate for the UI.
var (
	ErrLastOwner     = &i18n.Error{Key: "team.error.last_owner"}
	ErrSelf          = &i18n.Error{Key: "team.error.self"}
	ErrInviteInvalid = &i18n.Error{Key: "team.error.invite_invalid"}
	ErrNoProjects    = &i18n.Error{Key: "team.error.no_projects"}
	ErrInviteRole    = &i18n.Error{Key: "team.error.invite_role"}
)

// Access is what a user may reach: a role and, below admin, possibly only
// some projects (by slug).
type Access struct {
	Role        Role
	AllProjects bool
	Projects    []string
}

// normalize applies the rule that owners and admins see every project, and
// keeps a sorted, unique project list only when it matters.
func (a Access) normalize() (Access, error) {
	if a.Role >= RoleAdmin {
		a.AllProjects = true
	}
	if a.AllProjects {
		a.Projects = nil
		return a, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range a.Projects {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return a, ErrNoProjects
	}
	slices.Sort(out)
	a.Projects = out
	return a, nil
}

// Member is a user as the team page shows it.
type Member struct {
	ID        string
	Email     string
	Name      string
	Access    Access
	HasTOTP   bool
	Locked    bool
	LastSeen  time.Time // zero = never
	CreatedAt time.Time
}

// Invite is an open invitation.
type Invite struct {
	ID        string
	Email     string
	Access    Access
	ExpiresAt time.Time
}

// Team lists the users and the open invitations.
func (s *Service) Team(ctx context.Context) ([]Member, []Invite, error) {
	rows, err := s.q.ListUsers(ctx)
	if err != nil {
		return nil, nil, err
	}
	links, err := s.q.AllUserProjects(ctx)
	if err != nil {
		return nil, nil, err
	}
	byUser := map[string][]string{}
	for _, l := range links {
		byUser[l.UserID] = append(byUser[l.UserID], l.Slug)
	}
	members := make([]Member, 0, len(rows))
	for _, r := range rows {
		role, _ := ParseRole(r.Role)
		m := Member{
			ID: r.ID, Email: r.Email, Name: r.Name, HasTOTP: r.HasTotp == 1, Locked: r.LockedAt.Valid,
			Access:    Access{Role: role, AllProjects: r.AllProjects == 1, Projects: byUser[r.ID]},
			CreatedAt: time.Unix(r.CreatedAt, 0),
		}
		if r.LastSeenAt > 0 {
			m.LastSeen = time.Unix(r.LastSeenAt, 0)
		}
		members = append(members, m)
	}
	inv, err := s.q.ListOpenInvites(ctx, s.now().Unix())
	if err != nil {
		return nil, nil, err
	}
	invites := make([]Invite, 0, len(inv))
	for _, r := range inv {
		invites = append(invites, toInvite(r))
	}
	return members, invites, nil
}

func toInvite(r dbq.Invite) Invite {
	role, _ := ParseRole(r.Role)
	var projects []string
	_ = json.Unmarshal([]byte(r.ProjectsJson), &projects)
	return Invite{
		ID: r.ID, Email: r.Email, ExpiresAt: time.Unix(r.ExpiresAt, 0),
		Access: Access{Role: role, AllProjects: r.AllProjects == 1, Projects: projects},
	}
}

// CreateInvite records an invitation and returns its one-time token (only
// its hash is stored). Owners are not invited: an owner promotes someone
// already in the team.
func (s *Service) CreateInvite(ctx context.Context, p *Principal, email string, a Access, c Client) (string, error) {
	email = strings.TrimSpace(email)
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || len(email) > 254 {
		return "", i18n.E("user.error.email_invalid", "email", email)
	}
	if a.Role < RoleViewer || a.Role > RoleAdmin {
		return "", ErrInviteRole
	}
	a, err = s.checkAccess(ctx, a)
	if err != nil {
		return "", err
	}
	if _, err := s.q.GetUserByEmail(ctx, email); err == nil {
		return "", ErrEmailTaken
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	token := randomToken()
	projects, _ := json.Marshal(a.Projects)
	if a.Projects == nil {
		projects = []byte("[]")
	}
	now := s.now()
	id := "inv_" + randomID()
	if err := s.q.CreateInvite(ctx, dbq.CreateInviteParams{
		ID: id, TokenHash: inviteHash(token), Email: email, Role: a.Role.String(),
		AllProjects: boolInt(a.AllProjects), ProjectsJson: string(projects),
		CreatedBy: sql.NullString{String: p.UserID, Valid: true}, CreatedAt: now.Unix(), ExpiresAt: now.Add(InviteTTL).Unix(),
	}); err != nil {
		return "", fmt.Errorf("create invite: %w", err)
	}
	s.record(ctx, audit.Entry{
		ActorID: p.UserID, IP: c.IP, UserAgent: c.UserAgent, Action: "user.invite", Outcome: audit.OK,
		TargetType: "invite", TargetID: id, Summary: accessSummary(email, a),
	})
	return token, nil
}

// CancelInvite removes an open invitation.
func (s *Service) CancelInvite(ctx context.Context, p *Principal, id string, c Client) error {
	n, err := s.q.DeleteInvite(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInviteInvalid
	}
	s.record(ctx, audit.Entry{
		ActorID: p.UserID, IP: c.IP, UserAgent: c.UserAgent, Action: "user.invite.cancel", Outcome: audit.OK,
		TargetType: "invite", TargetID: id,
	})
	return nil
}

// InviteFor returns the open invitation of a token, for the accept page.
func (s *Service) InviteFor(ctx context.Context, token string) (Invite, error) {
	r, err := s.q.GetInviteByToken(ctx, inviteHash(token))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (r.UsedAt.Valid || s.now().Unix() >= r.ExpiresAt)) {
		return Invite{}, ErrInviteInvalid
	}
	if err != nil {
		return Invite{}, err
	}
	return toInvite(r), nil
}

// CheckInvite is InviteFor for a visitor: an unknown, used or expired link
// counts as a failed attempt from their address, with the login's limits,
// so links cannot be guessed by trying (they are 256-bit anyway).
func (s *Service) CheckInvite(ctx context.Context, token string, c Client) (Invite, error) {
	ipKey := "ip:" + c.IP
	if err := s.checkLimits(ipKey); err != nil {
		return Invite{}, err
	}
	defer s.limits.end(ipKey)
	inv, err := s.InviteFor(ctx, token)
	if errors.Is(err, ErrInviteInvalid) {
		s.fail(ctx, c, "", "invalid_invite", ipKey)
	}
	return inv, err
}

// AcceptInvite creates the invited user with the password they chose, gives
// them the invitation's access and opens their session. The invitation is
// spent in the same transaction: a link works once.
func (s *Service) AcceptInvite(ctx context.Context, token, password string, c Client) (string, error) {
	ipKey := "ip:" + c.IP
	if err := s.checkLimits(ipKey); err != nil {
		return "", err
	}
	defer s.limits.end(ipKey)

	inv, err := s.InviteFor(ctx, token)
	if err != nil {
		s.fail(ctx, c, "", "invalid_invite", ipKey)
		return "", err
	}
	email, hash, err := s.newAccount(inv.Email, password, inv.Access.Role)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)
	now := s.now().Unix()
	if n, err := q.UseInvite(ctx, dbq.UseInviteParams{UsedAt: sql.NullInt64{Int64: now, Valid: true}, ID: inv.ID, ExpiresAt: now}); err != nil {
		return "", err
	} else if n == 0 {
		return "", ErrInviteInvalid
	}
	id := "usr_" + randomID()
	if err := q.CreateUser(ctx, dbq.CreateUserParams{
		ID: id, Email: email, PasswordHash: hash, Role: inv.Access.Role.String(), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", ErrEmailTaken
		}
		return "", fmt.Errorf("create user: %w", err)
	}
	if err := setAccess(ctx, q, id, inv.Access, now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.limits.reset(ipKey)
	s.record(ctx, audit.Entry{
		ActorID: id, IP: c.IP, UserAgent: c.UserAgent, Action: "user.create", Outcome: audit.OK,
		TargetType: "user", TargetID: id, Summary: map[string]any{"role": inv.Access.Role.String(), "via": "invite", "invite": inv.ID},
	})
	sess, err := s.createSession(ctx, id, "active", c, s.now().Add(SessionMax), 0)
	if err != nil {
		return "", err
	}
	s.record(ctx, audit.Entry{
		ActorID: id, IP: c.IP, UserAgent: c.UserAgent, Action: "auth.login.ok", Outcome: audit.OK,
		Summary: map[string]any{"second_factor": "none", "via": "invite"},
	})
	return sess, nil
}

// UpdateMember changes another user's role and projects. Their sessions end
// at once, so the new access applies from the next page.
func (s *Service) UpdateMember(ctx context.Context, p *Principal, id string, a Access, c Client) error {
	if id == p.UserID {
		return ErrSelf
	}
	u, err := s.q.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return i18n.E("user.error.not_found", "email", id)
	}
	if err != nil {
		return err
	}
	a, err = s.checkAccess(ctx, a)
	if err != nil {
		return err
	}
	if u.Role == RoleOwner.String() && a.Role != RoleOwner {
		if n, err := s.q.CountOwners(ctx); err != nil {
			return err
		} else if n <= 1 {
			return ErrLastOwner
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)
	now := s.now().Unix()
	if err := setAccess(ctx, q, id, a, now); err != nil {
		return err
	}
	if err := q.DeleteUserSessions(ctx, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	sum := accessSummary(u.Email, a)
	sum["from_role"] = u.Role
	s.record(ctx, audit.Entry{
		ActorID: p.UserID, IP: c.IP, UserAgent: c.UserAgent, Action: "user.update", Outcome: audit.OK,
		TargetType: "user", TargetID: id, Summary: sum,
	})
	return nil
}

// RemoveMember deletes another user; their sessions go with them. The last
// owner cannot be removed.
func (s *Service) RemoveMember(ctx context.Context, p *Principal, id string, c Client) error {
	if id == p.UserID {
		return ErrSelf
	}
	u, err := s.q.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return i18n.E("user.error.not_found", "email", id)
	}
	if err != nil {
		return err
	}
	if u.Role == RoleOwner.String() {
		if n, err := s.q.CountOwners(ctx); err != nil {
			return err
		} else if n <= 1 {
			return ErrLastOwner
		}
	}
	if err := s.q.DeleteUser(ctx, id); err != nil {
		return err
	}
	s.record(ctx, audit.Entry{
		ActorID: p.UserID, IP: c.IP, UserAgent: c.UserAgent, Action: "user.remove", Outcome: audit.OK,
		TargetType: "user", TargetID: id, Summary: map[string]any{"email": u.Email, "role": u.Role},
	})
	return nil
}

// checkAccess normalizes the access and refuses projects that do not exist.
func (s *Service) checkAccess(ctx context.Context, a Access) (Access, error) {
	a, err := a.normalize()
	if err != nil {
		return a, err
	}
	for _, slug := range a.Projects {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM projects WHERE slug = ?`, slug).Scan(&n); err != nil {
			return a, err
		}
		if n == 0 {
			return a, i18n.E("team.error.project", "project", slug)
		}
	}
	return a, nil
}

// setAccess writes the user's project list (empty when they see all).
func setAccess(ctx context.Context, q *dbq.Queries, userID string, a Access, now int64) error {
	if err := q.SetUserAccess(ctx, dbq.SetUserAccessParams{Role: a.Role.String(), AllProjects: boolInt(a.AllProjects), UpdatedAt: now, ID: userID}); err != nil {
		return err
	}
	if err := q.ClearUserProjects(ctx, userID); err != nil {
		return err
	}
	for _, slug := range a.Projects {
		if err := q.AddUserProject(ctx, dbq.AddUserProjectParams{UserID: userID, Slug: slug}); err != nil {
			return err
		}
	}
	return nil
}

func accessSummary(email string, a Access) map[string]any {
	sum := map[string]any{"email": email, "role": a.Role.String(), "all_projects": a.AllProjects}
	if !a.AllProjects {
		sum["projects"] = a.Projects
	}
	return sum
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// inviteHash is how an invitation token is stored.
func inviteHash(token string) string { return hex.EncodeToString(hashToken(token)) }
