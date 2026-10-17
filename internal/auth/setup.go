package auth

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// First-run setup: while the panel has no user, whoever opens it can create
// the owner account from the browser, like other self-hosted panels. The page
// is open only for SetupWindow after the panel starts with no user: an
// install left behind does not stay claimable forever, and restarting the
// service (which needs a shell on the server) opens a new window. The owner
// is inserted only if the users table is still empty, so two requests racing
// each other cannot both win.

// SetupWindow is how long the first-run page stays open after the panel
// starts with no user.
const SetupWindow = 30 * time.Minute

// SetupState is where the first-run setup stands.
type SetupState int

const (
	// SetupDone: there is a user (or the browser setup is off).
	SetupDone SetupState = iota
	// SetupAvailable: no user yet and the window is open.
	SetupAvailable
	// SetupExpired: no user yet, but the window has closed.
	SetupExpired
)

// ErrSetupClosed tells the setup page the owner can no longer be created.
var ErrSetupClosed = &i18n.Error{Key: "setup.error.closed"}

// setupDeadline holds the end of the setup window (Unix seconds, 0 = never
// opened); handlers read it while the panel serves.
type setupDeadline = atomic.Int64

// Setup reports the first-run state and, while open, when it closes.
func (s *Service) Setup(ctx context.Context) (SetupState, time.Time) {
	if !s.firstRun {
		return SetupDone, time.Time{}
	}
	if n, err := s.q.CountUsers(ctx); err != nil || n > 0 {
		return SetupDone, time.Time{}
	}
	end := s.setupUntil.Load()
	if end == 0 || !s.now().Before(time.Unix(end, 0)) {
		return SetupExpired, time.Time{}
	}
	return SetupAvailable, time.Unix(end, 0)
}

// PrepareSetup opens the setup window when the panel starts with no user and
// returns when it closes (zero when there is nothing to set up).
func (s *Service) PrepareSetup(ctx context.Context) (time.Time, error) {
	if !s.firstRun {
		return time.Time{}, nil
	}
	n, err := s.q.CountUsers(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if n > 0 {
		return time.Time{}, nil
	}
	until := s.now().Add(SetupWindow)
	s.setupUntil.Store(until.Unix())
	return until, nil
}

// CreateOwner creates the first account (owner) from the setup page and
// opens its session, with the same attempt limits as the login.
func (s *Service) CreateOwner(ctx context.Context, email, password string, c Client) (string, error) {
	ipKey := "ip:" + c.IP
	if err := s.checkLimits(ipKey, "setup"); err != nil {
		return "", err
	}
	defer s.limits.end(ipKey, "setup")

	if st, _ := s.Setup(ctx); st != SetupAvailable {
		return "", ErrSetupClosed
	}
	email, hash, err := s.newAccount(email, password, RoleOwner)
	if err != nil {
		return "", err
	}
	id := "usr_" + randomID()
	now := s.now().Unix()
	n, err := s.q.CreateFirstUser(ctx, dbq.CreateFirstUserParams{
		ID: id, Email: email, PasswordHash: hash, Role: RoleOwner.String(), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return "", fmt.Errorf("create owner: %w", err)
	}
	if n == 0 {
		return "", ErrSetupClosed
	}
	s.limits.reset(ipKey)
	s.limits.reset("setup")
	s.record(ctx, audit.Entry{
		ActorID: id, IP: c.IP, UserAgent: c.UserAgent, Action: "user.create", Outcome: audit.OK,
		TargetType: "user", TargetID: id, Summary: map[string]any{"role": RoleOwner.String(), "via": "setup"},
	})
	token, err := s.createSession(ctx, id, "active", c, s.now().Add(SessionMax), 0)
	if err != nil {
		return "", err
	}
	s.record(ctx, audit.Entry{
		ActorID: id, IP: c.IP, UserAgent: c.UserAgent, Action: "auth.login.ok", Outcome: audit.OK,
		Summary: map[string]any{"second_factor": "none", "via": "setup"},
	})
	return token, nil
}
