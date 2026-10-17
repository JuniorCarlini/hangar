package projects

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Git credentials: a token saved once and picked by any number of services,
// for the whole server or for one project. Replacing the token here changes
// it for every service that uses it, at their next deploy.

const (
	credNameMax    = 60
	defaultGitHost = "github.com"
)

var credHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func credAD(id string) string { return "git_credentials|" + id + "|token" }

// tokenHint is the end of a token, enough to tell two of them apart.
func tokenHint(token string) string {
	if len(token) <= 8 {
		return ""
	}
	return token[len(token)-4:]
}

// GitCredential is what the panel shows about a saved credential (never the
// token).
type GitCredential struct {
	ID          string
	ProjectID   string // "" = any project on the server
	ProjectSlug string
	Name        string
	Host        string
	Hint        string
	Uses        int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastUsed    time.Time
}

// Server says whether every project can use the credential.
func (c GitCredential) Server() bool { return c.ProjectID == "" }

// GitCredentialInput creates a credential. ProjectSlug "" = server-wide.
type GitCredentialInput struct {
	ProjectSlug string
	Name        string
	Host        string
	Token       string
}

// ListGitCredentials returns every credential, server-wide ones first.
func (m *Manager) ListGitCredentials(ctx context.Context) ([]GitCredential, error) {
	rows, err := m.q.ListGitCredentials(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GitCredential, 0, len(rows))
	for _, r := range rows {
		c := GitCredential{
			ID: r.ID, ProjectID: r.ProjectID.String, ProjectSlug: r.ProjectSlug, Name: r.Name, Host: r.Host,
			Hint: r.TokenHint, Uses: int(r.Uses), CreatedAt: time.Unix(r.CreatedAt, 0), UpdatedAt: time.Unix(r.UpdatedAt, 0),
		}
		if r.LastUsedAt.Valid {
			c.LastUsed = time.Unix(r.LastUsedAt.Int64, 0)
		}
		out = append(out, c)
	}
	return out, nil
}

// GitCredentialsFor lists what a project's services can use: its own
// credentials first, then the server-wide ones.
func (m *Manager) GitCredentialsFor(ctx context.Context, projectID string) ([]GitCredential, error) {
	all, err := m.ListGitCredentials(ctx)
	if err != nil {
		return nil, err
	}
	var own, server []GitCredential
	for _, c := range all {
		switch c.ProjectID {
		case projectID:
			own = append(own, c)
		case "":
			server = append(server, c)
		}
	}
	return append(own, server...), nil
}

// CreateGitCredential saves a token under a name.
func (m *Manager) CreateGitCredential(ctx context.Context, a Actor, in GitCredentialInput) (GitCredential, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > credNameMax || strings.ContainsAny(name, "\n\r\t") {
		return GitCredential{}, i18n.E("gitcred.error.name")
	}
	host := strings.ToLower(strings.TrimSpace(in.Host))
	if host == "" {
		host = defaultGitHost
	}
	if !credHostRE.MatchString(host) || len(host) > 253 {
		return GitCredential{}, i18n.E("gitcred.error.host")
	}
	token, err := checkToken(in.Token)
	if err != nil {
		return GitCredential{}, err
	}
	if token == "" {
		return GitCredential{}, i18n.E("git.error.token")
	}
	var project sql.NullString
	slug := ""
	if in.ProjectSlug != "" {
		p, err := m.GetProject(ctx, in.ProjectSlug)
		if err != nil {
			return GitCredential{}, err
		}
		project, slug = sql.NullString{String: p.ID, Valid: true}, p.Slug
	}
	existing, err := m.ListGitCredentials(ctx)
	if err != nil {
		return GitCredential{}, err
	}
	for _, c := range existing {
		if c.ProjectID == project.String && strings.EqualFold(c.Name, name) {
			return GitCredential{}, i18n.E("gitcred.error.name_taken", "name", name)
		}
	}
	id := ids.New("gcr_")
	enc, err := m.box.Seal([]byte(token), credAD(id))
	if err != nil {
		return GitCredential{}, err
	}
	now := m.now()
	if err := m.q.CreateGitCredential(ctx, dbq.CreateGitCredentialParams{
		ID: id, ProjectID: project, Name: name, Host: host, TokenEnc: enc, TokenHint: tokenHint(token),
		CreatedAt: now.Unix(), UpdatedAt: now.Unix(),
	}); err != nil {
		return GitCredential{}, err
	}
	m.record(ctx, a, "git.credential.create", "git_credential", id, audit.OK, map[string]any{
		"name": name, "host": host, "project": slug,
	})
	return GitCredential{ID: id, ProjectID: project.String, ProjectSlug: slug, Name: name, Host: host, Hint: tokenHint(token), CreatedAt: now, UpdatedAt: now}, nil
}

func (m *Manager) gitCredential(ctx context.Context, id string) (dbq.GitCredential, error) {
	c, err := m.q.GetGitCredential(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// ReplaceGitCredentialToken puts a new token in a credential: every service
// using it clones with the new one from its next deploy.
func (m *Manager) ReplaceGitCredentialToken(ctx context.Context, a Actor, id, token string) error {
	c, err := m.gitCredential(ctx, id)
	if err != nil {
		return err
	}
	if token, err = checkToken(token); err != nil {
		return err
	}
	if token == "" {
		return i18n.E("git.error.token")
	}
	enc, err := m.box.Seal([]byte(token), credAD(c.ID))
	if err != nil {
		return err
	}
	if err := m.q.UpdateGitCredentialToken(ctx, dbq.UpdateGitCredentialTokenParams{
		TokenEnc: enc, TokenHint: tokenHint(token), UpdatedAt: m.now().Unix(), ID: c.ID,
	}); err != nil {
		return err
	}
	m.record(ctx, a, "git.credential.replace", "git_credential", c.ID, audit.OK, map[string]any{"name": c.Name})
	return nil
}

// DeleteGitCredential removes a credential no service uses (deleting one in
// use would break the next deploy of a private repository without warning).
func (m *Manager) DeleteGitCredential(ctx context.Context, a Actor, id string) error {
	c, err := m.gitCredential(ctx, id)
	if err != nil {
		return err
	}
	users, err := m.q.ListGitCredentialUsers(ctx, sql.NullString{String: c.ID, Valid: true})
	if err != nil {
		return err
	}
	if len(users) > 0 {
		names := make([]string, 0, len(users))
		for _, u := range users {
			names = append(names, u.ProjectSlug+"/"+u.ServiceSlug)
		}
		return i18n.E("gitcred.error.in_use", "services", strings.Join(names, ", "))
	}
	if err := m.q.DeleteGitCredential(ctx, c.ID); err != nil {
		return err
	}
	m.record(ctx, a, "git.credential.delete", "git_credential", c.ID, audit.OK, map[string]any{"name": c.Name})
	return nil
}

// usableCredential checks a project may use the credential for this
// repository: its own or a server-wide one, and made for the repository's
// host (a GitHub token must never be sent to another server).
func (m *Manager) usableCredential(ctx context.Context, projectID, repoURL, id string) (dbq.GitCredential, error) {
	c, err := m.gitCredential(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return c, i18n.E("gitcred.error.gone")
	}
	if err != nil {
		return c, err
	}
	if c.ProjectID.Valid && c.ProjectID.String != projectID {
		return c, i18n.E("gitcred.error.gone")
	}
	if h := hostOf(repoURL); !strings.HasPrefix(repoURL, "file://") && !strings.EqualFold(h, c.Host) {
		return c, i18n.E("gitcred.error.host_mismatch", "name", c.Name, "host", c.Host, "repo", h)
	}
	return c, nil
}

// cloneToken is the token a service clones with: its credential's, or the
// token of its own saved before credentials existed ("" = public).
func (m *Manager) cloneToken(ctx context.Context, s dbq.Service, g dbq.ServiceGit) (string, error) {
	if !g.CredentialID.Valid {
		return m.openGit(g.TokenEnc, s.ID, "token")
	}
	c, err := m.usableCredential(ctx, s.ProjectID, g.RepoUrl, g.CredentialID.String)
	if err != nil {
		return "", err
	}
	b, err := m.box.Open(c.TokenEnc, credAD(c.ID))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// credentialToken opens a credential chosen in a form, after checking the
// project may use it for this repository.
func (m *Manager) credentialToken(ctx context.Context, projectID, repoURL, id string) (string, error) {
	c, err := m.usableCredential(ctx, projectID, repoURL, id)
	if err != nil {
		return "", err
	}
	b, err := m.box.Open(c.TokenEnc, credAD(c.ID))
	return string(b), err
}

// SetGitCredential points a service at a saved credential ("" = public
// repository), after proving it can read the repository. A token of the
// service's own is dropped: from now on the credential is the only one.
func (m *Manager) SetGitCredential(ctx context.Context, a Actor, serviceID, credentialID string) error {
	g, ok, err := m.gitRow(ctx, serviceID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return err
	}
	token := ""
	if credentialID != "" {
		if token, err = m.credentialToken(ctx, s.ProjectID, g.RepoUrl, credentialID); err != nil {
			return err
		}
	}
	if err := checkAccess(ctx, g.RepoUrl, g.Branch, token); err != nil {
		return err
	}
	cred := sql.NullString{String: credentialID, Valid: credentialID != ""}
	if err := m.q.SetServiceGitCredential(ctx, dbq.SetServiceGitCredentialParams{CredentialID: cred, UpdatedAt: m.now().Unix(), ServiceID: serviceID}); err != nil {
		return err
	}
	m.record(ctx, a, "service.git.token", "service", serviceID, audit.OK, map[string]any{"credential": credentialID})
	return nil
}
