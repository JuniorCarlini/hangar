package projects

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Build from Git (docs/07, Etapa 10).
const (
	cloneTimeout = 5 * time.Minute
	buildTimeout = 20 * time.Minute
	checkTimeout = 30 * time.Second
	// webhookWindow: a push older than this (by the pushed_at inside the
	// signed body) is refused, so a captured delivery cannot be replayed
	// after its id is forgotten.
	webhookWindow = 10 * time.Minute
	// webhookSkew tolerates a GitHub clock slightly ahead of ours.
	webhookSkew = 2 * time.Minute
	// deliveryRetention keeps delivery ids far longer than the window.
	deliveryRetention = 7 * 24 * time.Hour
	gitTokenMax       = 512
	tokenUser         = "x-access-token"
	defaultDockerfile = "Dockerfile"
)

// HookPath is where GitHub posts: HookPath + <token> (docs/07, docs/11).
const HookPath = "/hooks/git/"

// SetBuildDir sets where builds check the code out (docs/07:
// /var/lib/hangar/builds/<deploy>). Without it, Git services cannot deploy.
// Call it before any deploy: workspaces left by a crash are removed.
func (m *Manager) SetBuildDir(dir string) {
	m.buildDir = dir
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dep_") {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

func gitAD(serviceID, field string) string { return "service_git|" + serviceID + "|" + field }

func (m *Manager) gitRow(ctx context.Context, serviceID string) (dbq.ServiceGit, bool, error) {
	g, err := m.q.GetServiceGit(ctx, serviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return g, false, nil
	}
	return g, err == nil, err
}

func (m *Manager) openGit(enc []byte, serviceID, field string) (string, error) {
	if len(enc) == 0 {
		return "", nil
	}
	b, err := m.box.Open(enc, gitAD(serviceID, field))
	if err != nil {
		return "", fmt.Errorf("git %s: %w", field, err)
	}
	return string(b), nil
}

// GitSourceInput is the repository part of a service.
type GitSourceInput struct {
	URL        string
	Branch     string
	Subdir     string
	Dockerfile string
}

func (in *GitSourceInput) normalize() error {
	var err error
	if in.URL, err = gitsrc.ValidateURL(in.URL); err != nil {
		return err
	}
	if strings.TrimSpace(in.Branch) == "" {
		in.Branch = "main"
	}
	if in.Branch, err = gitsrc.ValidateBranch(in.Branch); err != nil {
		return err
	}
	if in.Subdir, err = gitsrc.CleanPath(in.Subdir); err != nil {
		return err
	}
	if in.Dockerfile, err = gitsrc.CleanPath(in.Dockerfile); err != nil {
		return err
	}
	if in.Dockerfile == "" {
		in.Dockerfile = defaultDockerfile
	}
	return nil
}

func checkToken(t string) (string, error) {
	t = strings.TrimSpace(t)
	if len(t) > gitTokenMax || strings.IndexFunc(t, func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' }) >= 0 {
		return "", i18n.E("git.error.token")
	}
	return t, nil
}

// checkAccess proves the URL, token and branch work before saving them
// (git ls-remote; nothing is downloaded).
func checkAccess(ctx context.Context, url, branch, token string) error {
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	err := gitsrc.Check(cctx, gitsrc.Source{URL: url, Branch: branch, Token: token})
	if err == nil {
		return nil
	}
	var ie *i18n.Error
	if errors.As(err, &ie) {
		return err
	}
	// The transport error goes to the user with the token masked: a server
	// could echo the credentials back in it.
	return i18n.E("git.error.unreachable", "error", newMasker(token).apply(err.Error()))
}

// GitServiceInput creates a service built from a repository.
type GitServiceInput struct {
	ServiceInput
	GitSourceInput
	// CredentialID picks a saved credential; Token is a token of the
	// service's own (the way before credentials existed). Both empty =
	// public repository.
	CredentialID string
	Token        string
	// DetectPort: the form left the port empty, so it is read from the
	// Dockerfile's EXPOSE (DefaultGitPort when there is none).
	DetectPort bool
}

// DefaultGitPort is the port of a service built from Git whose Dockerfile
// exposes none.
const DefaultGitPort = 8000

// CreateGitService stores a service with a Git source and starts its first
// deploy (clone, build, run). The repository is checked with the token first,
// so a typo fails here and not in the build log.
func (m *Manager) CreateGitService(ctx context.Context, a Actor, projectSlug string, in GitServiceInput) (dbq.Service, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return dbq.Service{}, err
	}
	if strings.TrimSpace(in.Name) != "" {
		if in.Slug, err = slugFromName(in.Name); err != nil {
			return dbq.Service{}, err
		}
		in.Name = ""
	}
	in.Image = node.BuildRepo(p.Slug, strings.TrimSpace(in.Slug))
	if !node.SlugRE.MatchString(strings.TrimSpace(in.Slug)) {
		return dbq.Service{}, i18n.E("service.error.slug")
	}
	if err := m.checkServiceInput(ctx, p, &in.ServiceInput); err != nil {
		return dbq.Service{}, err
	}
	if err := in.normalize(); err != nil {
		return dbq.Service{}, err
	}
	if in.Token, err = checkToken(in.Token); err != nil {
		return dbq.Service{}, err
	}
	if err := m.requireNode(); err != nil {
		return dbq.Service{}, err
	}
	if _, ok := m.node.(node.Builder); !ok || m.buildDir == "" {
		return dbq.Service{}, i18n.E("git.error.no_builder")
	}
	token := in.Token
	if in.CredentialID != "" {
		if token, err = m.credentialToken(ctx, p.ID, in.URL, in.CredentialID); err != nil {
			return dbq.Service{}, err
		}
		in.Token = ""
	}
	if err := checkAccess(ctx, in.URL, in.Branch, token); err != nil {
		return dbq.Service{}, err
	}
	if in.DetectPort && in.Port == 0 {
		// The Dockerfile says where the app listens; a web app without an
		// EXPOSE most often listens on 8000 (gunicorn, uvicorn, Rails).
		if in.Port = m.dockerfilePort(ctx, in.GitSourceInput, token); in.Port == 0 {
			in.Port = DefaultGitPort
		}
	}
	params := m.serviceParams(p, in.ServiceInput)
	var tokenEnc []byte
	if in.Token != "" {
		if tokenEnc, err = m.box.Seal([]byte(in.Token), gitAD(params.ID, "token")); err != nil {
			return dbq.Service{}, err
		}
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return dbq.Service{}, err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := m.q.WithTx(tx)
	if err := qtx.CreateService(ctx, params); err != nil {
		return dbq.Service{}, err
	}
	if err := qtx.CreateServiceGit(ctx, dbq.CreateServiceGitParams{
		ServiceID: params.ID, RepoUrl: in.URL, Branch: in.Branch, Subdir: in.Subdir, Dockerfile: in.Dockerfile,
		TokenEnc: tokenEnc, CredentialID: sql.NullString{String: in.CredentialID, Valid: in.CredentialID != ""}, UpdatedAt: m.now().Unix(),
	}); err != nil {
		return dbq.Service{}, err
	}
	if err := defaultEndpoint(ctx, qtx, p.Slug, params.ID, params.Slug, params.InternalPort, m.now().Unix()); err != nil {
		return dbq.Service{}, err
	}
	if err := tx.Commit(); err != nil {
		return dbq.Service{}, err
	}
	m.record(ctx, a, "service.create", "service", params.ID, audit.OK, map[string]any{
		"project": p.Slug, "service": params.Slug, "repo": in.URL, "branch": in.Branch, "token": in.Token != "", "credential": in.CredentialID,
	})
	s, err := m.q.GetServiceByID(ctx, params.ID)
	if err != nil {
		return dbq.Service{}, err
	}
	if _, err := m.Deploy(ctx, a, p.Slug, s.Slug, "create"); err != nil {
		return s, err
	}
	return s, nil
}

// GitSource is what the UI shows about a service's repository (never the
// token or the webhook secret).
type GitSource struct {
	URL        string
	Display    string
	Branch     string
	Subdir     string
	Dockerfile string
	HasToken   bool // a token of the service's own (before credentials)
	Webhook    bool
	AutoDeploy bool // the panel polls the branch and deploys new commits
	// The saved credential it clones with ("" = none).
	CredentialID   string
	CredentialName string
	CredentialHost string
	CredentialHint string
	CredentialMine bool // the project's own, not server-wide
}

// GetGitSource returns the service's repository; ok is false for a service
// that runs an image.
func (m *Manager) GetGitSource(ctx context.Context, serviceID string) (GitSource, bool, error) {
	g, ok, err := m.gitRow(ctx, serviceID)
	if !ok || err != nil {
		return GitSource{}, false, err
	}
	src := GitSource{
		URL: g.RepoUrl, Display: gitsrc.Display(g.RepoUrl), Branch: g.Branch, Subdir: g.Subdir, Dockerfile: g.Dockerfile,
		HasToken: len(g.TokenEnc) > 0, Webhook: g.WebhookTokenHash.Valid, AutoDeploy: g.AutoDeploy == 1,
	}
	if g.CredentialID.Valid {
		src.CredentialID = g.CredentialID.String
		if c, err := m.q.GetGitCredential(ctx, g.CredentialID.String); err == nil {
			src.CredentialName, src.CredentialHost, src.CredentialHint, src.CredentialMine = c.Name, c.Host, c.TokenHint, c.ProjectID.Valid
		}
	}
	return src, true, nil
}

// GitDisplays maps service id to "host/owner/repo@branch" for a project's
// Git services (the canvas shows it in place of the image).
func (m *Manager) GitDisplays(ctx context.Context, projectID string) map[string]string {
	rows, err := m.q.ListProjectGitSources(ctx, projectID)
	out := map[string]string{}
	if err != nil {
		return out
	}
	for _, r := range rows {
		out[r.ServiceID] = gitsrc.Display(r.RepoUrl) + "@" + r.Branch
	}
	return out
}

// SetGitSource changes the repository, branch, subdirectory or Dockerfile.
// Pointing the service at another repository forgets the token, unless a
// new one comes with the change: the old token must never be sent to a
// host it was not created for.
func (m *Manager) SetGitSource(ctx context.Context, a Actor, serviceID string, in GitSourceInput, newToken string) error {
	g, ok, err := m.gitRow(ctx, serviceID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	if err := in.normalize(); err != nil {
		return err
	}
	if newToken, err = checkToken(newToken); err != nil {
		return err
	}
	token := newToken
	repoChanged := !gitsrc.SameRepo(in.URL, g.RepoUrl) || !strings.EqualFold(hostOf(in.URL), hostOf(g.RepoUrl))
	switch {
	case token == "" && g.CredentialID.Valid:
		// The credential follows the service to the new repository, as long
		// as it was made for that host.
		s, err := m.q.GetServiceByID(ctx, serviceID)
		if err != nil {
			return err
		}
		if token, err = m.credentialToken(ctx, s.ProjectID, in.URL, g.CredentialID.String); err != nil {
			return err
		}
	case token == "" && !repoChanged:
		if token, err = m.openGit(g.TokenEnc, serviceID, "token"); err != nil {
			return err
		}
	}
	if err := checkAccess(ctx, in.URL, in.Branch, token); err != nil {
		return err
	}
	if err := m.q.UpdateServiceGitSource(ctx, dbq.UpdateServiceGitSourceParams{
		RepoUrl: in.URL, Branch: in.Branch, Subdir: in.Subdir, Dockerfile: in.Dockerfile, UpdatedAt: m.now().Unix(), ServiceID: serviceID,
	}); err != nil {
		return err
	}
	if newToken != "" || (repoChanged && !g.CredentialID.Valid) {
		if err := m.storeToken(ctx, serviceID, newToken); err != nil {
			return err
		}
	}
	m.record(ctx, a, "service.git.source", "service", serviceID, audit.OK, map[string]any{
		"repo": in.URL, "branch": in.Branch, "subdir": in.Subdir, "dockerfile": in.Dockerfile,
		"token_replaced": newToken != "", "token_dropped": repoChanged && newToken == "" && len(g.TokenEnc) > 0,
	})
	return nil
}

func hostOf(u string) string {
	rest, _ := strings.CutPrefix(u, "https://")
	h, _, _ := strings.Cut(rest, "/")
	return h
}

func (m *Manager) storeToken(ctx context.Context, serviceID, token string) error {
	var enc []byte
	if token != "" {
		var err error
		if enc, err = m.box.Seal([]byte(token), gitAD(serviceID, "token")); err != nil {
			return err
		}
	}
	return m.q.SetServiceGitToken(ctx, dbq.SetServiceGitTokenParams{TokenEnc: enc, UpdatedAt: m.now().Unix(), ServiceID: serviceID})
}

// SetGitToken replaces the clone token (empty = public repository). The new
// token is tested against the repository before it is stored.
func (m *Manager) SetGitToken(ctx context.Context, a Actor, serviceID, token string) error {
	g, ok, err := m.gitRow(ctx, serviceID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	if token, err = checkToken(token); err != nil {
		return err
	}
	if err := checkAccess(ctx, g.RepoUrl, g.Branch, token); err != nil {
		return err
	}
	if err := m.storeToken(ctx, serviceID, token); err != nil {
		return err
	}
	m.record(ctx, a, "service.git.token", "service", serviceID, audit.OK, map[string]any{"token": token != ""})
	return nil
}

// RevealGitToken returns the token in clear (the route requires sudo) and
// records who saw it.
func (m *Manager) RevealGitToken(ctx context.Context, a Actor, serviceID string) (string, error) {
	g, ok, err := m.gitRow(ctx, serviceID)
	if err != nil {
		return "", err
	}
	if !ok || len(g.TokenEnc) == 0 {
		return "", ErrNotFound
	}
	t, err := m.openGit(g.TokenEnc, serviceID, "token")
	if err != nil {
		return "", err
	}
	m.record(ctx, a, "secret.reveal", "service", serviceID, audit.OK, map[string]any{"key": "git_token"})
	return t, nil
}

// Webhook is what GitHub needs: the URL token and the HMAC secret.
type Webhook struct {
	Token  string
	Secret string
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // without entropy there is no safe way forward
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hookHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// RotateWebhook creates (or replaces) the service's webhook: a new URL token
// and a new secret. The previous URL stops working at once.
func (m *Manager) RotateWebhook(ctx context.Context, a Actor, serviceID string) (Webhook, error) {
	if _, ok, err := m.gitRow(ctx, serviceID); err != nil || !ok {
		if err == nil {
			err = ErrNotFound
		}
		return Webhook{}, err
	}
	w := Webhook{Token: randomToken(32), Secret: randomToken(32)}
	tokEnc, err := m.box.Seal([]byte(w.Token), gitAD(serviceID, "webhook_token"))
	if err != nil {
		return Webhook{}, err
	}
	secEnc, err := m.box.Seal([]byte(w.Secret), gitAD(serviceID, "webhook_secret"))
	if err != nil {
		return Webhook{}, err
	}
	if err := m.q.SetServiceGitWebhook(ctx, dbq.SetServiceGitWebhookParams{
		WebhookTokenHash: sql.NullString{String: hookHash(w.Token), Valid: true},
		WebhookTokenEnc:  tokEnc, WebhookSecretEnc: secEnc, UpdatedAt: m.now().Unix(), ServiceID: serviceID,
	}); err != nil {
		return Webhook{}, err
	}
	m.record(ctx, a, "service.git.webhook", "service", serviceID, audit.OK, map[string]any{"action": "rotate"})
	return w, nil
}

// DisableWebhook turns automatic deploys off: the URL answers 404.
func (m *Manager) DisableWebhook(ctx context.Context, a Actor, serviceID string) error {
	if err := m.q.SetServiceGitWebhook(ctx, dbq.SetServiceGitWebhookParams{UpdatedAt: m.now().Unix(), ServiceID: serviceID}); err != nil {
		return err
	}
	m.record(ctx, a, "service.git.webhook", "service", serviceID, audit.OK, map[string]any{"action": "disable"})
	return nil
}

// RevealWebhook shows the URL token and secret again (sudo route).
func (m *Manager) RevealWebhook(ctx context.Context, a Actor, serviceID string) (Webhook, error) {
	g, ok, err := m.gitRow(ctx, serviceID)
	if err != nil {
		return Webhook{}, err
	}
	if !ok || !g.WebhookTokenHash.Valid {
		return Webhook{}, ErrNotFound
	}
	var w Webhook
	if w.Token, err = m.openGit(g.WebhookTokenEnc, serviceID, "webhook_token"); err != nil {
		return Webhook{}, err
	}
	if w.Secret, err = m.openGit(g.WebhookSecretEnc, serviceID, "webhook_secret"); err != nil {
		return Webhook{}, err
	}
	m.record(ctx, a, "secret.reveal", "service", serviceID, audit.OK, map[string]any{"key": "webhook"})
	return w, nil
}

// --- the build ---------------------------------------------------------------

// deployMask lists what must never appear in the deploy log: secret
// variables (as stored and after references are resolved), any value that
// came from a reference (they usually carry passwords), the clone token and
// the webhook secret.
func (m *Manager) deployMask(ctx context.Context, s dbq.Service, g dbq.ServiceGit, raw, resolved map[string]string) (*masker, error) {
	rows, err := m.q.ListEnv(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	var vals []string
	for _, r := range rows {
		if r.Secret == 1 {
			vals = append(vals, raw[r.Key], resolved[r.Key])
		}
	}
	for k, v := range resolved {
		if raw[k] != v {
			vals = append(vals, v)
		}
	}
	if g.ServiceID != "" {
		token, err := m.cloneToken(ctx, s, g)
		if err != nil {
			return nil, err
		}
		if token != "" {
			vals = append(vals, token, base64.StdEncoding.EncodeToString([]byte(tokenUser+":"+token)))
		}
		secret, err := m.openGit(g.WebhookSecretEnc, s.ID, "webhook_secret")
		if err != nil {
			return nil, err
		}
		vals = append(vals, secret)
	}
	return newMasker(vals...), nil
}

// buildFromGit clones the branch into a fresh workspace, builds it with
// BuildKit and returns the image tag. The workspace is removed at the end,
// whatever happens.
func (m *Manager) buildFromGit(ctx context.Context, p dbq.Project, s dbq.Service, g dbq.ServiceGit, depID string, b node.Builder, dl *deployLog, fresh bool) (string, error) {
	token, err := m.cloneToken(ctx, s, g)
	if err != nil {
		return "", err
	}
	if g.CredentialID.Valid {
		_ = m.q.TouchGitCredential(ctx, dbq.TouchGitCredentialParams{LastUsedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: g.CredentialID.String})
	}
	if err := os.MkdirAll(m.buildDir, 0o700); err != nil {
		return "", fmt.Errorf("build directory: %w", err)
	}
	ws := filepath.Join(m.buildDir, depID)
	defer func() {
		if err := os.RemoveAll(ws); err != nil {
			m.log.Warn("remove build workspace", "dir", ws, "error", err)
		}
	}()

	dl.progress(node.PhaseClone, gitsrc.Display(g.RepoUrl)+" @ "+g.Branch)
	cctx, cancel := context.WithTimeout(ctx, cloneTimeout)
	commit, err := gitsrc.Clone(cctx, ws, gitsrc.Source{URL: g.RepoUrl, Branch: g.Branch, Token: token})
	cancel()
	if err != nil {
		return "", err
	}
	_ = m.q.SetDeploymentCommit(ctx, dbq.SetDeploymentCommitParams{CommitSha: commit.SHA, CommitMessage: commit.Message, ID: depID})
	dl.progress(node.PhaseClone, shortSHA(commit.SHA)+" "+commit.Message)

	contextDir, err := buildContextDir(ws, g.Subdir)
	if err != nil {
		return "", err
	}
	// Before the build: a build that fails for lack of a variable is
	// exactly when the suggestions help.
	m.recordEnvSuggestions(ctx, s.ID, contextDir)
	dl.progress(node.PhaseBuild, filepath.ToSlash(filepath.Join(g.Subdir, g.Dockerfile)))
	tag := node.BuildRepo(p.Slug, s.Slug) + ":" + strings.TrimPrefix(depID, "dep_")
	bctx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()
	if _, err := b.Build(bctx, node.BuildSpec{
		ProjectID: p.ID, Project: p.Slug, ServiceID: s.ID, Service: s.Slug, Deployment: depID,
		ContextDir: contextDir, Dockerfile: g.Dockerfile, Tag: tag, Fresh: fresh,
	}, func(line string) { dl.progress("log", line) }); err != nil {
		if errors.Is(bctx.Err(), context.DeadlineExceeded) {
			return "", i18n.E("git.error.build_timeout", "minutes", int(buildTimeout.Minutes()))
		}
		return "", err
	}
	return tag, nil
}

// buildContextDir resolves the subdirectory inside the workspace, refusing
// one that is a symlink leading out of the repository.
func buildContextDir(ws, subdir string) (string, error) {
	root, err := filepath.EvalSymlinks(ws)
	if err != nil {
		return "", err
	}
	if subdir == "" {
		return root, nil
	}
	dir, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(subdir)))
	if err != nil || !strings.HasPrefix(dir, root+string(filepath.Separator)) {
		return "", i18n.E("git.error.subdir", "dir", subdir)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return "", i18n.E("git.error.subdir", "dir", subdir)
	}
	return dir, nil
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// pruneBuilds keeps the images rollback can still use (the last few that
// went live) and removes the service's other builds.
func (m *Manager) pruneBuilds(ctx context.Context, serviceID string) {
	b, ok := m.node.(node.Builder)
	if !ok {
		return
	}
	deps, err := m.q.ListDeployments(ctx, dbq.ListDeploymentsParams{ServiceID: serviceID, Limit: 50})
	if err != nil {
		return
	}
	var keep []string
	n := 0
	for _, d := range deps {
		if d.ImageRef == "" || (d.Status != "live" && d.Status != "superseded") {
			continue
		}
		keep = append(keep, d.ImageRef)
		if n++; n > rollbackDepth {
			break
		}
	}
	if len(keep) == 0 {
		return // nothing went live yet: keep everything rather than guess
	}
	if err := b.PruneBuilds(ctx, serviceID, keep); err != nil {
		m.log.Warn("remove old builds", "service", serviceID, "error", err)
	}
}

// --- automatic deploys --------------------------------------------------------

// queuedDeploy is a push that arrived while a deploy was running.
type queuedDeploy struct {
	project, service string
	actor            Actor
	trigger          string // "webhook" or "auto"
}

// queue remembers one pending webhook deploy per service; more pushes while
// it waits collapse into it (the build always takes the branch's tip).
func (m *Manager) queue(serviceID string, q queuedDeploy) {
	m.queueMu.Lock()
	defer m.queueMu.Unlock()
	if m.queued == nil {
		m.queued = map[string]queuedDeploy{}
	}
	m.queued[serviceID] = q
}

// runQueued starts the deploy a push left waiting, once the running one ends.
func (m *Manager) runQueued(ctx context.Context, serviceID string) {
	m.queueMu.Lock()
	q, ok := m.queued[serviceID]
	delete(m.queued, serviceID)
	m.queueMu.Unlock()
	if !ok {
		return
	}
	trigger := q.trigger
	if trigger == "" {
		trigger = "webhook"
	}
	if _, err := m.Deploy(ctx, q.actor, q.project, q.service, trigger); err != nil {
		m.log.Warn("queued automatic deploy", "service", q.project+"/"+q.service, "error", err)
	}
}

// Hook results.
var (
	ErrHookUnknown   = errors.New("unknown webhook")
	ErrHookSignature = errors.New("invalid signature")
	ErrHookReplay    = errors.New("delivery already received")
	ErrHookStale     = errors.New("push outside the accepted time window")
	ErrHookMalformed = errors.New("malformed delivery")
)

// HookOutcome says what an accepted delivery did.
type HookOutcome string

// Outcomes of a valid delivery.
const (
	HookDeployed      HookOutcome = "deploying"
	HookQueued        HookOutcome = "queued"
	HookPong          HookOutcome = "pong"
	HookIgnoredEvent  HookOutcome = "ignored: event"
	HookIgnoredBranch HookOutcome = "ignored: branch"
	HookIgnoredRepo   HookOutcome = "ignored: repository"
	HookIgnoredDelete HookOutcome = "ignored: branch deleted"
)

// HookDelivery is a GitHub webhook request.
type HookDelivery struct {
	Token     string // from the URL
	Event     string // X-GitHub-Event
	ID        string // X-GitHub-Delivery
	Signature string // X-Hub-Signature-256
	Body      []byte
	// ContentType: GitHub sends JSON, or a form with the JSON in "payload"
	// (its default). The signature always covers the raw body.
	ContentType string
	IP          string
}

// GitHubHook handles a GitHub delivery: the URL token finds the service, the
// HMAC proves GitHub sent it, the delivery id and the push time stop a
// replay, and only a push to the configured branch deploys.
func (m *Manager) GitHubHook(ctx context.Context, d HookDelivery) (HookOutcome, error) {
	if len(d.Token) < 20 || len(d.Token) > 100 {
		return "", ErrHookUnknown
	}
	row, err := m.q.GetServiceGitByWebhook(ctx, sql.NullString{String: hookHash(d.Token), Valid: true})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrHookUnknown
	}
	if err != nil {
		return "", err
	}
	a := Actor{IP: d.IP}
	deny := func(reason string, e error) (HookOutcome, error) {
		m.record(ctx, a, "service.webhook", "service", row.ServiceID, audit.Denied, map[string]any{"reason": reason, "delivery": truncate(d.ID, 64)})
		return "", e
	}
	secret, err := m.openGit(row.WebhookSecretEnc, row.ServiceID, "webhook_secret")
	if err != nil {
		return "", err
	}
	if !gitsrc.VerifySignature([]byte(secret), d.Body, d.Signature) {
		return deny("signature", ErrHookSignature)
	}
	switch d.Event {
	case "ping":
		return HookPong, nil
	case "push":
	default:
		return HookIgnoredEvent, nil
	}
	if !gitsrc.ValidDelivery(d.ID) {
		return "", ErrHookMalformed
	}
	payload := d.Body
	if strings.HasPrefix(d.ContentType, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(d.Body))
		if err != nil {
			return "", ErrHookMalformed
		}
		payload = []byte(vals.Get("payload"))
	}
	push, err := gitsrc.ParsePush(payload)
	if err != nil {
		return "", ErrHookMalformed
	}
	now := m.now()
	_ = m.q.PruneWebhookDeliveries(ctx, now.Add(-deliveryRetention).Unix())
	n, err := m.q.RecordWebhookDelivery(ctx, dbq.RecordWebhookDeliveryParams{DeliveryID: d.ID, ServiceID: row.ServiceID, ReceivedAt: now.Unix()})
	if err != nil {
		return "", err
	}
	if n == 0 {
		return deny("replay", ErrHookReplay)
	}
	if push.PushedAt.IsZero() || now.Sub(push.PushedAt) > webhookWindow || push.PushedAt.Sub(now) > webhookSkew {
		return deny("stale", ErrHookStale)
	}
	if len(push.Repo) > 0 {
		same := false
		for _, u := range push.Repo {
			same = same || gitsrc.SameRepo(u, row.RepoUrl)
		}
		if !same {
			return HookIgnoredRepo, nil
		}
	}
	if push.Deleted {
		return HookIgnoredDelete, nil
	}
	if push.Branch() != row.Branch {
		return HookIgnoredBranch, nil
	}
	summary := map[string]any{"delivery": d.ID, "commit": shortSHA(push.After), "branch": row.Branch}
	_, err = m.Deploy(ctx, a, row.ProjectSlug, row.ServiceSlug, "webhook")
	switch {
	case errors.Is(err, ErrDeployRunning):
		m.queue(row.ServiceID, queuedDeploy{project: row.ProjectSlug, service: row.ServiceSlug, actor: a})
		// The running deploy may have ended between the two steps and found
		// nothing queued: then start it here.
		if n, err := m.q.HasRunningDeployment(ctx, row.ServiceID); err == nil && n == 0 {
			m.runQueued(context.WithoutCancel(ctx), row.ServiceID)
		}
		summary["queued"] = true
		m.record(ctx, a, "service.webhook", "service", row.ServiceID, audit.OK, summary)
		return HookQueued, nil
	case err != nil:
		m.record(ctx, a, "service.webhook", "service", row.ServiceID, audit.Error, summary)
		return "", err
	}
	m.record(ctx, a, "service.webhook", "service", row.ServiceID, audit.OK, summary)
	return HookDeployed, nil
}
