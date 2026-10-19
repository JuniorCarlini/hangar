package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path"
	"time"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// ComposeRepo is the repository a compose file is read from; its services
// with build: are built from it.
type ComposeRepo struct {
	GitSourceInput
	CredentialID string
}

// composeFiles are the names docker compose looks for, in its order.
var composeFiles = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// maxDockerfile is how much of a Dockerfile is read to find its EXPOSE.
const maxDockerfile = 256 << 10

// peekTimeout bounds the clone that only reads a few files.
const peekTimeout = 2 * time.Minute

// fetchRepo clones the branch (shallow, bare, no checkout) into a temporary
// directory under the build directory (a crash leaves it to SetBuildDir's
// cleanup) and returns its tree and the function that removes it.
func (m *Manager) fetchRepo(ctx context.Context, url, branch, token string) (*gitsrc.Snapshot, func(), error) {
	if m.buildDir != "" {
		if err := os.MkdirAll(m.buildDir, 0o700); err != nil {
			return nil, func() {}, err
		}
	}
	dir, err := os.MkdirTemp(m.buildDir, "dep_peek_")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	cctx, cancel := context.WithTimeout(ctx, peekTimeout)
	defer cancel()
	snap, _, err := gitsrc.Fetch(cctx, dir, gitsrc.Source{URL: url, Branch: branch, Token: token})
	if err != nil {
		cleanup()
		var ie *i18n.Error
		if errors.As(err, &ie) {
			return nil, func() {}, err
		}
		return nil, func() {}, i18n.E("git.error.unreachable", "error", newMasker(token).apply(err.Error()))
	}
	return snap, cleanup, nil
}

// dockerfilePort reads the port a repository's Dockerfile EXPOSEs (0 = none
// or unreadable). It never fails the caller: the port is a convenience.
func (m *Manager) dockerfilePort(ctx context.Context, in GitSourceInput, token string) int {
	snap, cleanup, err := m.fetchRepo(ctx, in.URL, in.Branch, token)
	defer cleanup()
	if err != nil {
		return 0
	}
	b, ok, err := snap.ReadFile(path.Join(in.Subdir, in.Dockerfile), maxDockerfile)
	if !ok || err != nil {
		return 0
	}
	return exposedPort(b)
}

// PlanCompose parses a pasted compose file and checks it against the
// project (identifiers already taken).
func (m *Manager) PlanCompose(ctx context.Context, projectSlug string, data []byte) (ComposePlan, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return ComposePlan{}, err
	}
	plan, err := ParseCompose(data, false)
	if err != nil {
		return plan, err
	}
	return plan, m.checkPlan(ctx, p, &plan)
}

// repoToken validates the repository and returns the token to read it with.
func (m *Manager) repoToken(ctx context.Context, p dbq.Project, repo *ComposeRepo) (string, error) {
	if err := repo.normalize(); err != nil {
		return "", err
	}
	if repo.CredentialID == "" {
		return "", nil
	}
	return m.credentialToken(ctx, p.ID, repo.URL, repo.CredentialID)
}

// PlanComposeFromRepo reads the compose file at the root of the repository
// (compose.yaml, docker-compose.yml…) and plans it: services with build:
// become builds of that repository, and their port comes from the
// Dockerfile's EXPOSE when the file does not say.
func (m *Manager) PlanComposeFromRepo(ctx context.Context, projectSlug string, repo *ComposeRepo) (ComposePlan, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return ComposePlan{}, err
	}
	token, err := m.repoToken(ctx, p, repo)
	if err != nil {
		return ComposePlan{}, err
	}
	snap, cleanup, err := m.fetchRepo(ctx, repo.URL, repo.Branch, token)
	defer cleanup()
	if err != nil {
		return ComposePlan{}, err
	}
	var data []byte
	file := ""
	for _, name := range composeFiles {
		b, ok, err := snap.ReadFile(name, MaxComposeBytes)
		if errors.Is(err, gitsrc.ErrTooLarge) {
			return ComposePlan{}, i18n.E("compose.error.too_large", "max", MaxComposeBytes>>10)
		}
		if err != nil {
			return ComposePlan{}, err
		}
		if ok {
			data, file = b, name
			break
		}
	}
	if file == "" {
		return ComposePlan{}, i18n.E("compose.error.not_in_repo")
	}
	plan, err := ParseCompose(data, true)
	plan.File = file
	if err != nil {
		return plan, err
	}
	for i := range plan.Services {
		s := &plan.Services[i]
		if s.Kind != ComposeGit {
			continue
		}
		df := path.Join(s.Subdir, s.Dockerfile)
		b, ok, err := snap.ReadFile(df, maxDockerfile)
		switch {
		case !ok:
			s.Problem = &i18n.Error{Key: "compose.problem.no_dockerfile", Args: []any{"path", df}}
		case err == nil && s.Port == 0:
			if port := exposedPort(b); port > 0 {
				s.Port = port
				s.add(NoteOK, i18n.E("compose.note.port_expose", "port", port))
			}
		}
	}
	return plan, m.checkPlan(ctx, p, &plan)
}

// checkPlan marks the services that cannot be created in this project.
func (m *Manager) checkPlan(ctx context.Context, p dbq.Project, plan *ComposePlan) error {
	_, canBuild := m.node.(node.Builder)
	canBuild = canBuild && m.buildDir != ""
	for i := range plan.Services {
		s := &plan.Services[i]
		if s.Kind == ComposeSkip || s.Problem != nil {
			continue
		}
		if err := m.slugFree(ctx, p, s.Slug); errors.Is(err, ErrExists) {
			s.Problem = &i18n.Error{Key: "compose.problem.taken", Args: []any{"slug", s.Slug}}
		} else if err != nil {
			return err
		}
		if s.Kind == ComposeGit && !canBuild {
			s.Problem = &i18n.Error{Key: "git.error.no_builder"}
		}
	}
	return nil
}

// CreateFromCompose creates every service of the plan in one transaction —
// all or nothing — and deploys them, the databases first. The caller plans
// the file again right before (the preview is never trusted); repo is the
// repository the builds come from (nil for a pasted file).
func (m *Manager) CreateFromCompose(ctx context.Context, a Actor, projectSlug string, plan ComposePlan, repo *ComposeRepo) ([]dbq.Service, error) {
	if err := m.requireNode(); err != nil {
		return nil, err
	}
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return nil, err
	}
	if err := m.checkPlan(ctx, p, &plan); err != nil {
		return nil, err
	}
	if !plan.Creatable() {
		return nil, i18n.E("compose.error.blocked")
	}
	hasGit := false
	for _, s := range plan.Services {
		hasGit = hasGit || s.Kind == ComposeGit
	}
	if hasGit {
		if repo == nil || !plan.FromRepo {
			return nil, i18n.E("compose.note.build_needs_repo")
		}
		token, err := m.repoToken(ctx, p, repo)
		if err != nil {
			return nil, err
		}
		if err := checkAccess(ctx, repo.URL, repo.Branch, token); err != nil {
			return nil, err
		}
	}

	// Templates are rendered (and their passwords generated) before the
	// transaction: rendering checks the inputs and fails early.
	type tpl struct {
		t       *templates.Template
		r       templates.Rendered
		secrets []string
	}
	rendered := map[string]tpl{}
	for _, s := range plan.Services {
		if s.Kind != ComposeTemplate {
			continue
		}
		t, ok := m.catalog().Get(s.Template)
		if !ok {
			return nil, ErrNotFound
		}
		r, secrets, err := m.renderTemplate(ctx, p, t, s.Slug, s.Inputs)
		if err != nil {
			return nil, err
		}
		rendered[s.Slug] = tpl{t, r, secrets}
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	q := m.q.WithTx(tx)
	now := m.now().Unix()
	var dbs, apps []string
	for _, s := range plan.Services {
		var id string
		switch s.Kind {
		case ComposeSkip:
			continue
		case ComposeTemplate:
			x := rendered[s.Slug]
			created, err := m.insertRendered(ctx, q, p, x.t, x.r, x.secrets, a.Sudo)
			if err != nil {
				return nil, err
			}
			dbs = append(dbs, created...)
			id = created[0]
		default:
			in := ServiceInput{Slug: s.Slug, Image: s.Image, Port: s.Port, MemoryMB: s.MemoryMB, CPUs: s.CPUs}
			if s.Kind == ComposeGit {
				in.Image = node.BuildRepo(p.Slug, s.Slug)
			}
			if in.MemoryMB == 0 {
				in.MemoryMB = DefaultMemoryMB
			}
			if in.CPUs == 0 {
				in.CPUs = DefaultCPUs
			}
			params := m.serviceParams(p, in)
			params.StopGraceS = int64(s.StopGrace)
			if len(s.Command) > 0 {
				b, _ := json.Marshal(s.Command)
				params.CommandJson = string(b)
			}
			if err := q.CreateService(ctx, params); err != nil {
				return nil, err
			}
			id = params.ID
			if err := defaultEndpoint(ctx, q, p.Slug, id, s.Slug, int64(s.Port), now); err != nil {
				return nil, err
			}
			for _, e := range s.Env {
				sealed, err := m.box.Seal([]byte(e.Value), envAD(id, e.Key))
				if err != nil {
					return nil, err
				}
				if err := q.UpsertEnv(ctx, dbq.UpsertEnvParams{ServiceID: id, Key: e.Key, ValueEnc: sealed, Secret: boolInt(e.Secret), UpdatedAt: now}); err != nil {
					return nil, err
				}
			}
			for _, v := range s.Volumes {
				if err := q.AddVolume(ctx, dbq.AddVolumeParams{ServiceID: id, Name: v.Name, Path: v.Path}); err != nil {
					return nil, err
				}
			}
			if s.Kind == ComposeGit {
				if err := q.CreateServiceGit(ctx, dbq.CreateServiceGitParams{
					ServiceID: id, RepoUrl: repo.URL, Branch: repo.Branch, Subdir: s.Subdir, Dockerfile: s.Dockerfile,
					CredentialID: sql.NullString{String: repo.CredentialID, Valid: repo.CredentialID != ""}, UpdatedAt: now,
				}); err != nil {
					return nil, err
				}
			}
			apps = append(apps, id)
		}
		if s.Placed {
			if err := q.SetCanvasPosition(ctx, dbq.SetCanvasPositionParams{
				CanvasX: sql.NullInt64{Int64: int64(s.X), Valid: true}, CanvasY: sql.NullInt64{Int64: int64(s.Y), Valid: true}, ID: id,
			}); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	extra := map[string]any{"compose": true}
	if plan.File != "" {
		extra["compose_file"] = plan.File
	}
	out, err := m.recordCreated(ctx, a, p, append(dbs, apps...), extra)
	if err != nil {
		return out, err
	}
	// Databases first: the apps' first deploy resolves references to them.
	for _, s := range out {
		if _, err := m.Deploy(ctx, a, p.Slug, s.Slug, "create"); err != nil {
			return out, err
		}
	}
	return out, nil
}
