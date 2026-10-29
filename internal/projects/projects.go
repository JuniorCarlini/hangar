// Package projects manages projects, services, variables and deploys. It talks
// to containers only through node.Node and records every state change in the
// audit log.
package projects

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/edge"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
	"github.com/JuniorCarlini/hangar/internal/volumes"
)

// Limits and defaults for a new service (docs/05).
const (
	DefaultMemoryMB = 512
	DefaultCPUs     = 1.0
	DefaultPids     = 512
	MaxEnvValue     = 32 << 10
	deployTimeout   = 15 * time.Minute
)

// Errors the UI translates.
var (
	ErrNotFound       = &i18n.Error{Key: "error.not_found"}
	ErrExists         = &i18n.Error{Key: "error.exists"}
	ErrHasServices    = &i18n.Error{Key: "project.error.has_services"}
	ErrDeployRunning  = &i18n.Error{Key: "service.error.deploy_running"}
	ErrServiceBusy    = &i18n.Error{Key: "service.error.busy"}
	ErrDockerDisabled = &i18n.Error{Key: "error.docker_unavailable"}
)

// reservedProjects would collide with Hangar's own network (hangar_edge) and
// containers (hangar_*).
var reservedProjects = map[string]bool{"edge": true, "hangar": true}

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// Manager is the projects layer.
type Manager struct {
	db    *sql.DB
	q     *dbq.Queries
	box   *secrets.Box
	node  node.Node
	audit *audit.Logger
	log   *slog.Logger
	now   func() time.Time
	wg    sync.WaitGroup
	// edge is the EdgeApplier (SetEdge), in a box: the edge can come up
	// after the panel (Caddy or Docker late at boot) and is read by deploys
	// already running.
	edge atomic.Pointer[edgeBox]
	// edgeDown says why the edge proxy is not serving everything
	// (SetEdgeDown), "" when it is.
	edgeDown atomic.Pointer[string]
	// edgeStockImage: the edge runs the stock Caddy image, which has no DNS
	// provider module (SetEdgeImage).
	edgeStockImage atomic.Bool
	// firewall is set by SetFirewall.
	firewall FirewallWriter
	edgeCap  int
	// buildDir holds the build workspaces (SetBuildDir).
	buildDir string
	queueMu  sync.Mutex
	queued   map[string]queuedDeploy
	// busy holds the services with a start, stop, restart or the start of
	// a deploy under way (claim), so a second click cannot run the same
	// thing alongside.
	busy sync.Map
	// held are the services a backup paused or stopped (Hold).
	held heldSet
	// notifier hears about failed deploys (SetDeployNotifier).
	notifier DeployNotifier
	// created hears about services just created from a template
	// (SetTemplateCreated).
	created func(context.Context, Actor, []dbq.Service)
	// repos caches what each Git credential can list (github_repos.go).
	reposMu sync.Mutex
	repos   map[string]cachedRepos
	// cfgBase is the base domain from hangar.toml (SetBaseDomain); the one in
	// effect (baseDomain()) is the panel's edge_settings when set, else this.
	// Automatic links live under it, so a custom domain must not take one of
	// their names.
	cfgBase string
	dbBase  atomic.Value // string, from edge_settings (edgedns.go)
	// dnsCheck replaces edge.CheckDNSToken in tests.
	dnsCheck  func(ctx context.Context, provider, zone string, token []byte) error
	panelHost string
	// templates is the service catalog (SetTemplates); the embedded one
	// until the community catalog is wired in.
	templates *templates.Registry
	// vols writes the volume limits for the root unit (SetVolumeLimits);
	// volUsage reads a plain volume's size; volMu keeps the limit steps
	// and the admin's requests apart; volKick wakes RunVolumeLimits.
	vols     *volumes.Writer
	volUsage func(name string) (int64, bool)
	volMu    sync.Mutex
	volKick  chan struct{}
}

// New creates the Manager. n may be nil when Docker is unavailable: the panel
// stays up and container actions return ErrDockerDisabled.
func New(db *sql.DB, box *secrets.Box, n node.Node, al *audit.Logger, log *slog.Logger) *Manager {
	return &Manager{
		db: db, q: dbq.New(db), box: box, node: n, audit: al, log: log, now: time.Now,
		templates: templates.NewRegistry(templates.Builtin()),
	}
}

// DockerAvailable reports whether Docker is connected.
func (m *Manager) DockerAvailable() bool { return m.node != nil }

// claim marks a service busy; false when it already is.
func (m *Manager) claim(serviceID string) bool {
	_, taken := m.busy.LoadOrStore(serviceID, struct{}{})
	return !taken
}

func (m *Manager) release(serviceID string) { m.busy.Delete(serviceID) }

// Wait waits for in-flight deploys to finish (shutdown and tests).
func (m *Manager) Wait() { m.wg.Wait() }

// Actor is who is acting, for the audit log.
type Actor struct {
	UserID string
	IP     string
	// Sudo: the person confirmed their password moments ago. Only then may
	// a creation put something on the internet by itself (a template born
	// public); without it, everything is born internal.
	Sudo bool
}

func (m *Manager) record(ctx context.Context, a Actor, action, targetType, targetID string, outcome audit.Outcome, summary map[string]any) {
	if m.audit == nil {
		return
	}
	_ = m.audit.Record(context.WithoutCancel(ctx), audit.Entry{
		ActorID: a.UserID, IP: a.IP, Action: action, Outcome: outcome,
		TargetType: targetType, TargetID: targetID, Summary: summary,
	})
}

func (m *Manager) requireNode() error {
	if m.node == nil {
		return ErrDockerDisabled
	}
	return nil
}

// --- projects ---------------------------------------------------------------

// Project is what the UI shows about a project.
type Project struct {
	ID       string
	Slug     string
	Name     string
	Services int64
}

// ListProjects lists the projects.
func (m *Manager) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := m.q.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(rows))
	for _, r := range rows {
		out = append(out, Project{ID: r.ID, Slug: r.Slug, Name: r.Name, Services: r.ServiceCount})
	}
	return out, nil
}

// GetProject looks a project up by slug.
func (m *Manager) GetProject(ctx context.Context, slug string) (dbq.Project, error) {
	p, err := m.q.GetProjectBySlug(ctx, slug)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// CreateProject creates the project and its isolated network.
func (m *Manager) CreateProject(ctx context.Context, a Actor, slug, name string) (dbq.Project, error) {
	slug = strings.TrimSpace(slug)
	name = strings.TrimSpace(name)
	if !node.SlugRE.MatchString(slug) {
		return dbq.Project{}, i18n.E("project.error.slug")
	}
	if reservedProjects[slug] {
		return dbq.Project{}, i18n.E("project.error.reserved", "slug", slug)
	}
	if name == "" {
		name = slug
	}
	if len(name) > 80 {
		return dbq.Project{}, i18n.E("project.error.name_too_long", "max", 80)
	}
	if err := m.requireNode(); err != nil {
		return dbq.Project{}, err
	}
	if _, err := m.q.GetProjectBySlug(ctx, slug); err == nil {
		return dbq.Project{}, ErrExists
	}
	now := m.now().Unix()
	p := dbq.Project{ID: ids.New("prj_"), Slug: slug, Name: name, CreatedAt: now, UpdatedAt: now}
	if err := m.node.EnsureProjectNetwork(ctx, p.ID, p.Slug); err != nil {
		return dbq.Project{}, err
	}
	if err := m.q.CreateProject(ctx, dbq.CreateProjectParams{ID: p.ID, Slug: p.Slug, Name: p.Name, CreatedAt: now, UpdatedAt: now}); err != nil {
		return dbq.Project{}, err
	}
	m.record(ctx, a, "project.create", "project", p.ID, audit.OK, map[string]any{"slug": slug})
	return p, nil
}

// CreateProjectNamed creates a project from the name alone: its identifier
// (container prefix, network) is derived from the name, as for services,
// with -2, -3… when another project or a reserved name already has it.
func (m *Manager) CreateProjectNamed(ctx context.Context, a Actor, name string) (dbq.Project, error) {
	name = strings.TrimSpace(name)
	if Slugify(name) == "" {
		return dbq.Project{}, i18n.E("project.error.name")
	}
	rows, err := m.q.ListProjects(ctx)
	if err != nil {
		return dbq.Project{}, err
	}
	taken := map[string]bool{}
	for k := range reservedProjects {
		taken[k] = true
	}
	for _, p := range rows {
		taken[p.Slug] = true
	}
	return m.CreateProject(ctx, a, UniqueName(name, taken), name)
}

// SetServiceResources changes the memory and CPU limits a service runs
// with, with the same bounds as when it is created. They are part of the
// container, so they take effect on the next deploy.
func (m *Manager) SetServiceResources(ctx context.Context, a Actor, projectSlug, serviceSlug string, memoryMB int, cpus float64) error {
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	switch {
	case memoryMB < 16 || memoryMB > 64*1024:
		return i18n.E("service.error.memory")
	case cpus < 0.05 || cpus > 64:
		return i18n.E("service.error.cpus")
	}
	from := map[string]any{"memory_mb": s.MemoryBytes >> 20, "cpus": float64(s.NanoCpus) / 1e9}
	if err := m.q.SetServiceResources(ctx, dbq.SetServiceResourcesParams{
		MemoryBytes: int64(memoryMB) << 20, NanoCpus: int64(cpus * 1e9), UpdatedAt: m.now().Unix(), ID: s.ID,
	}); err != nil {
		return err
	}
	m.record(ctx, a, "service.resources", "service", s.ID, audit.OK, map[string]any{"from": from, "memory_mb": memoryMB, "cpus": cpus})
	return nil
}

// DeleteProject deletes an empty project and its network.
func (m *Manager) DeleteProject(ctx context.Context, a Actor, slug string) error {
	p, err := m.GetProject(ctx, slug)
	if err != nil {
		return err
	}
	svcs, err := m.q.ListServices(ctx, p.ID)
	if err != nil {
		return err
	}
	if len(svcs) > 0 {
		return ErrHasServices
	}
	if err := m.requireNode(); err != nil {
		return err
	}
	// Connected projects have containers on this network: disconnect them
	// first, or Docker refuses to remove it.
	linked, err := m.q.LinkedProjects(ctx, p.ID)
	if err != nil {
		return err
	}
	for _, l := range linked {
		if err := m.UnlinkProjects(ctx, a, p.Slug, l.Slug); err != nil {
			return err
		}
	}
	if err := m.node.RemoveProjectNetwork(ctx, p.Slug); err != nil {
		return err
	}
	if err := m.q.DeleteProject(ctx, p.ID); err != nil {
		return err
	}
	m.record(ctx, a, "project.delete", "project", p.ID, audit.OK, map[string]any{"slug": slug})
	return nil
}

// --- services ---------------------------------------------------------------

// ServiceInput is the service creation form. Name is what the user typed;
// the identifier (Slug) is derived from it. Slug alone is still accepted
// (the API and older callers send it).
type ServiceInput struct {
	Name     string
	Slug     string
	Image    string
	Port     int
	MemoryMB int
	CPUs     float64
}

// GetService looks the service up inside the project. Always looking up by
// the (project, service) pair keeps anyone from reaching another project's
// service by editing the URL.
func (m *Manager) GetService(ctx context.Context, projectSlug, serviceSlug string) (dbq.Project, dbq.Service, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return p, dbq.Service{}, err
	}
	s, err := m.q.GetService(ctx, dbq.GetServiceParams{ProjectID: p.ID, Slug: serviceSlug})
	if errors.Is(err, sql.ErrNoRows) {
		return p, s, ErrNotFound
	}
	return p, s, err
}

// ListServices lists the project's services.
func (m *Manager) ListServices(ctx context.Context, projectID string) ([]dbq.Service, error) {
	return m.q.ListServices(ctx, projectID)
}

// CreateService stores the service and triggers its first deploy.
func (m *Manager) CreateService(ctx context.Context, a Actor, projectSlug string, in ServiceInput) (dbq.Service, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return dbq.Service{}, err
	}
	if err := m.checkServiceInput(ctx, p, &in); err != nil {
		return dbq.Service{}, err
	}
	params := m.serviceParams(p, in)
	if err := m.q.CreateService(ctx, params); err != nil {
		return dbq.Service{}, err
	}
	if err := defaultEndpoint(ctx, m.q, p.Slug, params.ID, params.Slug, params.InternalPort, m.now().Unix()); err != nil {
		return dbq.Service{}, err
	}
	m.record(ctx, a, "service.create", "service", params.ID, audit.OK, map[string]any{"project": p.Slug, "service": params.Slug, "image": params.Image})
	s, err := m.q.GetServiceByID(ctx, params.ID)
	if err != nil {
		return dbq.Service{}, err
	}
	if _, err := m.Deploy(ctx, a, p.Slug, s.Slug, "create"); err != nil {
		return s, err
	}
	return s, nil
}

// checkServiceInput normalizes and validates the creation form (the image
// is checked only when set: services built from Git have none yet).
func (m *Manager) checkServiceInput(ctx context.Context, p dbq.Project, in *ServiceInput) error {
	in.Slug = strings.TrimSpace(in.Slug)
	if strings.TrimSpace(in.Name) != "" {
		var err error
		if in.Slug, err = slugFromName(in.Name); err != nil {
			return err
		}
	}
	in.Image = strings.TrimSpace(in.Image)
	if in.MemoryMB == 0 {
		in.MemoryMB = DefaultMemoryMB
	}
	if in.CPUs == 0 {
		in.CPUs = DefaultCPUs
	}
	switch {
	case !node.SlugRE.MatchString(in.Slug):
		return i18n.E("service.error.slug")
	case !node.ImageRE.MatchString(in.Image):
		return i18n.E("service.error.image")
	case in.Port < 0 || in.Port > 65535:
		return i18n.E("service.error.port")
	case in.MemoryMB < 16 || in.MemoryMB > 64*1024:
		return i18n.E("service.error.memory")
	case in.CPUs < 0.05 || in.CPUs > 64:
		return i18n.E("service.error.cpus")
	}
	return m.slugFree(ctx, p, in.Slug)
}

// slugFree fails with a clear message when the project already has a
// service with this identifier.
func (m *Manager) slugFree(ctx context.Context, p dbq.Project, slug string) error {
	_, err := m.q.GetService(ctx, dbq.GetServiceParams{ProjectID: p.ID, Slug: slug})
	switch {
	case err == nil:
		return slugTaken(slug)
	case errors.Is(err, sql.ErrNoRows):
		return nil
	}
	return err
}

// takenError is ErrExists with the identifier that collided, so the form
// can say which one.
type takenError struct{ msg *i18n.Error }

func slugTaken(slug string) error {
	return &takenError{msg: &i18n.Error{Key: "service.error.slug_taken", Args: []any{"slug", slug}}}
}

func (e *takenError) Error() string        { return e.msg.Error() }
func (e *takenError) Unwrap() error        { return e.msg }
func (e *takenError) Is(target error) bool { return target == ErrExists }

func (m *Manager) serviceParams(p dbq.Project, in ServiceInput) dbq.CreateServiceParams {
	now := m.now().Unix()
	return dbq.CreateServiceParams{
		ID: ids.New("svc_"), ProjectID: p.ID, Slug: in.Slug, Image: in.Image, InternalPort: int64(in.Port),
		MemoryBytes: int64(in.MemoryMB) << 20, NanoCpus: int64(in.CPUs * 1e9), PidsLimit: DefaultPids,
		CommandJson: "[]", CreatedAt: now, UpdatedAt: now,
	}
}

// Deploy starts a deploy in the background and returns its id. The result
// lands in the deploy history and the audit log. A service with a Git
// source is cloned and built first.
func (m *Manager) Deploy(ctx context.Context, a Actor, projectSlug, serviceSlug, trigger string) (string, error) {
	return m.deploy(ctx, a, projectSlug, serviceSlug, deployRequest{trigger: trigger})
}

// Rebuild deploys "from scratch": a service built from Git is built
// without the layer cache and with its base images pulled again; a service
// run from an image must get it from the registry (no falling back on the
// local copy). For a dependency that changed upstream under the same tag,
// or a cache that went bad.
func (m *Manager) Rebuild(ctx context.Context, a Actor, projectSlug, serviceSlug string) (string, error) {
	return m.deploy(ctx, a, projectSlug, serviceSlug, deployRequest{trigger: "rebuild", fresh: true})
}

// deployRequest is one deploy: image, when set, replaces the service's image
// for this deploy only and skips any build (rollback to a pinned image);
// commit is the commit that image was built from; fresh skips every cache
// (Rebuild); revertImage, when set, is the image the service ran before
// this deploy changed it (ChangeImageTag): a failed deploy puts it back.
type deployRequest struct {
	trigger     string
	image       string
	commit      gitsrc.Commit
	fresh       bool
	revertImage string
}

// deploy runs a deploy in the background.
func (m *Manager) deploy(ctx context.Context, a Actor, projectSlug, serviceSlug string, req deployRequest) (string, error) {
	if err := m.requireNode(); err != nil {
		return "", err
	}
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return "", err
	}
	src, isGit, err := m.gitRow(ctx, s.ID)
	if err != nil {
		return "", err
	}
	build := isGit && req.image == ""
	var builder node.Builder
	if build {
		var ok bool
		if builder, ok = m.node.(node.Builder); !ok || m.buildDir == "" {
			return "", i18n.E("git.error.no_builder")
		}
	}
	image := req.image
	if image == "" {
		image = s.Image
	}
	// The history shows the image as the user knows it (the tag, or the
	// repository and branch); the exact image that went live is pinned
	// separately in image_ref.
	shown := s.Image
	if isGit {
		shown = gitsrc.Display(src.RepoUrl) + "@" + src.Branch
	}
	// From the check to the deployment row (which then answers the
	// check), no other deploy or action of this service may start.
	if !m.claim(s.ID) {
		return "", ErrServiceBusy
	}
	defer m.release(s.ID)
	if n, err := m.q.HasRunningDeployment(ctx, s.ID); err != nil {
		return "", err
	} else if n > 0 {
		return "", ErrDeployRunning
	}
	env, hash, err := m.envFor(ctx, s)
	if err != nil {
		return "", err
	}
	raw := env
	if env, err = m.resolveRefs(ctx, p, env); err != nil {
		return "", err
	}
	mask, err := m.deployMask(ctx, s, src, raw, env)
	if err != nil {
		return "", err
	}
	domains, err := m.q.CountDomains(ctx, s.ID)
	if err != nil {
		return "", err
	}
	extras, err := m.specExtras(ctx, p, s)
	if err != nil {
		return "", err
	}
	// A volume whose data is moving to or from its size-limited image
	// must not be mounted meanwhile; a new one waits for its image.
	waitVolumes, err := m.checkVolumesFree(ctx, p, s, extras.volumes)
	if err != nil {
		return "", err
	}
	var cmd, preDeploy, validate []string
	_ = json.Unmarshal([]byte(s.CommandJson), &cmd)
	_ = json.Unmarshal([]byte(s.PredeployJson), &preDeploy)
	_ = json.Unmarshal([]byte(s.ValidateJson), &validate)
	// Whether a version was serving before this deploy: a failure that
	// never reached the node (clone, build) leaves it as it was.
	_, lastErr := m.q.LastLiveDeployment(ctx, s.ID)
	hadLive := lastErr == nil
	restore := m.restorePolicy(ctx, s, image)
	cmd = m.withWALArchiving(ctx, s, cmd, extras.volumes)

	depID := ids.New("dep_")
	if err := m.q.CreateDeployment(ctx, dbq.CreateDeploymentParams{
		ID: depID, ServiceID: s.ID, Image: shown, EnvHash: hash, Trigger: req.trigger,
		CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, StartedAt: m.now().Unix(),
	}); err != nil {
		return "", err
	}
	if req.commit.SHA != "" {
		_ = m.q.SetDeploymentCommit(ctx, dbq.SetDeploymentCommitParams{CommitSha: req.commit.SHA, CommitMessage: req.commit.Message, ID: depID})
	}
	if err := m.q.SetDesiredState(ctx, dbq.SetDesiredStateParams{DesiredState: "running", UpdatedAt: m.now().Unix(), ID: s.ID}); err != nil {
		return "", err
	}

	spec := node.ServiceSpec{
		ProjectID: p.ID, Project: p.Slug, ServiceID: s.ID, Service: s.Slug, Deployment: depID,
		Image: image, Env: env, Command: cmd, MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCpus,
		PidsLimit: s.PidsLimit, ReadOnly: s.ReadOnly == 1,
		Edge:    domains > 0 || s.DynamicDomains == 1,
		Volumes: extras.volumes, Health: extras.health, CapAdd: extras.capAdd,
		Ports: extras.ports, Linked: extras.linked,
		StopGrace: min(time.Duration(s.StopGraceS)*time.Second, node.MaxStopGrace),
	}
	opt := node.DeployOptions{
		Strategy: Strategy(s, extras), PreDeploy: preDeploy,
		Port: int(s.InternalPort), HealthPath: s.HealthPath,
		// The service's startup grace, or as long as its own healthcheck
		// may take to decide (a game server loading its world, a database
		// replaying its log), within the deploy's own limit.
		HealthTimeout: node.HealthWait(extras.health, time.Duration(s.StartupGraceS)*time.Second, deployTimeout),
		// Built images exist only here; pulling them by name could fetch
		// someone else's image from a registry.
		LocalImage: isGit,
		Validate:   validate, ValidateTimeout: time.Duration(s.ValidateTimeoutS) * time.Second,
		Restore: restore, Fresh: req.fresh,
	}
	// The deploy (pulling or building can take a while) must not depend on
	// the HTTP request staying open.
	bg := context.WithoutCancel(ctx)
	m.wg.Add(1)
	m.markDeploying(p.Slug, s.Slug, true)
	go func() {
		defer m.wg.Done()
		defer m.runQueued(bg, s.ID)
		defer m.markDeploying(p.Slug, s.Slug, false)
		dl := newDeployLog(m, bg, depID)
		dl.mask = mask
		opt.Progress = dl.progress
		var res node.DeployResult
		var err error
		if len(waitVolumes) > 0 {
			err = m.waitVolumesReady(bg, waitVolumes)
		}
		if build && err == nil {
			spec.Image, err = m.buildFromGit(bg, p, s, src, depID, builder, dl, req.fresh)
		}
		if err == nil {
			dctx, cancel := context.WithTimeout(bg, deployTimeout)
			res, err = m.node.Deploy(dctx, spec, opt)
			cancel()
		}
		dl.flush()
		if res.ImageRef != "" {
			_ = m.q.SetDeploymentImageRef(bg, dbq.SetDeploymentImageRefParams{ImageRef: res.ImageRef, ID: depID})
		}
		status, outcome, errText := "live", audit.OK, sql.NullString{}
		previous := ""
		if err != nil {
			status, outcome = "failed", audit.Error
			errText = sql.NullString{String: truncate(mask.apply(err.Error()), 2000), Valid: true}
			previous = res.Previous
			if previous == "" { // the node was never reached
				previous = node.PreviousNone
				if hadLive {
					previous = node.PreviousLive
				}
			}
			m.log.Warn("deploy failed", "service", p.Slug+"/"+s.Slug, "error", errText.String, "previous", previous)
			if req.revertImage != "" {
				m.revertImage(bg, a, s.ID, s.Image, req.revertImage, depID)
			}
		}
		if ferr := m.q.FinishDeployment(bg, dbq.FinishDeploymentParams{
			Status: status, Error: errText, FinishedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: depID,
		}); ferr != nil {
			m.log.Error("record deploy end", "error", ferr)
		}
		if status == "live" {
			_ = m.q.SupersedeLive(bg, dbq.SupersedeLiveParams{ServiceID: s.ID, ID: depID})
			m.emptyVolumeTrash(bg, p, s)
			// A domain added while this deploy ran: make sure Caddy is on
			// the project network (a no-op when it already is).
			if !spec.Edge && m.needsEdge(bg, s.ID) {
				if err := m.node.ConnectEdge(bg, p.Slug); err != nil {
					m.log.Warn("join caddy to the project network", "service", p.Slug+"/"+s.Slug, "error", err)
				}
			}
		}
		if isGit {
			m.pruneBuilds(bg, s.ID)
		}
		summary := map[string]any{"deploy": depID, "image": spec.Image, "image_ref": res.ImageRef, "trigger": req.trigger, "strategy": opt.Strategy, "error": errText.String}
		if previous != "" {
			summary["previous"] = previous
		}
		m.record(bg, a, "service.deploy", "service", s.ID, outcome, summary)
		if m.notifier != nil {
			if err != nil {
				m.notifier.DeployFailed(bg, DeployFailure{
					ServiceID: s.ID, Service: p.Slug + "/" + s.Slug, Deployment: depID, Trigger: req.trigger,
					Phase: dl.failedPhase(), Reason: shortReason(errText.String), Previous: previous,
				})
			} else {
				m.notifier.DeploySucceeded(bg, s.ID, p.Slug+"/"+s.Slug)
			}
		}
	}()
	return depID, nil
}

// bootGrace is how long a started or restarted service still shows
// "updating" rather than "down": the container is up, the app may not be.
const bootGrace = 20 * time.Second

// settleDeploying clears the marker once the app had time to boot.
func (m *Manager) settleDeploying(project, service string) {
	time.AfterFunc(bootGrace, func() { m.markDeploying(project, service, false) })
}

// Action is start, stop or restart.
func (m *Manager) Action(ctx context.Context, a Actor, projectSlug, serviceSlug, action string) error {
	if err := m.requireNode(); err != nil {
		return err
	}
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if !m.claim(s.ID) {
		return ErrServiceBusy
	}
	defer m.release(s.ID)
	switch action {
	case "start":
		m.markDeploying(p.Slug, s.Slug, true)
		err = m.node.Start(ctx, p.Slug, s.Slug)
		m.settleDeploying(p.Slug, s.Slug)
		if err == nil {
			err = m.q.SetDesiredState(ctx, dbq.SetDesiredStateParams{DesiredState: "running", UpdatedAt: m.now().Unix(), ID: s.ID})
		}
	case "stop":
		err = m.node.Stop(ctx, p.Slug, s.Slug)
		if err == nil {
			err = m.q.SetDesiredState(ctx, dbq.SetDesiredStateParams{DesiredState: "stopped", UpdatedAt: m.now().Unix(), ID: s.ID})
		}
	case "restart":
		m.markDeploying(p.Slug, s.Slug, true)
		err = m.node.Restart(ctx, p.Slug, s.Slug)
		m.settleDeploying(p.Slug, s.Slug)
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	m.record(ctx, a, "service."+action, "service", s.ID, outcome, map[string]any{"service": p.Slug + "/" + s.Slug})
	return err
}

// DeleteService removes the container and the record. Volumes (stage 5) are
// not deleted here.
func (m *Manager) DeleteService(ctx context.Context, a Actor, projectSlug, serviceSlug string) error {
	if err := m.requireNode(); err != nil {
		return err
	}
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	// Its disks go with it, so one another service mounts must keep its
	// owner: delete the others first.
	if err := m.sharedVolumeError(ctx, s); err != nil {
		return err
	}
	if err := m.limitsMoving(ctx, s.ID); err != nil {
		return err
	}
	vols, err := m.q.ListVolumes(ctx, s.ID)
	if err != nil {
		return err
	}
	trash, err := m.q.ListVolumeTrash(ctx, s.ID)
	if err != nil {
		return err
	}
	for _, name := range trash {
		vols = append(vols, dbq.ListVolumesRow{Name: name})
	}
	if err := m.node.Remove(ctx, p.Slug, s.Slug); err != nil {
		return err
	}
	if err := m.q.DeleteService(ctx, s.ID); err != nil {
		return err
	}
	// Its disks go with it: left behind they would hold its data with no
	// service to show or delete them. A size-limited disk is a file of its
	// own, removed with its limit; the others are plain Docker volumes.
	// Mounts of another service's disk only drop the mount.
	if err := m.forgetVolumeLimits(ctx, p, s, nil); err != nil {
		m.log.Warn("remove the service's limited disks", "service", p.Slug+"/"+s.Slug, "error", err)
	}
	if vr, ok := m.node.(volumeRemover); ok {
		for _, v := range vols {
			if v.OwnerSlug != "" {
				continue
			}
			if _, limited := m.limitOf(ctx, node.VolumeName(p.Slug, s.Slug, v.Name)); limited {
				continue
			}
			if err := vr.RemoveVolume(context.WithoutCancel(ctx), p.Slug, s.Slug, v.Name); err != nil {
				m.log.Warn("remove the service's disk", "service", p.Slug+"/"+s.Slug, "disk", v.Name, "error", err)
			}
		}
	}
	// Images built for it have no other use: free the disk.
	if b, ok := m.node.(node.Builder); ok {
		if err := b.PruneBuilds(context.WithoutCancel(ctx), s.ID, nil); err != nil {
			m.log.Warn("remove the service's builds", "service", p.Slug+"/"+s.Slug, "error", err)
		}
	}
	m.record(ctx, a, "service.delete", "service", s.ID, audit.OK, map[string]any{"service": p.Slug + "/" + s.Slug})
	// Its domains and automatic links went with it: drop their routes now,
	// not at the next unrelated reload. The service is already gone, so a
	// failure here is only logged.
	if err := m.applyEdge(ctx); err != nil {
		m.log.Warn("reload edge after delete", "service", p.Slug+"/"+s.Slug, "error", err)
	}
	return nil
}

// Status reads the container state.
func (m *Manager) Status(ctx context.Context, projectSlug, serviceSlug string) (node.Status, error) {
	if err := m.requireNode(); err != nil {
		return node.Status{}, err
	}
	return m.node.Status(ctx, projectSlug, serviceSlug)
}

// Logs forwards the container logs.
func (m *Manager) Logs(ctx context.Context, projectSlug, serviceSlug string, opt node.LogOptions, fn func(node.LogLine) error) error {
	if err := m.requireNode(); err != nil {
		return err
	}
	if _, _, err := m.GetService(ctx, projectSlug, serviceSlug); err != nil {
		return err
	}
	return m.node.Logs(ctx, projectSlug, serviceSlug, opt, fn)
}

// Deployments lists the latest deploys.
func (m *Manager) Deployments(ctx context.Context, serviceID string, limit int64) ([]dbq.Deployment, error) {
	return m.q.ListDeployments(ctx, dbq.ListDeploymentsParams{ServiceID: serviceID, Limit: limit})
}

// --- variables --------------------------------------------------------------

// EnvVar is a variable as the UI shows it: clear value only when not secret.
type EnvVar struct {
	Key    string
	Value  string // empty for secrets
	Secret bool
}

func envAD(serviceID, key string) string { return "env_vars|" + serviceID + "|" + key }

// ListEnv lists the variables, masking the secret ones.
func (m *Manager) ListEnv(ctx context.Context, serviceID string) ([]EnvVar, error) {
	rows, err := m.q.ListEnv(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	out := make([]EnvVar, 0, len(rows))
	for _, r := range rows {
		v := EnvVar{Key: r.Key, Secret: r.Secret == 1}
		if !v.Secret {
			plain, err := m.box.Open(r.ValueEnc, envAD(serviceID, r.Key))
			if err != nil {
				return nil, err
			}
			v.Value = string(plain)
		}
		out = append(out, v)
	}
	return out, nil
}

// ListEnvValues is ListEnv with the secrets' values too: the panel shows
// every value to admins, so the .env editor holds the whole file.
func (m *Manager) ListEnvValues(ctx context.Context, serviceID string) ([]EnvVar, error) {
	rows, err := m.q.ListEnv(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	out := make([]EnvVar, 0, len(rows))
	for _, r := range rows {
		plain, err := m.box.Open(r.ValueEnc, envAD(serviceID, r.Key))
		if err != nil {
			return nil, err
		}
		out = append(out, EnvVar{Key: r.Key, Secret: r.Secret == 1, Value: string(plain)})
	}
	return out, nil
}

// SetEnvFile makes the service's variables exactly the .env text and keeps
// the text itself (comments, blank lines, order) for the editor: lines set
// as SetEnvBulk does, a variable missing from the text is deleted, and a
// "KEY=••••" line (a secret the editor did not show) keeps its value. An
// empty text deletes every variable.
func (m *Manager) SetEnvFile(ctx context.Context, a Actor, serviceID, text string) (int, error) {
	text, err := m.unhide(ctx, serviceID, text)
	if err != nil {
		return 0, err
	}
	vars, err := ParseEnvFile(text)
	if err != nil {
		return 0, err
	}
	changed := 0
	if len(vars) > 0 {
		if changed, err = m.SetEnvBulk(ctx, a, serviceID, text, false); err != nil {
			return 0, err
		}
	}
	keep := map[string]bool{}
	for _, x := range vars {
		keep[x.Key] = true
	}
	cur, err := m.q.ListEnv(ctx, serviceID)
	if err != nil {
		return changed, err
	}
	for _, e := range cur {
		if keep[e.Key] {
			continue
		}
		if err := m.DeleteEnv(ctx, a, serviceID, e.Key); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, m.storeEnvFile(ctx, serviceID, text)
}

// SetEnv creates or replaces a variable.
// SetBaseDomain tells the manager the edge's base domain ("" = none).
func (m *Manager) SetBaseDomain(d string) { m.cfgBase = strings.ToLower(strings.TrimSuffix(d, ".")) }

// SetPanelHost reserves the panel's public hostname: no service domain may
// take it.
func (m *Manager) SetPanelHost(h string) { m.panelHost = strings.ToLower(h) }

func (m *Manager) SetEnv(ctx context.Context, a Actor, serviceID, key, value string, secret bool) error {
	key = strings.TrimSpace(key)
	if !envKeyRE.MatchString(key) {
		return i18n.E("env.error.key")
	}
	if len(value) > MaxEnvValue {
		return i18n.E("env.error.too_large", "max", MaxEnvValue>>10)
	}
	if strings.ContainsRune(value, 0) {
		return i18n.E("env.error.null_byte")
	}
	sealed, err := m.box.Seal([]byte(value), envAD(serviceID, key))
	if err != nil {
		return err
	}
	sec := int64(0)
	if secret {
		sec = 1
	}
	old, hadOld := "", false
	if cur, err := m.q.GetEnv(ctx, dbq.GetEnvParams{ServiceID: serviceID, Key: key}); err == nil {
		if plain, err := m.box.Open(cur.ValueEnc, envAD(serviceID, key)); err == nil {
			old, hadOld = string(plain), true
		}
	}
	if err := m.q.UpsertEnv(ctx, dbq.UpsertEnvParams{ServiceID: serviceID, Key: key, ValueEnc: sealed, Secret: sec, UpdatedAt: m.now().Unix()}); err != nil {
		return err
	}
	// The services that use this one follow the new value: what it offers
	// built from the old one is updated, and they show changes to apply.
	if hadOld && old != value {
		changed := m.syncExports(ctx, serviceID, old, value)
		if changed == nil {
			changed = map[string]bool{}
		}
		changed[key] = true
		if s, err := m.q.GetServiceByID(ctx, serviceID); err == nil {
			m.touchDependents(ctx, s, changed)
		}
	}
	// Never the value in the audit log: only the name and whether it is secret.
	m.record(ctx, a, "service.env.set", "service", serviceID, audit.OK, map[string]any{"key": key, "secret": secret})
	return nil
}

// envSecretRE matches variable names that usually hold a secret.
var envSecretRE = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|PASS$|_PASS_|TOKEN|PRIVATE|_KEY$|^KEY$|API_KEY|CREDENTIAL|DSN$)`)

// LooksSecret says whether a variable name usually holds a secret
// (SECRET_KEY, DB_PASSWORD, STRIPE_TOKEN...): those are kept masked without
// anyone having to tick a box. A reference (${{db.DATABASE_URL}}) shows
// what it points to, not a value, so it never needs masking.
func LooksSecret(key string) bool { return envSecretRE.MatchString(key) }

// SetEnvBulk imports KEY=VALUE lines (a .env file, see ParseEnvFile). It
// stops at the first invalid line, before writing anything.
func (m *Manager) SetEnvBulk(ctx context.Context, a Actor, serviceID, text string, secret bool) (int, error) {
	vars, err := ParseEnvFile(text)
	if err != nil {
		return 0, err
	}
	if len(vars) == 0 {
		return 0, i18n.E("env.error.bulk_empty")
	}
	if len(vars) > 200 {
		return 0, i18n.E("env.error.bulk_too_many", "max", 200)
	}
	changed := 0
	for _, x := range vars {
		sec := secret || LooksSecret(x.Key)
		// Saving the .env editor sends every line back: a variable whose
		// value did not change is left alone, so it does not mark the
		// service as having changes to apply. One already secret stays so.
		if cur, err := m.q.GetEnv(ctx, dbq.GetEnvParams{ServiceID: serviceID, Key: x.Key}); err == nil {
			if plain, err := m.box.Open(cur.ValueEnc, envAD(serviceID, x.Key)); err == nil && string(plain) == x.Value {
				continue
			}
			sec = sec || cur.Secret == 1
		}
		if err := m.SetEnv(ctx, a, serviceID, x.Key, x.Value, sec); err != nil {
			return 0, err
		}
		changed++
	}
	return changed, nil
}

// DeleteEnv deletes a variable.
func (m *Manager) DeleteEnv(ctx context.Context, a Actor, serviceID, key string) error {
	n, err := m.q.DeleteEnv(ctx, dbq.DeleteEnvParams{ServiceID: serviceID, Key: key})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	m.record(ctx, a, "service.env.delete", "service", serviceID, audit.OK, map[string]any{"key": key})
	return nil
}

// RevealEnv returns the clear value of a secret variable (the route requires
// sudo) and records who saw it.
func (m *Manager) RevealEnv(ctx context.Context, a Actor, serviceID, key string) (string, error) {
	r, err := m.q.GetEnv(ctx, dbq.GetEnvParams{ServiceID: serviceID, Key: key})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	plain, err := m.box.Open(r.ValueEnc, envAD(serviceID, key))
	if err != nil {
		return "", err
	}
	m.record(ctx, a, "secret.reveal", "service", serviceID, audit.OK, map[string]any{"key": key})
	return string(plain), nil
}

// PendingChanges reports whether the variables changed since the last live
// deploy.
func (m *Manager) PendingChanges(ctx context.Context, serviceID string) (bool, error) {
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return false, err
	}
	_, hash, err := m.envFor(ctx, s)
	if err != nil {
		return false, err
	}
	last, err := m.q.LastLiveDeployment(ctx, serviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return last.EnvHash != hash, nil
}

// envFor decrypts the variables for the deploy and computes a hash of them to
// detect pending changes. The hash covers the ENCRYPTED values: it changes
// when a variable changes but does not let anyone brute-force a secret from
// the stored hash.
//
// A dynamic-domain service also gets HANGAR_DOMAIN_CHECK_SECRET, and the
// secret counts toward the hash, so turning dynamic domains on shows the
// "redeploy to apply" notice. The panel's value always wins over a variable
// of the same name: the edge signs with it, rotating it takes an admin with
// sudo, and an operator's own value would only break the check.
func (m *Manager) envFor(ctx context.Context, s dbq.Service) (map[string]string, string, error) {
	serviceID := s.ID
	rows, err := m.q.ListEnv(ctx, serviceID)
	if err != nil {
		return nil, "", err
	}
	env := make(map[string]string, len(rows))
	h := sha256.New()
	h.Write([]byte(serviceID))
	for _, r := range rows { // ListEnv is already ordered by key
		plain, err := m.box.Open(r.ValueEnc, envAD(serviceID, r.Key))
		if err != nil {
			return nil, "", fmt.Errorf("variable %s: %w", r.Key, err)
		}
		env[r.Key] = string(plain)
		fmt.Fprintf(h, "\x00%s\x00%d\x00", r.Key, r.Secret)
		h.Write(r.ValueEnc)
	}
	// Turning continuous WAL archiving on or off changes the database's
	// command: it shows as a pending change until the next deploy.
	if m.walEnabled(ctx, s.ID) {
		h.Write([]byte("\x00wal\x00"))
	}
	if s.DynamicDomains == 1 && len(s.DomainCheckSecretEnc) > 0 {
		plain, err := m.box.Open(s.DomainCheckSecretEnc, edge.CheckSecretAD(s.ID))
		if err != nil {
			return nil, "", fmt.Errorf("domain check secret: %w", err)
		}
		env[CheckSecretEnv] = string(plain)
		h.Write([]byte("\x00dynamic\x00"))
		h.Write(s.DomainCheckSecretEnc)
	}
	return env, hex.EncodeToString(h.Sum(nil)), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
