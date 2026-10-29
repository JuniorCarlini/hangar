package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A project backup (docs/09 "Backup do projeto") carries the project's own
// configuration next to each service's: ProjectSnapshot is that part
// (project.json). Restoring one always makes a new project; it never
// touches an existing one.

// ProjectSnapshot is a project's configuration as a project backup
// carries it.
type ProjectSnapshot struct {
	Format  int    `json:"format"`
	Project string `json:"project"`
	Name    string `json:"name"`
	// Services are the project's services, in name order.
	Services []string `json:"services"`
	// Linked are the projects it is connected to.
	Linked []string `json:"linked_projects,omitempty"`
}

// SnapshotProject reads the configuration of a project (ProjectSnapshot).
func (m *Manager) SnapshotProject(ctx context.Context, slug string) (ProjectSnapshot, error) {
	p, err := m.GetProject(ctx, slug)
	if err != nil {
		return ProjectSnapshot{}, err
	}
	out := ProjectSnapshot{Format: 1, Project: p.Slug, Name: p.Name}
	svcs, err := m.q.ListServices(ctx, p.ID)
	if err != nil {
		return out, err
	}
	for _, s := range svcs {
		out.Services = append(out.Services, s.Slug)
	}
	sort.Strings(out.Services)
	linked, err := m.q.LinkedProjects(ctx, p.ID)
	if err != nil {
		return out, err
	}
	for _, l := range linked {
		out.Linked = append(out.Linked, l.Slug)
	}
	sort.Strings(out.Linked)
	return out, nil
}

// RestoredProject is what CreateFromSnapshots made.
type RestoredProject struct {
	Project dbq.Project
	// Services are the new services, in the order of the snapshots.
	Services []dbq.Service
	// Domains are the fixed domains of the original, "service: host",
	// left off so the copy takes no traffic from it.
	Domains []string
	// Public are the endpoints that were on the internet, "service:port":
	// the copy's are internal until someone publishes them.
	Public []string
	// Linked are the connections to other projects made again; Unlinked,
	// those whose project is not on this server.
	Linked, Unlinked []string
	// NoGitAccess are Git services whose credential did not come along:
	// a private repository needs one before they build.
	NoGitAccess []string
}

// Errors of a project backup the UI translates.
var errBadSnapshot = &i18n.Error{Key: "project.restore.error.invalid"}

func badSnapshot(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errBadSnapshot, fmt.Sprintf(format, args...))
}

// checkSnapshots validates the services of a project backup the way their
// creation would: a file that arrives from a browser goes through the same
// bounds as a form, whatever it claims.
func checkSnapshots(snaps []ServiceSnapshot) error {
	if len(snaps) == 0 {
		return badSnapshot("no services")
	}
	owners := map[string]map[string]bool{} // service -> volumes it owns
	for _, s := range snaps {
		if !node.SlugRE.MatchString(s.Service) {
			return badSnapshot("service name %q", s.Service)
		}
		if _, dup := owners[s.Service]; dup {
			return badSnapshot("service %q twice", s.Service)
		}
		owners[s.Service] = map[string]bool{}
		for _, v := range s.Vols {
			if v.From == "" {
				owners[s.Service][v.Name] = true
			}
		}
	}
	for _, s := range snaps {
		switch {
		case s.Image == "" && s.Git == nil, s.Image != "" && !node.ImageRE.MatchString(s.Image):
			return badSnapshot("%s: image %q", s.Service, s.Image)
		case s.Port < 0 || s.Port > 65535:
			return badSnapshot("%s: port", s.Service)
		case s.Res.MemoryBytes < 16<<20 || s.Res.MemoryBytes > 64<<30:
			return badSnapshot("%s: memory", s.Service)
		case s.Res.NanoCPUs < 5e7 || s.Res.NanoCPUs > 64e9:
			return badSnapshot("%s: cpus", s.Service)
		case s.Res.Pids < 0 || s.Res.StopGraceS < 0 || s.Res.StopGraceS > int64(node.MaxStopGrace.Seconds()):
			return badSnapshot("%s: limits", s.Service)
		case len(s.Vols) > MaxVolumes:
			return badSnapshot("%s: too many volumes", s.Service)
		}
		for _, c := range s.Res.CapAdd {
			if _, ok := node.AllowedCaps[c]; !ok {
				return badSnapshot("%s: capability %q", s.Service, c)
			}
		}
		if len(s.Check) > 0 && !json.Valid(s.Check) {
			return badSnapshot("%s: healthcheck", s.Service)
		}
		seen := map[string]bool{}
		for _, v := range s.Vols {
			if !node.VolumeNameRE.MatchString(v.Name) || seen[v.Name] {
				return badSnapshot("%s: volume %q", s.Service, v.Name)
			}
			seen[v.Name] = true
			if _, err := cleanMount(v.Path); err != nil {
				return badSnapshot("%s: volume path %q", s.Service, v.Path)
			}
			if v.From != "" && (v.From == s.Service || !owners[v.From][v.Name]) {
				return badSnapshot("%s: volume %q of %q", s.Service, v.Name, v.From)
			}
		}
		for _, list := range [][]SnapshotVar{s.Env, s.Exports} {
			for _, e := range list {
				if !envKeyRE.MatchString(e.Key) || len(e.Value) > MaxEnvValue || strings.ContainsRune(e.Value, 0) {
					return badSnapshot("%s: variable %q", s.Service, e.Key)
				}
			}
		}
		for _, e := range s.Endpoints {
			if e.Port < 1 || e.Port > 65535 {
				return badSnapshot("%s: endpoint port", s.Service)
			}
		}
		if s.Git != nil && s.Git.URL == "" {
			return badSnapshot("%s: git source", s.Service)
		}
	}
	return nil
}

// containerRE finds "<project>_<service>" as a whole word: what a variable
// holds when it names a container of the project by hand.
func containerRE(project, service string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(node.ContainerName(project, service)) + `($|[^A-Za-z0-9_-])`)
}

// RewriteRefs points a value of the original project at the copy: a
// reference that names the original project itself (${{old.svc.KEY}})
// becomes one to the copy's own service (${{svc.KEY}}), and the containers
// of the original ("old_svc") become the copy's ("new_svc"). References
// to services of the same project (${{svc.KEY}}) already resolve in the
// copy; references to other projects are left as they are.
func RewriteRefs(value, oldProject, newProject string, services []string) string {
	if oldProject == newProject {
		return value
	}
	in := map[string]bool{}
	for _, s := range services {
		in[s] = true
	}
	value = refRE.ReplaceAllStringFunc(value, func(ref string) string {
		m := refRE.FindStringSubmatch(ref)
		if m[1] == oldProject && in[m[2]] {
			return "${{" + m[2] + "." + m[3] + "}}"
		}
		return ref
	})
	// Longest names first, so "web-api" is not taken for "web".
	order := slices.Clone(services)
	slices.SortFunc(order, func(a, b string) int { return len(b) - len(a) })
	for _, s := range order {
		if !strings.Contains(value, node.ContainerName(oldProject, s)) {
			continue
		}
		re := containerRE(oldProject, s)
		repl := "${1}" + node.ContainerName(newProject, s) + "${2}"
		// Twice: two names separated by one character share it.
		value = re.ReplaceAllString(re.ReplaceAllString(value, repl), repl)
	}
	return value
}

// CreateFromSnapshots creates a new project named name with the services
// of a project backup, without deploying them: images, commands, limits,
// healthchecks, volumes (new and empty, shared ones mounted from their
// owner in the copy), variables and exports pointed at the copy, saved
// commands, deploy settings, endpoints (internal) and Git sources. The
// fixed domains are left off, so the copy takes no traffic from the
// original; they are listed in the result. Connections to projects that
// exist here are made again.
func (m *Manager) CreateFromSnapshots(ctx context.Context, a Actor, name string, ps ProjectSnapshot, snaps []ServiceSnapshot) (RestoredProject, error) {
	var out RestoredProject
	if err := checkSnapshots(snaps); err != nil {
		return out, err
	}
	p, err := m.CreateProjectNamed(ctx, a, name)
	if err != nil {
		return out, err
	}
	out.Project = p
	created := false
	defer func() {
		if !created {
			_ = m.q.DeleteProject(context.WithoutCancel(ctx), p.ID)
		}
	}()
	slugs := make([]string, 0, len(snaps))
	for _, s := range snaps {
		slugs = append(slugs, s.Service)
	}
	old := ps.Project
	rw := func(v string) string { return RewriteRefs(v, old, p.Slug, slugs) }

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	q := m.q.WithTx(tx)
	now := m.now().Unix()
	idOf := map[string]string{}
	for _, s := range snaps {
		id := ids.New("svc_")
		idOf[s.Service] = id
		cmd, _ := json.Marshal(s.Cmd)
		if s.Cmd == nil {
			cmd = []byte("[]")
		}
		caps := ""
		if s.Res.CapAdd != nil {
			b, _ := json.Marshal(s.Res.CapAdd)
			caps = string(b)
		}
		health := ""
		if len(s.Check) > 0 {
			health = string(s.Check)
		}
		if err := q.CreateService(ctx, dbq.CreateServiceParams{
			ID: id, ProjectID: p.ID, Slug: s.Service, Image: s.Image, InternalPort: s.Port,
			MemoryBytes: s.Res.MemoryBytes, NanoCpus: s.Res.NanoCPUs, PidsLimit: s.Res.Pids, ReadOnly: boolInt(s.Res.ReadOnly),
			CommandJson: string(cmd), Template: s.Template, Stateful: boolInt(s.Stateful),
			HealthJson: health, CapAddJson: caps, StopGraceS: s.Res.StopGraceS, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return out, err
		}
		if d := s.Deploy; d != nil {
			pre, val := "[]", "[]"
			if len(d.Predeploy) > 0 && json.Valid(d.Predeploy) {
				pre = string(d.Predeploy)
			}
			if len(d.Validate) > 0 && json.Valid(d.Validate) {
				val = string(d.Validate)
			}
			if err := q.SetServiceDeploySettings(ctx, dbq.SetServiceDeploySettingsParams{
				PredeployJson: pre, HealthPath: d.HealthPath, ValidateJson: val, ValidateTimeoutS: d.ValidateTimeoutS, UpdatedAt: now, ID: id,
			}); err != nil {
				return out, err
			}
		}
		if c := s.Canvas; c != nil {
			if err := q.SetCanvasPosition(ctx, dbq.SetCanvasPositionParams{
				CanvasX: sql.NullInt64{Int64: c.X, Valid: true}, CanvasY: sql.NullInt64{Int64: c.Y, Valid: true}, ID: id,
			}); err != nil {
				return out, err
			}
		}
	}
	for _, s := range snaps {
		id := idOf[s.Service]
		for _, v := range s.Vols {
			owner := sql.NullString{}
			if v.From != "" {
				owner = sql.NullString{String: idOf[v.From], Valid: true}
			}
			path, _ := cleanMount(v.Path)
			if err := q.AddVolume(ctx, dbq.AddVolumeParams{ServiceID: id, Name: v.Name, Path: path, ReadOnly: boolInt(v.ReadOnly), OwnerServiceID: owner}); err != nil {
				return out, err
			}
		}
		for _, e := range s.Env {
			sealed, err := m.box.Seal([]byte(rw(e.Value)), envAD(id, e.Key))
			if err != nil {
				return out, err
			}
			if err := q.UpsertEnv(ctx, dbq.UpsertEnvParams{ServiceID: id, Key: e.Key, ValueEnc: sealed, Secret: boolInt(e.Secret), UpdatedAt: now}); err != nil {
				return out, err
			}
		}
		for _, e := range s.Exports {
			sealed, err := m.box.Seal([]byte(rw(e.Value)), exportAD(id, e.Key))
			if err != nil {
				return out, err
			}
			if err := q.UpsertExport(ctx, dbq.UpsertExportParams{ServiceID: id, Key: e.Key, ValueEnc: sealed, Secret: boolInt(e.Secret)}); err != nil {
				return out, err
			}
		}
		for _, k := range s.Offers {
			if envKeyRE.MatchString(k) {
				if err := q.AddOffer(ctx, dbq.AddOfferParams{ServiceID: id, Key: k}); err != nil {
					return out, err
				}
			}
		}
		for _, e := range s.Endpoints {
			// Internal, whatever the original was: publishing the copy is
			// a decision of its own (and asks what publishing asks).
			if err := insertEndpoint(ctx, q, p.Slug, s.Service, dbq.CreateEndpointParams{
				ID: ids.New("ep_"), ServiceID: id, Name: e.Name, Port: int64(e.Port), Label: e.Label,
				Public: 0, SslipEnabled: boolInt(e.Sslip), CreatedAt: now,
			}); err != nil {
				return out, err
			}
			if e.Public {
				out.Public = append(out.Public, fmt.Sprintf("%s:%d", s.Service, e.Port))
			}
		}
		for _, c := range s.Commands {
			cmd, err := cleanCommand(c.Command)
			if err != nil || strings.TrimSpace(c.Name) == "" {
				continue
			}
			if err := q.CreateServiceCommand(ctx, dbq.CreateServiceCommandParams{ID: ids.New("cmd_"), ServiceID: id, Name: strings.TrimSpace(c.Name), Command: cmd, CreatedAt: now}); err != nil {
				return out, err
			}
		}
		if g := s.Git; g != nil {
			cred := sql.NullString{}
			if g.Credential != "" {
				if c, err := q.GetGitCredential(ctx, g.Credential); err == nil && !c.ProjectID.Valid {
					cred = sql.NullString{String: c.ID, Valid: true}
				}
			}
			if !cred.Valid {
				out.NoGitAccess = append(out.NoGitAccess, s.Service)
			}
			if err := q.CreateServiceGit(ctx, dbq.CreateServiceGitParams{
				ServiceID: id, RepoUrl: g.URL, Branch: g.Branch, Subdir: g.Subdir, Dockerfile: g.Dockerfile, CredentialID: cred, UpdatedAt: now,
			}); err != nil {
				return out, err
			}
		}
		for _, d := range s.Domains {
			out.Domains = append(out.Domains, s.Service+": "+d)
		}
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	created = true
	for _, s := range snaps {
		svc, err := m.q.GetServiceByID(ctx, idOf[s.Service])
		if err != nil {
			return out, err
		}
		out.Services = append(out.Services, svc)
		m.record(ctx, a, "service.create", "service", svc.ID, audit.OK,
			map[string]any{"project": p.Slug, "service": svc.Slug, "image": svc.Image, "restored_from": old + "/" + s.Service})
	}
	// Disk sizes before the first deploy creates the disks; without volume
	// limits here the volume is plain and holds the data anyway.
	for _, s := range snaps {
		for _, v := range s.Vols {
			if v.From != "" || v.LimitBytes <= 0 {
				continue
			}
			if err := m.SetVolumeLimit(ctx, a, p.Slug, s.Service, v.Name, v.LimitBytes); err != nil {
				m.log.Warn("give the restored copy its disk size", "service", p.Slug+"/"+s.Service, "volume", v.Name, "error", err)
			}
		}
	}
	for _, l := range ps.Linked {
		if l == p.Slug || l == old {
			continue
		}
		if _, err := m.q.GetProjectBySlug(ctx, l); err != nil {
			out.Unlinked = append(out.Unlinked, l)
			continue
		}
		if err := m.LinkProjects(ctx, a, p.Slug, l); err != nil {
			m.log.Warn("connect the restored project", "project", p.Slug, "other", l, "error", err)
			out.Unlinked = append(out.Unlinked, l)
			continue
		}
		out.Linked = append(out.Linked, l)
	}
	var tpl []dbq.Service
	for _, s := range out.Services {
		if s.Template != "" {
			tpl = append(tpl, s)
		}
	}
	m.templateCreated(ctx, a, tpl)
	return out, nil
}

// RemoveRestoredServices removes every service of a project a failed
// restore created (containers and disks), so nothing half restored looks
// restored. The empty project stays, with the restore's error on it, for
// its owner to read and delete. It is only ever called on that new
// project.
func (m *Manager) RemoveRestoredServices(ctx context.Context, a Actor, slug string) error {
	p, err := m.GetProject(ctx, slug)
	if err != nil {
		return err
	}
	svcs, err := m.q.ListServices(ctx, p.ID)
	if err != nil {
		return err
	}
	// A service whose disk another one mounts goes once that one is gone:
	// a second pass takes what the first could not.
	var errs []error
	for pass := 0; pass < 2 && len(svcs) > 0; pass++ {
		errs = nil
		var left []dbq.Service
		for _, s := range svcs {
			if err := m.DeleteService(ctx, a, slug, s.Slug); err != nil {
				errs = append(errs, err)
				left = append(left, s)
			}
		}
		svcs = left
	}
	return errors.Join(errs...)
}
