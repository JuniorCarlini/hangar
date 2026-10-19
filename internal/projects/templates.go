package projects

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// SetTemplates replaces the embedded catalog with r, which the community
// catalog sync keeps up to date (docs/08).
func (m *Manager) SetTemplates(r *templates.Registry) { m.templates = r }

// catalog is the template catalog in use.
func (m *Manager) catalog() *templates.Catalog { return m.templates.Catalog() }

// Templates lists the catalog.
func (m *Manager) Templates() []*templates.Template { return m.catalog().List() }

// Template finds a template.
func (m *Manager) Template(id string) (*templates.Template, bool) { return m.catalog().Get(id) }

func exportAD(serviceID, key string) string { return "service_exports|" + serviceID + "|" + key }

// CreateFromTemplate creates every service of a template in the project and
// deploys them. Generated values (passwords) are never shown in the form:
// they go straight into encrypted, secret variables and exports. name is
// what the user typed; the services' identifiers are derived from it.
func (m *Manager) CreateFromTemplate(ctx context.Context, a Actor, projectSlug, templateID, name string, inputs map[string]string) ([]dbq.Service, error) {
	if err := m.requireNode(); err != nil {
		return nil, err
	}
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return nil, err
	}
	t, ok := m.catalog().Get(templateID)
	if !ok {
		return nil, ErrNotFound
	}
	r, secrets, err := m.renderTemplate(ctx, p, t, name, inputs)
	if err != nil {
		return nil, err
	}

	// All rows in one transaction: a template is created whole or not at all.
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	created, err := m.insertRendered(ctx, m.q.WithTx(tx), p, t, r, secrets, a.Sudo)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	out, err := m.recordCreated(ctx, a, p, created, nil)
	if err != nil {
		return out, err
	}
	// A template that is born public (n8n, Uptime Kuma) shows its link right
	// away: the edge routes it now (to the "updating" page until the deploy
	// ends), not at the next unrelated reload, even if a deploy fails.
	if n, err := m.q.CountPublicEndpoints(ctx, out[0].ID); err == nil && n > 0 {
		if err := m.applyEdge(ctx); err != nil {
			return out, err
		}
	}
	// The main service (first) goes last: what it depends on (its own
	// database, say) starts first.
	order := append(slices.Clone(out[1:]), out[0])
	for _, s := range order {
		if _, err := m.Deploy(ctx, a, p.Slug, s.Slug, "create"); err != nil {
			return out, err
		}
	}
	return out, nil
}

// renderTemplate checks the inputs, generates the secrets and fills the
// template in for the service named name; every identifier it would create
// must be free in the project.
func (m *Manager) renderTemplate(ctx context.Context, p dbq.Project, t *templates.Template, name string, inputs map[string]string) (templates.Rendered, []string, error) {
	slug, err := slugFromName(name)
	if err != nil {
		return templates.Rendered{}, nil, err
	}
	vals := map[string]string{"name": slug, "project": p.Slug, "service": node.ContainerName(p.Slug, slug)}
	for _, in := range t.Inputs {
		v := strings.TrimSpace(inputs[in.Key])
		if v == "" {
			v = in.Default
		}
		if !regexp.MustCompile(in.Pattern).MatchString(v) {
			return templates.Rendered{}, nil, i18n.E("template.error.input", "field", in.Label.In(i18n.Locale(ctx)))
		}
		vals[in.Key] = v
	}
	var secrets []string
	for _, g := range t.Generated {
		v, err := templates.NewSecret()
		if err != nil {
			return templates.Rendered{}, nil, err
		}
		vals[g.Key] = v
		secrets = append(secrets, v)
	}
	r, err := t.Render(vals)
	if err != nil {
		return templates.Rendered{}, nil, err
	}
	for _, rs := range r.Services {
		if !node.SlugRE.MatchString(rs.Slug) {
			return templates.Rendered{}, nil, i18n.E("service.error.slug")
		}
		if err := m.slugFree(ctx, p, rs.Slug); err != nil {
			return templates.Rendered{}, nil, err
		}
	}
	return r, secrets, nil
}

// insertRendered writes a rendered template's rows (services, disks,
// variables, exports) with q, inside the caller's transaction, and returns
// the new service ids.
// allowPublic lets the template's public endpoints be born public (the
// creator has sudo); otherwise every endpoint starts internal.
func (m *Manager) insertRendered(ctx context.Context, q *dbq.Queries, p dbq.Project, t *templates.Template, r templates.Rendered, secrets []string, allowPublic bool) ([]string, error) {
	now := m.now().Unix()
	var created []string
	for i, rs := range r.Services {
		id := ids.New("svc_")
		cmd, _ := json.Marshal(rs.Command)
		if rs.Command == nil {
			cmd = []byte("[]")
		}
		health := ""
		if rs.Health != nil {
			b, _ := json.Marshal(rs.Health)
			health = string(b)
		}
		caps := ""
		if rs.CapAdd != nil {
			b, _ := json.Marshal(rs.CapAdd)
			caps = string(b)
		}
		ro, stateful := int64(0), int64(0)
		if rs.ReadOnly {
			ro = 1
		}
		if rs.Stateful {
			stateful = 1
		}
		if err := q.CreateService(ctx, dbq.CreateServiceParams{
			ID: id, ProjectID: p.ID, Slug: rs.Slug, Image: rs.Image, InternalPort: int64(rs.Port),
			MemoryBytes: int64(rs.MemoryMB) << 20, NanoCpus: int64(rs.CPUs * 1e9), PidsLimit: DefaultPids,
			ReadOnly: ro, CommandJson: string(cmd), Template: t.ID, Stateful: stateful,
			HealthJson: health, CapAddJson: caps, StopGraceS: int64(rs.StopGraceS), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return nil, err
		}
		for _, v := range rs.Volumes {
			if err := q.AddVolume(ctx, dbq.AddVolumeParams{ServiceID: id, Name: v.Name, Path: v.Path, ReadOnly: boolInt(v.ReadOnly)}); err != nil {
				return nil, err
			}
		}
		for k, v := range rs.Env {
			sealed, err := m.box.Seal([]byte(v), envAD(id, k))
			if err != nil {
				return nil, err
			}
			if err := q.UpsertEnv(ctx, dbq.UpsertEnvParams{ServiceID: id, Key: k, ValueEnc: sealed, Secret: boolInt(containsAny(v, secrets)), UpdatedAt: now}); err != nil {
				return nil, err
			}
		}
		// Exports and web endpoints belong to the main service (the first).
		if i == 0 {
			for _, e := range r.Exports {
				sealed, err := m.box.Seal([]byte(e.Value), exportAD(id, e.Key))
				if err != nil {
					return nil, err
				}
				if err := q.UpsertExport(ctx, dbq.UpsertExportParams{ServiceID: id, Key: e.Key, ValueEnc: sealed, Secret: boolInt(e.Secret || containsAny(e.Value, secrets))}); err != nil {
					return nil, err
				}
			}
			for _, ep := range t.Endpoints {
				if err := insertEndpoint(ctx, q, p.Slug, rs.Slug, dbq.CreateEndpointParams{
					ID: ids.New("ep_"), ServiceID: id, Name: ep.Name, Port: int64(ep.Port),
					Label: endpointLabel(ep.Label), Public: boolInt(ep.Public && allowPublic), SslipEnabled: 1, CreatedAt: now,
				}); err != nil {
					return nil, err
				}
			}
		}
		created = append(created, id)
	}
	return created, nil
}

// recordCreated loads the services just committed and writes one audit
// entry per service.
func (m *Manager) recordCreated(ctx context.Context, a Actor, p dbq.Project, created []string, extra map[string]any) ([]dbq.Service, error) {
	out := make([]dbq.Service, 0, len(created))
	for _, id := range created {
		s, err := m.q.GetServiceByID(ctx, id)
		if err != nil {
			return out, err
		}
		summary := map[string]any{"project": p.Slug, "service": s.Slug, "image": s.Image}
		if s.Template != "" {
			summary["template"] = s.Template
		}
		for k, v := range extra {
			summary[k] = v
		}
		m.record(ctx, a, "service.create", "service", s.ID, audit.OK, summary)
		out = append(out, s)
	}
	return out, nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if x != "" && strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// Export is a connection value the UI shows ("internal URL to copy").
type Export struct {
	Key    string
	Value  string // empty for secrets
	Secret bool
}

// ListExports lists what other services may reference, masking secrets.
func (m *Manager) ListExports(ctx context.Context, serviceID string) ([]Export, error) {
	rows, err := m.q.ListExports(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	out := make([]Export, 0, len(rows))
	for _, r := range rows {
		e := Export{Key: r.Key, Secret: r.Secret == 1}
		if !e.Secret {
			plain, err := m.box.Open(r.ValueEnc, exportAD(serviceID, r.Key))
			if err != nil {
				return nil, err
			}
			e.Value = string(plain)
		}
		out = append(out, e)
	}
	return out, nil
}

// RevealExport returns a secret export (the route requires sudo) and records
// who saw it.
func (m *Manager) RevealExport(ctx context.Context, a Actor, serviceID, key string) (string, error) {
	rows, err := m.q.ListExports(ctx, serviceID)
	if err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.Key == key {
			plain, err := m.box.Open(r.ValueEnc, exportAD(serviceID, key))
			if err != nil {
				return "", err
			}
			m.record(ctx, a, "secret.reveal", "service", serviceID, audit.OK, map[string]any{"export": key})
			return string(plain), nil
		}
	}
	return "", ErrNotFound
}
