package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// defaultEndpoint gives a non-template service its single web endpoint from
// its port — internal by default (fail-closed): the operator clicks to
// publish it and get the automatic link (docs/28). No port, no endpoint.
// It takes the queries so it works inside a transaction (git) or not.
func defaultEndpoint(ctx context.Context, q *dbq.Queries, projectSlug, serviceID, serviceSlug string, port, now int64) error {
	if port <= 0 {
		return nil
	}
	return insertEndpoint(ctx, q, projectSlug, serviceSlug, dbq.CreateEndpointParams{
		ID: ids.New("ep_"), ServiceID: serviceID, Port: port,
		Label: serviceSlug, Public: 0, SslipEnabled: 1, CreatedAt: now,
	})
}

// insertEndpoint creates an endpoint with a free host label. Two services
// created at the same moment can pick the same label (each checked before
// the other wrote); the unique index refuses the second, which then takes
// the label with a short random suffix instead of failing the creation.
func insertEndpoint(ctx context.Context, q *dbq.Queries, projectSlug, serviceSlug string, p dbq.CreateEndpointParams) error {
	label, err := newHostLabel(ctx, q, projectSlug, serviceSlug, p.Name)
	if err != nil {
		return err
	}
	p.HostLabel = label
	err = q.CreateEndpoint(ctx, p)
	for try := 0; err != nil && isHostLabelTaken(err) && try < 3; try++ {
		p.HostLabel = withSuffix(label, "-"+ids.New("")[:4])
		err = q.CreateEndpoint(ctx, p)
	}
	return err
}

// isHostLabelTaken reports a clash on the endpoints_host_label index.
func isHostLabelTaken(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: endpoints.host_label")
}

// maxHostLabel keeps room under DNS's 63-character label limit for the
// "-NN" suffix of a collision.
const maxHostLabel = 55

var hostLabelBad = regexp.MustCompile(`[^a-z0-9]+`)

// hostLabelBase is the readable part of an automatic link: project, service
// and endpoint name joined by single dashes, only [a-z0-9-], never starting
// or ending with a dash nor holding "--" (Let's Encrypt refuses "ab--x").
func hostLabelBase(project, service, name string) string {
	parts := []string{project, service}
	if name != "" {
		parts = append(parts, name)
	}
	s := strings.Trim(hostLabelBad.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-"), "-")
	if len(s) > maxHostLabel {
		s = strings.TrimRight(s[:maxHostLabel], "-")
	}
	if s == "" {
		s = "app"
	}
	return s
}

// withSuffix appends suffix to base, cutting base so the result still fits.
func withSuffix(base, suffix string) string {
	if len(base)+len(suffix) > maxHostLabel {
		base = strings.TrimRight(base[:maxHostLabel-len(suffix)], "-")
	}
	return base + suffix
}

// newHostLabel picks a host label no other endpoint uses: the readable base,
// or the base with "-2", "-3"... when taken, so "a-b"/"c" and "a"/"b-c" (same
// base) never share a link. The unique index backs it up.
func newHostLabel(ctx context.Context, q *dbq.Queries, project, service, name string) (string, error) {
	base := hostLabelBase(project, service, name)
	for i := 1; i < 1000; i++ {
		label := base
		if i > 1 {
			label = withSuffix(base, "-"+strconv.Itoa(i))
		}
		n, err := q.HostLabelTaken(ctx, label)
		if err != nil {
			return "", err
		}
		// Nor the first label of a custom domain: under a base domain the
		// automatic link would be that same hostname.
		d, err := q.DomainUnderLabel(ctx, sql.NullString{String: label, Valid: true})
		if err != nil {
			return "", err
		}
		if n == 0 && d == 0 {
			return label, nil
		}
	}
	return "", errors.New("projects: no free host label")
}

// Endpoint is a service's HTTP port that can get an external link (docs/28).
type Endpoint struct {
	ID           string
	Name         string
	HostLabel    string // first DNS label of its automatic link (unique)
	Port         int
	Label        string
	Public       bool
	SslipEnabled bool
}

// endpointLabel stores a template's label in every language it has (JSON),
// so each viewer reads it in theirs, not in the language of whoever created
// the service.
func endpointLabel(t templates.Text) string {
	b, err := json.Marshal(t)
	if err != nil || len(t) == 0 {
		return ""
	}
	return string(b)
}

// labelIn reads a stored label: a JSON object of languages (templates) or a
// plain name (other services).
func labelIn(stored, locale string) string {
	if !strings.HasPrefix(stored, "{") {
		return stored
	}
	var t templates.Text
	if json.Unmarshal([]byte(stored), &t) != nil {
		return stored
	}
	return t.In(locale)
}

// ListEndpoints lists a service's web endpoints, ordered by port, with the
// labels in the viewer's language.
func (m *Manager) ListEndpoints(ctx context.Context, serviceID string) ([]Endpoint, error) {
	rows, err := m.q.ListEndpoints(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	locale := i18n.Locale(ctx)
	out := make([]Endpoint, 0, len(rows))
	for _, e := range rows {
		out = append(out, Endpoint{
			ID: e.ID, Name: e.Name, Port: int(e.Port), Label: labelIn(e.Label, locale), HostLabel: e.HostLabel,
			Public: e.Public == 1, SslipEnabled: e.SslipEnabled == 1,
		})
	}
	return out, nil
}

// SetEndpointPublic exposes an endpoint (public = true gives it an external
// link) or keeps it on the project network only. Making it public joins
// Caddy to the project network so it can reach it; both reload the edge.
func (m *Manager) SetEndpointPublic(ctx context.Context, a Actor, projectSlug, serviceSlug, endpointID string, public bool) error {
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	ep, err := m.q.GetEndpoint(ctx, dbq.GetEndpointParams{ID: endpointID, ServiceID: s.ID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	// Custom domains on it would keep answering on the internet: they go
	// first, so "project network only" is always true.
	if !public {
		if n, err := m.q.CountDomainsOnEndpoint(ctx, sql.NullString{String: endpointID, Valid: true}); err != nil {
			return err
		} else if n > 0 {
			return i18n.E("endpoint.error.has_domains", "n", n)
		}
	}
	if err := m.q.SetEndpointPublic(ctx, dbq.SetEndpointPublicParams{Public: boolInt(public), ID: endpointID, ServiceID: s.ID}); err != nil {
		return err
	}
	action := "service.endpoint.internal"
	if public {
		action = "service.endpoint.public"
	}
	m.record(ctx, a, action, "service", s.ID, audit.OK, map[string]any{"port": ep.Port})
	if public && m.node != nil {
		if err := m.node.ConnectEdge(ctx, p.Slug); err != nil {
			m.log.Warn("join caddy to the project network", "service", p.Slug+"/"+s.Slug, "error", err)
		}
	}
	return m.applyEdge(ctx)
}

// SetEndpointSslip turns the automatic sslip.io link of a public endpoint on
// or off, without removing anything: off drops its route, on brings it back.
func (m *Manager) SetEndpointSslip(ctx context.Context, a Actor, projectSlug, serviceSlug, endpointID string, on bool) error {
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	ep, err := m.q.GetEndpoint(ctx, dbq.GetEndpointParams{ID: endpointID, ServiceID: s.ID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if err := m.q.SetEndpointSslip(ctx, dbq.SetEndpointSslipParams{SslipEnabled: boolInt(on), ID: endpointID, ServiceID: s.ID}); err != nil {
		return err
	}
	action := "service.endpoint.sslip_off"
	if on {
		action = "service.endpoint.sslip_on"
	}
	m.record(ctx, a, action, "service", s.ID, audit.OK, map[string]any{"port": ep.Port})
	return m.applyEdge(ctx)
}

// EnsureEndpoints runs once at startup, before the edge is configured. In
// this order it gives a unique host label to every endpoint that lacks one
// (the existing ones first, so a link already on the internet keeps its
// name), creates the web endpoints of services older than them —
// internal, whatever the template says today: nothing new goes on the
// internet by an upgrade — and ties their old domains to them. A row that
// fails is logged and skipped: one bad row must not keep the panel from
// starting. Returns how many rows it changed.
func (m *Manager) EnsureEndpoints(ctx context.Context) (int, error) {
	n := 0
	rows, err := m.q.ListEndpointsWithoutHostLabel(ctx)
	if err != nil {
		return n, err
	}
	for _, e := range rows {
		host, err := newHostLabel(ctx, m.q, e.ProjectSlug, e.ServiceSlug, e.Name)
		if err == nil {
			err = m.q.SetEndpointHostLabel(ctx, dbq.SetEndpointHostLabelParams{HostLabel: host, ID: e.ID})
		}
		if err != nil {
			m.log.Error("label endpoint", "endpoint", e.ID, "error", err)
			continue
		}
		n++
	}

	svcs, err := m.q.ListServicesWithoutEndpoints(ctx)
	if err != nil {
		return n, err
	}
	now := m.now().Unix()
	for _, s := range svcs {
		created, err := m.backfillEndpoints(ctx, s, now)
		if err != nil {
			m.log.Error("create endpoints of an older service", "service", s.ProjectSlug+"/"+s.Slug, "error", err)
			continue
		}
		n += created
	}

	unbound, err := m.q.ListUnboundDomainEndpoints(ctx)
	if err != nil {
		return n, err
	}
	for _, u := range unbound {
		if err := m.bindOldDomain(ctx, u); err != nil {
			m.log.Error("tie an older domain to its endpoint", "domain", u.DomainID, "error", err)
			continue
		}
		n++
	}
	return n, nil
}

// backfillEndpoints creates the endpoints of a service older than them:
// the default one for an image or Git service; for a template service, the
// template's endpoints that answer on its own port (the app, not its
// database sidecar). Always internal. Returns how many it created (none for
// a database, which has no web port, nor for a template's sidecar: like at
// creation, endpoints belong to the main service only).
func (m *Manager) backfillEndpoints(ctx context.Context, s dbq.ListServicesWithoutEndpointsRow, now int64) (int, error) {
	if s.Template == "" {
		return 1, defaultEndpoint(ctx, m.q, s.ProjectSlug, s.ID, s.Slug, s.InternalPort, now)
	}
	t, ok := m.templates.Catalog().Get(s.Template)
	if !ok || m.isSidecar(ctx, s, t) {
		return 0, nil
	}
	created := 0
	for _, ep := range t.Endpoints {
		if int64(ep.Port) != s.InternalPort {
			continue
		}
		if err := insertEndpoint(ctx, m.q, s.ProjectSlug, s.Slug, dbq.CreateEndpointParams{
			ID: ids.New("ep_"), ServiceID: s.ID, Name: ep.Name, Port: int64(ep.Port),
			Label: endpointLabel(ep.Label), Public: 0, SslipEnabled: 1, CreatedAt: now,
		}); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

// isSidecar reports whether s is a sidecar of template t: its slug is a
// main service's slug plus one of t's sidecar suffixes, and that main
// service exists in the same project from the same template.
func (m *Manager) isSidecar(ctx context.Context, s dbq.ListServicesWithoutEndpointsRow, t *templates.Template) bool {
	for _, side := range t.Services[1:] {
		main, ok := strings.CutSuffix(s.Slug, side.Suffix)
		if !ok || main == "" {
			continue
		}
		if svc, err := m.q.GetService(ctx, dbq.GetServiceParams{ProjectID: s.ProjectID, Slug: main}); err == nil && svc.Template == s.Template {
			return true
		}
	}
	return false
}

// bindOldDomain ties a domain older than endpoints to the endpoint on its
// service's port, where it has always answered, in one transaction (half
// done, the domain would drop off the routes). The endpoint becomes public
// (it already is, through the domain) and its automatic link steps aside
// as for a new domain: it comes back when the domain goes only if the
// endpoint was public before; otherwise it stays off.
func (m *Manager) bindOldDomain(ctx context.Context, u dbq.ListUnboundDomainEndpointsRow) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := m.q.WithTx(tx)
	if err := q.BindDomainEndpoint(ctx, dbq.BindDomainEndpointParams{EndpointID: sql.NullString{String: u.EndpointID, Valid: true}, ID: u.DomainID}); err != nil {
		return err
	}
	autoOff := int64(1)
	if u.Public == 0 {
		autoOff = 0
		if err := q.SetEndpointPublic(ctx, dbq.SetEndpointPublicParams{Public: 1, ID: u.EndpointID, ServiceID: u.ServiceID}); err != nil {
			return err
		}
	}
	if u.SslipEnabled == 1 || u.Public == 0 {
		if err := q.SetEndpointSslipAutoOff(ctx, dbq.SetEndpointSslipAutoOffParams{SslipEnabled: 0, SslipAutoOff: autoOff, ID: u.EndpointID, ServiceID: u.ServiceID}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetServicePort changes the port a service listens on, or takes it away
// (0) for a worker that serves nothing: with a port, a deploy waits for it
// to answer, and a worker never would. The service's own endpoint follows
// the port, with its domains; going to no port is refused while that
// endpoint is public or has domains, so nothing on the internet loses its
// route silently. A template's ports are part of the template.
func (m *Manager) SetServicePort(ctx context.Context, a Actor, projectSlug, serviceSlug string, port int) error {
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if port < 0 || port > 65535 {
		return i18n.E("service.error.port")
	}
	old := s.InternalPort
	if int64(port) == old {
		return nil
	}
	if s.Template != "" {
		return i18n.E("service.error.port_template")
	}
	eps, err := m.q.ListEndpoints(ctx, s.ID)
	if err != nil {
		return err
	}
	var own *dbq.Endpoint
	for i := range eps {
		switch {
		case eps[i].Port == int64(port):
			return i18n.E("service.error.port_taken", "port", port)
		case eps[i].Port == old && old > 0:
			own = &eps[i]
		}
	}
	if port == 0 && own != nil {
		n, err := m.q.CountEndpointDomains(ctx, sql.NullString{String: own.ID, Valid: true})
		if err != nil {
			return err
		}
		if n > 0 || own.Public == 1 {
			return i18n.E("service.error.port_in_use")
		}
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := m.q.WithTx(tx)
	now := m.now().Unix()
	switch {
	case own != nil && port == 0:
		err = q.DeleteEndpoint(ctx, dbq.DeleteEndpointParams{ID: own.ID, ServiceID: s.ID})
	case own != nil:
		err = q.SetEndpointPort(ctx, dbq.SetEndpointPortParams{Port: int64(port), ID: own.ID, ServiceID: s.ID})
	default:
		err = defaultEndpoint(ctx, q, projectSlug, s.ID, s.Slug, int64(port), now)
	}
	if err != nil {
		return err
	}
	if err := q.SetServiceInternalPort(ctx, dbq.SetServiceInternalPortParams{InternalPort: int64(port), UpdatedAt: now, ID: s.ID}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.record(ctx, a, "service.port", "service", s.ID, audit.OK, map[string]any{"from": old, "port": port})
	return m.applyEdge(ctx)
}
