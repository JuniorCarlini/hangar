package projects

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/edge"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// CheckSecretEnv is the variable that carries the domain-check HMAC secret
// into the dynamic-domain service, so it never has to be copied by hand.
const CheckSecretEnv = "HANGAR_DOMAIN_CHECK_SECRET" //nolint:gosec // a variable name, not a credential

// EdgeApplier reloads the edge proxy after domains change.
type EdgeApplier interface {
	Apply(ctx context.Context) error
}

// SetEdge connects the edge proxy. Without it (edge disabled) domains are
// stored but not served.
func (m *Manager) SetEdge(e EdgeApplier) { m.edge = e }

// deployMarker is the edge's "this service is being deployed" switch: while
// on, a visitor gets the "updating" page instead of "down".
type deployMarker interface {
	SetDeploying(container string, on bool)
}

// markDeploying flips the marker when the edge has one.
func (m *Manager) markDeploying(project, service string, on bool) {
	if d, ok := m.edge.(deployMarker); ok {
		d.SetDeploying(node.ContainerName(project, service), on)
	}
}

// certStore is the edge's certificate storage, when it can be read.
type certStore interface {
	HasCertificate(host string) bool
}

// Certificate states of a fixed domain, for the UI.
const (
	CertUnknown = ""        // no edge, or its storage cannot be read
	CertActive  = "active"  // Caddy holds a certificate for it
	CertPending = "pending" // not issued yet (or failing: see Caddy's log)
)

// CertificateState says whether an exact hostname already has its
// certificate. Wildcards are always CertUnknown: theirs are per subdomain.
func (m *Manager) CertificateState(host string) string {
	c, ok := m.edge.(certStore)
	if !ok || edge.IsWildcard(host) {
		return CertUnknown
	}
	if c.HasCertificate(host) {
		return CertActive
	}
	return CertPending
}

// EdgeEnabled reports whether the edge proxy is running.
func (m *Manager) EdgeEnabled() bool { return m.edge != nil }

func (m *Manager) applyEdge(ctx context.Context) error {
	if m.edge == nil {
		return nil
	}
	if err := m.edge.Apply(ctx); err != nil {
		m.log.Error("reload edge proxy", "error", err)
		return i18n.E("domain.error.edge_apply", "error", err)
	}
	return nil
}

// needsEdge reports whether the service has a domain, takes dynamic ones, or
// has a public endpoint (its sslip/base link) — any of which needs Caddy to
// reach it on the edge network.
func (m *Manager) needsEdge(ctx context.Context, serviceID string) bool {
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return false
	}
	if n, err := m.q.CountDomains(ctx, serviceID); err == nil && (n > 0 || s.DynamicDomains == 1) {
		return true
	}
	pub, err := m.q.CountPublicEndpoints(ctx, serviceID)
	return err == nil && pub > 0
}

// ListDomains lists the fixed domains of a service.
func (m *Manager) ListDomains(ctx context.Context, serviceID string) ([]dbq.Domain, error) {
	return m.q.ListDomains(ctx, serviceID)
}

// AddDomain routes a hostname to the service and reloads Caddy, which then
// gets its certificate.
func (m *Manager) AddDomain(ctx context.Context, a Actor, projectSlug, serviceSlug, hostname, endpointID string) error {
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	host, ok := edge.NormalizeDomain(hostname)
	if !ok {
		return i18n.E("domain.error.hostname")
	}
	// Automatic links own sslip.io names and the names right under the base
	// domain that match an endpoint: a custom domain there would give two
	// services the same hostname.
	if strings.HasSuffix(strings.TrimPrefix(host, "*."), ".sslip.io") {
		return i18n.E("domain.error.reserved", "domain", host)
	}
	// The panel's own public hostname is never a service's.
	if m.panelHost != "" && (host == m.panelHost || (strings.HasPrefix(host, "*.") && strings.HasSuffix(m.panelHost, host[1:]) && !strings.Contains(strings.TrimSuffix(m.panelHost, host[1:]), "."))) {
		return i18n.E("domain.error.reserved", "domain", host)
	}
	if base := m.baseDomain(); base != "" {
		if label, ok := strings.CutSuffix(strings.TrimPrefix(host, "*."), "."+base); ok && !strings.Contains(label, ".") {
			if n, err := m.q.HostLabelTaken(ctx, label); err != nil {
				return err
			} else if n > 0 {
				return i18n.E("domain.error.reserved", "domain", host)
			}
		}
	}
	// A domain may point at a specific endpoint (its port); without one it
	// falls back to the service's internal_port, which must then exist.
	var ep sql.NullString
	var endpoint dbq.Endpoint
	if endpointID != "" {
		if endpoint, err = m.q.GetEndpoint(ctx, dbq.GetEndpointParams{ID: endpointID, ServiceID: s.ID}); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		ep = sql.NullString{String: endpointID, Valid: true}
	} else if s.InternalPort == 0 {
		return i18n.E("domain.error.no_port")
	}
	if _, err := m.q.GetDomainByHostname(ctx, host); err == nil {
		return ErrExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := m.q.CreateDomain(ctx, dbq.CreateDomainParams{ID: ids.New("dom_"), ServiceID: s.ID, EndpointID: ep, Hostname: host, CreatedAt: m.now().Unix()}); err != nil {
		return err
	}
	if ep.Valid {
		// A domain on an endpoint is the operator publishing it (adding a
		// domain already takes admin + sudo): an internal endpoint becomes
		// public, so the screen never says "project network only" while the
		// domain answers on the internet.
		// A custom domain takes over: the endpoint's automatic link steps
		// aside (not removed, its route only turns off). When the endpoint
		// was already public, the link is marked as switched off by the
		// domain and comes back when the domain goes. When it was internal,
		// the domain is the only thing published: the link stays off for
		// good, so removing the domain never puts a new address on the
		// internet that nobody approved.
		autoOff := int64(1)
		if endpoint.Public == 0 {
			autoOff = 0
			if err := m.q.SetEndpointPublic(ctx, dbq.SetEndpointPublicParams{Public: 1, ID: endpointID, ServiceID: s.ID}); err != nil {
				return err
			}
		}
		if endpoint.SslipEnabled == 1 || endpoint.Public == 0 {
			if err := m.q.SetEndpointSslipAutoOff(ctx, dbq.SetEndpointSslipAutoOffParams{SslipEnabled: 0, SslipAutoOff: autoOff, ID: endpointID, ServiceID: s.ID}); err != nil {
				return err
			}
		}
	}
	m.record(ctx, a, "domain.add", "service", s.ID, audit.OK, map[string]any{"hostname": host})
	if m.node != nil {
		if err := m.node.ConnectEdge(ctx, p.Slug, s.Slug); err != nil {
			m.log.Warn("join edge network", "service", p.Slug+"/"+s.Slug, "error", err)
		}
	}
	return m.applyEdge(ctx)
}

// RemoveDomain stops routing a hostname. Its certificate stays in Caddy's
// storage until it expires; it is no longer served or renewed.
func (m *Manager) RemoveDomain(ctx context.Context, a Actor, serviceID, domainID string) error {
	row, err := m.q.DeleteDomain(ctx, dbq.DeleteDomainParams{ID: domainID, ServiceID: serviceID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// If this was the last custom domain on its endpoint and the domain is
	// what switched the automatic link off, the link comes back; one the
	// operator switched off stays off.
	if row.EndpointID.Valid {
		if n, err := m.q.CountDomainsOnEndpoint(ctx, row.EndpointID); err == nil && n == 0 {
			if e, err := m.q.GetEndpoint(ctx, dbq.GetEndpointParams{ID: row.EndpointID.String, ServiceID: serviceID}); err == nil && e.SslipAutoOff == 1 {
				_ = m.q.SetEndpointSslipAutoOff(ctx, dbq.SetEndpointSslipAutoOffParams{SslipEnabled: 1, SslipAutoOff: 0, ID: row.EndpointID.String, ServiceID: serviceID})
			}
		}
	}
	m.record(ctx, a, "domain.remove", "service", serviceID, audit.OK, map[string]any{"hostname": row.Hostname})
	return m.applyEdge(ctx)
}

// SetMaintenance turns the service's maintenance mode on or off and reloads
// the edge: while on, every host of the service gets the maintenance page
// instead of the app, which keeps running.
func (m *Manager) SetMaintenance(ctx context.Context, a Actor, serviceID string, on bool) error {
	if _, err := m.q.GetServiceByID(ctx, serviceID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var flag int64
	action := "service.maintenance.off"
	if on {
		flag, action = 1, "service.maintenance.on"
	}
	if err := m.q.SetServiceMaintenance(ctx, dbq.SetServiceMaintenanceParams{Maintenance: flag, UpdatedAt: m.now().Unix(), ID: serviceID}); err != nil {
		return err
	}
	m.record(ctx, a, action, "service", serviceID, audit.OK, nil)
	return m.applyEdge(ctx)
}

// EnableDynamicDomains makes the service receive every hostname that is not a
// fixed domain, with certificates issued on demand after the app approves
// each one (docs/03). A new HMAC secret is generated; it reaches the app as
// HANGAR_DOMAIN_CHECK_SECRET on the next deploy.
func (m *Manager) EnableDynamicDomains(ctx context.Context, a Actor, projectSlug, serviceSlug string) error {
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if s.InternalPort == 0 {
		return i18n.E("domain.error.no_port")
	}
	if cur, err := m.q.DynamicService(ctx); err == nil && cur.ID != s.ID {
		return i18n.E("domain.error.dynamic_taken", "service", cur.ProjectSlug+"/"+cur.Slug)
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	sealed, err := m.box.Seal([]byte(hex.EncodeToString(secret)), edge.CheckSecretAD(s.ID))
	if err != nil {
		return err
	}
	if err := m.q.SetDynamicDomains(ctx, dbq.SetDynamicDomainsParams{
		DynamicDomains: 1, DomainCheckPath: s.DomainCheckPath, DomainCheckSecretEnc: sealed, UpdatedAt: m.now().Unix(), ID: s.ID,
	}); err != nil {
		return err
	}
	m.record(ctx, a, "domain.dynamic.enable", "service", s.ID, audit.OK, map[string]any{"service": p.Slug + "/" + s.Slug})
	if m.node != nil {
		if err := m.node.ConnectEdge(ctx, p.Slug, s.Slug); err != nil {
			m.log.Warn("join edge network", "service", p.Slug+"/"+s.Slug, "error", err)
		}
	}
	return m.applyEdge(ctx)
}

// DisableDynamicDomains turns customer domains off and discards the secret.
func (m *Manager) DisableDynamicDomains(ctx context.Context, a Actor, serviceID string) error {
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return err
	}
	if err := m.q.SetDynamicDomains(ctx, dbq.SetDynamicDomainsParams{
		DynamicDomains: 0, DomainCheckPath: s.DomainCheckPath, UpdatedAt: m.now().Unix(), ID: s.ID,
	}); err != nil {
		return err
	}
	m.record(ctx, a, "domain.dynamic.disable", "service", s.ID, audit.OK, nil)
	return m.applyEdge(ctx)
}

// RevealCheckSecret returns the HMAC secret (the route requires sudo) and
// records who saw it.
func (m *Manager) RevealCheckSecret(ctx context.Context, a Actor, serviceID string) (string, error) {
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return "", err
	}
	if s.DynamicDomains != 1 || len(s.DomainCheckSecretEnc) == 0 {
		return "", ErrNotFound
	}
	plain, err := m.box.Open(s.DomainCheckSecretEnc, edge.CheckSecretAD(s.ID))
	if err != nil {
		return "", err
	}
	m.record(ctx, a, "secret.reveal", "service", s.ID, audit.OK, map[string]any{"key": CheckSecretEnv})
	return string(plain), nil
}

// RotateCheckSecret replaces the dynamic-domain HMAC secret with a fresh one
// and returns the new value (shown once). The app only receives it as
// HANGAR_DOMAIN_CHECK_SECRET on its next deploy, so the panel tells the
// operator to deploy right after; until then the old secret is gone and
// domain checks fail, which is why the route needs sudo.
func (m *Manager) RotateCheckSecret(ctx context.Context, a Actor, serviceID string) (string, error) {
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return "", err
	}
	if s.DynamicDomains != 1 {
		return "", ErrNotFound
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	value := hex.EncodeToString(secret)
	sealed, err := m.box.Seal([]byte(value), edge.CheckSecretAD(s.ID))
	if err != nil {
		return "", err
	}
	if err := m.q.SetDynamicDomains(ctx, dbq.SetDynamicDomainsParams{
		DynamicDomains: 1, DomainCheckPath: s.DomainCheckPath, DomainCheckSecretEnc: sealed, UpdatedAt: m.now().Unix(), ID: s.ID,
	}); err != nil {
		return "", err
	}
	m.record(ctx, a, "domain.dynamic.rotate_secret", "service", s.ID, audit.OK, map[string]any{"key": CheckSecretEnv})
	return value, nil
}

// DomainActivity is what the dynamic domains page shows.
type DomainActivity struct {
	Recent      []dbq.TlsAskLog
	Blocked     []dbq.DomainBlocklist
	Certified   int64 // hostnames ever approved
	NewThisHour int64
	HourCap     int
	DeniedToday int64
}

// SetEdgeCap tells the page the hourly cap on new customer domains.
func (m *Manager) SetEdgeCap(n int) { m.edgeCap = n }

// DomainActivity lists recent certificate decisions (all, or only "allow"
// or "deny") and the blocklist, with the numbers on top of the page.
func (m *Manager) DomainActivity(ctx context.Context, decision string) (DomainActivity, error) {
	var recent []dbq.TlsAskLog
	var err error
	if decision == "allow" || decision == "deny" {
		recent, err = m.q.RecentAsksByDecision(ctx, dbq.RecentAsksByDecisionParams{Decision: decision, Limit: 200})
	} else {
		recent, err = m.q.RecentAsks(ctx, 200)
	}
	if err != nil {
		return DomainActivity{}, err
	}
	blocked, err := m.q.ListBlocked(ctx)
	if err != nil {
		return DomainActivity{}, err
	}
	hour := m.now().Unix() / 3600
	act := DomainActivity{Recent: recent, Blocked: blocked, HourCap: m.edgeCap}
	act.Certified, _ = m.q.CountAllowedHosts(ctx)
	act.NewThisHour, _ = m.q.CountNewAllowsSince(ctx, hour)
	if v, err := m.q.CountDeniedSince(ctx, hour-23); err == nil {
		act.DeniedToday = toInt64(v)
	}
	return act, nil
}

// BlockHostname refuses certificates for a hostname, whatever the app says.
func (m *Manager) BlockHostname(ctx context.Context, a Actor, hostname, reason string) error {
	host, ok := edge.NormalizeHostname(hostname)
	if !ok {
		return i18n.E("domain.error.hostname")
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if err := m.q.BlockHostname(ctx, dbq.BlockHostnameParams{
		Hostname: host, Reason: reason, CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, CreatedAt: m.now().Unix(),
	}); err != nil {
		return err
	}
	m.record(ctx, a, "domain.block", "domain", host, audit.OK, map[string]any{"reason": reason})
	return m.applyEdge(ctx)
}

// UnblockHostname removes a hostname from the blocklist.
func (m *Manager) UnblockHostname(ctx context.Context, a Actor, hostname string) error {
	n, err := m.q.UnblockHostname(ctx, hostname)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	m.record(ctx, a, "domain.unblock", "domain", hostname, audit.OK, nil)
	return m.applyEdge(ctx)
}

// DynamicServiceRef returns the service that takes customer domains, if any.
func (m *Manager) DynamicServiceRef(ctx context.Context) (project, service string, ok bool) {
	s, err := m.q.DynamicService(ctx)
	if err != nil {
		return "", "", false
	}
	return s.ProjectSlug, s.Slug, true
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return 0
}
