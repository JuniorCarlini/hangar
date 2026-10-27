package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/firewall"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Who may reach a published port.
const (
	AccessAny       = "any"
	AccessIPs       = "ips"
	AccessLocalhost = "localhost"
)

// FirewallWriter receives the IP restrictions of every published port.
type FirewallWriter interface {
	Write(rules []firewall.Rule) error
}

// SetFirewall connects the firewall writer. Without it, "only these IPs" is
// refused (it would silently be "any IP").
func (m *Manager) SetFirewall(f FirewallWriter) { m.firewall = f }

// PortInput is the "Ports" form.
type PortInput struct {
	HostPort      int
	ContainerPort int
	Protocol      string
	Access        string
	IPs           []string
	ExpiresIn     time.Duration // 0 = never
	// KeepExpiry: an edit leaves the port's closing time as it was.
	KeepExpiry bool
}

// AddPort publishes a port and redeploys the service (Docker only publishes
// ports when the container is created).
func (m *Manager) AddPort(ctx context.Context, a Actor, projectSlug, serviceSlug string, in PortInput) error {
	return m.savePort(ctx, a, projectSlug, serviceSlug, "", in)
}

// UpdatePort changes a published port (its ports, protocol, who can reach it
// and when it closes) in one redeploy: the firewall follows first, so a
// narrower access is never wider for a moment.
func (m *Manager) UpdatePort(ctx context.Context, a Actor, projectSlug, serviceSlug, portID string, in PortInput) error {
	return m.savePort(ctx, a, projectSlug, serviceSlug, portID, in)
}

// savePort creates the port (portID "") or replaces the one given, after
// the same checks for both.
func (m *Manager) savePort(ctx context.Context, a Actor, projectSlug, serviceSlug, portID string, in PortInput) error {
	if err := m.requireNode(); err != nil {
		return err
	}
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	// An edit starts from the port as it is (its closing time, to keep).
	var current *dbq.Port
	if portID != "" {
		ports, err := m.q.ListPorts(ctx, s.ID)
		if err != nil {
			return err
		}
		for i := range ports {
			if ports[i].ID == portID {
				current = &ports[i]
			}
		}
		if current == nil {
			return ErrNotFound
		}
	}
	switch {
	case in.HostPort < 1 || in.HostPort > 65535:
		return i18n.E("port.error.host_port")
	case node.ReservedHostPorts[in.HostPort]:
		return i18n.E("port.error.reserved", "port", in.HostPort)
	case in.ContainerPort < 1 || in.ContainerPort > 65535:
		return i18n.E("port.error.container_port")
	case in.Protocol != "tcp" && in.Protocol != "udp":
		return i18n.E("port.error.protocol")
	case in.Access != AccessAny && in.Access != AccessIPs && in.Access != AccessLocalhost:
		return i18n.E("port.error.access")
	case in.ExpiresIn < 0 || in.ExpiresIn > 90*24*time.Hour:
		return i18n.E("port.error.expires")
	}
	// Publishing needs a redeploy: refuse now instead of storing a port that
	// would not be published.
	if err := m.noDeployRunning(ctx, s.ID); err != nil {
		return err
	}
	var allow []string
	if in.Access == AccessIPs {
		if m.firewall == nil {
			return i18n.E("port.error.no_firewall")
		}
		for _, raw := range in.IPs {
			if raw == "" {
				continue
			}
			pfx, err := firewall.ParseAllow(raw)
			if err != nil {
				return i18n.E("port.error.ip", "value", raw)
			}
			allow = append(allow, pfx.String())
		}
		if len(allow) == 0 || len(allow) > 64 {
			return i18n.E("port.error.ips_count")
		}
	}
	if n, err := m.q.PortInUseByOther(ctx, dbq.PortInUseByOtherParams{HostPort: int64(in.HostPort), Protocol: in.Protocol, ID: portID}); err != nil {
		return err
	} else if n > 0 {
		return i18n.E("port.error.in_use", "port", in.HostPort)
	}
	ipsJSON, _ := json.Marshal(allow)
	if allow == nil {
		ipsJSON = []byte("[]")
	}
	var expires sql.NullInt64
	if in.ExpiresIn > 0 {
		expires = sql.NullInt64{Int64: m.now().Add(in.ExpiresIn).Unix(), Valid: true}
	}
	if in.KeepExpiry && current != nil {
		expires = current.ExpiresAt
	}
	// A change is recorded as an opening too, so the security alerts
	// (a port opened to any IP) see a port widened by editing it.
	if portID == "" {
		err = m.q.CreatePort(ctx, dbq.CreatePortParams{
			ID: ids.New("prt_"), ServiceID: s.ID, HostPort: int64(in.HostPort), ContainerPort: int64(in.ContainerPort),
			Protocol: in.Protocol, Access: in.Access, AllowedIps: string(ipsJSON), ExpiresAt: expires,
			CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, CreatedAt: m.now().Unix(),
		})
	} else {
		var n int64
		n, err = m.q.UpdatePort(ctx, dbq.UpdatePortParams{
			HostPort: int64(in.HostPort), ContainerPort: int64(in.ContainerPort), Protocol: in.Protocol,
			Access: in.Access, AllowedIps: string(ipsJSON), ExpiresAt: expires, ID: portID, ServiceID: s.ID,
		})
		if err == nil && n == 0 {
			return ErrNotFound
		}
	}
	if err != nil {
		return err
	}
	m.record(ctx, a, "port.open", "service", s.ID, audit.OK, map[string]any{
		"service": p.Slug + "/" + s.Slug, "host_port": in.HostPort, "container_port": in.ContainerPort,
		"protocol": in.Protocol, "access": in.Access, "ips": allow, "expires_in": in.ExpiresIn.String(),
		"changed": portID != "",
	})
	// The firewall goes first: a restricted port must never be open for a
	// moment to everyone.
	if err := m.syncFirewall(ctx); err != nil {
		return err
	}
	_, err = m.Deploy(ctx, a, p.Slug, s.Slug, "ports")
	return err
}

// RemovePort closes a published port.
func (m *Manager) RemovePort(ctx context.Context, a Actor, projectSlug, serviceSlug, portID string) error {
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if err := m.noDeployRunning(ctx, s.ID); err != nil {
		return err
	}
	hostPort, err := m.q.DeletePort(ctx, dbq.DeletePortParams{ID: portID, ServiceID: s.ID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	m.record(ctx, a, "port.close", "service", s.ID, audit.OK, map[string]any{"service": p.Slug + "/" + s.Slug, "host_port": hostPort})
	if m.node == nil {
		return m.syncFirewall(ctx)
	}
	if _, err := m.Deploy(ctx, a, p.Slug, s.Slug, "ports"); err != nil {
		return err
	}
	return m.syncFirewall(ctx)
}

// Port is a published port as the UI shows it.
type Port struct {
	dbq.Port
	Project string
	Service string
	IPs     []string
	Owner   string // e-mail of who opened it
}

func toPort(r dbq.Port, project, service string) Port {
	pt := Port{Port: r, Project: project, Service: service}
	_ = json.Unmarshal([]byte(r.AllowedIps), &pt.IPs)
	return pt
}

// ListPorts lists a service's published ports.
func (m *Manager) ListPorts(ctx context.Context, serviceID string) ([]Port, error) {
	rows, err := m.q.ListPorts(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	out := make([]Port, 0, len(rows))
	for _, r := range rows {
		out = append(out, toPort(r, "", ""))
	}
	return out, nil
}

// ListAllPorts lists every published port on the server ("Open ports").
func (m *Manager) ListAllPorts(ctx context.Context) ([]Port, error) {
	rows, err := m.q.ListAllPortsWithOwner(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Port, 0, len(rows))
	for _, r := range rows {
		pt := toPort(dbq.Port{
			ID: r.ID, ServiceID: r.ServiceID, HostPort: r.HostPort, ContainerPort: r.ContainerPort, Protocol: r.Protocol,
			Access: r.Access, AllowedIps: r.AllowedIps, ExpiresAt: r.ExpiresAt, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		}, r.ProjectSlug, r.ServiceSlug)
		pt.Owner = r.OwnerEmail
		out = append(out, pt)
	}
	return out, nil
}

// syncFirewall rewrites the IP restrictions from the database.
func (m *Manager) syncFirewall(ctx context.Context) error {
	if m.firewall == nil {
		return nil
	}
	rows, err := m.q.ListAllPorts(ctx)
	if err != nil {
		return err
	}
	var rules []firewall.Rule
	for _, r := range rows {
		if r.Access != AccessIPs {
			continue
		}
		var ips []string
		_ = json.Unmarshal([]byte(r.AllowedIps), &ips)
		rule := firewall.Rule{Port: int(r.HostPort), Protocol: r.Protocol}
		for _, ip := range ips {
			if pfx, err := netip.ParsePrefix(ip); err == nil {
				rule.Allow = append(rule.Allow, pfx)
			}
		}
		rules = append(rules, rule)
	}
	if err := m.firewall.Write(rules); err != nil {
		m.log.Error("write firewall rules", "error", err)
		return i18n.E("port.error.firewall", "error", err)
	}
	return nil
}

// RunPortExpiry closes expired ports every interval until ctx ends. It also
// rewrites the firewall once at start, so a reboot or a lost file never
// leaves a restricted port open.
func (m *Manager) RunPortExpiry(ctx context.Context, every time.Duration) {
	if err := m.syncFirewall(ctx); err != nil {
		m.log.Error("firewall at start", "error", err)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.expirePorts(ctx)
		}
	}
}

func (m *Manager) expirePorts(ctx context.Context) {
	rows, err := m.q.ExpiredPorts(ctx, sql.NullInt64{Int64: m.now().Unix(), Valid: true})
	if err != nil {
		m.log.Error("expired ports", "error", err)
		return
	}
	system := Actor{}
	for _, r := range rows {
		if err := m.RemovePort(ctx, system, r.ProjectSlug, r.ServiceSlug, r.ID); err != nil {
			m.log.Warn("close expired port", "port", r.HostPort, "error", err)
			continue
		}
		m.log.Info("expired port closed", "port", r.HostPort, "service", r.ProjectSlug+"/"+r.ServiceSlug)
	}
}

// FirewallStatus reports whether the root unit still has to apply the
// current rules, or failed to.
func (m *Manager) FirewallStatus() (pending bool, errText string, appliedAt time.Time) {
	st, ok := m.firewall.(interface {
		Status() (bool, firewall.Applied)
	})
	if !ok {
		return false, "", time.Time{}
	}
	pending, applied := st.Status()
	return pending, applied.Error, applied.At
}

func (m *Manager) noDeployRunning(ctx context.Context, serviceID string) error {
	n, err := m.q.HasRunningDeployment(ctx, serviceID)
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrDeployRunning
	}
	return nil
}
