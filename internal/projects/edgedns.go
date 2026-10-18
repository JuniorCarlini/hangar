package projects

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/edge"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// The edge's DNS settings live in edge_settings so they can be set from the
// panel: the base domain whose wildcard certificate is obtained by DNS-01
// ("Em escala" in the add-domain dialog), its provider and API token.

func edgeDNSAD() string { return "edge_settings|1|dns_token" }

// baseDomain is the base domain in effect: the panel's when set, else the
// one from hangar.toml.
func (m *Manager) baseDomain() string {
	if v, _ := m.dbBase.Load().(string); v != "" {
		return v
	}
	return m.cfgBase
}

// LoadEdgeDNS reads the panel's base domain at startup, so automatic links
// and reserved names follow it before anything is changed.
func (m *Manager) LoadEdgeDNS(ctx context.Context) error {
	row, err := m.q.GetEdgeSettings(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	m.dbBase.Store(row.BaseDomain)
	return nil
}

// EdgeDNS returns the panel's DNS settings with the token decrypted, for the
// edge (edge.DNSSource). Empty when none were set: the edge then uses
// hangar.toml.
func (m *Manager) EdgeDNS(ctx context.Context) (edge.DNSSettings, error) {
	row, err := m.q.GetEdgeSettings(ctx)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && row.BaseDomain == "") {
		return edge.DNSSettings{}, nil
	}
	if err != nil {
		return edge.DNSSettings{}, err
	}
	out := edge.DNSSettings{BaseDomain: row.BaseDomain, Provider: row.DnsProvider}
	if len(row.DnsTokenEnc) > 0 {
		if out.Token, err = m.box.Open(row.DnsTokenEnc, edgeDNSAD()); err != nil {
			return edge.DNSSettings{}, err
		}
	}
	return out, nil
}

// EdgeDNSInfo is what the screens show about the DNS settings: never the
// token itself.
type EdgeDNSInfo struct {
	BaseDomain string
	Provider   string
	HasToken   bool
	// FromConfig: the base domain comes from hangar.toml, not the panel.
	FromConfig bool
}

// EdgeDNSInfo describes the base domain in effect.
func (m *Manager) EdgeDNSInfo(ctx context.Context) (EdgeDNSInfo, error) {
	row, err := m.q.GetEdgeSettings(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return EdgeDNSInfo{}, err
	}
	if err == nil && row.BaseDomain != "" {
		return EdgeDNSInfo{BaseDomain: row.BaseDomain, Provider: row.DnsProvider, HasToken: len(row.DnsTokenEnc) > 0}, nil
	}
	return EdgeDNSInfo{BaseDomain: m.cfgBase, FromConfig: m.cfgBase != ""}, nil
}

// checkDNS asks the provider whether the token can manage the zone; tests
// replace it.
func (m *Manager) checkDNS(ctx context.Context, provider, zone string, token []byte) error {
	if m.dnsCheck != nil {
		return m.dnsCheck(ctx, provider, zone, token)
	}
	return edge.CheckDNSToken(ctx, provider, zone, token)
}

// setEdgeDNS validates and stores the DNS settings. An empty token keeps
// the stored one when the zone and provider do not change (changing only
// what is around it); a new zone always needs a token the provider accepts
// for that zone, so "Em escala" is only possible on a domain whose DNS the
// operator controls.
func (m *Manager) setEdgeDNS(ctx context.Context, a Actor, zone, provider string, token []byte) error {
	if !slices.Contains(edge.DNSProviders, provider) {
		return i18n.E("domain.error.dns_provider")
	}
	// The stock Caddy image would reject the DNS-01 config and keep the
	// whole edge on its previous one.
	if m.edgeStockImage.Load() {
		return i18n.E("domain.error.dns_image")
	}
	cur, err := m.q.GetEdgeSettings(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	sealed := cur.DnsTokenEnc
	if len(token) == 0 {
		if cur.BaseDomain != zone || cur.DnsProvider != provider || len(sealed) == 0 {
			return i18n.E("domain.error.dns_token_missing")
		}
	} else {
		if err := m.checkDNS(ctx, provider, zone, token); err != nil {
			m.log.Info("dns token refused", "zone", zone, "provider", provider, "error", err)
			return i18n.E("domain.error.dns_token", "zone", zone)
		}
		if sealed, err = m.box.Seal(token, edgeDNSAD()); err != nil {
			return err
		}
	}
	if err := m.q.UpsertEdgeSettings(ctx, dbq.UpsertEdgeSettingsParams{
		BaseDomain: zone, DnsProvider: provider, DnsTokenEnc: sealed,
		UpdatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, UpdatedAt: m.now().Unix(),
	}); err != nil {
		return err
	}
	m.dbBase.Store(zone)
	m.record(ctx, a, "edge.dns.set", "edge", "dns", audit.OK, map[string]any{
		"base_domain": zone, "provider": provider, "token_changed": len(token) > 0,
	})
	return nil
}

// AddScaledDomain is "Em escala": *.zone on this service, its certificate a
// single wildcard obtained by DNS-01 with the provider's token. The zone
// becomes the edge's base domain; replacing a different one must be asked
// for (replace), since every automatic link moves with it.
func (m *Manager) AddScaledDomain(ctx context.Context, a Actor, projectSlug, serviceSlug, zone, endpointID, provider string, token []byte, replace bool) error {
	// NormalizeDomain on the wildcard refuses a public suffix ("*.com.br")
	// before anything is asked of the provider.
	wild, ok := edge.NormalizeDomain("*." + strings.TrimPrefix(strings.TrimSpace(zone), "*."))
	if !ok {
		return i18n.E("domain.error.hostname")
	}
	zone = strings.TrimPrefix(wild, "*.")
	if _, err := m.q.GetDomainByHostname(ctx, wild); err == nil {
		return ErrExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if base := m.baseDomain(); base != "" && base != zone && !replace {
		return i18n.E("domain.error.base_taken", "base", base)
	}
	prev, err := m.q.GetEdgeSettings(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := m.setEdgeDNS(ctx, a, zone, provider, token); err != nil {
		return err
	}
	if err := m.AddDomain(ctx, a, projectSlug, serviceSlug, wild, endpointID); err != nil {
		// The domain was not added: put the previous settings back, so the
		// next edge reload does not obtain a wildcard nobody routes.
		if rerr := m.q.UpsertEdgeSettings(ctx, dbq.UpsertEdgeSettingsParams{
			BaseDomain: prev.BaseDomain, DnsProvider: prev.DnsProvider, DnsTokenEnc: prev.DnsTokenEnc,
			UpdatedBy: prev.UpdatedBy, UpdatedAt: m.now().Unix(),
		}); rerr != nil {
			m.log.Error("restore edge dns settings", "error", rerr)
		}
		m.dbBase.Store(prev.BaseDomain)
		return err
	}
	return nil
}

// RotateEdgeDNSToken replaces the provider token of the current base domain.
func (m *Manager) RotateEdgeDNSToken(ctx context.Context, a Actor, token []byte) error {
	cur, err := m.q.GetEdgeSettings(ctx)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && cur.BaseDomain == "") {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if len(token) == 0 {
		return i18n.E("domain.error.dns_token_missing")
	}
	if err := m.setEdgeDNS(ctx, a, cur.BaseDomain, cur.DnsProvider, token); err != nil {
		return err
	}
	return m.applyEdge(ctx)
}

// BaseDomain is the base domain in effect (panel first, then hangar.toml),
// for the screens that build automatic links.
func (m *Manager) BaseDomain() string { return m.baseDomain() }
