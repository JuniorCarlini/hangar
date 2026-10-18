package projects

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/edge"
)

// TestScaledDomainStoresTheTokenEncrypted: "Em escala" checks the token with
// the provider for that zone, keeps it encrypted, makes the zone the base
// domain and adds *.zone to the service.
func TestScaledDomainStoresTheTokenEncrypted(t *testing.T) {
	f := newFixture(t)
	f.m.SetEdge(&countingEdge{})
	f.service(t)
	ctx := context.Background()
	var asked []string
	f.m.dnsCheck = func(_ context.Context, provider, zone string, token []byte) error {
		asked = append(asked, provider+"|"+zone)
		if string(token) != "good-token" {
			return edge.ErrDNSTokenRejected
		}
		return nil
	}

	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "lojas.exemplo.com.br", "", "cloudflare", []byte("bad"), false); err == nil {
		t.Fatal("a token the provider refuses was accepted")
	}
	if got := f.m.BaseDomain(); got != "" {
		t.Fatalf("base domain = %q after a refused token", got)
	}
	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "lojas.exemplo.com.br", "", "route66", []byte("good-token"), false); err == nil {
		t.Fatal("an unknown provider was accepted")
	}
	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "*.Lojas.Exemplo.com.br", "", "cloudflare", []byte("good-token"), false); err != nil {
		t.Fatal(err)
	}
	if asked[len(asked)-1] != "cloudflare|lojas.exemplo.com.br" {
		t.Errorf("token checked for %v", asked)
	}
	if got := f.m.BaseDomain(); got != "lojas.exemplo.com.br" {
		t.Errorf("base domain = %q", got)
	}
	if _, err := f.m.q.GetDomainByHostname(ctx, "*.lojas.exemplo.com.br"); err != nil {
		t.Errorf("*.lojas.exemplo.com.br not added: %v", err)
	}
	row, err := f.m.q.GetEdgeSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(row.DnsTokenEnc, []byte("good-token")) {
		t.Fatal("the token is stored in clear")
	}
	dns, err := f.m.EdgeDNS(ctx)
	if err != nil || string(dns.Token) != "good-token" || dns.Provider != "cloudflare" || dns.BaseDomain != "lojas.exemplo.com.br" {
		t.Fatalf("EdgeDNS = %+v, %v", dns, err)
	}
	info, _ := f.m.EdgeDNSInfo(ctx)
	if !info.HasToken || info.FromConfig {
		t.Errorf("info = %+v", info)
	}
}

// TestScaledDomainAsksBeforeReplacingTheBase: another zone replaces the base
// domain (and every automatic link with it) only when asked for.
func TestScaledDomainAsksBeforeReplacingTheBase(t *testing.T) {
	f := newFixture(t)
	f.m.SetEdge(&countingEdge{})
	f.service(t)
	ctx := context.Background()
	f.m.dnsCheck = func(context.Context, string, string, []byte) error { return nil }
	f.m.SetBaseDomain("painel.exemplo.com.br")

	err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "lojas.exemplo.com.br", "", "cloudflare", []byte("t"), false)
	if err == nil {
		t.Fatal("the base domain was replaced without asking")
	}
	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "lojas.exemplo.com.br", "", "cloudflare", []byte("t"), true); err != nil {
		t.Fatal(err)
	}
	if got := f.m.BaseDomain(); got != "lojas.exemplo.com.br" {
		t.Errorf("base domain = %q, want the panel's over hangar.toml", got)
	}
	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "lojas.exemplo.com.br", "", "cloudflare", []byte("t"), true); !errors.Is(err, ErrExists) {
		t.Errorf("adding the same scaled domain again: %v", err)
	}
}

// TestRotateDNSToken replaces the token only with one the provider accepts.
func TestRotateDNSToken(t *testing.T) {
	f := newFixture(t)
	f.m.SetEdge(&countingEdge{})
	f.service(t)
	ctx := context.Background()
	if err := f.m.RotateEdgeDNSToken(ctx, f.who, []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate without a base domain: %v", err)
	}
	f.m.dnsCheck = func(_ context.Context, _, _ string, token []byte) error {
		if string(token) == "refused" {
			return edge.ErrDNSTokenRejected
		}
		return nil
	}
	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "lojas.exemplo.com.br", "", "cloudflare", []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	if err := f.m.RotateEdgeDNSToken(ctx, f.who, []byte("refused")); err == nil {
		t.Fatal("a refused token replaced the good one")
	}
	if err := f.m.RotateEdgeDNSToken(ctx, f.who, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if dns, _ := f.m.EdgeDNS(ctx); string(dns.Token) != "second" {
		t.Errorf("token = %q", dns.Token)
	}
}

// TestScaledDomainRollsBackWhenTheDomainFails: if *.zone cannot be added,
// the DNS settings go back to what they were, so no wildcard is obtained
// for a domain nobody routes; a public suffix is refused up front.
func TestScaledDomainRollsBackWhenTheDomainFails(t *testing.T) {
	f := newFixture(t)
	f.m.SetEdge(&countingEdge{})
	f.service(t)
	ctx := context.Background()
	calls := 0
	f.m.dnsCheck = func(context.Context, string, string, []byte) error { calls++; return nil }

	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "web", "com.br", "", "cloudflare", []byte("t"), false); err == nil {
		t.Fatal("a public suffix was accepted")
	}
	if calls != 0 {
		t.Error("the provider was asked about a public suffix")
	}
	// A service that does not exist makes AddDomain fail after the settings
	// were written.
	if err := f.m.AddScaledDomain(ctx, f.who, "lab", "nope", "lojas.exemplo.com.br", "", "cloudflare", []byte("t"), false); err == nil {
		t.Fatal("added to a missing service")
	}
	if got := f.m.BaseDomain(); got != "" {
		t.Errorf("base domain = %q after the failure", got)
	}
	if dns, _ := f.m.EdgeDNS(ctx); dns.BaseDomain != "" {
		t.Errorf("settings kept after the failure: %+v", dns)
	}
}
