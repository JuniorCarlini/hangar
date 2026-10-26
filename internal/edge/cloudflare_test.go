package edge

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A name proxied by Cloudflare (orange cloud) reaches the server through
// Cloudflare's edge: it counts as pointing here, and the path is recorded.
// A name that resolves somewhere else is refused before the app is asked.
func TestCloudflareProxiedDomainsPointHere(t *testing.T) {
	f := newFixture(t, true)
	here := netip.MustParseAddr("203.0.113.10")
	f.a.PublicIPs = []netip.Addr{here}
	cf := netip.MustParseAddr("104.21.56.199")
	answers := map[string][]netip.Addr{
		"loja1.com.br":  {cf, netip.MustParseAddr("2606:4700:3030::6815:38c7")},
		"www.loja2.com": {cf, netip.MustParseAddr("198.51.100.7")}, // half Cloudflare: not ours
	}
	f.a.LookupIP = func(_ context.Context, host string) ([]netip.Addr, error) { return answers[host], nil }
	ctx := context.Background()
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); !ok || why != ReasonAppAllowed {
		t.Fatalf("via Cloudflare: %v %s", ok, why)
	}
	rows, _ := f.q.RecentAsks(ctx, 5)
	if len(rows) == 0 || rows[0].Via != string(PathCloudflare) {
		t.Errorf("path not recorded: %+v", rows)
	}
	calls := f.app.calls.Load()
	if ok, why := f.a.Decide(ctx, "www.loja2.com"); ok || why != ReasonDNSMismatch {
		t.Fatalf("mixed answer: %v %s", ok, why)
	}
	if f.app.calls.Load() != calls {
		t.Error("the app was asked about a name that does not reach the server")
	}
	if !isCloudflare(netip.MustParseAddr("::ffff:172.67.156.10")) || isCloudflare(here) {
		t.Error("Cloudflare ranges")
	}
}

// A service that requires the ownership TXT approves a domain only when
// _hangar.<domain> holds its code; a missing record waits and is not cached.
func TestOwnershipTXT(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	if err := f.q.SetDomainRequireTXT(ctx, dbq.SetDomainRequireTXTParams{DomainRequireTxt: 1, UpdatedAt: 1, ID: "svc_1"}); err != nil {
		t.Fatal(err)
	}
	txt := map[string][]string{}
	f.a.LookupTXT = func(_ context.Context, name string) ([]string, error) {
		if v, ok := txt[name]; ok {
			return v, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	calls := f.app.calls.Load()
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); ok || why != ReasonTXTMissing {
		t.Fatalf("without the TXT: %v %s", ok, why)
	}
	if f.app.calls.Load() != calls {
		t.Error("the app was asked before the ownership check")
	}
	txt["_hangar.loja1.com.br"] = []string{"hg-000000000000"}
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); ok || why != ReasonTXTMissing {
		t.Fatalf("wrong code: %v %s", ok, why)
	}
	txt["_hangar.loja1.com.br"] = []string{"outra coisa", OwnershipCode(checkSecret, "loja1.com.br")}
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatalf("right code (not cached as a refusal): %s", why)
	}
	if OwnershipCode(checkSecret, "a.com") == OwnershipCode(checkSecret, "b.com") || len(OwnershipCode(checkSecret, "a.com")) != 15 {
		t.Error("the code must depend on the domain and be hg- plus 12 hex")
	}
}

// The panel's hourly cap overrides the configured default.
func TestHourlyCapFromThePanel(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	if err := f.q.SetSetting(ctx, dbq.SetSettingParams{Key: MaxNewSetting, ValueJson: "2"}); err != nil {
		t.Fatal(err)
	}
	allowed := 0
	for i := range 5 {
		if ok, _ := f.a.Decide(ctx, "loja-extra-"+strconv.Itoa(i)+".com"); ok {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("allowed %d, want the panel's cap of 2", allowed)
	}
}

// Turning the TXT on later must not break the renewals of customers already
// served: a host approved before passes without the record.
func TestOwnershipTXTSparesServedHosts(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatalf("first approval: %s", why)
	}
	if err := f.q.SetDomainRequireTXT(ctx, dbq.SetDomainRequireTXTParams{DomainRequireTxt: 1, UpdatedAt: 1, ID: "svc_1"}); err != nil {
		t.Fatal(err)
	}
	f.a.Forget()
	f.a.LookupTXT = func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatalf("renewal of a served host: %s", why)
	}
	if ok, why := f.a.Decide(ctx, "loja-nova.com.br"); ok || why != ReasonTXTMissing {
		t.Fatalf("new host without the TXT: %v %s", ok, why)
	}
}

// The panel's test shows every check and leaves no trace: no log row, no
// cache entry, nothing counted toward the hourly cap.
func TestProbeHasNoSideEffects(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	f.a.LookupTXT = func(_ context.Context, name string) ([]string, error) {
		return []string{OwnershipCode(checkSecret, "loja1.com.br")}, nil
	}
	p, err := f.a.Probe(ctx, "Loja1.com.br")
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "loja1.com.br" || p.App != ReasonAppAllowed || !p.TXTFound || p.TXTRecord != "_hangar.loja1.com.br" {
		t.Errorf("probe: %+v", p)
	}
	if rows, _ := f.q.RecentAsks(ctx, 5); len(rows) != 0 {
		t.Errorf("the probe was logged: %+v", rows)
	}
	if len(f.a.cache) != 0 {
		t.Error("the probe was cached")
	}
	if _, err := f.a.Probe(ctx, "1.2.3.4"); !IsInvalidHost(err) {
		t.Errorf("an IP is not a hostname: %v", err)
	}
}
