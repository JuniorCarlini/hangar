package edge

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{"*.Loja.com.br": "*.loja.com.br", " app.loja.com ": "app.loja.com", "*.a.b.example": "*.a.b.example"}
	for in, want := range ok {
		if got, valid := NormalizeDomain(in); !valid || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v", in, got, valid)
		}
	}
	for _, bad := range []string{"*", "*.", "*.com", "*.com.br", "*.co.uk", "**.loja.com", "a.*.loja.com", "*loja.com", "*.*.loja.com", "*.localhost"} {
		if _, valid := NormalizeDomain(bad); valid {
			t.Errorf("NormalizeDomain(%q) should be invalid", bad)
		}
	}
	if _, valid := NormalizeHostname("*.loja.com.br"); valid {
		t.Error("a handshake hostname is never a wildcard")
	}
}

func TestWildcardCoversOneLevelWithCapAndDNS(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	if err := f.q.CreateDomain(ctx, dbq.CreateDomainParams{ID: "dom_w", ServiceID: "svc_1", Hostname: "*.loja.com.br", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	if ok, why := f.a.Decide(ctx, "abc.loja.com.br"); !ok || why != ReasonWildcard {
		t.Fatalf("subdomain of a wildcard: %v %s", ok, why)
	}
	for _, host := range []string{"loja.com.br", "a.b.loja.com.br", "outra.com.br"} {
		if ok, _ := f.a.Decide(ctx, host); ok {
			t.Errorf("%s is not covered by *.loja.com.br", host)
		}
	}
	if f.app.calls.Load() != 0 {
		t.Error("a wildcard does not ask the app")
	}

	f.a.MaxNewPerHour = 1
	f.a.Forget()
	if ok, why := f.a.Decide(ctx, "xyz.loja.com.br"); ok || why != ReasonRateLimited {
		t.Fatalf("made-up subdomains count toward the hourly cap: %v %s", ok, why)
	}
	if ok, _ := f.a.Decide(ctx, "abc.loja.com.br"); !ok {
		t.Fatal("a subdomain approved before must keep renewing")
	}

	f.a.MaxNewPerHour = 30
	f.a.PublicIPs = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	f.a.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
	}
	if ok, why := f.a.Decide(ctx, "novo.loja.com.br"); ok || why != ReasonDNSMismatch {
		t.Fatalf("DNS elsewhere: %v %s", ok, why)
	}
	if err := f.q.BlockHostname(ctx, dbq.BlockHostnameParams{Hostname: "ruim.loja.com.br", Reason: "x", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if ok, why := f.a.Decide(ctx, "ruim.loja.com.br"); ok || why != ReasonBlocked {
		t.Fatalf("blocklist wins over the wildcard: %v %s", ok, why)
	}
}

func TestWildcardIsServedOnDemandAfterExactNames(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//run/caddy/admin.sock",
		AskURL:      "http://172.30.0.1:7701/internal/tls/ask",
		Fixed: []Route{
			{Hosts: []string{"*.loja.com.br", "loja.com.br"}, Upstream: "a_web:80", Key: "a_web"},
			{Hosts: []string{"admin.loja.com.br"}, Upstream: "b_web:80", Key: "b_web"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	routes, _ := get(m, "apps", "http", "servers", "edge", "routes").([]any)
	var order []string
	for _, r := range routes {
		js, _ := json.Marshal(r)
		switch {
		case strings.Contains(string(js), `"*.loja.com.br"`):
			order = append(order, "wild")
		case strings.Contains(string(js), `"host":["admin.loja.com.br"]`), strings.Contains(string(js), `"host":["loja.com.br"]`):
			order = append(order, "exact")
		}
	}
	if strings.Join(order, ",") != "exact,exact,wild" {
		t.Errorf("exact names must route before the wildcard: %v", order)
	}
	pols, _ := get(m, "apps", "tls", "automation", "policies").([]any)
	if len(pols) != 2 {
		t.Fatalf("policies: %d", len(pols))
	}
	exact, _ := json.Marshal(pols[0])
	wild, _ := json.Marshal(pols[1])
	if strings.Contains(string(exact), "*.") || strings.Contains(string(exact), "on_demand") {
		t.Errorf("exact names get a regular certificate: %s", exact)
	}
	// No wildcard certificate (it needs DNS-01): one per subdomain, on demand.
	if !strings.Contains(string(wild), `"subjects":["*.loja.com.br"]`) || !strings.Contains(string(wild), `"on_demand":true`) {
		t.Errorf("the wildcard must be issued on demand: %s", wild)
	}
	if get(m, "apps", "tls", "automation", "on_demand", "permission", "endpoint") != "http://172.30.0.1:7701/internal/tls/ask" {
		t.Error("a wildcard needs the ask endpoint, even without dynamic domains")
	}
}

func TestWildcardNeedsAskEndpoint(t *testing.T) {
	if _, err := BuildConfig(ConfigInput{
		AdminListen: "unix//run/caddy/admin.sock",
		Fixed:       []Route{{Hosts: []string{"*.loja.com.br"}, Upstream: "a_web:80"}},
	}); err == nil {
		t.Fatal("a wildcard without the ask endpoint would issue certificates for any name")
	}
}
