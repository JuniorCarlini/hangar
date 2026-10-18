package edge

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store"
)

// fakeCaddy is the admin API: it rejects any config containing reject, and
// remembers the last one it accepted.
type fakeCaddy struct {
	mu       sync.Mutex
	reject   []string
	accepted string
	loads    int
}

func (c *fakeCaddy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}
	c.loads++
	for _, bad := range c.reject {
		if strings.Contains(string(body), bad) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("module not registered: dns.providers.cloudflare"))
			return
		}
	}
	c.accepted = string(body)
	w.WriteHeader(http.StatusOK)
}

func (c *fakeCaddy) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepted
}

// edgeNode is a node that only knows how to (pretend to) start Caddy.
type edgeNode struct {
	node.Node
	ensured int
}

func (n *edgeNode) EnsureEdge(context.Context, node.EdgeSpec) error { n.ensured++; return nil }

// newBootManager is a Manager whose admin API is caddy (nil = Caddy does not
// answer at all), with the DNS-01 wildcard configured in hangar.toml.
func newBootManager(t *testing.T, caddy http.Handler) *Manager {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	addr := "127.0.0.1:1" // nothing listens: Caddy does not answer
	if caddy != nil {
		srv := httptest.NewServer(caddy)
		t.Cleanup(srv.Close)
		addr = srv.Listener.Addr().String()
	}
	admin := filepath.Join(dir, "admin")
	if err := os.MkdirAll(admin, 0o700); err != nil {
		t.Fatal(err)
	}
	m := NewManager(st.Q, &edgeNode{}, NewAuthorizer(st.DB, nil, nil), Options{
		Spec: node.EdgeSpec{
			AdminDir: admin, DataDir: filepath.Join(dir, "data"),
			Gateway: netip.MustParseAddr("172.30.0.1"), CaddyIP: netip.MustParseAddr("172.30.0.2"),
		},
		PanelHost:  "hangar.apps.exemplo.com",
		BaseDomain: "apps.exemplo.com", DNSProvider: "cloudflare", DNSToken: "tok-123",
	}, log)
	m.loadWait = 300 * time.Millisecond
	m.http = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}}
	return m
}

func readBoot(t *testing.T, m *Manager) string {
	t.Helper()
	b, err := os.ReadFile(m.bootPath())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A config Caddy rejects must never become its boot config: on the next
// reboot Caddy would crash-loop on it and take every site and the panel down.
func TestApplySavesTheBootConfigOnlyWhenCaddyAcceptsIt(t *testing.T) {
	caddy := &fakeCaddy{}
	m := newBootManager(t, caddy)
	ctx := context.Background()
	if err := m.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	good := readBoot(t, m)
	if good != caddy.last() || !strings.Contains(good, "tok-123") {
		t.Fatal("the accepted config should be the boot config")
	}

	caddy.mu.Lock()
	caddy.reject = []string{"cloudflare"}
	caddy.mu.Unlock()
	if err := m.Apply(ctx); err == nil {
		t.Fatal("a rejected config should return an error")
	}
	if got := readBoot(t, m); got != good {
		t.Error("a rejected config replaced the last good boot config")
	}
}

// When Caddy rejects the full config, the last good one keeps serving and
// Degraded says why.
func TestBringUpFallsBackToTheLastGoodConfig(t *testing.T) {
	caddy := &fakeCaddy{reject: []string{"cloudflare"}}
	m := newBootManager(t, caddy)
	const last = `{"last":"good"}`
	if err := writeFile(m.bootPath(), []byte(last)); err != nil {
		t.Fatal(err)
	}
	if err := m.bringUp(context.Background()); err != nil {
		t.Fatalf("the edge should stay up on the last good config: %v", err)
	}
	if caddy.last() != last {
		t.Errorf("caddy runs %q, want the last good config", caddy.last())
	}
	if readBoot(t, m) != last {
		t.Error("the boot config changed")
	}
	if d := m.Degraded(); !strings.Contains(d, "rejected") {
		t.Errorf("Degraded = %q, want the rejection", d)
	}
}

// With no last good config (or one Caddy rejects too), the minimal config
// serves the panel and the error pages, and becomes the boot config.
func TestBringUpFallsBackToTheMinimalConfig(t *testing.T) {
	caddy := &fakeCaddy{reject: []string{"cloudflare", `"last"`}}
	m := newBootManager(t, caddy)
	if err := writeFile(m.bootPath(), []byte(`{"last":"bad"}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.bringUp(context.Background()); err != nil {
		t.Fatalf("the minimal config should load: %v", err)
	}
	got := caddy.last()
	if !strings.Contains(got, "hangar.apps.exemplo.com") || !strings.Contains(got, "unknown.html") {
		t.Errorf("the minimal config must serve the panel and the error pages: %s", got)
	}
	if strings.Contains(got, "cloudflare") {
		t.Error("the minimal config must not depend on the DNS provider")
	}
	if readBoot(t, m) != got {
		t.Error("the minimal config Caddy accepted should be the boot config")
	}
	if m.Degraded() == "" {
		t.Error("Degraded should say why the full config is not running")
	}
	// Once the full config loads again, the edge is no longer degraded.
	caddy.mu.Lock()
	caddy.reject = nil
	caddy.mu.Unlock()
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Degraded() != "" {
		t.Error("Degraded should clear after the full config loads")
	}
}

// A Caddy that never answers may be crash-looping on its boot config (one an
// older Hangar wrote without checking): it is replaced by the minimal one.
func TestBringUpReplacesTheBootConfigWhenCaddyNeverAnswers(t *testing.T) {
	m := newBootManager(t, nil)
	if err := writeFile(m.bootPath(), []byte(`{"crash":"loop"}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.bringUp(context.Background()); err == nil {
		t.Fatal("a Caddy that never answers is an error")
	}
	minimal, err := m.minimal()
	if err != nil {
		t.Fatal(err)
	}
	if readBoot(t, m) != string(minimal) {
		t.Error("the boot config should now be the minimal one")
	}
}

func TestEnsureBootFileWritesTheMinimalConfigOnce(t *testing.T) {
	m := newBootManager(t, &fakeCaddy{})
	if err := m.ensureBootFile(); err != nil {
		t.Fatal(err)
	}
	minimal, _ := m.minimal()
	if readBoot(t, m) != string(minimal) {
		t.Fatal("a first start boots Caddy from the minimal config")
	}
	if err := writeFile(m.bootPath(), []byte(`{"kept":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := m.ensureBootFile(); err != nil {
		t.Fatal(err)
	}
	if readBoot(t, m) != `{"kept":true}` {
		t.Error("an existing boot config must be kept")
	}
}

func TestCheckAndHeal(t *testing.T) {
	caddy := &fakeCaddy{}
	m := newBootManager(t, caddy)
	if err := m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Heal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.node.(*edgeNode).ensured != 1 || caddy.last() == "" {
		t.Error("Heal should ensure the container and load the config")
	}
	if err := newBootManager(t, nil).Check(context.Background()); err == nil {
		t.Error("a Caddy that does not answer should fail the check")
	}
}

// The panel never rides the DNS-01 wildcard: a revoked DNS token would stop
// its certificate from renewing and lock everyone out of the panel.
func TestPanelHostKeepsItsOwnCertificate(t *testing.T) {
	m := newBootManager(t, &fakeCaddy{})
	cfg, err := m.build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := decode(t, cfg)
	policies, _ := get(c, "apps", "tls", "automation", "policies").([]any)
	var own bool
	for _, p := range policies {
		subjects, _ := get(p, "subjects").([]any)
		for _, s := range subjects {
			if s == "hangar.apps.exemplo.com" {
				own = get(p, "issuers") != nil && !strings.Contains(mustJSON(t, p), "dns")
			}
		}
	}
	if !own {
		t.Errorf("the panel host needs its own HTTP-01 policy: %v", policies)
	}
	if skip := mustJSON(t, get(c, "apps", "http", "servers", "edge", "automatic_https")); strings.Contains(skip, "hangar.apps.exemplo.com") {
		t.Errorf("the panel host must not be skipped by automatic HTTPS: %s", skip)
	}
	// :80 waits on the panel's own certificate file, not the wildcard's.
	redirect := mustJSON(t, get(c, "apps", "http", "servers", "redirect", "routes"))
	if !strings.Contains(redirect, "hangar.apps.exemplo.com") || strings.Contains(redirect, "wildcard_") {
		t.Errorf("the panel should wait on its own certificate: %s", redirect)
	}

	// A wildcard certificate on disk does not count for the panel.
	certs := filepath.Join(m.opts.Spec.DataDir, "caddy", "certificates", "acme", "wildcard_.apps.exemplo.com")
	if err := os.MkdirAll(certs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certs, "wildcard_.apps.exemplo.com.crt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if m.HasCertificate("hangar.apps.exemplo.com") {
		t.Error("the panel has no certificate of its own yet")
	}
	if !m.HasCertificate("loja-web.apps.exemplo.com") {
		t.Error("other hosts under the base are covered by the wildcard")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
