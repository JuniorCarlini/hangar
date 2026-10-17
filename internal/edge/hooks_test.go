package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// The hooks hostname publishes /hooks/git/* only, before the dynamic
// catch-all, and gets a regular certificate.
func TestConfigPublishesOnlyTheHooksPath(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//run/caddy/admin.sock|0660",
		AskURL:      "http://172.30.0.1:7701/internal/tls/ask",
		Hooks:       &Route{Hosts: []string{"hooks.hangar.dev"}, Upstream: "172.30.0.1:7701"},
		Dynamic:     &Route{Upstream: "lab_web:8000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	routes, _ := get(m, "apps", "http", "servers", "edge", "routes").([]any)
	if len(routes) != 4 {
		t.Fatalf("routes: %d", len(routes))
	}
	hook, _ := json.Marshal(routes[1])
	if !strings.Contains(string(hook), `"/hooks/git/*"`) || !strings.Contains(string(hook), "172.30.0.1:7701") || !strings.Contains(string(hook), "hooks.hangar.dev") {
		t.Errorf("hooks route: %s", hook)
	}
	rest, _ := json.Marshal(routes[2])
	if !strings.Contains(string(rest), "hooks.hangar.dev") || !strings.Contains(string(rest), "404") || strings.Contains(string(rest), "reverse_proxy") {
		t.Errorf("the rest of the hooks host must be 404: %s", rest)
	}
	pol, _ := json.Marshal(get(m, "apps", "tls", "automation", "policies"))
	if !strings.Contains(string(pol), "hooks.hangar.dev") {
		t.Errorf("hooks host needs a certificate policy: %s", pol)
	}
}

func TestListenerHandsHooksOnlyFromCaddy(t *testing.T) {
	caddy := netip.MustParseAddr("172.30.0.2")
	var got string
	hooks := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ForwardedIP(r)
		w.WriteHeader(http.StatusAccepted)
	})
	ask := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := listenerHandler(ask, hooks, caddy)

	r := httptest.NewRequest(http.MethodPost, "/hooks/git/abc", nil)
	r.RemoteAddr = "172.30.0.9:5000" // another container on the edge network
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("hooks from outside Caddy: %d", rec.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/hooks/git/abc", nil)
	r.RemoteAddr = "172.30.0.2:5000"
	r.Header.Set("X-Forwarded-For", "140.82.115.4")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusAccepted || got != "140.82.115.4" {
		t.Fatalf("hooks from Caddy: %d ip %q", rec.Code, got)
	}

	r = httptest.NewRequest(http.MethodGet, AskPath, nil)
	r.RemoteAddr = "172.30.0.2:5000"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("ask endpoint not reached: %d", rec.Code)
	}
}
