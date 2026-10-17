package edge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func get(m any, path ...string) any {
	for _, p := range path {
		mm, ok := m.(map[string]any)
		if !ok {
			return nil
		}
		m = mm[p]
	}
	return m
}

func TestConfigRefusesTCPAdmin(t *testing.T) {
	if _, err := BuildConfig(ConfigInput{AdminListen: "localhost:2019"}); err == nil {
		t.Fatal("the admin API must never listen on TCP")
	}
}

func TestConfigWithDynamicDomains(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//run/caddy/admin.sock|0660",
		AskURL:      "http://172.30.0.1:7701/internal/tls/ask",
		Email:       "ops@hangar.dev",
		Fixed:       []Route{{Hosts: []string{"painel.hangar.dev"}, Upstream: "lab_web:8000"}},
		Dynamic:     &Route{Upstream: "lab_web:8000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)

	if get(m, "admin", "listen") != "unix//run/caddy/admin.sock|0660" {
		t.Error("admin listen")
	}
	perm := get(m, "apps", "tls", "automation", "on_demand", "permission")
	if get(perm, "module") != "http" || get(perm, "endpoint") != "http://172.30.0.1:7701/internal/tls/ask" {
		t.Errorf("on-demand permission: %v", perm)
	}
	routes, _ := get(m, "apps", "http", "servers", "edge", "routes").([]any)
	if len(routes) != 3 {
		t.Fatalf("routes: %d", len(routes))
	}
	// The internal domain-check path is blocked before anything else.
	first, _ := json.Marshal(routes[0])
	if !strings.Contains(string(first), "/.well-known/hangar/*") || !strings.Contains(string(first), "404") {
		t.Errorf("first route must block the internal path: %s", first)
	}
	last, _ := json.Marshal(routes[2])
	if strings.Contains(string(last), "match") || !strings.Contains(string(last), "lab_web:8000") {
		t.Errorf("the catch-all must send every other host to the dynamic service: %s", last)
	}
}

func TestConfigWithoutDynamicHasNoOnDemand(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//run/caddy/admin.sock|0660",
		Fixed:       []Route{{Hosts: []string{"b.hangar.dev", "a.hangar.dev"}, Upstream: "x_web:80"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("on_demand")) {
		t.Fatal("no dynamic service means no on-demand TLS at all")
	}
	m := decode(t, b)
	routes, _ := get(m, "apps", "http", "servers", "edge", "routes").([]any)
	last, _ := json.Marshal(routes[len(routes)-1])
	if !strings.Contains(string(last), `"handler":"error","status_code":404`) {
		t.Errorf("unknown hosts should get a 404 error (the unknown-domain page): %s", last)
	}
}

func TestErrorPagesPerSite(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//run/caddy/admin.sock",
		AskURL:      "http://172.30.0.1:7701/internal/tls/ask",
		Fixed:       []Route{{Hosts: []string{"b.test", "a.test"}, Upstream: "lab_web:8000", Key: "lab_web"}},
		Dynamic:     &Route{Upstream: "loja_web:8000", Key: "loja_web"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	errs, _ := get(m, "apps", "http", "servers", "edge", "errors", "routes").([]any)
	all, _ := json.Marshal(errs)
	s := string(all)
	for _, want := range []string{
		`"/unknown.html"`, `"/timeout.html"`, `"/down.html"`, `"/deploy.html"`,
		`"try_files":["/lab_web.deploying"]`, `"try_files":["/loja_web.deploying"]`,
		`"host":["a.test","b.test"]`, `"delimiters":["[[","]]"]`, `"root":"/run/caddy/pages"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("error routes lack %s", want)
		}
	}
	// The site routes come before the catch-all "down" page.
	last, _ := json.Marshal(errs[len(errs)-1])
	if !strings.Contains(string(last), "/down.html") || strings.Contains(string(last), "host") {
		t.Errorf("last error route should be the generic down page: %s", last)
	}
	if !bytes.Contains(b, []byte(`"response_header_timeout": "100s"`)) {
		t.Error("the proxy should give up after 100 s (timeout page)")
	}
}

func TestConfigIsDeterministic(t *testing.T) {
	in := ConfigInput{
		AdminListen: "unix//x|0660",
		Fixed: []Route{
			{Hosts: []string{"z.dev", "a.dev"}, Upstream: "p_b:80"},
			{Hosts: []string{"m.dev"}, Upstream: "p_a:80"},
		},
	}
	a, _ := BuildConfig(in)
	in.Fixed[0], in.Fixed[1] = in.Fixed[1], in.Fixed[0]
	b, _ := BuildConfig(in)
	if !bytes.Equal(a, b) {
		t.Fatal("the same input in another order must produce the same config")
	}
}

func TestConfigPebbleIssuer(t *testing.T) {
	b, _ := BuildConfig(ConfigInput{
		AdminListen: "unix//x|0660", ACMECA: "https://pebble:14000/dir", ACMECARoots: []string{"/run/caddy/pebble.pem"},
		Fixed: []Route{{Hosts: []string{"a.dev"}, Upstream: "p_a:80"}},
	})
	if !bytes.Contains(b, []byte(`"ca": "https://pebble:14000/dir"`)) || !bytes.Contains(b, []byte("trusted_roots_pem_files")) {
		t.Fatalf("custom ACME CA not set: %s", b)
	}
}

func TestProxyRetriesDuringDeploys(t *testing.T) {
	b, _ := BuildConfig(ConfigInput{AdminListen: "unix//x|0660", Fixed: []Route{{Hosts: []string{"a.dev"}, Upstream: "p_a:80"}}})
	if !bytes.Contains(b, []byte(`"try_duration": "10s"`)) {
		t.Fatal("the proxy must retry refused connections while a deploy switches containers")
	}
}

// siteRouteFor finds the main route that matches exactly hosts (nil = the
// catch-all), as JSON.
func siteRouteFor(t *testing.T, m map[string]any, hosts ...string) string {
	t.Helper()
	want, _ := json.Marshal(hosts)
	routes, _ := get(m, "apps", "http", "servers", "edge", "routes").([]any)
	for _, r := range routes {
		j, _ := json.Marshal(r)
		if len(hosts) == 0 && !strings.Contains(string(j), "match") ||
			len(hosts) > 0 && strings.Contains(string(j), `"host":`+string(want)) && !strings.Contains(string(j), `"path"`) {
			return string(j)
		}
	}
	t.Fatalf("no route for %v", hosts)
	return ""
}

func TestMaintenanceServesThePageInsteadOfProxying(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//x|0660",
		AskURL:      "http://172.30.0.1:7701/internal/tls/ask",
		Fixed: []Route{
			{Hosts: []string{"loja.dev", "*.loja.dev"}, Upstream: "loja_web:80", Key: "loja_web", Maintenance: true},
			{Hosts: []string{"blog.dev"}, Upstream: "blog_web:80", Key: "blog_web"},
		},
		Dynamic: &Route{Upstream: "saas_web:80", Key: "saas_web", Maintenance: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	for name, r := range map[string]string{
		"loja.dev":   siteRouteFor(t, m, "loja.dev"),
		"*.loja.dev": siteRouteFor(t, m, "*.loja.dev"),
		"dynamic":    siteRouteFor(t, m),
	} {
		if !strings.Contains(r, `"/maint.html"`) || !strings.Contains(r, `"status_code":"503"`) || !strings.Contains(r, `"Retry-After":["30"]`) {
			t.Errorf("%s should get the maintenance page: %s", name, r)
		}
		if strings.Contains(r, "reverse_proxy") {
			t.Errorf("%s is in maintenance and must not be proxied: %s", name, r)
		}
	}
	if r := siteRouteFor(t, m, "blog.dev"); !strings.Contains(r, `"dial":"blog_web:80"`) || strings.Contains(r, "maint") {
		t.Errorf("a service not in maintenance is proxied as usual: %s", r)
	}
}

func TestHTTPWaitsForTheCertificateOfFixedHosts(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//x|0660",
		AskURL:      "http://172.30.0.1:7701/internal/tls/ask",
		Fixed: []Route{
			{Hosts: []string{"loja.dev", "*.loja.dev"}, Upstream: "loja_web:80", Key: "loja_web"},
			{Hosts: []string{"blog.dev"}, Upstream: "blog_web:80", Key: "blog_web", Maintenance: true},
		},
		Dynamic: &Route{Upstream: "saas_web:80", Key: "saas_web"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	routes, _ := get(m, "apps", "http", "servers", "redirect", "routes").([]any)
	if len(routes) != 2 {
		t.Fatalf(":80 routes: %d", len(routes))
	}
	wait, _ := json.Marshal(routes[0])
	s := string(wait)
	for _, want := range []string{
		// Only exact names: wildcards and customer domains get their
		// certificate at the first HTTPS handshake, never by waiting here.
		`"host":["blog.dev","loja.dev"]`,
		`"root":"/data/caddy/certificates"`, `"try_files":["/*/{http.request.host}/{http.request.host}.crt"]`,
		`"path":["/.well-known/acme-challenge/*"]`,
		`"/https.html"`, `"status_code":"503"`, `"Retry-After":["5"]`, `"Cache-Control":["no-store"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the waiting route lacks %s: %s", want, s)
		}
	}
	if strings.Contains(s, "*.loja.dev") {
		t.Error("a wildcard must not wait for a certificate on http://")
	}
	// Both the certificate check and the challenge path sit under "not".
	not, _ := get(routes[0].(map[string]any)["match"].([]any)[0], "not").([]any)
	if len(not) != 2 {
		t.Errorf("the waiting route must skip hosts with a certificate and ACME challenges: %v", not)
	}
	last, _ := json.Marshal(routes[1])
	if strings.Contains(string(last), "match") || !strings.Contains(string(last), `"status_code":308`) {
		t.Errorf("everything else is redirected to HTTPS: %s", last)
	}
}

func TestHTTPOnlyRedirectsWithoutFixedHosts(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//x|0660",
		AskURL:      "http://172.30.0.1:7701/internal/tls/ask",
		Dynamic:     &Route{Upstream: "saas_web:80", Key: "saas_web"},
	})
	if err != nil {
		t.Fatal(err)
	}
	routes, _ := get(decode(t, b), "apps", "http", "servers", "redirect", "routes").([]any)
	if j, _ := json.Marshal(routes); len(routes) != 1 || strings.Contains(string(j), "https.html") {
		t.Fatalf("with only customer domains, :80 just redirects: %s", j)
	}
}

func TestConfigDNS01Wildcard(t *testing.T) {
	b, err := BuildConfig(ConfigInput{
		AdminListen: "unix//run/caddy/admin.sock|0660",
		Email:       "ops@exemplo.com",
		BaseDomain:  "apps.exemplo.com", DNSProvider: "cloudflare", DNSToken: "tok-123",
		Fixed: []Route{
			{Hosts: []string{"loja-web.apps.exemplo.com"}, Upstream: "loja_web:3000", Key: "loja_web"},
			{Hosts: []string{"loja.cliente.com"}, Upstream: "loja_web:3000", Key: "loja_web"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"*.apps.exemplo.com"`, `"name": "cloudflare"`, `"api_token": "tok-123"`, `wildcard_.apps.exemplo.com`,
		`"automate"`, // the wildcard is proactively obtained, not left to on-demand
		`"skip"`,     // base-covered hosts are skipped by automatic HTTPS
	} {
		if !strings.Contains(s, want) {
			t.Errorf("DNS-01 config missing %q", want)
		}
	}
	// The covered host is skipped (no per-host cert) and is NOT a managed
	// subject of its own.
	if !strings.Contains(s, `"loja-web.apps.exemplo.com"`) {
		t.Error("the covered host should be listed under automatic_https skip")
	}
	if !strings.Contains(s, `"loja.cliente.com"`) {
		t.Error("the customer domain must still be routed on its own")
	}
}

func TestCoveredByBase(t *testing.T) {
	base := "apps.x.com"
	for _, h := range []string{"a.apps.x.com", "loja-web.apps.x.com"} {
		if !coveredByBase(h, base) {
			t.Errorf("%q should be covered by *.%s", h, base)
		}
	}
	for _, h := range []string{"apps.x.com", "a.b.apps.x.com", "a.other.com", ""} {
		if coveredByBase(h, base) {
			t.Errorf("%q should not be covered by *.%s", h, base)
		}
	}
}
