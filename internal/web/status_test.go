package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// Names chosen so that any leak is unmistakable in the public answers.
const (
	leakProject = "zephyrshop"
	leakService = "checkoutapi"
	leakImage   = "nginx:1.29.3-alpine"
)

// leakyService creates a service whose real names, image and version must
// never reach a status link, and makes it show in the metrics.
func (e *env) leakyService(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, leakProject, "Zephyr Shop"); err != nil {
		t.Fatal(err)
	}
	s, err := e.pm.CreateService(ctx, a, leakProject, projects.ServiceInput{Slug: leakService, Image: leakImage})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	name := node.ContainerName(leakProject, leakService)
	e.stats.mu.Lock()
	e.stats.managed = []node.Managed{{ID: "c9", Name: name, ServiceID: s.ID, Project: leakProject, Service: leakService, State: "running"}}
	e.stats.stats = map[string]node.ContainerStats{"c9": {CPUTotal: 1e9, SystemCPU: 100e9, OnlineCPUs: 2, MemUsed: 64 << 20, MemLimit: 256 << 20, NetRx: 10, NetTx: 10}}
	e.stats.mu.Unlock()
	e.mc.Sample(ctx)
	e.stats.mu.Lock()
	e.stats.stats["c9"] = node.ContainerStats{CPUTotal: 3e9, SystemCPU: 110e9, OnlineCPUs: 2, MemUsed: 80 << 20, MemLimit: 256 << 20, NetRx: 5000, NetTx: 9000}
	e.stats.mu.Unlock()
	e.mc.Sample(ctx)
	return s.ID
}

// sudoSession logs in with the role and confirms sudo.
func (e *env) sudoSession(t *testing.T, role auth.Role) (*http.Cookie, string) {
	t.Helper()
	c, p := e.session(t, role)
	e.now = e.now.Add(30 * time.Second)
	rec := e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/status-links"}}, cookies: []*http.Cookie{c}})
	sc := cookie(rec, sessionCookie)
	if sc == nil {
		t.Fatalf("sudo failed: %d %s", rec.Code, rec.Body)
	}
	sp, _ := e.svc.Authenticate(context.Background(), sc.Value)
	return sc, sp.CSRFToken
}

var linkTokenRE = regexp.MustCompile(`/s/([A-Za-z0-9_-]{43})`)

func (e *env) createLink(t *testing.T, c *http.Cookie, csrf string, form url.Values) string {
	t.Helper()
	form.Set("csrf", csrf)
	rec := e.do(req{method: "POST", target: "/status-links", form: form, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusOK {
		t.Fatalf("create link: %d %s", rec.Code, rec.Body)
	}
	m := linkTokenRE.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("the new link's URL is not shown once: %s", rec.Body)
	}
	return m[1]
}

func (e *env) public(target string) *httptest.ResponseRecorder {
	return e.do(req{method: "GET", target: target, header: map[string]string{"Accept": "text/html"}})
}

// TestStatusLinkLeaksNothing checks that none of the
// public formats (page, TV, JSON, Prometheus) carries a container name, an
// image, a version, an IP or the host name.
func TestStatusLinkLeaksNothing(t *testing.T) {
	e := newEnv(t)
	id := e.leakyService(t)
	c, csrf := e.sudoSession(t, auth.RoleAdmin)

	for _, naming := range []string{"alias", "generic", "hidden"} {
		token := e.createLink(t, c, csrf, url.Values{"name": {"Monitor " + naming}, "naming": {naming}, "service": {id}, "expiry": {"never"}})
		forbidden := []string{
			leakProject, leakService, node.ContainerName(leakProject, leakService), "nginx", "1.29", "alpine",
			id, "Zephyr", "v1.0.0", testHost, "Monitor",
		}
		if h, _ := os.Hostname(); len(h) > 3 {
			forbidden = append(forbidden, h)
		}
		// IPv4, or IPv6 (3+ groups or "::", so a clock time "18:42:10" is not one).
		ipRE := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b|\b[0-9a-f]{1,4}::[0-9a-f]`)
		for _, target := range []string{"/s/" + token, "/s/" + token + "?tv=1", "/s/" + token + "?period=7d", "/s/" + token + ".json", "/s/" + token + "/metrics"} {
			rec := e.public(target)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s: status %d", naming, target, rec.Code)
			}
			body := rec.Body.String()
			for _, f := range forbidden {
				if strings.Contains(body, f) {
					t.Errorf("%s %s leaks %q", naming, target, f)
				}
			}
			if m := ipRE.FindString(body); m != "" {
				t.Errorf("%s %s contains an IP-like value %q", naming, target, m)
			}
			for _, bad := range []string{"style=", "<script", "javascript:"} {
				if strings.Contains(body, bad) {
					t.Errorf("%s %s contains %q (CSP)", naming, target, bad)
				}
			}
			if rec.Header().Get("X-Robots-Tag") == "" || rec.Header().Get("Referrer-Policy") != "no-referrer" ||
				rec.Header().Get("Content-Security-Policy") == "" || len(rec.Result().Cookies()) != 0 {
				t.Errorf("%s %s: missing privacy headers or sets cookies: %v", naming, target, rec.Header())
			}
		}
		js := e.public("/s/" + token + ".json")
		var snap struct {
			Server   map[string]float64 `json:"server"`
			Services []struct {
				Label string `json:"label"`
				State string `json:"state"`
			} `json:"services"`
		}
		if err := json.Unmarshal(js.Body.Bytes(), &snap); err != nil {
			t.Fatalf("json: %v", err)
		}
		switch naming {
		case "hidden":
			if len(snap.Services) != 0 {
				t.Errorf("hidden link shows services: %+v", snap.Services)
			}
		default:
			if len(snap.Services) != 1 || snap.Services[0].Label != "Serviço A" || snap.Services[0].State != "running" {
				t.Errorf("%s link services = %+v", naming, snap.Services)
			}
		}
	}
}

func TestStatusLinkAliasRevokeAndRestrictions(t *testing.T) {
	e := newEnv(t)
	id := e.leakyService(t)
	c, csrf := e.sudoSession(t, auth.RoleAdmin)

	rec := e.do(req{method: "POST", target: "/status-links/alias", form: url.Values{"csrf": {csrf}, "service": {id}, "alias": {"Loja principal"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("set alias: %d %s", rec.Code, rec.Body)
	}
	token := e.createLink(t, c, csrf, url.Values{"name": {"Casa"}, "naming": {"alias"}, "service": {id}, "expiry": {"7d"}})
	page := e.public("/s/" + token)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Loja principal") {
		t.Fatalf("alias not shown: %d", page.Code)
	}
	if !strings.Contains(e.public("/s/"+token+"/metrics").Body.String(), `hangar_service_up{service="Loja principal"} 1`) {
		t.Error("prometheus without the alias")
	}

	// The list counts the visits and never shows the token.
	list := e.do(req{method: "GET", target: "/status-links", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(list, token) || !strings.Contains(list, "Casa") || !strings.Contains(list, "189.x.x.x") {
		t.Error("link list leaks the token or misses the access")
	}

	unknown := e.public("/s/" + strings.Repeat("x", 43))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown token: %d", unknown.Code)
	}

	// Revoke: every format answers the same 404 right away.
	linkID := regexp.MustCompile(`name="id" value="(stl_[a-z0-9]+)"`).FindStringSubmatch(list)
	if linkID == nil {
		t.Fatal("revoke form not found")
	}
	rec = e.do(req{method: "POST", target: "/status-links/revoke", form: url.Values{"csrf": {csrf}, "id": {linkID[1]}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	for _, target := range []string{"/s/" + token, "/s/" + token + "?tv=1", "/s/" + token + ".json", "/s/" + token + "/metrics"} {
		r := e.public(target)
		if r.Code != http.StatusNotFound || r.Body.String() != unknown.Body.String() {
			t.Errorf("revoked %s: status %d (must be the generic 404)", target, r.Code)
		}
	}

	// Restricted to another IP: 404 for this visitor (189.10.20.30).
	token = e.createLink(t, c, csrf, url.Values{"name": {"Sócio"}, "naming": {"generic"}, "service": {id}, "expiry": {"never"}, "ips": {"10.1.2.3, 192.168.0.0/16"}})
	if r := e.public("/s/" + token); r.Code != http.StatusNotFound {
		t.Errorf("IP-restricted link: status %d", r.Code)
	}
	token = e.createLink(t, c, csrf, url.Values{"name": {"Escritório"}, "naming": {"hidden"}, "expiry": {"never"}, "ips": {"189.10.20.0/24"}})
	if r := e.public("/s/" + token); r.Code != http.StatusOK {
		t.Errorf("allowed IP: status %d", r.Code)
	}

	// Bad input comes back to the dialog with the error.
	rec = e.do(req{method: "POST", target: "/status-links", form: url.Values{"csrf": {csrf}, "name": {"X"}, "naming": {"alias"}, "expiry": {"never"}, "ips": {"not-an-ip"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusUnprocessableEntity || linkTokenRE.MatchString(rec.Body.String()) {
		t.Errorf("invalid IP: %d", rec.Code)
	}
}

func TestStatusLinksNeedAdminAndSudo(t *testing.T) {
	e := newEnv(t)
	c, _ := e.session(t, auth.RoleOperator)
	if rec := e.do(req{method: "GET", target: "/status-links", cookies: []*http.Cookie{c}}); rec.Code != http.StatusForbidden {
		t.Errorf("operator sees status links: %d", rec.Code)
	}

	e2 := newEnv(t)
	c2, p := e2.session(t, auth.RoleAdmin)
	rec := e2.do(req{method: "POST", target: "/status-links", form: url.Values{"csrf": {p.CSRFToken}, "name": {"x"}, "naming": {"hidden"}, "expiry": {"never"}}, cookies: []*http.Cookie{c2}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("create without sudo: %d", rec.Code)
	}
	if rec := e2.do(req{method: "GET", target: "/status-links", cookies: []*http.Cookie{c2}}); rec.Code != http.StatusOK {
		t.Errorf("admin page: %d", rec.Code)
	}
}

func TestStatusHostOnlyReachesStatusPages(t *testing.T) {
	e := newEnv(t)
	c, csrf := e.sudoSession(t, auth.RoleOwner)
	token := e.createLink(t, c, csrf, url.Values{"name": {"TV"}, "naming": {"hidden"}, "expiry": {"never"}})
	for target, want := range map[string]int{
		"/s/" + token:           http.StatusOK,
		"/assets/app.css":       http.StatusOK,
		"/":                     http.StatusNotFound,
		"/login":                http.StatusNotFound,
		"/status-links":         http.StatusNotFound,
		"/healthz":              http.StatusNotFound,
		"/s/" + token + ".json": http.StatusOK,
	} {
		hr := httptest.NewRequest("GET", target, nil)
		hr.Host = testStatusHost
		hr.RemoteAddr = "189.10.20.30:5000"
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, hr)
		if rec.Code != want {
			t.Errorf("status host %s: %d, want %d", target, rec.Code, want)
		}
	}
}

func TestStatusLinkRateLimit(t *testing.T) {
	e := newEnv(t)
	got429 := false
	for i := 0; i < publicPerMinute+5; i++ {
		if rec := e.public("/s/" + strings.Repeat("y", 43)); rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("no rate limit on the public status route")
	}
}
