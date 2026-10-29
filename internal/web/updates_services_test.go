package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// addService creates project/slug (the project must exist) and returns
// its id.
func (e *env) addService(t *testing.T, project, slug, image string) string {
	t.Helper()
	s, err := e.pm.CreateService(context.Background(), projects.Actor{UserID: "usr_x"}, project, projects.ServiceInput{Slug: slug, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	return s.ID
}

// seedServices: lab/web with every bucket (seedBuckets, plus the edge),
// lab/api with one high finding in its code, lab/cache scanned clean.
func (e *env) seedServices(t *testing.T) (web, api, cache string) {
	t.Helper()
	web = e.labService(t)
	e.seedBuckets(t, web)
	api = e.addService(t, "lab", "api", "python:3.12")
	cache = e.addService(t, "lab", "cache", "redis:8")
	for _, q := range []string{
		`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, fixed_version, severity, level,
			advisory_id, source, kind, remedy, first_seen_at, last_seen_at)
		 VALUES ('dep_api', '` + api + `', '', 'PyPI', 'requests', '2.0', '2.32.4', 'high', 'critical', 'GHSA-req-1', '/app/requirements.txt', 'vuln', 'code', 1, 1)`,
		`INSERT INTO dependency_scans (target_key, scanned_at, packages, error) VALUES ('` + cache + `', 1, 12, '')`,
		`INSERT INTO dependency_scans (target_key, scanned_at, packages, error) VALUES ('` + web + `', 1, 80, 'find: not found')`,
	} {
		if _, err := e.st.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return web, api, cache
}

// The list has one row per service and one for the server, the riskiest
// first, with counts by severity and by action, and filters by severity,
// action and a search.
func TestUpdatesListPerService(t *testing.T) {
	e := newEnv(t)
	e.seedServices(t)
	c, _ := e.session(t, auth.RoleViewer)
	get := func(target string) string {
		t.Helper()
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, rec.Code)
		}
		return rec.Body.String()
	}
	web, server, api, cache := `href="/updates/lab/web"`, `href="/updates/server"`, `href="/updates/lab/api"`, `href="/updates/lab/cache"`

	list := get("/updates")
	// lab/web: 1 critical and 3 high; the server: 1 critical; lab/api: 1
	// high; lab/cache: nothing.
	if !before(t, list, web, server) || !before(t, list, server, api) || !before(t, list, api, cache) {
		t.Error("services not sorted by risk")
	}
	for _, want := range []string{
		"4 serviços", "1 crítica", "3 altas", "1 com deploy", "1 trocar versão", "1 no código", "2 aguardando",
		"Nada pendente", "python:3.12", "nginx:1.29-alpine", "imagem do Caddy, vem com o Hangar", "Inventário incompleto",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("list misses %q", want)
		}
	}
	// Rows, not findings: the list does not carry the advisories.
	if strings.Contains(list, "CVE-2026-0001") || strings.Contains(list, `id="bucket-deploy"`) {
		t.Error("the list renders findings")
	}

	for target, want := range map[string][]string{
		"/updates?sev=critical": {web, server},
		"/updates?sev=high":     {web, api},
		"/updates?bucket=code":  {web, api},
		"/updates?bucket=wait":  {web, server},
		"/updates?q=python":     {api},
		"/updates?q=CADDY":      {server},
		"/updates?q=lab":        {web, api, cache},
	} {
		body := get(target)
		for _, href := range []string{web, server, api, cache} {
			in := false
			for _, w := range want {
				in = in || w == href
			}
			if got := strings.Contains(body, href+` aria-label="Abrir`); got != in {
				t.Errorf("%s: %s listed %v, want %v", target, href, got, in)
			}
		}
	}
	// A chip toggles and keeps the other filters; an unknown value is no
	// filter at all.
	if body := get("/updates?sev=critical&q=lab"); !strings.Contains(body, `href="/updates?q=lab"`) || !strings.Contains(body, `href="/updates?bucket=code&amp;q=lab&amp;sev=critical"`) {
		t.Error("chips do not toggle or keep the other filters")
	}
	if body := get("/updates?sev=nope&bucket=nope"); !strings.Contains(body, cache) {
		t.Error("invalid filters should be ignored")
	}
	if body := get("/updates?q=nada-disso"); !strings.Contains(body, "Nenhum serviço com esses filtros.") {
		t.Error("no-match message missing")
	}
}

// The list loads 50 services at a time; "Load more" brings the next ones.
func TestUpdatesListLoadMore(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	for i := range 54 {
		id := e.addService(t, "lab", fmt.Sprintf("s%02d", i), "redis:8")
		if _, err := e.st.DB.Exec(`INSERT INTO dependency_scans (target_key, scanned_at, packages, error) VALUES (?, 1, 1, '')`, id); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := e.session(t, auth.RoleViewer)
	rows := func(body string) int { return strings.Count(body, `aria-label="Abrir lab/`) }
	first := e.do(req{method: "GET", target: "/updates", cookies: []*http.Cookie{c}}).Body.String()
	if rows(first) != 50 || !strings.Contains(first, `href="/updates?page=2" data-load-more`) || !strings.Contains(first, "54 serviços") {
		t.Errorf("first page: %d rows", rows(first))
	}
	second := e.do(req{method: "GET", target: "/updates?page=2", cookies: []*http.Cookie{c}}).Body.String()
	if rows(second) != 4 || strings.Contains(second, "data-load-more") || !strings.Contains(second, "51–54 de 54") {
		t.Errorf("second page: %d rows", rows(second))
	}
	// Filters ride along.
	q := e.do(req{method: "GET", target: "/updates?q=lab", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(q, `href="/updates?page=2&amp;q=lab" data-load-more`) {
		t.Error("load more drops the filters")
	}
}

// A user limited to some projects reaches neither the list nor a
// service's page (the route's {project} is no way in), nor the summary in
// the service's drawer.
func TestUpdatesServicePageLimitedUser(t *testing.T) {
	e := newEnv(t)
	c := e.limitedSession(t)
	id := e.addService(t, "lab", "web", "nginx:1.29-alpine")
	e.seedBuckets(t, id)
	for _, target := range []string{"/updates", "/updates/lab/web", "/updates/server", "/updates/loja/web", "/updates/export?service=lab/web"} {
		if rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}}); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", target, rec.Code)
		}
	}
	rec := e.do(req{method: "GET", target: "/p/lab/s/web", cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusOK {
		t.Fatalf("service page: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `id="svc-vulns"`) || strings.Contains(rec.Body.String(), "/updates/lab/web") {
		t.Error("limited user gets the vulnerability summary")
	}
}

// The service's Visão tab sums up its findings, links to its page and
// copies only them.
func TestServiceDrawerVulnSummary(t *testing.T) {
	e := newEnv(t)
	_, _, _ = e.seedServices(t)
	c, _ := e.session(t, auth.RoleViewer)
	get := func(target string, fragment bool) string {
		t.Helper()
		r := req{method: "GET", target: target, cookies: []*http.Cookie{c}}
		if fragment {
			r.header = map[string]string{"X-Hangar-Fragment": "panel"}
		}
		rec := e.do(r)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, rec.Code)
		}
		return rec.Body.String()
	}
	for _, fragment := range []bool{false, true} {
		web := get("/p/lab/s/web", fragment)
		for _, want := range []string{`id="svc-vulns"`, `href="/updates/lab/web"`, `data-copy-url="/updates/export?service=lab%2Fweb"`, "1 crítica", "3 altas", "1 com deploy"} {
			if !strings.Contains(web, want) {
				t.Errorf("drawer (fragment %v) misses %q", fragment, want)
			}
		}
	}
	// The server's own image is not this service's.
	if web := get("/p/lab/s/web", true); strings.Contains(web, "2 críticas") {
		t.Error("drawer counts the server's findings")
	}
	if cache := get("/p/lab/s/cache", true); !strings.Contains(cache, "Nada pendente na última verificação") || strings.Contains(cache, `data-copy-url="/updates/export`) {
		t.Error("clean service: nothing pending and nothing to copy")
	}
	if api := get("/p/lab/s/api", true); !strings.Contains(api, "1 alta") || !strings.Contains(api, "1 no código") {
		t.Error("api summary")
	}
	// Only on the Visão tab.
	if logs := get("/p/lab/s/web?tab=logs", true); strings.Contains(logs, `id="svc-vulns"`) {
		t.Error("summary outside the Visão tab")
	}
}
