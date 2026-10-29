package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// before reports whether a comes before b in s (both present).
func before(t *testing.T, s, a, b string) bool {
	t.Helper()
	i, j := strings.Index(s, a), strings.Index(s, b)
	if i < 0 || j < 0 {
		t.Fatalf("missing %q (%d) or %q (%d) in:\n%s", a, i, b, j, s)
	}
	return i < j
}

// The export is the page as Markdown: sections in page order, then
// services, then packages, each with what to do and every advisory.
func TestUpdatesExportMarkdown(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedBuckets(t, id)
	c, _ := e.session(t, auth.RoleViewer)

	rec := e.do(req{method: "GET", target: "/updates/export", cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("content type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache control %q", cc)
	}
	md := rec.Body.String()
	for _, want := range []string{
		"# Vulnerabilidades em ", "Atualize cada pacote para a versão indicada",
		"## Resolve com deploy", "### lab/web", "Imagem: `nginx:1.29-alpine`", "#### `openssl` · Alpine 3.23 — alta",
		"Versão: `3.5.1-r0` → `3.5.4-r0`", "Faça redeploy do serviço", "Encontrado em: `/lib/apk/db/installed`",
		"#### imagem nginx", "Troque a tag da imagem `nginx` para `1.31-alpine`",
		"#### `pillow` · Python · uv (PyPI) — alta", "O que fazer: `uv lock --upgrade-package pillow`", "Encontrado em: `/app/uv.lock`",
		"[GHSA-pil-1](https://osv.dev/vulnerability/GHSA-pil-1) · alta",
		"### servidor · Caddy", "- Versão: `1.2.5-r9`\n", "Nada a fazer agora (sem correção ainda).", "3 falhas:", "[GO-2026-2](https://osv.dev/vulnerability/GO-2026-2)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("export misses %q\n%s", want, md)
		}
	}
	// Page order of the sections; inside a row the loudest advisory first.
	if !before(t, md, "## Resolve com deploy", "## Trocar a versão") || !before(t, md, "## Trocar a versão", "## No seu código") ||
		!before(t, md, "## No seu código", "## Aguardando correção") {
		t.Error("sections out of page order")
	}
	if !before(t, md, "CVE-2026-0001", "CVE-2026-0002") {
		t.Error("advisories not sorted by severity")
	}
	// Environment values never leave the panel this way.
	if strings.Contains(md, "valor-super-secreto-42") || strings.Contains(md, "SECRET_KEY") {
		t.Error("export leaks the service's environment")
	}

	// One section only.
	code := e.do(req{method: "GET", target: "/updates/export?bucket=code", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(code, "## No seu código") || strings.Contains(code, "## Resolve com deploy") || strings.Contains(code, "openssl") {
		t.Errorf("bucket filter: %s", code)
	}
	if rec := e.do(req{method: "GET", target: "/updates/export?bucket=nope", cookies: []*http.Cookie{c}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown bucket: %d", rec.Code)
	}

	// In the viewer's language.
	en := e.do(req{method: "GET", target: "/updates/export?bucket=code", cookies: []*http.Cookie{c}, header: map[string]string{"Accept-Language": "en"}}).Body.String()
	if !strings.Contains(en, "# Vulnerabilities on ") || !strings.Contains(en, "## In your code") || !strings.Contains(en, "What to do: `uv lock") {
		t.Errorf("english export: %s", en)
	}

	// The list offers everything and each service; a service's page, the
	// service and each of its sections.
	page := e.do(req{method: "GET", target: "/updates", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `data-copy-url="/updates/export"`) || !strings.Contains(page, `data-copy-url="/updates/export?service=lab%2Fweb"`) ||
		!strings.Contains(page, `data-copy-url="/updates/export?service=edge"`) {
		t.Error("updates list without the copy buttons")
	}
	svc := e.do(req{method: "GET", target: "/updates/lab/web", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(svc, `data-copy-url="/updates/export?service=lab%2Fweb"`) || !strings.Contains(svc, `data-copy-url="/updates/export?bucket=code&amp;service=lab%2Fweb"`) {
		t.Error("service page without the copy buttons")
	}
}

// Copying one service gives only its findings; one project, only its
// services; the scope never widens what the user may see.
func TestUpdatesExportScope(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedBuckets(t, id)
	other, err := e.pm.CreateService(context.Background(), projects.Actor{UserID: "usr_x"}, "lab", projects.ServiceInput{Slug: "api", Image: "python:3.12"})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if _, err := e.st.DB.Exec(`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, fixed_version,
		severity, level, advisory_id, source, kind, remedy, first_seen_at, last_seen_at)
		VALUES ('dep_api', ?, '', 'PyPI', 'django', '5.2.3', '5.2.7', 'critical', 'critical', 'GHSA-api-1', '/app/uv.lock', 'vuln', 'code', 1, 1)`, other.ID); err != nil {
		t.Fatal(err)
	}
	c, _ := e.session(t, auth.RoleViewer)
	get := func(target string) (int, string) {
		t.Helper()
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}})
		return rec.Code, rec.Body.String()
	}

	_, web := get("/updates/export?service=lab/web")
	if !strings.HasPrefix(web, "# Vulnerabilidades de lab/web em ") || !strings.Contains(web, "### lab/web") || !strings.Contains(web, "openssl") {
		t.Errorf("service export:\n%s", web)
	}
	if strings.Contains(web, "lab/api") || strings.Contains(web, "GHSA-api-1") || strings.Contains(web, "CVE-2026-0006") {
		t.Errorf("service export carries other services:\n%s", web)
	}
	_, api := get("/updates/export?service=lab%2Fapi&bucket=code")
	if !strings.Contains(api, "GHSA-api-1") || strings.Contains(api, "pillow") || strings.Contains(api, "## Resolve com deploy") {
		t.Errorf("service section export:\n%s", api)
	}
	_, edge := get("/updates/export?service=edge")
	if !strings.Contains(edge, "# Vulnerabilidades de servidor · Caddy em ") || !strings.Contains(edge, "CVE-2026-0006") || strings.Contains(edge, "openssl") {
		t.Errorf("server export:\n%s", edge)
	}
	_, proj := get("/updates/export?project=lab")
	if !strings.Contains(proj, "# Vulnerabilidades de projeto lab em ") || !strings.Contains(proj, "### lab/web") || !strings.Contains(proj, "### lab/api") || strings.Contains(proj, "CVE-2026-0006") {
		t.Errorf("project export:\n%s", proj)
	}
	if _, none := get("/updates/export?service=loja/web"); !strings.Contains(none, "Nada pendente nesta seção.") {
		t.Errorf("unknown service: %s", none)
	}
	for _, bad := range []string{"?service=lab", "?service=../web", "?service=lab/web/x", "?project=LAB", "?project=a/b"} {
		if code, _ := get("/updates/export" + bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
}

// The export answers to whoever may open the page, nobody else.
func TestUpdatesExportGating(t *testing.T) {
	e := newEnv(t)
	c := e.limitedSession(t)
	if rec := e.do(req{method: "GET", target: "/updates/export", cookies: []*http.Cookie{c}}); rec.Code != http.StatusNotFound {
		t.Errorf("limited user: %d, want 404", rec.Code)
	}
	if rec := e.do(req{method: "GET", target: "/updates/export"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rec.Code)
	}
}

func TestVisibleFindingsForLimitedUser(t *testing.T) {
	fs := []deps.Finding{
		{ID: "a", Project: "lab", Service: "web"},
		{ID: "b", Project: "loja", Service: "api"},
		{ID: "c", Target: deps.EdgeTarget},
	}
	ids := func(fs []deps.Finding) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.ID)
		}
		return strings.Join(out, ",")
	}
	all := &auth.Principal{Role: auth.RoleViewer, AllProjects: true}
	if got := ids(visibleFindings(all, fs)); got != "a,b,c" {
		t.Errorf("all projects: %s", got)
	}
	limited := &auth.Principal{Role: auth.RoleOperator, Projects: map[string]bool{"lab": true}}
	if got := ids(visibleFindings(limited, fs)); got != "a" {
		t.Errorf("limited: %s", got)
	}
	// Admins always see everything, even with a project list.
	admin := &auth.Principal{Role: auth.RoleAdmin, Projects: map[string]bool{"lab": true}}
	if got := ids(visibleFindings(admin, fs)); got != "a,b,c" {
		t.Errorf("admin: %s", got)
	}
}

func TestVulnMarkdown(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), "en")
	fs := []deps.Finding{
		{
			ID: "f1", ServiceID: "svc_api", Project: "shop", Service: "api", Ecosystem: "Go", Package: "golang.org/x/net", Current: "0.30.0",
			Suggested: "0.33.0", Severity: deps.SevMedium, Level: deps.LevelSecurity, Kind: deps.KindVuln, Advisory: "GO-2025-0002",
			Summary: "Excessive\nmemory   use", Source: "/app/server", Remedy: deps.RemedyCode,
		},
		{
			ID: "f2", ServiceID: "svc_api", Project: "shop", Service: "api", Ecosystem: "Go", Package: "golang.org/x/net", Current: "0.30.0",
			Suggested: "0.31.0", Severity: deps.SevCritical, Level: deps.LevelCritical, Kind: deps.KindVuln, Advisory: "GO-2025-0001",
			Aliases: []string{"CVE-2025-1", "GHSA-xxxx"}, Summary: strings.Repeat("a", 300), Source: "/app/server", Remedy: deps.RemedyCode,
		},
		{
			ID: "f3", ServiceID: "svc_web", Project: "shop", Service: "web", Ecosystem: "crates.io", Package: "time", Current: "0.3.1",
			Suggested: "0.3.6", Severity: deps.SevLow, Level: deps.LevelSecurity, Kind: deps.KindVuln, Advisory: "RUSTSEC-2020-0071",
			Source: "/app/Cargo.lock", Remedy: deps.RemedyCode,
		},
	}
	x := vulnExport{
		Host: "vps1", At: time.Date(2026, 10, 28, 14, 5, 0, 0, time.UTC), Buckets: []string{deps.BucketCode},
		Groups: deps.GroupFindings(fs, false),
		Repos: map[string]projects.GitSource{
			"svc_api": {URL: "https://user:token@github.com/acme/api?x=1#frag", Branch: "main", Subdir: "backend"},
		},
	}
	md := vulnMarkdown(ctx, x)
	for _, want := range []string{
		"# Vulnerabilities on vps1", "on vps1 on 2026-10-28 14:05 UTC.",
		"## In your code (2 items)",
		"### shop/api", "Repository: https://github.com/acme/api (branch `main`) · folder backend",
		"#### `golang.org/x/net` · Go — critical", "Version: `0.30.0` → `0.33.0`", "Found in: `/app/server`",
		"What to do: Update the module and deploy: `go get golang.org/x/net@v0.33.0`", "2 advisories:",
		"[GO-2025-0001](https://osv.dev/vulnerability/GO-2025-0001) (CVE-2025-1, GHSA-xxxx) · critical — " + strings.Repeat("a", summaryMax) + "…",
		"[GO-2025-0002](https://osv.dev/vulnerability/GO-2025-0002) · medium — Excessive memory use",
		"### shop/web", "#### `time` · Rust (crates.io) — low", "Found in: `/app/Cargo.lock`", "cargo update -p time --precise 0.3.6",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown misses %q\n%s", want, md)
		}
	}
	// The loudest service first, its loudest advisory first.
	if !before(t, md, "### shop/api", "### shop/web") || !before(t, md, "GO-2025-0001", "GO-2025-0002") {
		t.Error("not sorted by severity")
	}
	if strings.Contains(md, "token") || strings.Contains(md, "user:") || strings.Contains(md, "x=1") {
		t.Errorf("repository URL carries credentials:\n%s", md)
	}

	// Nothing to copy says so.
	x.Groups = map[string][]deps.Group{}
	if md := vulnMarkdown(i18n.WithLocale(context.Background(), "pt-BR"), x); !strings.Contains(md, "Nada pendente nesta seção.") {
		t.Errorf("empty export: %s", md)
	}
}
