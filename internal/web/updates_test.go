package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/update"
)

// seedFindings stores what a scan would have found for the lab service.
func (e *env) seedFindings(t *testing.T, serviceID string) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, fixed_version, severity, level,
			advisory_id, aliases, summary, source, kind, first_seen_at, last_seen_at)
		 VALUES ('dep_django', '` + serviceID + `', '', 'PyPI', 'django', '5.2.3', '5.2.7', 'critical', 'critical',
			'GHSA-test-1', 'CVE-2026-1111', 'SQL injection <script>alert(1)</script>', '/usr/lib/site-packages', 'vuln', 1, 1)`,
		`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, latest_version, severity, level,
			kind, first_seen_at, last_seen_at)
		 VALUES ('dep_nginx', '` + serviceID + `', '', 'image', 'nginx', '1.29-alpine', '1.30-alpine', 'none', 'minor', 'minor', 1, 1)`,
		`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, latest_version, severity, level,
			kind, first_seen_at, last_seen_at)
		 VALUES ('dep_caddy', NULL, 'edge', 'image', 'caddy', '2.11-alpine', '3.0-alpine', 'none', 'major', 'major', 1, 1)`,
	} {
		if _, err := e.st.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpdatesPageAndOverviewAlert(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedFindings(t, id)
	c, _ := e.session(t, auth.RoleViewer)
	get := func(target string) string {
		t.Helper()
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, rec.Code)
		}
		return rec.Body.String()
	}

	// The list names the service and the server, each with its page.
	list := get("/updates")
	for _, want := range []string{`id="svc-list"`, `href="/updates/lab/web"`, `href="/updates/server"`, "servidor · Caddy", "1 crítica", "1 aguardando", "1 versão nova"} {
		if !strings.Contains(list, want) {
			t.Errorf("updates list misses %q", want)
		}
	}
	// Found before remedies existed: waits, marked as not checked yet (no
	// command: a waiting row is never the user's own code).
	body := get("/updates/lab/web")
	for _, want := range []string{
		"django", "5.2.7", "GHSA-test-1", "ainda não verificado", "1.30-alpine", "https://osv.dev/vulnerability/GHSA-test-1",
		`id="bucket-wait"`, `id="bucket-updates"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("service page misses %q", want)
		}
	}
	// Another service's rows (the server's Caddy) stay on its own page.
	if strings.Contains(body, "3.0-alpine") {
		t.Error("the service page lists the server's image")
	}
	if srv := get("/updates/server"); !strings.Contains(srv, "3.0-alpine") || strings.Contains(srv, "django") {
		t.Error("server page: its image only")
	}
	// Text from OSV is data: escaped, never markup.
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("advisory summary rendered as HTML")
	}
	// A viewer sees but cannot ignore, scan, deploy or switch.
	for _, act := range []string{`action="/updates/ignore"`, `action="/updates/scan"`, `/deploy"`, `/image"`, `#sudo-dialog`} {
		if strings.Contains(body, act) || strings.Contains(list, act) {
			t.Errorf("viewer gets the operator action %s", act)
		}
	}

	ov := get("/")
	if !strings.Contains(ov, "1 vulnerabilidade crítica") || !strings.Contains(ov, `href="/updates"`) {
		t.Error("overview without the vulnerability alert")
	}

	if body := get("/updates/lab/web?bucket=updates"); strings.Contains(body, "GHSA-test-1") || !strings.Contains(body, "1.30-alpine") {
		t.Error("bucket filter of the service page ignored")
	}
	for _, target := range []string{"/updates/lab/nope", "/updates/nope/web", "/updates/LAB/web"} {
		if rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}}); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", target, rec.Code)
		}
	}
}

// seedBuckets stores one finding set per bucket for the lab service
// (nginx:1.29-alpine) and the edge.
func (e *env) seedBuckets(t *testing.T, serviceID string) {
	t.Helper()
	ins := func(id, svc, target, eco, pkg, cur, fixed, sev, level, adv, source, remedy, remedyTag string) {
		t.Helper()
		var svcArg any = svc
		if svc == "" {
			svcArg = nil
		}
		if _, err := e.st.DB.Exec(`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, fixed_version,
			severity, level, advisory_id, source, kind, remedy, remedy_tag, first_seen_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'vuln', ?, ?, 1, 1)`,
			id, svcArg, target, eco, pkg, cur, fixed, sev, level, adv, source, remedy, remedyTag); err != nil {
			t.Fatal(err)
		}
	}
	ins("dep_ssl1", serviceID, "", "Alpine:v3.23", "openssl", "3.5.1-r0", "3.5.4-r0", "high", "critical", "CVE-2026-0001", "/lib/apk/db/installed", "deploy", "")
	ins("dep_ssl2", serviceID, "", "Alpine:v3.23", "openssl", "3.5.1-r0", "3.5.3-r0", "medium", "security", "CVE-2026-0002", "/lib/apk/db/installed", "deploy", "")
	ins("dep_zlib", serviceID, "", "Alpine:v3.23", "zlib", "1.3.1-r0", "1.3.2-r1", "critical", "critical", "CVE-2026-0003", "/lib/apk/db/installed", "tag", "1.31-alpine")
	ins("dep_expat", serviceID, "", "Alpine:v3.23", "expat", "2.7.1-r0", "2.7.3-r0", "medium", "security", "CVE-2026-0004", "/lib/apk/db/installed", "tag", "1.31-alpine")
	ins("dep_pil", serviceID, "", "PyPI", "pillow", "10.0.0", "10.3.0", "high", "critical", "GHSA-pil-1", "/app/uv.lock", "code", "")
	for i := range 3 {
		ins(fmt.Sprintf("dep_std%d", i), serviceID, "", "Go", "stdlib", "1.24.6", fmt.Sprintf("1.25.%d", i+2), "medium", "security", fmt.Sprintf("GO-2026-%d", i), "/usr/local/bin/gosu", "wait_image", "")
	}
	ins("dep_glibc", serviceID, "", "Alpine:v3.23", "musl", "1.2.5-r9", "", "high", "security", "CVE-2026-0005", "/lib/apk/db/installed", "no_fix", "")
	ins("dep_edge", "", "edge", "Alpine:v3.22", "zlib", "1.3.1-r0", "1.3.2-r1", "critical", "critical", "CVE-2026-0006", "/lib/apk/db/installed", "edge", "")
}

// The page groups vulnerabilities by what to do, one row per package (or
// per image for a tag switch), and offers a button only where the panel
// can fix it: deploy (operator), switch tag (admin with sudo), update
// Hangar (owner, when a release is out).
func TestUpdatesPageSections(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedBuckets(t, id)
	c, _ := e.session(t, auth.RoleOwner)
	getAt := func(target string) string {
		t.Helper()
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, rec.Code)
		}
		return rec.Body.String()
	}
	get := func() string { t.Helper(); return getAt("/updates/lab/web") }
	section := func(body, bucket string) string {
		t.Helper()
		i := strings.Index(body, `id="bucket-`+bucket+`"`)
		if i < 0 {
			t.Fatalf("section %s missing", bucket)
		}
		rest := body[i:]
		if j := strings.Index(rest[1:], "</section>"); j > 0 {
			rest = rest[:j]
		}
		// The rows, not their dialogs (which hold the ignore form).
		if j := strings.Index(rest, `<div class="contents" data-more-items>`); j > 0 {
			rest = rest[:j]
		}
		return rest
	}

	// The list's cards count every service's rows: openssl (2 advisories)
	// is one deploy row; the image switch is one row; the edge waits (no
	// Hangar release yet).
	list := getAt("/updates")
	for _, want := range []string{`text-danger">1<`, `text-warning">1<`, `text-info">1<`, `">3</span>`} {
		if !strings.Contains(list, want) {
			t.Errorf("cards: missing %s", want)
		}
	}
	// The service's own cards leave the server's row out.
	body := get()
	if !strings.Contains(body, `">2</span>`) || strings.Contains(body, `">3</span>`) {
		t.Error("service cards should count only its rows")
	}
	dep := section(body, "deploy")
	if !strings.Contains(dep, "openssl") || !strings.Contains(dep, "2 falhas") || !strings.Contains(dep, `action="/p/lab/s/web/deploy"`) || !strings.Contains(dep, "3.5.4-r0") {
		t.Errorf("deploy section: %s", dep)
	}
	tag := section(body, "tag")
	if !strings.Contains(tag, "imagem nginx") || !strings.Contains(tag, "1.29-alpine") || !strings.Contains(tag, "Trocar para 1.31-alpine") ||
		!strings.Contains(tag, `data-tuc-modal="#sudo-dialog"`) || strings.Contains(tag, `/image"`) {
		t.Errorf("tag section without sudo: %s", tag)
	}
	code := section(body, "code")
	if !strings.Contains(code, "uv lock --upgrade-package pillow") || !strings.Contains(code, "Python · uv") || strings.Contains(code, "<form") {
		t.Errorf("code section: %s", code)
	}
	wait := section(body, "wait")
	for _, want := range []string{"stdlib (gosu)", "3 falhas", "1.25.4", "imagem ainda não saiu", "sem correção ainda"} {
		if !strings.Contains(wait, want) {
			t.Errorf("wait section misses %q", want)
		}
	}
	if strings.Contains(wait, "<form") || strings.Contains(wait, "tuc-btn is-primary") {
		t.Error("the wait section offers an action")
	}
	if strings.Contains(body, `id="bucket-updates"`) {
		t.Error("an empty section is shown")
	}
	// Every advisory is listed with its link in the row's dialog.
	if !strings.Contains(body, `id="flaws-dep_std`) || !strings.Contains(body, "https://osv.dev/vulnerability/GO-2026-2") {
		t.Error("advisory list of the stdlib row")
	}

	if srv := section(getAt("/updates/server"), "wait"); !strings.Contains(srv, "vem com uma versão do Hangar") {
		t.Errorf("server's wait section: %s", srv)
	}
	// A Hangar release is out: the edge goes to "deploy", as "Update Hangar".
	e.upd.available = &update.Available{Version: "v1.1.0"}
	dep = section(getAt("/updates/server"), "deploy")
	if !strings.Contains(dep, `href="/update"`) || !strings.Contains(dep, "Atualizar Hangar") {
		t.Errorf("edge with a Hangar release: %s", dep)
	}

	// With sudo the switch is a form posting the tag.
	e.now = e.now.Add(30 * time.Second)
	p, _ := e.svc.Authenticate(context.Background(), c.Value)
	rec := e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/updates/lab/web"}}, cookies: []*http.Cookie{c}})
	c = cookie(rec, sessionCookie)
	tag = section(get(), "tag")
	if !strings.Contains(tag, `action="/p/lab/s/web/image"`) || !strings.Contains(tag, `name="tag" value="1.31-alpine"`) {
		t.Errorf("tag section with sudo: %s", tag)
	}
}

func TestUpdatesActionsByRole(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedBuckets(t, id)
	c, _ := e.session(t, auth.RoleOperator)
	body := e.do(req{method: "GET", target: "/updates/lab/web", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(body, `action="/p/lab/s/web/deploy"`) || !strings.Contains(body, `action="/updates/ignore"`) {
		t.Error("operator: deploy and ignore expected")
	}
	if strings.Contains(body, `/image"`) || strings.Contains(body, "#sudo-dialog") || !strings.Contains(body, "um admin troca para 1.31-alpine") {
		t.Error("operator: no tag switch, only who can do it")
	}
}

func TestIgnoreFindingNeedsOperatorAndReason(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedFindings(t, id)
	c, p := e.session(t, auth.RoleOperator)

	rec := e.do(req{method: "POST", target: "/updates/ignore", form: url.Values{"csrf": {p.CSRFToken}, "id": {"dep_django"}, "mode": {"version"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("ignore without reason: %d", rec.Code)
	}
	rec = e.do(req{method: "POST", target: "/updates/ignore", form: url.Values{
		"csrf": {p.CSRFToken}, "id": {"dep_django"}, "mode": {"version"}, "reason": {"corrigido no proxy"},
	}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("ignore: %d %s", rec.Code, rec.Body)
	}
	ov := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(ov, "vulnerabilidade crítica") {
		t.Error("ignored finding still alerts on the overview")
	}
	var reason string
	if err := e.st.DB.QueryRow(`SELECT summary_json FROM audit_log WHERE action = 'deps.ignore'`).Scan(&reason); err != nil || !strings.Contains(reason, "corrigido no proxy") {
		t.Errorf("ignore not audited with its reason: %q %v", reason, err)
	}

	page := e.do(req{method: "GET", target: "/updates", cookies: []*http.Cookie{c}}).Body.String()
	m := regexp.MustCompile(`name="id" value="(ign_[a-z0-9]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("ignore rule not listed")
	}
	rec = e.do(req{method: "POST", target: "/updates/unignore", form: url.Values{"csrf": {p.CSRFToken}, "id": {m[1]}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("unignore: %d", rec.Code)
	}

	e2 := newEnv(t)
	c2, p2 := e2.session(t, auth.RoleViewer)
	rec = e2.do(req{method: "POST", target: "/updates/scan", form: url.Values{"csrf": {p2.CSRFToken}}, cookies: []*http.Cookie{c2}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer starts a scan: %d", rec.Code)
	}
}

// The history lists every update applied from the panel, rebuilt from the
// audit log as it really happens: the version running, the request, the
// start of the next version. An update undone keeps the version it tried.
func TestUpdateHistoryListsEveryUpdate(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	session := e.login(t)
	al := audit.New(e.st.DB)
	rec := func(action string, sum map[string]any) {
		t.Helper()
		if err := al.Record(context.Background(), audit.Entry{Action: action, Outcome: audit.OK, Summary: sum}); err != nil {
			t.Fatal(err)
		}
	}
	rec("system.start", map[string]any{"version": "v0.3.2"})
	rec("system.update.request", map[string]any{"status": 303})
	rec("system.start", map[string]any{"version": "v0.3.3"})
	rec("system.start", map[string]any{"version": "v0.3.3"}) // a plain restart: not an update
	rec("system.update.request", map[string]any{"status": 303})
	rec("system.start", map[string]any{"version": "v0.4.0"})
	rec("system.update.request", map[string]any{"status": 303})
	rec("system.start", map[string]any{"version": "v0.4.0"})
	rec("system.update.rolled_back", map[string]any{"from": "v0.4.0", "to": "v0.4.1", "message": "não subiu em 90 s"})
	body := e.do(req{method: "GET", target: "/update", cookies: []*http.Cookie{session}}).Body.String()
	third, first, second := strings.Index(body, "v0.4.0 → v0.4.1"), strings.Index(body, "v0.3.3 → v0.4.0"), strings.Index(body, "v0.3.2 → v0.3.3")
	if third < 0 || first < 0 || second < 0 || third >= first || first >= second {
		t.Fatalf("history should list the three updates, newest first (%d, %d, %d)", third, first, second)
	}
	if !strings.Contains(body, "não subiu em 90 s") || strings.Count(body, "→") != 3 {
		t.Error("the rollback reason should show, and a plain restart is not an update")
	}
}

// A service's section shows its first 50 rows and a "Load more" to the
// next ones (server-side: the link opens just that section's next rows);
// out-of-range pages are clamped; the cards count every row; ignoring a
// row returns to the service's page at its section.
func TestUpdatesPagination(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedFindings(t, id)
	for i := range 119 {
		q := fmt.Sprintf(`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, fixed_version, severity, level,
			advisory_id, kind, remedy, first_seen_at, last_seen_at)
		 VALUES ('dep_pkg%03d', '%s', '', 'Debian:13', 'pkg-%03d', '1.0', '', 'high', 'security', 'CVE-%03d', 'vuln', 'no_fix', 1, 1)`, i, id, i, i)
		if _, err := e.st.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// One row per package of the language, one for every waiting
	// distribution package of an image: give each its own ecosystem.
	if _, err := e.st.DB.Exec(`UPDATE dependency_findings SET ecosystem = 'Debian:13-' || package WHERE id LIKE 'dep_pkg%'`); err != nil {
		t.Fatal(err)
	}
	c, p := e.session(t, auth.RoleOperator)
	get := func(target string) string {
		t.Helper()
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, rec.Code)
		}
		return rec.Body.String()
	}
	rows := func(body string) int { return strings.Count(body, `data-tuc-modal="#ignore-`) }

	full := get("/updates/lab/web")
	if rows(full) != 50+1 || !strings.Contains(full, `href="/updates/lab/web?bucket=wait&amp;page=2" data-load-more`) || !strings.Contains(full, "120 itens") {
		t.Errorf("first page: %d rows, or no load more", rows(full))
	}
	if !strings.Contains(full, "ainda não verificado") {
		t.Error("the loudest row is not first")
	}
	second := get("/updates/lab/web?bucket=wait&page=2")
	if rows(second) != 50 || !strings.Contains(second, "51–100 de 120") || strings.Contains(second, `id="bucket-updates"`) ||
		!strings.Contains(second, `page=3" data-load-more`) {
		t.Errorf("page 2: %d rows or wrong slice", rows(second))
	}
	last := get("/updates/lab/web?bucket=wait&page=3")
	if rows(last) != 20 || strings.Contains(last, "data-load-more") {
		t.Errorf("last page: %d rows, or a load more past the end", rows(last))
	}
	for target, want := range map[string]string{"/updates/lab/web?bucket=wait&page=99": "101–120 de 120", "/updates/lab/web?bucket=wait&page=abc": "page=2\" data-load-more", "/updates/lab/web?bucket=wait&page=-3": "page=2\" data-load-more"} {
		if body := get(target); !strings.Contains(body, want) {
			t.Errorf("%s not clamped to %q", target, want)
		}
	}
	// The cards count every row, not the page.
	if !strings.Contains(second, `">120</span>`) {
		t.Error("summary cards count only the page")
	}
	// The ignore form carries the page to come back to.
	if !strings.Contains(second, `name="back" value="/updates/lab/web"`) || !strings.Contains(second, `name="bucket" value="wait"`) {
		t.Error("ignore form does not carry the service's page and section")
	}

	rec := e.do(req{method: "POST", target: "/updates/ignore", form: url.Values{
		"csrf": {p.CSRFToken}, "id": {"dep_pkg030"}, "mode": {"days"}, "reason": {"sem pressa"}, "back": {"/updates/lab/web"}, "bucket": {"wait"},
	}, cookies: []*http.Cookie{c}})
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != "/updates/lab/web?ok=ignored#bucket-wait" {
		t.Errorf("ignore redirect: %d %q", rec.Code, loc)
	}
	// Anywhere else than an updates page goes back to the list.
	for _, back := range []string{"https://evil.example/", "//evil.example", "/updates/lab/web/../../x", "/p/lab/s/web"} {
		rec = e.do(req{method: "POST", target: "/updates/ignore", form: url.Values{
			"csrf": {p.CSRFToken}, "id": {"dep_pkg031"}, "mode": {"days"}, "reason": {"sem pressa"}, "back": {back},
		}, cookies: []*http.Cookie{c}})
		if loc := rec.Header().Get("Location"); loc != "/updates?ok=ignored" {
			t.Errorf("back %q: redirect %q", back, loc)
		}
	}
}

// Ignoring a row hides every package in it, now and for later advisories.
func TestIgnoreRowHidesItsPackages(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedBuckets(t, id)
	c, p := e.session(t, auth.RoleOperator)
	rec := e.do(req{method: "POST", target: "/updates/ignore", form: url.Values{
		"csrf": {p.CSRFToken}, "id": {"dep_ssl1", "dep_ssl2"}, "mode": {"version"}, "reason": {"janela de sábado"},
	}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("ignore: %d %s", rec.Code, rec.Body)
	}
	var until string
	if err := e.st.DB.QueryRow(`SELECT until_version FROM finding_ignores WHERE package = 'openssl' AND advisory_id = ''`).Scan(&until); err != nil || until != "3.5.4-r0" {
		t.Errorf("rule until %q (%v), want the highest fixed version", until, err)
	}
	body := e.do(req{method: "GET", target: "/updates/lab/web", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(body, `id="bucket-deploy"`) {
		t.Error("the ignored row is still listed")
	}
	// A waiting row without a fixed version cannot wait "until a newer version".
	rec = e.do(req{method: "POST", target: "/updates/ignore", form: url.Values{
		"csrf": {p.CSRFToken}, "id": {"dep_glibc"}, "mode": {"version"}, "reason": {"sem correção"},
	}, cookies: []*http.Cookie{c}})
	if rec.Code == http.StatusSeeOther {
		t.Error("version mode accepted without a fixed version")
	}
}
