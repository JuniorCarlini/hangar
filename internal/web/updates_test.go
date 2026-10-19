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

	page := e.do(req{method: "GET", target: "/updates", cookies: []*http.Cookie{c}})
	body := page.Body.String()
	if page.Code != http.StatusOK {
		t.Fatalf("updates page: %d", page.Code)
	}
	// Found before remedies existed: waits, marked as not checked yet (no
	// command: a waiting row is never the user's own code).
	for _, want := range []string{
		"django", "5.2.7", "GHSA-test-1", "ainda não verificado", "1.30-alpine", "Caddy", "https://osv.dev/vulnerability/GHSA-test-1",
		`id="bucket-wait"`, `id="bucket-updates"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("updates page misses %q", want)
		}
	}
	// Text from OSV is data: escaped, never markup.
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("advisory summary rendered as HTML")
	}
	// A viewer sees but cannot ignore, scan, deploy or switch.
	for _, act := range []string{`action="/updates/ignore"`, `action="/updates/scan"`, `/deploy"`, `/image"`, `#sudo-dialog`} {
		if strings.Contains(body, act) {
			t.Errorf("viewer gets the operator action %s", act)
		}
	}

	ov := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(ov, "1 vulnerabilidade crítica") || !strings.Contains(ov, `href="/updates"`) {
		t.Error("overview without the vulnerability alert")
	}

	if rec := e.do(req{method: "GET", target: "/updates?bucket=updates", cookies: []*http.Cookie{c}}); strings.Contains(rec.Body.String(), "django==") {
		t.Error("bucket filter ignored")
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
	get := func() string {
		t.Helper()
		rec := e.do(req{method: "GET", target: "/updates", cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("updates: %d", rec.Code)
		}
		return rec.Body.String()
	}
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
		return rest
	}

	body := get()
	// Cards count rows: openssl (2 advisories) is one deploy row; the
	// image switch is one row; edge waits (no Hangar release yet).
	for _, want := range []string{`text-danger">1<`, `text-warning">1<`, `text-info">1<`, `">3</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("cards: missing %s", want)
		}
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
	for _, want := range []string{"stdlib (gosu)", "3 falhas", "1.25.4", "imagem ainda não saiu", "sem correção ainda", "vem com uma versão do Hangar", "servidor · Caddy"} {
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

	// A Hangar release is out: the edge goes to "deploy", as "Update Hangar".
	e.upd.available = &update.Available{Version: "v1.1.0"}
	dep = section(get(), "deploy")
	if !strings.Contains(dep, `href="/update"`) || !strings.Contains(dep, "Atualizar Hangar") {
		t.Errorf("edge with a Hangar release: %s", dep)
	}

	// With sudo the switch is a form posting the tag.
	e.now = e.now.Add(30 * time.Second)
	p, _ := e.svc.Authenticate(context.Background(), c.Value)
	rec := e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/updates"}}, cookies: []*http.Cookie{c}})
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
	body := e.do(req{method: "GET", target: "/updates", cookies: []*http.Cookie{c}}).Body.String()
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

// A filtered section shows 25 rows per page, loudest first; the full page
// shows the first rows of each section with a link to the rest; the cards
// count every row; out-of-range pages are clamped, and ignoring a row
// returns to its section and page.
func TestUpdatesPagination(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.seedFindings(t, id)
	for i := range 57 {
		q := fmt.Sprintf(`INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, fixed_version, severity, level,
			advisory_id, kind, remedy, first_seen_at, last_seen_at)
		 VALUES ('dep_pkg%02d', '%s', '', 'Debian:13', 'pkg-%02d', '1.0', '', 'high', 'security', 'CVE-%02d', 'vuln', 'no_fix', 1, 1)`, i, id, i, i)
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

	full := get("/updates")
	if !strings.Contains(full, `href="/updates?bucket=wait"`) || !strings.Contains(full, "Ver todos (58)") || strings.Contains(full, "tuc-pagination") {
		t.Error("full page: the wait section should show its first rows and link to the rest")
	}
	first := get("/updates?bucket=wait")
	if rows(first) != 25 || !strings.Contains(first, "1–25 de 58") || !strings.Contains(first, "ainda não verificado") {
		t.Errorf("page 1: %d rows, range or loudest row missing", rows(first))
	}
	if !strings.Contains(first, `class="tuc-pagination"`) || !strings.Contains(first, `href="/updates?bucket=wait&amp;page=2"`) {
		t.Error("page 1 without Tucano pagination")
	}
	second := get("/updates?bucket=wait&page=2&ok=scan")
	if rows(second) != 25 || !strings.Contains(second, "26–50 de 58") || strings.Contains(second, "django==") {
		t.Errorf("page 2: %d rows or wrong slice", rows(second))
	}
	if !strings.Contains(second, `aria-current="page">2<`) || regexp.MustCompile(`href="/updates\?[^"]*ok=scan`).MatchString(second) {
		t.Error("page 2 not current, or page links keep the flash")
	}
	if !strings.Contains(second, `name="page" value="2"`) || !strings.Contains(second, `name="bucket" value="wait"`) {
		t.Error("ignore form does not carry the section and page")
	}
	// The cards count every row, not the page.
	if !strings.Contains(second, `">58</span>`) {
		t.Error("summary cards count only the page")
	}
	for target, want := range map[string]string{"/updates?bucket=wait&page=99": "51–58 de 58", "/updates?bucket=wait&page=abc": "1–25 de 58", "/updates?bucket=wait&page=-3": "1–25 de 58"} {
		if body := get(target); !strings.Contains(body, want) {
			t.Errorf("%s not clamped to %q", target, want)
		}
	}
	// One page of results: no pagination at all.
	if body := get("/updates?bucket=updates"); strings.Contains(body, "tuc-pagination") || !strings.Contains(body, "1.30-alpine") {
		t.Error("pagination shown for a single page")
	}

	rec := e.do(req{method: "POST", target: "/updates/ignore", form: url.Values{
		"csrf": {p.CSRFToken}, "id": {"dep_pkg30"}, "mode": {"days"}, "reason": {"sem pressa"}, "page": {"2"}, "bucket": {"wait"},
	}, cookies: []*http.Cookie{c}})
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != "/updates?bucket=wait&ok=ignored&page=2" {
		t.Errorf("ignore redirect: %d %q", rec.Code, loc)
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
	body := e.do(req{method: "GET", target: "/updates", cookies: []*http.Cookie{c}}).Body.String()
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
