package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/auth"
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
	for _, want := range []string{"django", "5.2.7", "GHSA-test-1", "django==5.2.7", "nginx:1.30-alpine", "Caddy", "https://osv.dev/vulnerability/GHSA-test-1"} {
		if !strings.Contains(body, want) {
			t.Errorf("updates page misses %q", want)
		}
	}
	// Text from OSV is data: escaped, never markup.
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("advisory summary rendered as HTML")
	}
	// A viewer sees but cannot ignore or scan.
	if strings.Contains(body, `action="/updates/ignore"`) || strings.Contains(body, `action="/updates/scan"`) {
		t.Error("viewer gets operator actions")
	}

	ov := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(ov, "1 vulnerabilidade crítica") || !strings.Contains(ov, `href="/updates"`) {
		t.Error("overview without the vulnerability alert")
	}

	if rec := e.do(req{method: "GET", target: "/updates?level=major", cookies: []*http.Cookie{c}}); strings.Contains(rec.Body.String(), "django==") {
		t.Error("level filter ignored")
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
