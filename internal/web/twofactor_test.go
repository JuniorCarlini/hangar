package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

var htmlAccept = map[string]string{"Accept": "text/html"}

// An admin without a second factor (an upgraded panel, or a factor reset
// from the command line) signs in with the password and lands on the
// enrollment page: every other page sends them back there, every write is
// refused, leaving is allowed, and enrolling opens the panel.
func TestAdminWithoutTOTPMustEnroll(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.CreateUser(context.Background(), testEmail, testPassword, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	rec := e.do(req{method: "POST", target: "/login", form: url.Values{"email": {testEmail}, "password": {testPassword}}})
	session := cookie(rec, sessionCookie)
	if rec.Code != http.StatusSeeOther || session == nil {
		t.Fatalf("password login: %d", rec.Code)
	}
	for _, target := range []string{"/", "/account", "/backups", "/updates", "/p/lab"} {
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{session}, header: htmlAccept})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != enrollPath {
			t.Errorf("%s before enrolling: %d %q", target, rec.Code, rec.Header().Get("Location"))
		}
	}
	p, _ := e.svc.Authenticate(context.Background(), session.Value)
	before := countDenied(t, e, "project.create")
	rec = e.do(req{method: "POST", target: "/projects", form: url.Values{"csrf": {p.CSRFToken}, "slug": {"lab"}}, cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("a write before enrolling: %d", rec.Code)
	}
	if countDenied(t, e, "project.create") != before+1 {
		t.Error("a refused write must be audited")
	}
	rec = e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {testPassword}}, cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("sudo before enrolling: %d", rec.Code)
	}

	page := e.do(req{method: "GET", target: enrollPath, cookies: []*http.Cookie{session}})
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(body, `src="data:image/png;base64,`) || !strings.Contains(body, `action="/logout"`) {
		t.Fatalf("enrollment page: %d", page.Code)
	}
	e.secret = regexp.MustCompile(`name="secret" value="([A-Z2-7]+)"`).FindStringSubmatch(body)[1]
	rec = e.do(req{
		method: "POST", target: "/account/totp/enable", cookies: []*http.Cookie{session},
		form: url.Values{"csrf": {p.CSRFToken}, "secret": {e.secret}, "code": {e.code(t)}, "password": {testPassword}},
	})
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), "select-all") < 10 {
		t.Fatalf("enroll: %d", rec.Code)
	}
	if rec := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{session}, header: htmlAccept}); rec.Code != http.StatusOK {
		t.Fatalf("after enrolling the panel opens: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Once enrolled the page is no longer the way in.
	if rec := e.do(req{method: "GET", target: enrollPath, cookies: []*http.Cookie{session}}); rec.Code != http.StatusSeeOther {
		t.Errorf("enrollment page after enrolling: %d", rec.Code)
	}
}

// Leaving is always possible before enrolling.
func TestLogoutBeforeEnrolling(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.CreateUser(context.Background(), testEmail, testPassword, auth.RoleOwner); err != nil {
		t.Fatal(err)
	}
	rec := e.do(req{method: "POST", target: "/login", form: url.Values{"email": {testEmail}, "password": {testPassword}}})
	session := cookie(rec, sessionCookie)
	p, _ := e.svc.Authenticate(context.Background(), session.Value)
	rec = e.do(req{method: "POST", target: "/logout", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("logout: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if p, _ := e.svc.Authenticate(context.Background(), session.Value); p != nil {
		t.Error("the session survived the logout")
	}
}

// "Require 2FA of everyone" is the owner's, on the team page. Turning it off
// asks for sudo at every level (and is audited); turning it on does not,
// and reaches the sessions already open.
func TestRequire2FAToggle(t *testing.T) {
	e := newEnv(t)
	e.setLevel(t, auth.LevelBasic) // even where nothing else asks again
	c, p := e.session(t, auth.RoleOwner)
	team := e.do(req{method: "GET", target: "/team", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(team, `id="security"`) || !strings.Contains(team, `data-tuc-modal="#sudo-dialog"`) {
		t.Fatal("the team page must show the 2FA card, behind the identity check")
	}
	rec := e.do(req{method: "POST", target: "/team/2fa/optional", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden || !e.svc.Require2FA(context.Background()) {
		t.Fatalf("turning 2FA off without sudo: %d", rec.Code)
	}
	sc, sp := e.sudo(t, c, p)
	team = e.do(req{method: "GET", target: "/team", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(team, `action="/team/2fa/optional"`) || !strings.Contains(team, `data-tone="danger"`) {
		t.Fatal("with sudo, turning it off is a form behind a red confirmation")
	}
	rec = e.do(req{method: "POST", target: "/team/2fa/optional", form: url.Values{"csrf": {sp.CSRFToken}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther || e.svc.Require2FA(context.Background()) {
		t.Fatalf("turning 2FA off with sudo: %d", rec.Code)
	}
	if n := countAudit(t, e, "security.require_2fa"); n != 1 {
		t.Errorf("%d audit records for turning it off", n)
	}

	// An operator without 2FA now signs in with the password alone...
	if _, err := e.svc.CreateUser(context.Background(), "op@hangar.dev", testPassword, auth.RoleOperator); err != nil {
		t.Fatal(err)
	}
	rec = e.do(req{method: "POST", target: "/login", form: url.Values{"email": {"op@hangar.dev"}, "password": {testPassword}}})
	op := cookie(rec, sessionCookie)
	if rec := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{op}, header: htmlAccept}); rec.Code != http.StatusOK {
		t.Fatalf("optional 2FA: %d", rec.Code)
	}
	// ...until the owner turns it back on: no sudo for raising the bar.
	rec = e.do(req{method: "POST", target: "/team/2fa/require", form: url.Values{"csrf": {sp.CSRFToken}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther || !e.svc.Require2FA(context.Background()) {
		t.Fatalf("turning 2FA on: %d", rec.Code)
	}
	if rec := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{op}, header: htmlAccept}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != enrollPath {
		t.Errorf("an open session without 2FA after it became required: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if n := countAudit(t, e, "security.require_2fa"); n != 2 {
		t.Errorf("%d audit records, want 2", n)
	}
	// Only the owner may change it.
	e2 := newEnv(t)
	ac, ap := e2.session(t, auth.RoleAdmin)
	if rec := e2.do(req{method: "POST", target: "/team/2fa/require", form: url.Values{"csrf": {ap.CSRFToken}}, cookies: []*http.Cookie{ac}}); rec.Code != http.StatusForbidden {
		t.Errorf("an admin changing the 2FA policy: %d", rec.Code)
	}
}

func countDenied(t *testing.T, e *env, action string) int {
	t.Helper()
	var n int
	if err := e.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = ? AND outcome = 'denied'`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func countAudit(t *testing.T, e *env, action string) int {
	t.Helper()
	var n int
	if err := e.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = ? AND outcome = 'ok'`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
