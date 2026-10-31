package web

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// newSetupEnv is a panel with no user that just started: the setup window
// is open.
func newSetupEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, func(o *auth.Options) { o.FirstRunSetup = true })
	if _, err := e.svc.PrepareSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

// postSetup sends the setup form with the page's own form token.
func (e *env) postSetup(form url.Values) *httptest.ResponseRecorder {
	page := e.do(req{method: http.MethodGet, target: "/setup"})
	var cookies []*http.Cookie
	if c := cookie(page, loginCookie); c != nil {
		form.Set("csrf", c.Value)
		cookies = append(cookies, c)
	}
	return e.do(req{method: http.MethodPost, target: "/setup", form: form, cookies: cookies})
}

func TestFirstVisitCreatesTheOwner(t *testing.T) {
	e := newSetupEnv(t)

	rec := e.do(req{method: "GET", target: "/login"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("login with no user: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = e.do(req{method: "GET", target: "/setup"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="email"`) || !strings.Contains(rec.Body.String(), "30 min") {
		t.Fatalf("setup page: status %d", rec.Code)
	}
	// 2FA is recommended, not forced: a ticked box the owner may untick.
	if !strings.Contains(rec.Body.String(), `name="twofa" value="1" checked`) {
		t.Error("the setup page must offer 2FA, ticked by default")
	}

	form := url.Values{"email": {testEmail}, "password": {testPassword}, "confirm": {testPassword + "x"}, "twofa": {"1"}}
	if rec = e.postSetup(form); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), i18n.Tl("pt-BR", "setup.error.mismatch")) {
		t.Fatalf("passwords that differ: status %d", rec.Code)
	}
	form.Set("confirm", testPassword)
	rec = e.postSetup(form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account#totp" {
		t.Fatalf("setup: status %d, location %q, body %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	session := cookie(rec, sessionCookie)
	if session == nil || !session.Secure || !session.HttpOnly {
		t.Fatalf("session cookie: %+v", session)
	}
	// With the box ticked the owner lands on the 2FA card of My account.
	if rec = e.do(req{method: "GET", target: "/account", cookies: []*http.Cookie{session}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `src="data:image/png;base64,`) {
		t.Fatalf("2FA card after setup: status %d", rec.Code)
	}

	// Done once, the page is gone for everyone.
	if rec = e.do(req{method: "GET", target: "/setup"}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("setup after the owner: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = e.do(req{method: "POST", target: "/setup", form: url.Values{"email": {"outro@hangar.dev"}, "password": {testPassword}, "confirm": {testPassword}}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("second setup: status %d", rec.Code)
	}
	if n, _ := e.svc.CountUsers(context.Background()); n != 1 {
		t.Errorf("%d users", n)
	}
}

// A new panel does not force 2FA: an owner who unticks the box goes
// straight to the panel.
func TestSetupWithoutTwoFactor(t *testing.T) {
	e := newSetupEnv(t)
	rec := e.postSetup(url.Values{"email": {testEmail}, "password": {testPassword}, "confirm": {testPassword}, "twofa": {"0"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("setup without 2FA: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	session := cookie(rec, sessionCookie)
	p, _ := e.svc.Authenticate(context.Background(), session.Value)
	if p == nil || p.MustEnroll || p.HasTOTP {
		t.Fatalf("principal: %+v", p)
	}
	if rec := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{session}, header: map[string]string{"Accept": "text/html"}}); rec.Code != http.StatusOK {
		t.Errorf("the panel after a setup without 2FA: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// When the panel requires 2FA of everyone, the owner cannot skip it:
// whatever the form says, the setup ends on the enrollment page and the
// panel stays closed until a factor is on.
func TestSetupCannotSkipTwoFactor(t *testing.T) {
	e := newSetupEnv(t)
	e.require2FA(t)
	if page := e.do(req{method: "GET", target: "/setup"}); strings.Contains(page.Body.String(), `name="twofa"`) {
		t.Error("with 2FA required the setup page must not offer to skip it")
	}
	rec := e.postSetup(url.Values{"email": {testEmail}, "password": {testPassword}, "confirm": {testPassword}, "twofa": {"0"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != enrollPath {
		t.Fatalf("setup without 2FA: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	session := cookie(rec, sessionCookie)
	for _, target := range []string{"/", "/account", "/team", "/backups"} {
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{session}, header: map[string]string{"Accept": "text/html"}})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != enrollPath {
			t.Errorf("%s before enrolling: %d %q", target, rec.Code, rec.Header().Get("Location"))
		}
	}
	p, _ := e.svc.Authenticate(context.Background(), session.Value)
	if p == nil || !p.MustEnroll {
		t.Fatalf("principal: %+v", p)
	}
	rec = e.do(req{method: "POST", target: "/projects", form: url.Values{"csrf": {p.CSRFToken}, "slug": {"lab"}}, cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("a write before enrolling: %d", rec.Code)
	}
}

// After the window, with no user, the page says how to open it again and
// creates nothing.
func TestSetupClosesAfterTheWindow(t *testing.T) {
	e := newSetupEnv(t)
	e.now = e.now.Add(auth.SetupWindow)
	rec := e.do(req{method: "GET", target: "/login"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("login: status %d", rec.Code)
	}
	rec = e.do(req{method: "GET", target: "/setup"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "systemctl restart hangard") {
		t.Fatalf("expired setup page: status %d", rec.Code)
	}
	rec = e.do(req{method: "POST", target: "/setup", form: url.Values{"email": {testEmail}, "password": {testPassword}, "confirm": {testPassword}}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("setup after the window: status %d", rec.Code)
	}
	if n, _ := e.svc.CountUsers(context.Background()); n != 0 {
		t.Error("an owner was created after the window")
	}
}

// Without the browser setup (or with a user), /setup is closed.
func TestSetupClosedByDefault(t *testing.T) {
	e := newEnv(t)
	if rec := e.do(req{method: "GET", target: "/setup"}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := e.do(req{method: "GET", target: "/login"}); rec.Code != http.StatusOK {
		t.Fatalf("login: status %d", rec.Code)
	}
}

func TestSetupNeedsTheFormToken(t *testing.T) {
	e := newSetupEnv(t)
	rec := e.do(req{method: "POST", target: "/setup", form: url.Values{"email": {testEmail}, "password": {testPassword}, "confirm": {testPassword}}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("setup without the form token: status %d", rec.Code)
	}
	if n, _ := e.svc.CountUsers(context.Background()); n != 0 {
		t.Error("an owner was created without the form token")
	}
}

// The public panel listener accepts only Caddy and takes the visitor's
// address from X-Forwarded-For.
func TestBehindEdgeTrustsOnlyCaddy(t *testing.T) {
	caddy := netip.MustParseAddr("172.30.0.2")
	var seen string
	h := BehindEdge(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, _, _ = net.SplitHostPort(r.RemoteAddr)
	}), caddy)
	serve := func(remote, xff string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := serve("172.30.0.9:4000", "189.10.20.30"); code != http.StatusForbidden {
		t.Errorf("another container on the gateway: %d", code)
	}
	if code := serve("172.30.0.2:4000", ""); code != http.StatusForbidden {
		t.Errorf("Caddy without X-Forwarded-For: %d", code)
	}
	seen = ""
	if code := serve("172.30.0.2:4000", "6.6.6.6, 189.10.20.30"); code != http.StatusOK || seen != "189.10.20.30" {
		t.Errorf("through Caddy: %d, client %q", code, seen)
	}
}

// A browser that opens an address the panel does not have sees the panel's
// own error page, not Go's plain text; scripts keep the plain answer.
func TestUnknownAddressShowsThePanelErrorPage(t *testing.T) {
	e := newEnv(t)
	rec := e.do(req{method: "GET", target: "/setupdasd", header: map[string]string{"Accept": "text/html,application/xhtml+xml"}})
	body := rec.Body.String()
	if rec.Code != http.StatusNotFound || !strings.Contains(body, i18n.Tl("pt-BR", "errorpage.not_found.title")) || strings.Contains(body, "404 page not found") {
		t.Fatalf("browser: status %d, body %.200s", rec.Code, body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q", ct)
	}
	rec = e.do(req{method: "GET", target: "/setupdasd"})
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "404 page not found") {
		t.Errorf("non-browser: status %d, body %q", rec.Code, rec.Body)
	}
	rec = e.do(req{method: "GET", target: "/setupdasd", header: map[string]string{"Accept": "text/html", "HX-Request": "true"}})
	if strings.Contains(rec.Body.String(), "<html") {
		t.Error("an htmx request must keep the plain answer")
	}
}
