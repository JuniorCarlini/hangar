package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

func newSetupEnv(t *testing.T) (*env, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "setup-code")
	e := newEnv(t, func(o *auth.Options) { o.SetupCodeFile = file })
	if _, err := e.svc.PrepareSetup(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return e, strings.TrimSpace(string(raw))
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
	e, code := newSetupEnv(t)

	rec := e.do(req{method: "GET", target: "/login"})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
		t.Fatalf("login with no user: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = e.do(req{method: "GET", target: "/setup"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="code"`) {
		t.Fatalf("setup page: status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), code) {
		t.Fatal("the setup page must never show the code itself")
	}

	form := url.Values{"code": {"AAAA-AAAA-AAAA-AAAA"}, "email": {testEmail}, "password": {testPassword}, "confirm": {testPassword}, "twofa": {"1"}}
	if rec = e.postSetup(form); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), i18n.Tl("pt-BR", "setup.error.code")) {
		t.Fatalf("wrong code: status %d", rec.Code)
	}
	form.Set("code", code)
	form.Set("confirm", testPassword+"x")
	if rec = e.postSetup(form); rec.Code != http.StatusUnprocessableEntity {
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
	if rec = e.do(req{method: "GET", target: "/account", cookies: []*http.Cookie{session}}); rec.Code != http.StatusOK {
		t.Fatalf("account after setup: status %d", rec.Code)
	}

	// Done once, the page is gone for everyone.
	if rec = e.do(req{method: "GET", target: "/setup"}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("setup after the owner: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec = e.postSetup(form); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("second setup: status %d", rec.Code)
	}
	if n, _ := e.svc.CountUsers(context.Background()); n != 1 {
		t.Errorf("%d users", n)
	}
}

func TestSetupWithoutTwoFactorGoesHome(t *testing.T) {
	e, code := newSetupEnv(t)
	rec := e.postSetup(url.Values{"code": {code}, "email": {testEmail}, "password": {testPassword}, "confirm": {testPassword}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("setup without 2FA: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
}

// Without the browser setup configured (or with a user), /setup is closed.
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
	e, code := newSetupEnv(t)
	rec := e.do(req{method: "POST", target: "/setup", form: url.Values{"code": {code}, "email": {testEmail}, "password": {testPassword}, "confirm": {testPassword}}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("setup without the form token: status %d", rec.Code)
	}
	if n, _ := e.svc.CountUsers(context.Background()); n != 0 {
		t.Error("an owner was created without the form token")
	}
}
