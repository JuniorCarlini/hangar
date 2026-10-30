package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

// Where 2FA is optional (an operator, with the team's setting off), an
// account without it signs in with the password, sees the banner on every
// page and can turn 2FA on from "My account" without being logged out.
func TestOptionalTOTPThroughTheWeb(t *testing.T) {
	e := newEnv(t)
	e.optional2FA(t)
	if _, err := e.svc.CreateUser(context.Background(), testEmail, testPassword, auth.RoleOperator); err != nil {
		t.Fatal(err)
	}
	rec := e.do(req{method: "POST", target: "/login", form: url.Values{"email": {testEmail}, "password": {testPassword}}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("password-only login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	session := cookie(rec, sessionCookie)
	if session == nil {
		t.Fatal("no session cookie")
	}
	home := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{session}})
	if !strings.Contains(home.Body.String(), `href="/account#totp"`) {
		t.Error("the 2FA banner must show on every page")
	}

	acc := e.do(req{method: "GET", target: "/account", cookies: []*http.Cookie{session}}).Body.String()
	if !strings.Contains(acc, `src="data:image/png;base64,`) {
		t.Error("the QR code is missing")
	}
	secret := regexp.MustCompile(`name="secret" value="([A-Z2-7]+)"`).FindStringSubmatch(acc)[1]
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(acc)[1]
	e.secret = secret
	rec = e.do(req{
		method: "POST", target: "/account/totp/enable", cookies: []*http.Cookie{session},
		form: url.Values{"csrf": {csrf}, "secret": {secret}, "code": {e.code(t)}, "password": {testPassword}},
	})
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), `select-all`) < 10 {
		t.Fatalf("enable: %d", rec.Code)
	}
	home = e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{session}})
	if home.Code != http.StatusOK || strings.Contains(home.Body.String(), `href="/account#totp"`) {
		t.Errorf("after enabling: still signed in and no banner (status %d)", home.Code)
	}

	// Next login asks for the code.
	e.now = e.now.Add(30 * time.Second)
	e.login(t)
}
