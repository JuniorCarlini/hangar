package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

func (e *env) setLevel(t *testing.T, l auth.Level) {
	t.Helper()
	if err := e.svc.SetLevel(context.Background(), "", l, auth.Client{}); err != nil {
		t.Fatal(err)
	}
}

// The level decides which actions ask for the password again: standard
// lets ports through and still guards secrets; basic guards neither.
func TestLevelDecidesWhichActionsAsk(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleOwner)
	post := func(target string, form url.Values) int {
		form.Set("csrf", p.CSRFToken)
		return e.do(req{method: "POST", target: target, form: form, cookies: []*http.Cookie{c}}).Code
	}
	port := func(n string) url.Values {
		return url.Values{"host_port": {n}, "container_port": {"80"}, "protocol": {"tcp"}, "access": {"localhost"}, "expires": {"1h"}}
	}
	reveal := url.Values{"key": {"APP_KEY"}}

	e.setLevel(t, auth.LevelStandard)
	if code := post("/p/lab/s/web/ports", port("15433")); code != http.StatusSeeOther {
		t.Errorf("standard: open port without sudo: %d, want 303", code)
	}
	if code := post("/p/lab/s/web/env/reveal", reveal); code != http.StatusForbidden {
		t.Errorf("standard: reveal a secret without sudo: %d, want 403", code)
	}
	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `id="sudo-dialog"`) {
		t.Error("standard: the service page lacks the sudo dialog the critical actions need")
	}

	e.setLevel(t, auth.LevelBasic)
	if code := post("/p/lab/s/web/env/reveal", reveal); code == http.StatusForbidden {
		t.Errorf("basic: reveal a secret was refused (%d)", code)
	}
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(page, `id="sudo-dialog"`) {
		t.Error("basic: the service page still asks for the password")
	}
}

// Changing the level asks for the password at every level, or whoever
// finds the panel open would lower it first.
func TestChangingTheLevelAlwaysAsks(t *testing.T) {
	e := newEnv(t)
	e.setLevel(t, auth.LevelBasic)
	c, p := e.session(t, auth.RoleOwner)
	post := func(c *http.Cookie, csrf, level string) int {
		form := url.Values{"csrf": {csrf}, "level": {level}}
		return e.do(req{method: "POST", target: "/security", form: form, cookies: []*http.Cookie{c}}).Code
	}

	page := e.do(req{method: "GET", target: "/security", cookies: []*http.Cookie{c}}).Body.String()
	for _, want := range []string{`value="basic" checked`, `value="standard"`, `value="strict"`, `id="sudo-dialog"`} {
		if !strings.Contains(page, want) {
			t.Errorf("security page lacks %q", want)
		}
	}
	if code := post(c, p.CSRFToken, "strict"); code != http.StatusForbidden {
		t.Fatalf("change without sudo at basic: %d, want 403", code)
	}

	sc, sp := e.sudo(t, c, p)
	if code := post(sc, sp.CSRFToken, "lax"); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown level: %d, want 422", code)
	}
	if code := post(sc, sp.CSRFToken, "strict"); code != http.StatusSeeOther {
		t.Fatalf("change with sudo: %d, want 303", code)
	}
	if got := e.svc.Level(context.Background()); got != auth.LevelStrict {
		t.Errorf("level %q, want strict", got)
	}

	// Only the owner reaches the page and the change.
	for _, pattern := range []string{"GET /security", "POST /security"} {
		if r := routeFor(t, pattern); r.Policy.Role != auth.RoleOwner {
			t.Errorf("%s is open to %s", pattern, r.Policy.Role)
		}
	}
}
