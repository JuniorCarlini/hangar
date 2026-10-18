package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// limitedSession creates two projects and an operator who only sees "lab",
// signed in with a password (the env does not require 2FA).
func (e *env) limitedSession(t *testing.T) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	for _, slug := range []string{"lab", "loja"} {
		if _, err := e.pm.CreateProject(ctx, projects.Actor{UserID: "usr_x"}, slug, slug); err != nil {
			t.Fatal(err)
		}
	}
	id, err := e.svc.CreateUser(ctx, "maria@hangar.dev", testPassword, auth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB.Exec(`UPDATE users SET all_projects = 0 WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB.Exec(`INSERT INTO user_projects (user_id, project_id) SELECT ?, id FROM projects WHERE slug = 'lab'`, id); err != nil {
		t.Fatal(err)
	}
	rec := e.do(req{method: "POST", target: "/login", form: url.Values{"email": {"maria@hangar.dev"}, "password": {testPassword}}})
	c := cookie(rec, sessionCookie)
	if c == nil {
		t.Fatalf("login: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	return c
}

func TestLimitedUserSeesOnlyTheirProjects(t *testing.T) {
	e := newEnv(t)
	c := e.limitedSession(t)
	get := func(target string) int {
		return e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}}).Code
	}
	if code := get("/p/lab"); code != http.StatusOK {
		t.Errorf("own project: %d", code)
	}
	for _, target := range []string{"/p/loja", "/p/loja/settings", "/domains", "/ports", "/backups", "/alerts", "/updates"} {
		if code := get(target); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", target, code)
		}
	}
	home := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(home, `href="/p/lab"`) || strings.Contains(home, `href="/p/loja"`) || strings.Contains(home, `href="/domains"`) {
		t.Error("the sidebar must list only lab and no server pages")
	}
	pal := e.do(req{method: "GET", target: "/palette.json", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(pal, "/p/loja") || strings.Contains(pal, `"/domains"`) {
		t.Error("the search must not offer other projects or server pages")
	}
	// Writes to another project are refused the same way.
	rec := e.do(req{method: "POST", target: "/p/loja/tidy", form: url.Values{}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("write to another project: %d", rec.Code)
	}
}

var inviteRE = regexp.MustCompile(`/invite/([A-Za-z0-9_-]{43})`)

func TestOwnerInvitesAndThePersonJoins(t *testing.T) {
	e := newEnv(t)
	sc, csrf := e.sudoSession(t, auth.RoleOwner)
	if _, err := e.pm.CreateProject(context.Background(), projects.Actor{UserID: "usr_x"}, "lab", "lab"); err != nil {
		t.Fatal(err)
	}
	rec := e.do(req{method: "POST", target: "/team/invites", cookies: []*http.Cookie{sc}, form: url.Values{
		"csrf": {csrf}, "email": {"pedro@hangar.dev"}, "role": {"viewer"}, "scope": {"some"}, "projects": {"lab"},
	}})
	m := inviteRE.FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || m == nil {
		t.Fatalf("invite: %d", rec.Code)
	}
	token := m[1]
	page := e.do(req{method: "GET", target: "/invite/" + token})
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "pedro@hangar.dev") {
		t.Fatalf("invite page: %d", page.Code)
	}
	login := cookie(page, loginCookie)
	rec = e.do(req{method: "POST", target: "/invite/" + token, cookies: []*http.Cookie{login}, form: url.Values{
		"csrf": {login.Value}, "password": {testPassword}, "confirm": {testPassword},
	}})
	if rec.Code != http.StatusSeeOther || cookie(rec, sessionCookie) == nil {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	if again := e.do(req{method: "GET", target: "/invite/" + token}); again.Code != http.StatusNotFound {
		t.Errorf("a used link: %d", again.Code)
	}
	team := e.do(req{method: "GET", target: "/team", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(team, "pedro@hangar.dev") {
		t.Error("the new person should be listed")
	}
}

func TestOnlyOwnersManageTheTeam(t *testing.T) {
	e := newEnv(t)
	c, _ := e.session(t, auth.RoleAdmin)
	if rec := e.do(req{method: "GET", target: "/team", cookies: []*http.Cookie{c}}); rec.Code != http.StatusForbidden {
		t.Fatalf("admin on the team page: %d", rec.Code)
	}
}
