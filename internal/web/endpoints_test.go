package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// endpointService creates lab/app with one internal endpoint on port 80.
func (e *env) endpointService(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", "Laboratório"); err != nil {
		t.Fatal(err)
	}
	s, err := e.pm.CreateService(ctx, a, "lab", projects.ServiceInput{Slug: "app", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	eps, err := e.pm.ListEndpoints(ctx, s.ID)
	if err != nil || len(eps) != 1 || eps[0].Public {
		t.Fatalf("endpoints: %+v %v", eps, err)
	}
	return eps[0].ID
}

func (e *env) endpointPublic(t *testing.T) bool {
	t.Helper()
	_, s, err := e.pm.GetService(context.Background(), "lab", "app")
	if err != nil {
		t.Fatal(err)
	}
	eps, _ := e.pm.ListEndpoints(context.Background(), s.ID)
	return len(eps) == 1 && eps[0].Public
}

// Putting a port on the internet takes what adding a domain takes: an
// admin with sudo. An operator, or an admin without sudo, cannot.
func TestMakingPublicTakesAdminAndSudo(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleOperator, auth.RoleAdmin} {
		e := newEnv(t)
		id := e.endpointService(t)
		c, p := e.session(t, role)
		rec := e.do(req{method: "POST", target: "/p/lab/s/app/endpoints/public", form: url.Values{"csrf": {p.CSRFToken}, "id": {id}}, cookies: []*http.Cookie{c}})
		if rec.Code == http.StatusSeeOther && strings.Contains(rec.Header().Get("Location"), "ok=endpoint") || e.endpointPublic(t) {
			t.Errorf("%v without sudo made the port public (%d)", role, rec.Code)
		}
	}

	e := newEnv(t)
	id := e.endpointService(t)
	sc, csrf := e.sudoSession(t, auth.RoleAdmin)
	rec := e.do(req{method: "POST", target: "/p/lab/s/app/endpoints/public", form: url.Values{"csrf": {csrf}, "id": {id}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/lab/s/app?tab=network&ok=endpoint#domains" || !e.endpointPublic(t) {
		t.Fatalf("admin with sudo: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// The switch asks before putting anything on the internet.
	page := e.do(req{method: "GET", target: "/p/lab/s/app?tab=network", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, `action="/p/lab/s/app/endpoints/internal" data-confirm=`) {
		t.Error("a public port should offer to go internal, with a confirmation")
	}

	// A domain on the port keeps it public: it cannot go internal while the
	// domain would still answer on the internet.
	if rec := e.do(req{method: "POST", target: "/p/lab/s/app/domains", form: url.Values{"csrf": {csrf}, "hostname": {"loja.exemplo.com.br"}, "endpoint": {id}}, cookies: []*http.Cookie{sc}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("add domain: %d", rec.Code)
	}
	rec = e.do(req{method: "POST", target: "/p/lab/s/app/endpoints/internal", form: url.Values{"csrf": {csrf}, "id": {id}}, cookies: []*http.Cookie{sc}})
	if rec.Code == http.StatusSeeOther || !e.endpointPublic(t) || !strings.Contains(rec.Body.String(), "Remova o domínio") {
		t.Errorf("went internal with a domain on it: %d", rec.Code)
	}
}

// A domain added to an internal port publishes it, so the screen never says
// "project network only" while the domain answers.
func TestDomainOnInternalPortPublishesIt(t *testing.T) {
	e := newEnv(t)
	id := e.endpointService(t)
	sc, csrf := e.sudoSession(t, auth.RoleAdmin)
	if rec := e.do(req{method: "POST", target: "/p/lab/s/app/domains", form: url.Values{"csrf": {csrf}, "hostname": {"app.exemplo.com.br"}, "endpoint": {id}}, cookies: []*http.Cookie{sc}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("add domain: %d", rec.Code)
	}
	if !e.endpointPublic(t) {
		t.Error("the port with a domain should be public")
	}
}
