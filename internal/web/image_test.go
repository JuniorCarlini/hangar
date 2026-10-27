package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

// Changing a service's image tag changes what runs: admin with sudo only,
// audited with the old and the new image.
func TestChangeImageNeedsAdminAndSudo(t *testing.T) {
	route := routeFor(t, "POST /p/{project}/s/{service}/image")
	if route.Policy.Role != auth.RoleAdmin || route.Policy.Sudo != auth.SudoStrict || route.Policy.Audit != "service.image.change" {
		t.Fatalf("policy = %+v", route.Policy)
	}

	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleAdmin)
	form := url.Values{"csrf": {p.CSRFToken}, "tag": {"1.31-alpine"}}
	if rec := e.do(req{method: "POST", target: "/p/lab/s/web/image", form: form, cookies: []*http.Cookie{c}}); rec.Code != http.StatusForbidden {
		t.Fatalf("without sudo: %d", rec.Code)
	}
	// The Settings tab offers the change only through the sudo dialog.
	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(page, `action="/p/lab/s/web/image"`) || !strings.Contains(page, `id="image"`) {
		t.Error("settings tab: the image card should show, with the form behind sudo")
	}

	e.now = e.now.Add(30 * time.Second)
	rec := e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/p/lab/s/web"}}, cookies: []*http.Cookie{c}})
	sc := cookie(rec, sessionCookie)
	if sc == nil {
		t.Fatalf("sudo: %d", rec.Code)
	}
	sp, _ := e.svc.Authenticate(context.Background(), sc.Value)
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, `action="/p/lab/s/web/image"`) || !strings.Contains(page, `value="nginx:1.29-alpine"`) {
		t.Error("settings tab with sudo: no image form with the current tag")
	}
	form.Set("csrf", sp.CSRFToken)
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/image", form: form, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "ok=image") {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	_, s, _ := e.pm.GetService(context.Background(), "lab", "web")
	if s.Image != "nginx:1.31-alpine" {
		t.Errorf("image = %q", s.Image)
	}
	var summary string
	if err := e.st.DB.QueryRow(`SELECT summary_json FROM audit_log WHERE action = 'service.image.change' AND outcome = 'ok'`).Scan(&summary); err != nil ||
		!strings.Contains(summary, "nginx:1.29-alpine") || !strings.Contains(summary, "nginx:1.31-alpine") {
		t.Errorf("audit = %q %v", summary, err)
	}

	// The settings card sends the whole reference: the repository may change.
	e.pm.Wait()
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/image", form: url.Values{"csrf": {sp.CSRFToken}, "image": {"ghcr.io/lab/web:2"}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change the whole image: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	if _, s, _ = e.pm.GetService(context.Background(), "lab", "web"); s.Image != "ghcr.io/lab/web:2" {
		t.Errorf("image = %q", s.Image)
	}
	if rec := e.do(req{method: "POST", target: "/p/lab/s/web/image", form: url.Values{"csrf": {sp.CSRFToken}, "image": {"Not An Image"}}, cookies: []*http.Cookie{sc}}); rec.Code == http.StatusSeeOther {
		t.Error("accepted an invalid image")
	}

	// Another repository is not a tag.
	form.Set("tag", "redis:8")
	if rec := e.do(req{method: "POST", target: "/p/lab/s/web/image", form: form, cookies: []*http.Cookie{sc}}); rec.Code == http.StatusSeeOther {
		t.Error("accepted another image as a tag")
	}
}

// routeFor returns the registered route with this pattern.
func routeFor(t *testing.T, pattern string) RouteInfo {
	t.Helper()
	rt := newRouter(nil, nil)
	routes(rt, &handlers{})
	for _, r := range rt.Routes() {
		if r.Pattern == pattern {
			return r
		}
	}
	t.Fatalf("route %s not registered", pattern)
	return RouteInfo{}
}
