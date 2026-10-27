package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

type fakeNode struct {
	mu   sync.Mutex
	logs []node.LogLine
}

func newFakeNode() *fakeNode { return &fakeNode{} }

func (f *fakeNode) EnsureProjectNetwork(context.Context, string, string) error { return nil }
func (f *fakeNode) RemoveProjectNetwork(context.Context, string) error         { return nil }
func (f *fakeNode) Deploy(_ context.Context, s node.ServiceSpec, _ node.DeployOptions) (node.DeployResult, error) {
	return node.DeployResult{ContainerID: "c1", ImageRef: s.Image + "@sha256:1"}, s.Validate()
}
func (f *fakeNode) Start(context.Context, string, string) error   { return nil }
func (f *fakeNode) Stop(context.Context, string, string) error    { return nil }
func (f *fakeNode) Restart(context.Context, string, string) error { return nil }
func (f *fakeNode) Remove(context.Context, string, string) error  { return nil }
func (f *fakeNode) Status(context.Context, string, string) (node.Status, error) {
	return node.Status{Exists: true, Running: true, State: "running"}, nil
}

func (f *fakeNode) Logs(_ context.Context, _, _ string, _ node.LogOptions, fn func(node.LogLine) error) error {
	f.mu.Lock()
	lines := append([]node.LogLine(nil), f.logs...)
	f.mu.Unlock()
	for _, l := range lines {
		if err := fn(l); err != nil {
			return err
		}
	}
	return nil
}
func (f *fakeNode) ListManaged(context.Context) ([]node.Managed, error) { return nil, nil }
func (f *fakeNode) EnsureEdge(context.Context, node.EdgeSpec) error     { return nil }
func (f *fakeNode) ConnectEdge(context.Context, string) error           { return nil }
func (f *fakeNode) Exec(_ context.Context, _, _ string, cmd []string, w io.Writer) error {
	_, err := io.WriteString(w, "exec:"+strings.Join(cmd, " "))
	return err
}
func (f *fakeNode) SetLinked(context.Context, string, string, []string) error { return nil }
func (f *fakeNode) ServiceAddress(context.Context, string, string, int) (string, error) {
	return "", nil
}

// session creates a user with the role, logs in and returns cookie and principal.
func (e *env) session(t *testing.T, role auth.Role) (*http.Cookie, *auth.Principal) {
	t.Helper()
	e.createUser(t, role)
	c := e.login(t)
	p, _ := e.svc.Authenticate(context.Background(), c.Value)
	return c, p
}

func (e *env) labService(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", "Laboratório"); err != nil {
		t.Fatal(err)
	}
	s, err := e.pm.CreateService(ctx, a, "lab", projects.ServiceInput{Slug: "web", Image: "nginx:1.29-alpine"})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.pm.SetEnv(ctx, a, s.ID, "SECRET_KEY", "valor-super-secreto-42", true); err != nil {
		t.Fatal(err)
	}
	return s.ID
}

func TestOperatorCannotCreateProject(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleOperator)
	rec := e.do(req{method: "POST", target: "/projects", form: url.Values{"csrf": {p.CSRFToken}, "slug": {"lab"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator creating a project: status %d", rec.Code)
	}
}

func TestAdminCreatesProjectAndService(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	rec := e.do(req{method: "POST", target: "/projects", form: url.Values{"csrf": {p.CSRFToken}, "slug": {"lab"}, "name": {"Lab"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/lab" {
		t.Fatalf("create project: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(req{method: "POST", target: "/p/lab/services", form: url.Values{
		"csrf": {p.CSRFToken}, "slug": {"web"}, "image": {"nginx:1.29-alpine"}, "memory_mb": {"256"}, "cpus": {"0,5"},
	}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create service: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	rec = e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}})
	if !strings.Contains(rec.Body.String(), "lab_web") {
		t.Error("service missing from the project page")
	}
	rec = e.do(req{method: "POST", target: "/p/lab/services", form: url.Values{
		"csrf": {p.CSRFToken}, "slug": {"x"}, "image": {"nginx; rm -rf /"},
	}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("image with a shell command: status %d", rec.Code)
	}
}

// Admins see every value in the Variables tab (the .env editor holds the
// whole file); below admin a secret never reaches the HTML, on any tab, and
// the reveal route still asks for sudo.
func TestSecretOnlyForAdmins(t *testing.T) {
	eo := newEnv(t)
	eo.labService(t)
	op, _ := eo.session(t, auth.RoleOperator)
	for _, tab := range []string{"", "?tab=variables", "?tab=overview", "?tab=network", "?tab=deploys", "?tab=connection", "?tab=settings"} {
		if strings.Contains(eo.do(req{method: "GET", target: "/p/lab/s/web" + tab, cookies: []*http.Cookie{op}}).Body.String(), "valor-super-secreto-42") {
			t.Fatalf("an operator got the secret in the HTML of %q", tab)
		}
	}
	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleAdmin)
	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}})
	if !strings.Contains(page.Body.String(), "valor-super-secreto-42") {
		t.Fatal("an admin does not see the secret's value")
	}
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Error("a page with secrets must not be cached")
	}

	rec := e.do(req{method: "POST", target: "/p/lab/s/web/env/reveal", form: url.Values{"csrf": {p.CSRFToken}, "key": {"SECRET_KEY"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "valor-super-secreto-42") {
		t.Fatalf("reveal without sudo: status %d", rec.Code)
	}

	e.now = e.now.Add(30 * time.Second)
	rec = e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/p/lab/s/web"}}, cookies: []*http.Cookie{c}})
	sudoCookie := cookie(rec, sessionCookie)
	sp, _ := e.svc.Authenticate(context.Background(), sudoCookie.Value)

	rec = e.do(req{method: "POST", target: "/p/lab/s/web/env/reveal", form: url.Values{"csrf": {sp.CSRFToken}, "key": {"SECRET_KEY"}}, cookies: []*http.Cookie{sudoCookie}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "valor-super-secreto-42") {
		t.Fatalf("reveal with sudo: status %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("a page with a revealed secret must not be cached")
	}
}

func TestServiceURLScopedToProject(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	if _, err := e.pm.CreateProject(context.Background(), projects.Actor{}, "outro", ""); err != nil {
		t.Fatal(err)
	}
	c, _ := e.session(t, auth.RoleOwner)
	if rec := e.do(req{method: "GET", target: "/p/outro/s/web", cookies: []*http.Cookie{c}}); rec.Code != http.StatusNotFound {
		t.Fatalf("another project's service by URL: status %d", rec.Code)
	}
}

func TestDeleteServiceNeedsSudoAndName(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleOwner)
	rec := e.do(req{method: "POST", target: "/p/lab/s/web/delete", form: url.Values{"csrf": {p.CSRFToken}, "confirm": {"web"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete without sudo: %d", rec.Code)
	}
}

func TestLogsStreamEscapesAndStrips(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	e.node.logs = []node.LogLine{
		{Stream: "stdout", Time: time.Now(), Text: "GET / 200"},
		{Stream: "stderr", Time: time.Now(), Text: "\x1b[31m<script>alert(1)</script>\x1b[0m"},
	}
	c, _ := e.session(t, auth.RoleViewer)
	rec := e.do(req{method: "GET", target: "/p/lab/s/web/logs", cookies: []*http.Cookie{c}})
	body := rec.Body.String()
	if rec.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" {
		t.Fatalf("content-type: %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, "GET / 200") {
		t.Error("log line missing")
	}
	if strings.Contains(body, "\x1b[") {
		t.Error("ANSI sequence was not stripped")
	}
	if strings.Contains(body, "<script>") {
		t.Error("raw HTML in the stream: it must be escaped in the JSON")
	}
	if !strings.Contains(body, "event: end") {
		t.Error("end of stream not signaled")
	}
}

func TestMaintenanceToggle(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleAdmin)
	post := func(form url.Values) *httptest.ResponseRecorder {
		return e.do(req{method: "POST", target: "/p/lab/s/web/maintenance", form: form, cookies: []*http.Cookie{c}})
	}
	maint := func() int64 {
		_, s, err := e.pm.GetService(context.Background(), "lab", "web")
		if err != nil {
			t.Fatal(err)
		}
		return s.Maintenance
	}

	if rec := post(url.Values{"action": {"on"}}); rec.Code != http.StatusForbidden || maint() != 0 {
		t.Fatalf("without the CSRF token: %d", rec.Code)
	}
	if rec := post(url.Values{"csrf": {p.CSRFToken}, "action": {"maybe"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown action: %d", rec.Code)
	}
	rec := post(url.Values{"csrf": {p.CSRFToken}, "action": {"on"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/lab/s/web?ok=maintenance-on#maintenance" || maint() != 1 {
		t.Fatalf("turn on: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	body := e.do(req{method: "GET", target: "/p/lab/s/web?ok=maintenance-on", cookies: []*http.Cookie{c}}).Body.String()
	for _, want := range []string{`id="maintenance"`, `value="off"`, "Em manutenção", "lucide-wrench"} {
		if !strings.Contains(body, want) {
			t.Errorf("drawer in maintenance lacks %s", want)
		}
	}
	rec = post(url.Values{"csrf": {p.CSRFToken}, "action": {"off"}})
	if rec.Code != http.StatusSeeOther || maint() != 0 {
		t.Fatalf("turn off: %d", rec.Code)
	}
	body = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(body, `value="on"`) || !strings.Contains(body, `data-tone="warning"`) || strings.Contains(body, `lucide-wrench shrink-0 size-3"`) {
		t.Error("out of maintenance: the card should offer to turn it on, with a warning confirmation, and no badge")
	}
}

// Maintenance takes the service's domains off the air: admins only.
func TestOnlyAdminsToggleMaintenance(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator} {
		e := newEnv(t)
		e.labService(t)
		c, p := e.session(t, role)
		rec := e.do(req{method: "POST", target: "/p/lab/s/web/maintenance", form: url.Values{"csrf": {p.CSRFToken}, "action": {"on"}}, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%v turning maintenance on: %d", role, rec.Code)
		}
	}
}

// certEdge is an edge whose certificate storage holds the issued hosts.
type certEdge struct{ issued map[string]bool }

func (certEdge) Apply(context.Context) error       { return nil }
func (c certEdge) HasCertificate(host string) bool { return c.issued[host] }

func TestDomainCertificateBadgeTellsTheTruth(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	e.pm.SetEdge(certEdge{issued: map[string]bool{"pronto.dev": true}})
	if _, err := e.pm.CreateProject(ctx, a, "lab", "Laboratório"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateService(ctx, a, "lab", projects.ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80}); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	for _, h := range []string{"pronto.dev", "novo.dev", "*.lojas.dev"} {
		if err := e.pm.AddDomain(ctx, a, "lab", "web", h, ""); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := e.session(t, auth.RoleViewer)
	body := e.do(req{method: "GET", target: "/p/lab/s/web?tab=network", cookies: []*http.Cookie{c}}).Body.String()
	for _, want := range []string{"HTTPS ativo", "Emitindo certificado", "por subdomínio, sob demanda"} {
		if strings.Count(body, want) != 1 {
			t.Errorf("certificate column should show %q once", want)
		}
	}
	if strings.Contains(body, "HTTPS automático") {
		t.Error("with the edge storage readable, no domain falls back to the generic badge")
	}
}
