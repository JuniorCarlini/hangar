package web

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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

// SEC-004: a secret never reaches a page by just opening it, for any role,
// admins included, on any tab; it shows only in the response to a reveal,
// which asks for sudo and leaves a secret.reveal record (one key, or every
// value for the .env editor).
func TestSecretsMaskedUntilRevealed(t *testing.T) {
	e := newEnv(t)
	webID := e.labService(t)
	ctx := context.Background()
	db, err := e.pm.CreateService(ctx, projects.Actor{UserID: "usr_x"}, "lab", projects.ServiceInput{Slug: "db", Image: "postgres:18-alpine", Port: 5432})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.pm.SetEnv(ctx, projects.Actor{UserID: "usr_x"}, db.ID, "POSTGRES_PASSWORD", "senha-do-banco-77", true); err != nil {
		t.Fatal(err)
	}
	if err := e.pm.SetEnv(ctx, projects.Actor{UserID: "usr_x"}, webID, "DATABASE_URL", "postgres://app:${{db.POSTGRES_PASSWORD}}@db/app", false); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"valor-super-secreto-42", "senha-do-banco-77"}
	leaks := func(body string) string {
		for _, s := range secrets {
			if strings.Contains(body, s) {
				return s
			}
		}
		return ""
	}
	c, p := e.session(t, auth.RoleAdmin)
	for _, tab := range []string{"", "?tab=variables", "?tab=overview", "?tab=network", "?tab=settings", "?tab=backups"} {
		page := e.do(req{method: "GET", target: "/p/lab/s/web" + tab, cookies: []*http.Cookie{c}})
		if s := leaks(page.Body.String()); s != "" {
			t.Fatalf("an admin got %q in the HTML of %q without revealing it", s, tab)
		}
		if page.Header().Get("Cache-Control") != "no-store" {
			t.Error("a service page must not be cached")
		}
	}
	frag := e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}, header: map[string]string{"X-Hangar-Fragment": "panel"}})
	if s := leaks(frag.Body.String()); s != "" {
		t.Fatalf("the drawer fragment carried %q", s)
	}

	for _, form := range []url.Values{{"key": {"SECRET_KEY"}}, {"all": {"1"}}} {
		form.Set("csrf", p.CSRFToken)
		rec := e.do(req{method: "POST", target: "/p/lab/s/web/env/reveal", form: form, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusForbidden || leaks(rec.Body.String()) != "" {
			t.Fatalf("reveal %v without sudo: status %d", form, rec.Code)
		}
	}
	before := countAudit(t, e, "secret.reveal")

	e.now = e.now.Add(30 * time.Second)
	rec := e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/p/lab/s/web"}}, cookies: []*http.Cookie{c}})
	sc := cookie(rec, sessionCookie)
	sp, _ := e.svc.Authenticate(ctx, sc.Value)

	rec = e.do(req{method: "POST", target: "/p/lab/s/web/env/reveal", form: url.Values{"csrf": {sp.CSRFToken}, "key": {"SECRET_KEY"}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "valor-super-secreto-42") || strings.Contains(rec.Body.String(), "senha-do-banco-77") {
		t.Fatalf("reveal one key with sudo: status %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("a page with a revealed secret must not be cached")
	}
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/env/reveal", form: url.Values{"csrf": {sp.CSRFToken}, "all": {"1"}}, cookies: []*http.Cookie{sc}})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "SECRET_KEY=valor-super-secreto-42") || !strings.Contains(body, "senha-do-banco-77") {
		t.Fatalf("reveal all to edit: status %d", rec.Code)
	}
	if !strings.Contains(body, `id="env-bulk" aria-labelledby="env-bulk-title" data-open="true"`) {
		t.Error("revealing to edit must open the .env editor")
	}
	if n := countAudit(t, e, "secret.reveal"); n != before+2 {
		t.Errorf("secret.reveal records: %d, want %d", n, before+2)
	}
	// The next plain visit is masked again.
	if s := leaks(e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{sc}}).Body.String()); s != "" {
		t.Fatalf("%q stayed on the page after the reveal", s)
	}
}

var envEditorRE = regexp.MustCompile(`(?s)id="bulk-env"[^>]*>(.*?)</textarea>`)

// SEC-004: the .env editor loads secrets as "KEY=••••" and saving that text
// keeps each secret as it is, for an admin who did not reveal and for an
// operator; a line written anew replaces the value.
func TestEnvEditorRoundTripKeepsSecrets(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleOperator} {
		e := newEnv(t)
		id := e.labService(t)
		c, p := e.session(t, role)
		page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}}).Body.String()
		m := envEditorRE.FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("%s: no .env editor", role)
		}
		text := html.UnescapeString(m[1])
		if strings.Contains(text, "valor-super-secreto-42") || !strings.Contains(text, "SECRET_KEY="+projects.HiddenValue) {
			t.Fatalf("%s: editor text %q", role, text)
		}
		rec := e.do(req{method: "POST", target: "/p/lab/s/web/env/bulk", form: url.Values{"csrf": {p.CSRFToken}, "mode": {"replace"}, "env": {text + "NOVA=1\n"}}, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: save: %d %s", role, rec.Code, rec.Body)
		}
		vals, _ := e.pm.ListEnvValues(context.Background(), id)
		got := map[string]string{}
		for _, v := range vals {
			got[v.Key] = v.Value
		}
		if got["SECRET_KEY"] != "valor-super-secreto-42" || got["NOVA"] != "1" {
			t.Fatalf("%s: after the round trip: %v", role, got)
		}
		rec = e.do(req{method: "POST", target: "/p/lab/s/web/env/bulk", form: url.Values{"csrf": {p.CSRFToken}, "mode": {"replace"}, "env": {"SECRET_KEY=outro-valor-123\nNOVA=1\n"}}, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: replace: %d", role, rec.Code)
		}
		if v, _ := e.pm.RevealEnv(context.Background(), projects.Actor{}, id, "SECRET_KEY"); v != "outro-valor-123" {
			t.Errorf("%s: a line written anew must replace the secret, got %q", role, v)
		}
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
