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

func (e *env) emptyLab(t *testing.T) {
	t.Helper()
	if _, err := e.pm.CreateProject(context.Background(), projects.Actor{UserID: "usr_x"}, "lab", "Laboratório"); err != nil {
		t.Fatal(err)
	}
}

func (e *env) slugs(t *testing.T) map[string]bool {
	t.Helper()
	p, err := e.pm.GetProject(context.Background(), "lab")
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := e.pm.ListServices(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, s := range svcs {
		out[s.Slug] = true
	}
	return out
}

func TestNewServiceIsAModalOverTheCanvas(t *testing.T) {
	e := newEnv(t)
	e.emptyLab(t)
	c, _ := e.session(t, auth.RoleAdmin)
	page := e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `<dialog class="tuc-modal is-lg new-service" id="new-service"`) || !strings.Contains(page, `data-open="false"`) {
		t.Fatal("the canvas must carry the new-service dialog, closed")
	}
	if !strings.Contains(page, `data-tuc-modal="#new-service"`) || !strings.Contains(page, "/assets/newservice.js") {
		t.Error("the button must open the dialog in place")
	}
	if strings.Contains(page, "postgres://") {
		t.Error("the model file must not be inlined in every canvas page")
	}
	page = e.do(req{method: "GET", target: "/p/lab/new?from=web&x=320&y=160", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `data-open="true"`) || !strings.Contains(page, `class="canvas-area dots"`) {
		t.Fatal("/new is the canvas with the dialog open")
	}
	for _, want := range []string{`name="from" value="web"`, `name="x" value="320"`, `name="y" value="160"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the place must travel in the forms: %s missing", want)
		}
	}
	// One name per tab, already filled in, with its internal address.
	for _, want := range []string{`id="tpl-postgres-name"`, `value="db"`, `data-slug-out>db<`, `id="ns-img-name"`, `id="ns-git-name"`, `value="web"`} {
		if !strings.Contains(page, want) {
			t.Errorf("dialog without %s", want)
		}
	}
	dialog := page[strings.Index(page, `id="new-service"`):]
	dialog = dialog[:strings.Index(dialog, "</dialog>")]
	if strings.Contains(dialog, `name="slug"`) {
		t.Error("the user no longer types an identifier")
	}
	viewer := newEnv(t)
	viewer.emptyLab(t)
	vc, _ := viewer.session(t, auth.RoleViewer)
	if strings.Contains(viewer.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{vc}}).Body.String(), `id="new-service"`) {
		t.Error("a viewer must not get the dialog")
	}
}

func TestCreateServiceFromOneName(t *testing.T) {
	e := newEnv(t)
	e.emptyLab(t)
	c, p := e.session(t, auth.RoleAdmin)
	rec := e.do(req{method: "POST", target: "/p/lab/services", cookies: []*http.Cookie{c}, form: url.Values{
		"csrf": {p.CSRFToken}, "name": {"Loja Café"}, "image": {"nginx:1.29-alpine"}, "port": {""},
	}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/lab/s/loja-cafe" {
		t.Fatalf("create: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	e.pm.Wait()
	_, s, err := e.pm.GetService(context.Background(), "lab", "loja-cafe")
	if err != nil || s.InternalPort != 80 {
		t.Errorf("nginx's port must be filled in: %d %v", s.InternalPort, err)
	}
	rec = e.do(req{method: "POST", target: "/p/lab/services", cookies: []*http.Cookie{c}, form: url.Values{
		"csrf": {p.CSRFToken}, "name": {"loja cafe"}, "image": {"nginx:1.29-alpine"},
	}})
	body := rec.Body.String()
	if rec.Code != http.StatusConflict || !strings.Contains(body, "loja-cafe") || !strings.Contains(body, `data-open="true"`) {
		t.Fatalf("a taken name must come back in the open dialog with the address: %d", rec.Code)
	}
	if !strings.Contains(body, `value="loja cafe"`) {
		t.Error("the typed name must be kept")
	}

	rec = e.do(req{method: "POST", target: "/p/lab/templates", cookies: []*http.Cookie{c}, form: url.Values{
		"csrf": {p.CSRFToken}, "template": {"postgres"}, "name": {"db"}, "x": {"640"}, "y": {"48"},
	}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("template: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	page := e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `id="tpl-postgres-name" name="name" required maxlength="80" autocomplete="off" value="db-2"`) {
		t.Error("the next PostgreSQL must be suggested as db-2")
	}
	if !strings.Contains(page, `data-key="db" data-h="92" data-movable="true" x="624"`) {
		t.Error("the dropped place must be kept")
	}
}

const webCompose = `
services:
  db:
    image: postgres:17
    environment: {POSTGRES_DB: loja, POSTGRES_USER: loja, POSTGRES_PASSWORD: segredo-local}
  web:
    image: ghcr.io/dono/loja:2.1
    privileged: true
    ports: ["80:8000"]
    volumes: ["./src:/app", "media:/app/media"]
    environment:
      DATABASE_URL: postgres://loja:segredo-local@db:5432/loja
volumes:
  media:
`

func TestComposePreviewThenCreate(t *testing.T) {
	e := newEnv(t)
	e.emptyLab(t)
	c, p := e.session(t, auth.RoleAdmin)
	form := url.Values{"csrf": {p.CSRFToken}, "source": {"paste"}, "compose": {webCompose}}
	rec := e.do(req{method: "POST", target: "/p/lab/compose/preview", cookies: []*http.Cookie{c}, form: form})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `id="compose-preview"`) {
		t.Fatalf("preview: %d", rec.Code)
	}
	for _, want := range []string{"${{db.DATABASE_URL}}", "./src:/app", "privileged", "80:8000", "media:/app/media", "Criar 2 serviços"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview without %q", want)
		}
	}
	if len(e.slugs(t)) != 0 {
		t.Fatal("the preview must not create anything")
	}

	viewer := newEnv(t)
	viewer.emptyLab(t)
	oc, op := viewer.session(t, auth.RoleOperator)
	if r := viewer.do(req{method: "POST", target: "/p/lab/compose", cookies: []*http.Cookie{oc}, form: url.Values{"csrf": {op.CSRFToken}, "compose": {webCompose}}}); r.Code != http.StatusForbidden {
		t.Errorf("an operator imported a compose file: %d", r.Code)
	}

	rec = e.do(req{method: "POST", target: "/p/lab/compose", cookies: []*http.Cookie{c}, form: form})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/lab?ok=compose" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	if s := e.slugs(t); !s["db"] || !s["web"] {
		t.Fatalf("services: %v", s)
	}
	page := e.do(req{method: "GET", target: "/p/lab?ok=compose", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `class="edge"`) || !strings.Contains(page, `data-key="db" data-h="92" data-movable="true" x="384"`) {
		t.Error("the import must draw the reference and put the database beside the app")
	}

	// The same file again: names taken, the dialog says so, nothing doubles.
	rec = e.do(req{method: "POST", target: "/p/lab/compose", cookies: []*http.Cookie{c}, form: form})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "Já existe um serviço db") {
		t.Errorf("second import: %d", rec.Code)
	}
}

func TestComposeRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	e.emptyLab(t)
	c, p := e.session(t, auth.RoleAdmin)
	for name, text := range map[string]string{
		"too large": strings.Repeat("#", projects.MaxComposeBytes+1),
		"not yaml":  "services: [",
		"empty":     " ",
	} {
		rec := e.do(req{method: "POST", target: "/p/lab/compose/preview", cookies: []*http.Cookie{c}, form: url.Values{
			"csrf": {p.CSRFToken}, "source": {"paste"}, "compose": {text},
		}})
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `role="alert"`) {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	sample := e.do(req{method: "GET", target: "/compose-sample.yaml", cookies: []*http.Cookie{c}})
	if sample.Code != http.StatusOK || !strings.HasPrefix(sample.Header().Get("Content-Type"), "text/plain") || !strings.Contains(sample.Body.String(), "celery") {
		t.Errorf("model file: %d %s", sample.Code, sample.Header().Get("Content-Type"))
	}
}

func TestComposeFromRepository(t *testing.T) {
	e := newEnv(t)
	e.pm.SetBuildDir(t.TempDir())
	e.emptyLab(t)
	c, p := e.session(t, auth.RoleAdmin)
	repo := labRepoWith(t, map[string]string{
		"Dockerfile":         "FROM alpine\nEXPOSE 8000\n",
		"docker-compose.yml": "services:\n  api:\n    build: .\n  cache:\n    image: redis:8\n",
	})
	form := url.Values{"csrf": {p.CSRFToken}, "source": {"git"}, "repo": {repo}, "branch": {"main"}, "credential": {""}}
	rec := e.do(req{method: "POST", target: "/p/lab/compose/preview", cookies: []*http.Cookie{c}, form: form})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "docker-compose.yml") || !strings.Contains(body, "Build do repositório") {
		t.Fatalf("preview from the repository: %d", rec.Code)
	}
	rec = e.do(req{method: "POST", target: "/p/lab/compose", cookies: []*http.Cookie{c}, form: form})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	_, s, err := e.pm.GetService(context.Background(), "lab", "api")
	if err != nil || s.InternalPort != 8000 {
		t.Errorf("api port from EXPOSE: %d %v", s.InternalPort, err)
	}
}
