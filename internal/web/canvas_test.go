package web

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

func TestCanvasDrawsReferencesAndPanel(t *testing.T) {
	e := newEnv(t)
	webID := e.labService(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateFromTemplate(ctx, a, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.pm.SetEnv(ctx, a, webID, "DATABASE_URL", "${{db.DATABASE_URL}}", false); err != nil {
		t.Fatal(err)
	}
	c, _ := e.session(t, auth.RoleAdmin)

	body := e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String()
	page := html.UnescapeString(body)
	for _, want := range []string{
		`data-slug="web"`, `data-slug="db"`, // both cards
		"DATABASE_URL = ${{db.DATABASE_URL}}", // the line and its tooltip
		`data-exports="DATABASE`,              // what the drop target offers
		`data-tuc-contextmenu="#menu-web"`,    // right-click menu
		`/assets/canvas.js`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("canvas without %q", want)
		}
	}
	if strings.Contains(page, "valor-super-secreto-42") || strings.Contains(page, "postgres://") {
		t.Fatal("the canvas must show references, never values")
	}
	if strings.Contains(page, `id="svc-panel"`) {
		t.Error("no panel without a selected service")
	}

	// An old tab (connection) lands where its content lives now.
	panel := e.do(req{method: "GET", target: "/p/lab/s/db?tab=connection", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(panel, `id="svc-panel"`) || !strings.Contains(panel, `aria-selected="true" href="/p/lab/s/db?tab=variables"`) {
		t.Error("the service page is the canvas with the panel open on the asked tab")
	}
	if !strings.Contains(panel, "node is-selected") && !strings.Contains(panel, "is-selected") {
		t.Error("the selected card must be highlighted")
	}

	for _, path := range []string{"/p/lab/new", "/p/lab/settings"} {
		if rec := e.do(req{method: "GET", target: path, cookies: []*http.Cookie{c}}); rec.Code != http.StatusOK {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestBrokenReferencesWarn(t *testing.T) {
	e := newEnv(t)
	webID := e.labService(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if err := e.pm.SetEnv(ctx, a, webID, "DATABASE_URL", "${{db.DATABASE_URL}}", false); err != nil {
		t.Fatal(err)
	}
	c, _ := e.session(t, auth.RoleAdmin)

	canvas := html.UnescapeString(e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String())
	if !strings.Contains(canvas, `class="node-warn" title="Referência quebrada em DATABASE_URL: o próximo deploy vai falhar."`) {
		t.Error("the card must mark the broken reference")
	}

	tab := html.UnescapeString(e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}}).Body.String())
	why := "DATABASE_URL aponta para o serviço db, que não existe neste projeto."
	for _, want := range []string{
		`class="tuc-alert is-danger"`, "1 referência quebrada", why,
		`<span class="tuc-badge is-danger ref-badge" title="` + why + `">ref</span>`,
	} {
		if !strings.Contains(tab, want) {
			t.Errorf("variables tab without %q", want)
		}
	}

	// Once db exists, the same reference is fine and the warnings go away.
	if _, err := e.pm.CreateFromTemplate(ctx, a, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	tab = html.UnescapeString(e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}}).Body.String())
	canvas = e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(tab, "referência quebrada") || strings.Contains(canvas, "node-warn") {
		t.Error("a resolvable reference must not warn")
	}
	// A whole reference shows as a connection: where the value comes from.
	if !strings.Contains(tab, `title="${{db.DATABASE_URL}}"`) || !strings.Contains(tab, `<span class="font-mono">db</span>`) {
		t.Error("the variable does not show its connection")
	}
}

func TestCanvasRemembersCardPosition(t *testing.T) {
	ve := newEnv(t)
	ve.labService(t)
	viewer, vp := ve.session(t, auth.RoleViewer)
	move := url.Values{"csrf": {vp.CSRFToken}, "x": {"512"}, "y": {"320"}}
	if rec := ve.do(req{method: "POST", target: "/p/lab/s/web/position", form: move, cookies: []*http.Cookie{viewer}}); rec.Code != http.StatusForbidden {
		t.Fatalf("a viewer moved a card: %d", rec.Code)
	}

	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleOperator)
	move.Set("csrf", p.CSRFToken)
	if rec := e.do(req{method: "POST", target: "/p/lab/s/web/position", form: move, cookies: []*http.Cookie{c}}); rec.Code != http.StatusNoContent {
		t.Fatalf("move: %d", rec.Code)
	}
	body := e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String()
	// The card's frame is drawn 16px around the card itself (room for its shadow).
	if !strings.Contains(body, `data-key="web" data-h="92" data-movable="true" x="496" y="304"`) {
		t.Error("the card did not stay where it was dropped")
	}
	if rec := e.do(req{method: "POST", target: "/p/lab/s/nada/position", form: move, cookies: []*http.Cookie{c}}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown service: %d", rec.Code)
	}
}

func TestLogMarkIsSavedAndSigned(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	c, p := e.session(t, auth.RoleOperator)
	rec := e.do(req{method: "POST", target: "/p/lab/s/web/logs/mark", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"by":`) || !strings.Contains(rec.Body.String(), `"n":`) {
		t.Fatalf("mark: %d %s", rec.Code, rec.Body.String())
	}
	marks, err := e.pm.LogMarks(context.Background(), id, time.Now().Add(-time.Minute))
	if err != nil || len(marks) != 1 {
		t.Fatalf("the mark must be saved for later viewers: %v %d", err, len(marks))
	}
}

// A card with a saved position (a compose file places its cards) must not
// end up under one the automatic layout puts in the same column.
func TestCanvasAutoLayoutSkipsSavedCards(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	ctx := context.Background()
	if _, err := e.pm.CreateService(ctx, projects.Actor{UserID: "usr_x"}, "lab", projects.ServiceInput{Slug: "api", Image: "nginx:1.29-alpine"}); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	// "api" sorts first and takes the first row; "web" would take the
	// second (y=200), right where this saved card sits.
	if err := e.pm.SetCanvasPosition(ctx, "lab", "api", 48, 240); err != nil {
		t.Fatal(err)
	}
	c, _ := e.session(t, auth.RoleOperator)
	body := e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(body, `data-key="web" data-h="92" data-movable="true" x="32" y="32"`) {
		t.Error("the automatic card did not take the free first row")
	}
}
