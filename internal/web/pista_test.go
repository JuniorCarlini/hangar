package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

// The catalog opens for any logged-in user, stays behind login, and keeps
// to the CSP like every other page.
func TestPistaCatalog(t *testing.T) {
	e := newEnv(t)
	rec := e.do(req{method: "GET", target: "/_pista", header: map[string]string{"Accept": "text/html"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("no session: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}

	c, _ := e.session(t, auth.RoleViewer)
	rec = e.do(req{method: "GET", target: "/_pista", cookies: []*http.Cookie{c}})
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer: status %d", rec.Code)
	}
	for _, want := range []string{
		"Catálogo do Pista", `class="theme-dark `, `class="theme-light `, "tuc-btn is-success",
		`data-demo-confirm=`, `data-tone="danger"`, `data-demo-toast=`, `class="node is-selected"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("catalog is missing %q", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("catalog has an inline style, which the CSP would block")
	}
	if strings.Contains(body, `href="/_pista"`) {
		t.Error("only owners see the catalog link in the sidebar")
	}
}
