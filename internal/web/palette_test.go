package web

import (
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// paletteAs fetches /palette.json as a fresh user with the role, with the
// lab project and its web service in place.
func paletteAs(t *testing.T, role auth.Role) (paletteData, string, *auth.Principal) {
	t.Helper()
	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, role)
	rec := e.do(req{method: "GET", target: "/palette.json", cookies: []*http.Cookie{c}, header: map[string]string{"Accept": "application/json"}})
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("palette as %s: status %d, type %q", role, rec.Code, rec.Header().Get("Content-Type"))
	}
	var d paletteData
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("palette JSON: %v", err)
	}
	return d, rec.Body.String(), p
}

func findItem(d paletteData, match func(paletteItem) bool) *paletteItem {
	for i := range d.Items {
		if match(d.Items[i]) {
			return &d.Items[i]
		}
	}
	return nil
}

func hasHref(d paletteData, href string) bool {
	return findItem(d, func(it paletteItem) bool { return it.Href == href }) != nil
}

func hasPost(d paletteData, url string) bool {
	return findItem(d, func(it paletteItem) bool { return it.Post != nil && it.Post.URL == url }) != nil
}

func TestPaletteViewer(t *testing.T) {
	d, body, p := paletteAs(t, auth.RoleViewer)

	ids := []string{}
	for _, g := range d.Groups {
		ids = append(ids, g.ID)
	}
	if !slices.Equal(ids, []string{"pages", "projects", "services", "actions"}) || d.Groups[0].Label != "Páginas" {
		t.Errorf("groups: %+v", d.Groups)
	}
	for _, href := range []string{"/", "/domains", "/ports", "/account", "/p/lab", "/p/lab/s/web", "/p/lab/s/web?tab=variables", "/p/lab/s/web?tab=logs", "/p/lab/s/web?tab=settings"} {
		if !hasHref(d, href) {
			t.Errorf("viewer palette is missing %s", href)
		}
	}
	if it := findItem(d, func(it paletteItem) bool { return it.Href == "/p/lab/s/web?tab=variables" }); it == nil || it.Label != "web › Variáveis" || !it.Deep || it.Hint != "lab" {
		t.Errorf("variables tab item: %+v", it)
	}
	if it := findItem(d, func(it paletteItem) bool { return it.Href == "/p/lab" }); it == nil || it.Hint != "Laboratório" || it.Group != "projects" {
		t.Errorf("project item: %+v", it)
	}
	// Viewers only look: no deploy, restart, new project or new service, and
	// no owner page.
	if hasHref(d, "/update") || hasHref(d, "/p/lab/new") || hasPost(d, "/p/lab/s/web/deploy") || hasPost(d, "/p/lab/s/web/action") ||
		findItem(d, func(it paletteItem) bool { return it.Modal != "" }) != nil {
		t.Error("viewer palette offers actions beyond the role")
	}
	// Everyone may switch theme and log out (with a danger confirmation).
	if out := findItem(d, func(it paletteItem) bool { return it.Post != nil && it.Post.URL == "/logout" }); out == nil || out.Post.Confirm == nil || out.Post.Confirm.Tone != "danger" {
		t.Errorf("logout item: %+v", out)
	}
	themes := 0
	for _, it := range d.Items {
		if it.Post != nil && it.Post.URL == "/account/preferences" {
			themes++
			if !it.Post.Next || it.Post.Fields["theme"] == "system" {
				t.Errorf("theme item %+v: should return to the page and skip the current theme", it)
			}
		}
	}
	if themes != 2 {
		t.Errorf("theme items: %d, want the two not in use", themes)
	}
	// Never secrets nor the session's tokens.
	if strings.Contains(body, "valor-super-secreto-42") || strings.Contains(body, "SECRET_KEY") || strings.Contains(body, p.CSRFToken) {
		t.Error("palette JSON leaks a secret or the CSRF token")
	}
	for _, it := range d.Items {
		if !slices.Contains(views.PaletteIcons, it.Icon) {
			t.Errorf("item %q uses icon %q, not rendered in the palette template", it.Label, it.Icon)
		}
	}
}

func TestPaletteOperatorAndAdmin(t *testing.T) {
	d, _, _ := paletteAs(t, auth.RoleOperator)
	if !hasPost(d, "/p/lab/s/web/deploy") {
		t.Error("operator should get deploy")
	}
	restart := findItem(d, func(it paletteItem) bool { return it.Post != nil && it.Post.URL == "/p/lab/s/web/action" })
	if restart == nil || restart.Post.Fields["action"] != "restart" || restart.Post.Confirm == nil || restart.Post.Confirm.Tone != "warning" {
		t.Errorf("operator restart item: %+v", restart)
	}
	if hasHref(d, "/p/lab/new") || hasHref(d, "/update") {
		t.Error("operator must not get admin or owner items")
	}

	d, _, _ = paletteAs(t, auth.RoleAdmin)
	if !hasHref(d, "/p/lab/new") || findItem(d, func(it paletteItem) bool { return it.Modal == "new-project" }) == nil {
		t.Error("admin should get new service and new project")
	}
	if hasHref(d, "/update") {
		t.Error("admin must not get the owner's update page")
	}

	d, _, _ = paletteAs(t, auth.RoleOwner)
	if !hasHref(d, "/update") {
		t.Error("owner should get the update page")
	}
}

func TestPaletteNeedsSession(t *testing.T) {
	e := newEnv(t)
	rec := e.do(req{method: "GET", target: "/palette.json", header: map[string]string{"Accept": "application/json"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("palette without a session: status %d", rec.Code)
	}
}

// The palette is on every authenticated page, with the shortcut for the
// visitor's system.
func TestPaletteInFrame(t *testing.T) {
	e := newEnv(t)
	c, _ := e.session(t, auth.RoleViewer)
	page := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}, header: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)"}}).Body.String()
	for _, want := range []string{`id="palette"`, `data-palette-open`, "⌘K", `aria-keyshortcuts="Meta+K"`, "palette.js"} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	page = e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}, header: map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}}).Body.String()
	if !strings.Contains(page, "Ctrl K") || strings.Contains(page, "⌘K") {
		t.Error("off Apple devices the hint should read Ctrl K")
	}
}

// Every icon palette.go names is in the palette's <template>, whatever role
// would see the item (the tests above only list some roles' items).
func TestPaletteIconsAreRendered(t *testing.T) {
	raw, err := os.ReadFile("palette.go")
	if err != nil {
		t.Fatal(err)
	}
	names := slices.Collect(maps.Values(tabIcons))
	for _, m := range regexp.MustCompile(`Icon: "([a-z0-9-]+)"`).FindAllStringSubmatch(string(raw), -1) {
		names = append(names, m[1])
	}
	for _, name := range names {
		if !slices.Contains(views.PaletteIcons, name) {
			t.Errorf("palette.go uses icon %q, not rendered in the palette template", name)
		}
	}
}
