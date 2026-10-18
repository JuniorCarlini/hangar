package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

func TestServiceTabPicksWhereContentLives(t *testing.T) {
	cases := []struct {
		target    string
		canBackup bool
		want      string
	}{
		{"/p/lab/s/web", false, "overview"},
		{"/p/lab/s/web?tab=deploys", false, "overview"},
		{"/p/lab/s/web?tab=metrics", false, "overview"},
		{"/p/lab/s/web?tab=terminal", false, "overview"},
		{"/p/lab/s/web?tab=connection", false, "variables"},
		{"/p/lab/s/web?tab=domains", false, "network"},
		{"/p/lab/s/web?tab=ports", false, "network"},
		{"/p/lab/s/web?tab=nope", false, "overview"},
		{"/p/lab/s/web?tab=backups", false, "overview"},
		{"/p/lab/s/db?tab=backups", true, "backups"},
		{"/p/lab/s/web?ok=port", false, "network"},
		{"/p/lab/s/web?ok=volume", false, "settings"},
		{"/p/lab/s/web/domains", false, "network"},
		{"/p/lab/s/web/ports/delete", false, "network"},
		{"/p/lab/s/web/exports/reveal", false, "variables"},
		{"/p/lab/s/web/volumes", false, "settings"},
	}
	for _, c := range cases {
		if got := serviceTab(httptest.NewRequest(http.MethodGet, c.target, nil), c.canBackup); got != c.want {
			t.Errorf("%s (backup %v): %s, want %s", c.target, c.canBackup, got, c.want)
		}
	}
}

func TestDrawerTabsAndTerminalButton(t *testing.T) {
	e := newEnv(t)
	e.labService(t)

	op, _ := e.session(t, auth.RoleOperator)
	page := e.do(req{method: "GET", target: "/p/lab/s/web", cookies: []*http.Cookie{op}}).Body.String()
	for _, tab := range []string{"overview", "variables", "network", "logs", "settings"} {
		if !strings.Contains(page, `href="/p/lab/s/web?tab=`+tab+`"`) {
			t.Errorf("tab %s missing", tab)
		}
	}
	for _, gone := range []string{"?tab=backups", "?tab=terminal", "?tab=deploys", "?tab=ports", "?tab=connection"} {
		if strings.Contains(page, `href="/p/lab/s/web`+gone+`"`) {
			t.Errorf("an app has no %s tab", gone)
		}
	}
	if strings.Contains(page, "terminal-modal") || strings.Contains(page, "terminal-sudo") {
		t.Error("only admins get the terminal")
	}

	// An admin without sudo is asked to confirm, and comes back with the
	// terminal open.
	e = newEnv(t)
	e.labService(t)
	adm, ap := e.session(t, auth.RoleAdmin)
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=logs", cookies: []*http.Cookie{adm}}).Body.String()
	if !strings.Contains(page, `data-tuc-modal="#terminal-sudo"`) || !strings.Contains(page, `name="next" value="/p/lab/s/web?tab=logs&amp;terminal=1"`) {
		t.Error("terminal without sudo: the button opens the identity check that returns with the terminal")
	}
	if strings.Contains(page, `id="terminal-modal"`) {
		t.Error("no terminal before sudo")
	}

	sc, _ := e.sudo(t, adm, ap)
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=overview&terminal=1", cookies: []*http.Cookie{sc}}).Body.String()
	for _, want := range []string{
		`data-tuc-modal="#terminal-modal"`, `id="terminal-modal"`, `data-open="true"`,
		`data-src="/p/lab/s/web/terminal"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("terminal modal lacks %s", want)
		}
	}
	if strings.Contains(page, ` src="/p/lab/s/web/terminal"`) {
		t.Error("the frame must load only when the modal opens (it opens a shell)")
	}
	if strings.Contains(page, "/assets/terminal.js") {
		t.Error("the drawer itself does not load xterm")
	}
}

func TestTerminalPageAndSavedCommands(t *testing.T) {
	e := newEnv(t)
	e.labService(t)

	other := newEnv(t)
	other.labService(t)
	op, _ := other.session(t, auth.RoleOperator)
	if rec := other.do(req{method: "GET", target: "/p/lab/s/web/terminal", cookies: []*http.Cookie{op}}); rec.Code != http.StatusForbidden {
		t.Errorf("operator on the terminal page: %d", rec.Code)
	}

	sc, csrf := e.sudoSession(t, auth.RoleAdmin)
	rec := e.do(req{method: "GET", target: "/p/lab/s/web/terminal", cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusOK {
		t.Fatalf("terminal page: %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self'") || !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") || !strings.Contains(csp, "script-src 'self';") {
		t.Errorf("terminal CSP: %s", csp)
	}
	if rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("the terminal page is framed by the panel")
	}
	page := rec.Body.String()
	for _, want := range []string{`name="shell" value="bash" checked`, `value="sh"`, `id="save-command"`, "/assets/terminal.js"} {
		if !strings.Contains(page, want) {
			t.Errorf("terminal page lacks %s", want)
		}
	}
	// Commands are typed in the shell: no separate "custom command" mode.
	if strings.Contains(page, `value="custom"`) {
		t.Error("the terminal still offers a custom-command mode")
	}
	// Every other page stays unframeable, with no inline style.
	svc := e.do(req{method: "GET", target: "/p/lab/s/web?tab=terminal", cookies: []*http.Cookie{sc}})
	if csp := svc.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("service page CSP relaxed: %s", csp)
	}

	rec = e.do(req{method: "POST", target: "/p/lab/s/web/terminal/commands", form: url.Values{"csrf": {csrf}, "name": {"migrar"}, "command": {"python manage.py migrate"}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/lab/s/web/terminal" {
		t.Fatalf("save command: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	page = e.do(req{method: "GET", target: "/p/lab/s/web/terminal", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, `data-run-command="python manage.py migrate"`) || !strings.Contains(page, "migrar") {
		t.Error("the saved command is listed with its run button")
	}
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/terminal/commands", form: url.Values{"csrf": {csrf}, "name": {"x"}, "command": {"ls\nid"}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "numa linha") {
		t.Errorf("a multi-line command must be refused on the page: %d", rec.Code)
	}

	_, s, _ := e.pm.GetService(context.Background(), "lab", "web")
	cmds, _ := e.pm.ListCommands(context.Background(), s.ID)
	if len(cmds) != 1 {
		t.Fatalf("commands: %+v", cmds)
	}
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/terminal/commands/delete", form: url.Values{"csrf": {csrf}, "id": {cmds[0].ID}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete command: %d", rec.Code)
	}
	if cmds, _ := e.pm.ListCommands(context.Background(), s.ID); len(cmds) != 0 {
		t.Error("command not deleted")
	}
}

func TestNetworkTabModals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateService(ctx, a, "lab", projects.ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80}); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	sc, csrf := e.sudoSession(t, auth.RoleAdmin)

	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=network", cookies: []*http.Cookie{sc}}).Body.String()
	for _, want := range []string{
		`id="domains"`, `id="ports"`, `data-tuc-modal="#domain-new"`, `data-tuc-modal="#port-new"`,
		`id="domain-wildcard" name="wildcard" value="1"`, `data-domain-preview`,
		`class="tuc-btn-group is-segmented port-access flex w-full"`,
		`data-shown-when="access=ips"`, `data-shown-when="access=any"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("network tab lacks %s", want)
		}
	}

	rec := e.do(req{method: "POST", target: "/p/lab/s/web/domains", form: url.Values{"csrf": {csrf}, "hostname": {"Lojas.Exemplo.com.br"}, "wildcard": {"1"}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/p/lab/s/web?tab=network&ok=domain") {
		t.Fatalf("add wildcard: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=network", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, "*.lojas.exemplo.com.br") {
		t.Error("the wildcard is stored with *. in front")
	}
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/domains", form: url.Values{"csrf": {csrf}, "hostname": {"com.br"}, "wildcard": {"1"}}, cookies: []*http.Cookie{sc}})
	if rec.Code == http.StatusSeeOther {
		t.Error("a wildcard over a public suffix must be refused")
	}

	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, `data-tuc-modal="#volume-new"`) || !strings.Contains(page, `id="volume-new"`) {
		t.Error("disks are added in a modal")
	}
}

// The canvas opens a service by asking only for its drawer: the answer has
// the drawer and its opener, not the canvas, the menu or the dialogs, and
// is a fraction of the full page.
func TestCanvasGetsOnlyTheDrawer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateService(ctx, a, "lab", projects.ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80}); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	c, _ := e.session(t, auth.RoleAdmin)
	full := e.do(req{method: "GET", target: "/p/lab/s/web", cookies: []*http.Cookie{c}}).Body.String()
	rec := e.do(req{method: "GET", target: "/p/lab/s/web", cookies: []*http.Cookie{c}, header: map[string]string{"X-Hangar-Fragment": "panel"}})
	frag := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(frag, `id="svc-panel"`) || !strings.Contains(frag, `id="svc-open"`) {
		t.Fatalf("fragment: %d", rec.Code)
	}
	for _, not := range []string{`id="canvas"`, `class="sidebar`, `id="new-service"`, "<html"} {
		if strings.Contains(frag, not) {
			t.Errorf("the drawer fragment must not carry %s", not)
		}
	}
	t.Logf("drawer only: %d KB; full page: %d KB", len(frag)/1024, len(full)/1024)
	if len(frag)*3 > len(full) {
		t.Errorf("fragment %d bytes vs full page %d: should be much smaller", len(frag), len(full))
	}
}
