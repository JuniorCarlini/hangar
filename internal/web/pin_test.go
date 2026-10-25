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

// Pinning moves a project to the top of the person's sidebar and back.
func TestPinnedProjectsComeFirst(t *testing.T) {
	e := newEnv(t)
	e.labService(t) // "Laboratório"
	if _, err := e.pm.CreateProject(context.Background(), projects.Actor{UserID: "usr_x"}, "zeta", "Zeta"); err != nil {
		t.Fatal(err)
	}
	c, p := e.session(t, auth.RoleViewer)
	order := func() (int, int) {
		page := e.do(req{method: "GET", target: "/p/lab", cookies: []*http.Cookie{c}}).Body.String()
		return strings.Index(page, `href="/p/lab"`), strings.Index(page, `href="/p/zeta"`)
	}
	pin := func(on string) int {
		form := url.Values{"csrf": {p.CSRFToken}, "on": {on}, "next": {"/p/lab"}}
		return e.do(req{method: "POST", target: "/p/zeta/pin", form: form, cookies: []*http.Cookie{c}}).Code
	}
	if lab, zeta := order(); lab < 0 || zeta < lab {
		t.Fatalf("before pinning: lab at %d, zeta at %d", lab, zeta)
	}
	if code := pin("1"); code != http.StatusSeeOther {
		t.Fatalf("pin: %d", code)
	}
	if lab, zeta := order(); zeta > lab {
		t.Errorf("pinned zeta is not first: lab at %d, zeta at %d", lab, zeta)
	}
	if code := pin("0"); code != http.StatusSeeOther {
		t.Fatalf("unpin: %d", code)
	}
	if lab, zeta := order(); zeta < lab {
		t.Error("unpinned zeta is still first")
	}
}
