package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

func TestTemplateLogo(t *testing.T) {
	e := newEnv(t)
	if res := e.do(req{method: "GET", target: "/templates/postgres/logo.svg"}); res.Code == http.StatusOK {
		t.Error("the logo is a panel page: it needs a session")
	}
	c, _ := e.session(t, auth.RoleViewer)
	tp, _ := templates.Builtin().Get("postgres")

	res := e.do(req{method: "GET", target: tp.LogoURL(), cookies: []*http.Cookie{c}})
	h := res.Header()
	if res.Code != http.StatusOK || !strings.HasPrefix(res.Body.String(), "<svg") {
		t.Fatalf("logo: %d %q", res.Code, res.Body.String())
	}
	for k, want := range map[string]string{
		"Content-Type":            "image/svg+xml",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
		"ETag":                    tp.LogoETag(),
		"Cache-Control":           "private, max-age=31536000, immutable",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(tp.LogoETag(), "postgres-v1-") {
		t.Errorf("the ETag carries the template version: %s", tp.LogoETag())
	}

	res = e.do(req{method: "GET", target: "/templates/postgres/logo.svg", cookies: []*http.Cookie{c}, header: map[string]string{"If-None-Match": tp.LogoETag()}})
	if res.Code != http.StatusNotModified || res.Header().Get("Cache-Control") != "private, no-cache" {
		t.Errorf("revalidation: %d %q", res.Code, res.Header().Get("Cache-Control"))
	}
	if res := e.do(req{method: "GET", target: "/templates/nope/logo.svg", cookies: []*http.Cookie{c}}); res.Code != http.StatusNotFound {
		t.Errorf("unknown template: %d", res.Code)
	}
}
