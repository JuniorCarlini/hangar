package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

func TestBrandSavesAndRendersPages(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	form := url.Values{"csrf": {p.CSRFToken}, "name": {"Minha Agência"}, "contact": {"suporte@agencia.com"}, "color": {"#112233"}}
	if rec := e.do(req{method: "POST", target: "/brand", form: form, cookies: []*http.Cookie{c}}); rec.Code != http.StatusForbidden {
		t.Fatalf("saving the brand without sudo: %d", rec.Code)
	}

	e = newEnv(t)
	c, csrf := e.sudoSession(t, auth.RoleAdmin)
	form.Set("csrf", csrf)
	if rec := e.do(req{method: "POST", target: "/brand", form: form, cookies: []*http.Cookie{c}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	down := string(e.pages["down.html"])
	for _, want := range []string{"Minha Agência", "mailto:suporte@agencia.com", "--accent:#112233"} {
		if !strings.Contains(down, want) {
			t.Errorf("rendered down page lacks %q", want)
		}
	}
	if len(e.pages) != 6 {
		t.Errorf("pages written: %d", len(e.pages))
	}

	page := url.Values{"csrf": {csrf}, "title": {"Volto já"}, "html": {""}}
	if rec := e.do(req{method: "POST", target: "/brand/pages/down", form: page, cookies: []*http.Cookie{c}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("page save: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(string(e.pages["down.html"]), "<h1>Volto já</h1>") {
		t.Error("page title not applied")
	}

	rec := e.do(req{method: "GET", target: "/brand/preview/down", cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Volto já") {
		t.Fatalf("preview: %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") || strings.Contains(csp, "script-src") {
		t.Errorf("preview must run sandboxed without scripts: %q", csp)
	}
	if rec := e.do(req{method: "GET", target: "/brand", cookies: []*http.Cookie{c}}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Minha Agência") {
		t.Errorf("settings page: %d", rec.Code)
	}
}

func TestBrandRefusesBadInput(t *testing.T) {
	e := newEnv(t)
	c, csrf := e.sudoSession(t, auth.RoleAdmin)
	rec := e.do(req{method: "POST", target: "/brand", form: url.Values{"csrf": {csrf}, "color": {"vermelho"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad color: %d", rec.Code)
	}
	if e.pages != nil {
		t.Error("pages written for a refused brand")
	}
}
