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

func TestVariablesTabSuggestsRepositoryVariables(t *testing.T) {
	e := newEnv(t)
	e.pm.SetBuildDir(t.TempDir())
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", ""); err != nil {
		t.Fatal(err)
	}
	repo := labRepoWith(t, map[string]string{
		"Dockerfile":   "FROM alpine\n",
		".env.example": "APP_NAME=<b>loja</b>\nSECRET_KEY=troque-isto\nDEBUG=1\n",
	})
	s, err := e.pm.CreateGitService(ctx, a, "lab", projects.GitServiceInput{
		ServiceInput: projects.ServiceInput{Slug: "web", Port: 8000}, GitSourceInput: projects.GitSourceInput{URL: repo},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.pm.SetEnv(ctx, a, s.ID, "DEBUG", "0", false); err != nil {
		t.Fatal(err)
	}

	c, p := e.session(t, auth.RoleOperator)
	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}}).Body.String()
	for _, want := range []string{`id="env-suggested"`, "Variáveis sugeridas", ".env.example", "APP_NAME", "SECRET_KEY", "data-env-suggest", "data-envsuggest", "&lt;b&gt;loja&lt;/b&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("variables tab lacks %q", want)
		}
	}
	if strings.Contains(page, "<b>loja</b>") || strings.Contains(page, "troque-isto") {
		t.Error("an example value was not escaped, or a secret's example was shown")
	}
	card := page[strings.Index(page, `id="env-suggested"`):]
	card = card[:strings.Index(card, "</section>")]
	if strings.Contains(card, ">DEBUG<") {
		t.Error("a variable the service already has is still suggested")
	}

	rec := e.do(req{method: "POST", target: "/p/lab/s/web/env/suggestions/dismiss", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("dismiss: %d %s", rec.Code, rec.Body)
	}
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(page, `id="env-suggested"`) || strings.Contains(page, "data-envsuggest") {
		t.Error("dismissed suggestions still on the page")
	}
}
