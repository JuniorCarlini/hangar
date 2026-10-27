package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

func init() { gitsrc.AllowLocalForTesting() }

// The web fake node can build too.
func (f *fakeNode) Build(_ context.Context, _ node.BuildSpec, log func(string)) (string, error) {
	log("#1 building")
	return "sha256:built", nil
}

func (f *fakeNode) PruneBuilds(context.Context, string, []string) error { return nil }

// labRepo creates a repository with a Dockerfile on main.
func labRepo(t *testing.T) string {
	t.Helper()
	return labRepoWith(t, map[string]string{"Dockerfile": "FROM alpine\n"})
}

// labRepoWith creates a repository with these files (at the root) on main.
func labRepoWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo")
	repo, err := git.PlainInitWithOptions(dir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName("main")},
	})
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if _, err := wt.Add(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := wt.Commit("app", &git.CommitOptions{Author: &object.Signature{Name: "Lab", Email: "lab@hangar.dev", When: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	return "file://" + dir
}

func (e *env) gitService(t *testing.T, token string) (string, string) {
	t.Helper()
	e.pm.SetBuildDir(t.TempDir())
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", "Laboratório"); err != nil {
		t.Fatal(err)
	}
	repo := labRepo(t)
	s, err := e.pm.CreateGitService(ctx, a, "lab", projects.GitServiceInput{
		ServiceInput: projects.ServiceInput{Slug: "web", Port: 8000}, GitSourceInput: projects.GitSourceInput{URL: repo}, Token: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	return s.ID, repo
}

func TestNewServiceHasGitTab(t *testing.T) {
	e := newEnv(t)
	e.pm.SetBuildDir(t.TempDir())
	if _, err := e.pm.CreateProject(context.Background(), projects.Actor{}, "lab", ""); err != nil {
		t.Fatal(err)
	}
	c, p := e.session(t, auth.RoleAdmin)
	page := e.do(req{method: "GET", target: "/p/lab/new", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, "Meus repositórios") || !strings.Contains(page, `action="/p/lab/services/git"`) {
		t.Fatal("the Git tab is missing from the new service dialog")
	}
	// A refused URL keeps the form (on the Git tab), never the token.
	rec := e.do(req{method: "POST", target: "/p/lab/services/git", cookies: []*http.Cookie{c}, form: url.Values{
		"csrf": {p.CSRFToken}, "slug": {"web"}, "repo": {"http://github.com/dono/app"}, "token": {"ghp_naoEcoar123456"},
	}})
	body := rec.Body.String()
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(body, "HTTPS") {
		t.Fatalf("plain http URL: %d", rec.Code)
	}
	if strings.Contains(body, "ghp_naoEcoar123456") {
		t.Fatal("the token was echoed back into the page")
	}
	if !strings.Contains(body, "http://github.com/dono/app") {
		t.Error("the form lost the typed URL")
	}

	repo := labRepo(t)
	rec = e.do(req{method: "POST", target: "/p/lab/services/git", cookies: []*http.Cookie{c}, form: url.Values{
		"csrf": {p.CSRFToken}, "slug": {"api"}, "repo": {repo}, "branch": {"main"}, "port": {"8000"},
	}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/p/lab/s/api" {
		t.Fatalf("create from Git: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	page = e.do(req{method: "GET", target: "/p/lab/s/api", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, "@main") {
		t.Error("the panel should show repository@branch")
	}
}

func TestGitTokenNeverInHTMLUntilSudo(t *testing.T) {
	e := newEnv(t)
	const token = "ghp_tokenSecretoDeLeitura42"
	e.gitService(t, token)
	c, p := e.session(t, auth.RoleAdmin)
	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(page, token) {
		t.Fatal("token in the HTML")
	}
	if !strings.Contains(page, `id="git-source"`) || !strings.Contains(page, `id="git-auto"`) {
		t.Fatal("repository cards missing from the settings tab")
	}
	rec := e.do(req{method: "POST", target: "/p/lab/s/web/git/token/reveal", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), token) {
		t.Fatalf("reveal without sudo: %d", rec.Code)
	}
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/git/webhook", form: url.Values{"csrf": {p.CSRFToken}, "action": {"rotate"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("webhook without sudo: %d", rec.Code)
	}

	e.now = e.now.Add(30 * time.Second)
	rec = e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/p/lab/s/web"}}, cookies: []*http.Cookie{c}})
	sc := cookie(rec, sessionCookie)
	sp, _ := e.svc.Authenticate(context.Background(), sc.Value)
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/git/token/reveal", form: url.Values{"csrf": {sp.CSRFToken}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), token) {
		t.Fatalf("reveal with sudo: %d", rec.Code)
	}
	rec = e.do(req{method: "POST", target: "/p/lab/s/web/git/webhook", form: url.Values{"csrf": {sp.CSRFToken}, "action": {"rotate"}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/hooks/git/") {
		t.Fatalf("webhook with sudo: %d", rec.Code)
	}
}

func signedPush(secret, ref, repo string, at time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"ref": ref, "after": strings.Repeat("b", 40),
		"repository": map[string]any{"pushed_at": at.Unix(), "clone_url": repo},
	})
	return b
}

func TestWebhookEndpoint(t *testing.T) {
	e := newEnv(t)
	id, repo := e.gitService(t, "")
	ctx := context.Background()
	hook, err := e.pm.RotateWebhook(ctx, projects.Actor{}, id)
	if err != nil {
		t.Fatal(err)
	}
	post := func(token, delivery string, body []byte, sig, ctype string) *httptest.ResponseRecorder {
		hr := httptest.NewRequest(http.MethodPost, "/hooks/git/"+token, strings.NewReader(string(body)))
		hr.Host = testHost
		hr.RemoteAddr = "140.82.115.10:443"
		hr.Header.Set("Content-Type", ctype)
		hr.Header.Set("X-GitHub-Event", "push")
		hr.Header.Set("X-GitHub-Delivery", delivery)
		if sig != "" {
			hr.Header.Set("X-Hub-Signature-256", sig)
		}
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, hr)
		return rec
	}
	body := signedPush(hook.Secret, "refs/heads/main", repo, time.Now())
	sig := gitsrc.Sign([]byte(hook.Secret), body)
	const js = "application/json"

	if rec := post(hook.Token, "w-0001-aaaa", body, gitsrc.Sign([]byte("errado"), body), js); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong signature: %d", rec.Code)
	}
	if rec := post(strings.Repeat("z", 43), "w-0002-aaaa", body, sig, js); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown token: %d", rec.Code)
	}
	if rec := post(hook.Token, "w-0003-aaaa", body, sig, js); rec.Code != http.StatusAccepted {
		t.Fatalf("valid push: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	if rec := post(hook.Token, "w-0003-aaaa", body, sig, js); rec.Code != http.StatusConflict {
		t.Fatalf("replay: %d", rec.Code)
	}
	other := signedPush(hook.Secret, "refs/heads/dev", repo, time.Now())
	if rec := post(hook.Token, "w-0004-aaaa", other, gitsrc.Sign([]byte(hook.Secret), other), js); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "branch") {
		t.Fatalf("other branch: %d %s", rec.Code, rec.Body)
	}
	// GitHub's default content type: the JSON in a form field.
	form := []byte("payload=" + url.QueryEscape(string(body)))
	if rec := post(hook.Token, "w-0005-aaaa", form, gitsrc.Sign([]byte(hook.Secret), form), "application/x-www-form-urlencoded"); rec.Code != http.StatusAccepted {
		t.Fatalf("form-encoded push: %d %s", rec.Code, rec.Body)
	}
	e.pm.Wait()
	deps, _ := e.pm.Deployments(ctx, id, 10)
	n := 0
	for _, d := range deps {
		if d.Trigger == "webhook" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("webhook deploys: %d, want 2", n)
	}
}

// The repository card edits the owner and the name; the address is
// joined back from them, on the host the service already uses.
func TestRepoFromFormParts(t *testing.T) {
	for _, c := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"repo": {"https://github.com/a/b.git"}}, "https://github.com/a/b.git"},
		{url.Values{"host": {"github.com"}, "owner": {" JuniorCarlini "}, "name": {"lab.git"}}, "https://github.com/JuniorCarlini/lab.git"},
		{url.Values{"host": {"gitlab.com"}, "owner": {"grupo/sub"}, "name": {"app"}}, "https://gitlab.com/grupo/sub/app.git"},
		{url.Values{"host": {"github.com"}, "owner": {""}, "name": {"app"}}, ""},
	} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(c.form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if got := repoFromForm(r); got != c.want {
			t.Errorf("%v: %q, want %q", c.form, got, c.want)
		}
	}
}
