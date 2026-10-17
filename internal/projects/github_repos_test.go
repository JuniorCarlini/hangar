package projects

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
)

func TestGitHubReposScopeAndCache(t *testing.T) {
	g := newGitFixture(t)
	ctx := context.Background()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer github_pat_revoked000" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"full_name": "dono/loja", "clone_url": "https://github.com/dono/loja.git", "default_branch": "main"}})
	}))
	defer srv.Close()
	old := gitsrc.GitHubAPI
	gitsrc.GitHubAPI = srv.URL
	defer func() { gitsrc.GitHubAPI = old }()

	if _, err := g.m.CreateProject(ctx, g.who, "outro", ""); err != nil {
		t.Fatal(err)
	}
	other, err := g.m.CreateGitCredential(ctx, g.who, GitCredentialInput{ProjectSlug: "outro", Name: "Do outro", Token: "github_pat_33CCCCCCCC0x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.m.GitHubRepos(ctx, "lab", other.ID); errKey(err) != "gitcred.error.gone" {
		t.Errorf("other project's credential listed: %v", err)
	}
	gl, err := g.m.CreateGitCredential(ctx, g.who, GitCredentialInput{Name: "GitLab", Host: "gitlab.com", Token: "glpat-xxxxxxxxxxxx"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.m.GitHubRepos(ctx, "lab", gl.ID); errKey(err) != "gitcred.error.host_mismatch" {
		t.Errorf("a GitLab token was sent to GitHub: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("GitHub called %d times for refused credentials", calls.Load())
	}

	srvCred, err := g.m.CreateGitCredential(ctx, g.who, GitCredentialInput{Name: "Conta", Token: "github_pat_44DDDDDDDD0x"})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		repos, err := g.m.GitHubRepos(ctx, "lab", srvCred.ID)
		if err != nil || len(repos) != 1 || repos[0].FullName != "dono/loja" {
			t.Fatalf("repos = %+v, %v", repos, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("cache: GitHub called %d times", calls.Load())
	}
	// A new token drops the cache, and a refused one says so.
	g.m.now = func() time.Time { return time.Now().Add(time.Second) }
	if err := g.m.ReplaceGitCredentialToken(ctx, g.who, srvCred.ID, "github_pat_revoked000"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.m.GitHubRepos(ctx, "lab", srvCred.ID); errKey(err) != "github.error.token" {
		t.Errorf("revoked token: %v", err)
	}
}
