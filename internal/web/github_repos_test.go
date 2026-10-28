package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// The repository list says when a token reads no private repository (the
// dialog then explains the missing permission), and refresh asks GitHub
// again instead of answering from the cache.
func TestGitHubReposPublicOnlyAndRefresh(t *testing.T) {
	var calls atomic.Int32
	private := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		repos := []map[string]any{{"full_name": "dono/site", "clone_url": "https://github.com/dono/site.git", "private": false}}
		if private.Load() {
			repos = append(repos, map[string]any{"full_name": "dono/lobot", "clone_url": "https://github.com/dono/lobot.git", "private": true})
		}
		_ = json.NewEncoder(w).Encode(repos)
	}))
	defer srv.Close()
	old := gitsrc.GitHubAPI
	gitsrc.GitHubAPI = srv.URL
	defer func() { gitsrc.GitHubAPI = old }()

	e := newEnv(t)
	e.labService(t)
	c, _ := e.session(t, auth.RoleAdmin)
	cred, err := e.pm.CreateGitCredential(context.Background(), projects.Actor{UserID: "usr_x"}, projects.GitCredentialInput{Name: "Conta", Token: "github_pat_11AAAAAAAA0x"})
	if err != nil {
		t.Fatal(err)
	}
	get := func(query string) (repos []map[string]any, publicOnly bool) {
		t.Helper()
		rec := e.do(req{method: "GET", target: "/p/lab/github/repos?credential=" + cred.ID + query, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		var out struct {
			Repos      []map[string]any `json:"repos"`
			PublicOnly bool             `json:"public_only"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Repos, out.PublicOnly
	}

	if repos, publicOnly := get(""); len(repos) != 1 || !publicOnly {
		t.Fatalf("a token without private access: %d repos, public_only=%v", len(repos), publicOnly)
	}
	// The owner widens the token on GitHub: same token, so the cache still
	// answers until the list is refreshed.
	private.Store(true)
	if repos, _ := get(""); len(repos) != 1 {
		t.Errorf("the cache should answer the plain request: %d repos", len(repos))
	}
	if repos, publicOnly := get("&refresh=1"); len(repos) != 2 || publicOnly {
		t.Errorf("refresh: %d repos, public_only=%v", len(repos), publicOnly)
	}
}
