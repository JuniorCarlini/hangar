package gitsrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGitHubRepos(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/user/repos":
			if r.URL.Query().Get("page") == "1" {
				page := make([]map[string]any, 0, githubPerPage)
				for i := range githubPerPage {
					page = append(page, map[string]any{"full_name": fmt.Sprintf("o/r%d", i), "clone_url": fmt.Sprintf("https://github.com/o/r%d.git", i), "archived": i == 0})
				}
				_ = json.NewEncoder(w).Encode(page)
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{"full_name": "o/last", "clone_url": "https://github.com/o/last.git", "private": true}})
		case "/repos/o/last/branches":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"name": "main"}, {"name": "dev"}})
		case "/repos/o/gone/branches":
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	// A plain client for the local server: the package-wide switch that
	// lifts the address filter would leak into the other tests.
	old, oldClient := GitHubAPI, githubClient
	GitHubAPI, githubClient = srv.URL, srv.Client()
	defer func() { GitHubAPI, githubClient = old, oldClient }()

	repos, err := GitHubRepos(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer tok" {
		t.Fatalf("authorization header = %q", auth)
	}
	// Two pages read, the archived repository left out.
	if len(repos) != githubPerPage || repos[0].FullName != "o/r1" || !repos[len(repos)-1].Private {
		t.Fatalf("got %d repos, first %q", len(repos), repos[0].FullName)
	}
	br, err := GitHubBranches(context.Background(), "tok", "o/last")
	if err != nil || len(br) != 2 || br[0] != "main" {
		t.Fatalf("branches = %v, %v", br, err)
	}
	if _, err := GitHubBranches(context.Background(), "tok", "o/gone"); !errors.Is(err, ErrAccess) {
		t.Fatalf("missing repo: %v", err)
	}
	for _, bad := range []string{"o", "o/../x", "../o/r", "o/r?x=1", "o/r/branches", "o/.."} {
		if _, err := GitHubBranches(context.Background(), "tok", bad); !errors.Is(err, ErrPath) {
			t.Errorf("%q accepted", bad)
		}
	}
	GitHubAPI = srv.URL + "/nothing"
	if _, err := GitHubRepos(context.Background(), "bad"); !errors.Is(err, ErrGitHubToken) {
		t.Fatalf("refused token: %v", err)
	}
}
