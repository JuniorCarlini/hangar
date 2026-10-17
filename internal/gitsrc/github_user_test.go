package gitsrc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGitHubWhoami(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/user" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if auth != "Bearer good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"login": "JuniorCarlini", "name": "Junior Carlini", "type": "User",
			"html_url": "https://github.com/JuniorCarlini",
		})
	}))
	defer srv.Close()
	old, oldClient := GitHubAPI, githubClient
	GitHubAPI, githubClient = srv.URL, srv.Client()
	defer func() { GitHubAPI, githubClient = old, oldClient }()

	acc, err := GitHubWhoami(context.Background(), "good")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if auth != "Bearer good" {
		t.Fatalf("authorization header = %q", auth)
	}
	if acc.Login != "JuniorCarlini" || acc.Name != "Junior Carlini" || acc.Type != "User" {
		t.Fatalf("account = %+v", acc)
	}
	if _, err := GitHubWhoami(context.Background(), "bad"); !errors.Is(err, ErrGitHubToken) {
		t.Fatalf("bad token: want ErrGitHubToken, got %v", err)
	}
}
