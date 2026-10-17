package web

import (
	"encoding/json"
	"net/http"
	"time"
)

// The new-service dialog asks for the repositories (and then the branches)
// a saved GitHub credential can read. JSON, never the token.

type githubRepoJSON struct {
	FullName      string `json:"full_name"`
	Description   string `json:"description"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	URL           string `json:"url"`
	Language      string `json:"language"`
	PushedAt      string `json:"pushed_at"`
}

func (h *handlers) githubRepos(w http.ResponseWriter, r *http.Request) {
	repos, err := h.projects.GitHubRepos(r.Context(), r.PathValue("project"), r.URL.Query().Get("credential"))
	if err != nil {
		jsonError(w, r, err)
		return
	}
	out := make([]githubRepoJSON, 0, len(repos))
	for _, g := range repos {
		pushed := ""
		if !g.PushedAt.IsZero() {
			pushed = g.PushedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, githubRepoJSON{
			FullName: g.FullName, Description: g.Description, Private: g.Private,
			DefaultBranch: g.DefaultBranch, URL: g.CloneURL, Language: g.Language, PushedAt: pushed,
		})
	}
	writeJSON(w, r, map[string]any{"repos": out})
}

func (h *handlers) githubBranches(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	b, err := h.projects.GitHubBranches(r.Context(), r.PathValue("project"), q.Get("credential"), q.Get("repo"))
	if err != nil {
		jsonError(w, r, err)
		return
	}
	writeJSON(w, r, map[string]any{"branches": b})
}

func writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		loggerFrom(r.Context()).Error("json", "route", r.URL.Path, "error", err)
	}
}

func jsonError(w http.ResponseWriter, r *http.Request, err error) {
	code, msg := userError(r, err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
