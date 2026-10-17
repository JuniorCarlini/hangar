package gitsrc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Listing what a GitHub token can read, so the new-service dialog offers a
// list instead of a URL to type. A fine-grained token restricted to one
// repository lists only that one: GitHub itself decides what is visible.
// Calls go through the same client as clones (public addresses only, no
// proxies) and every answer is size-capped.

// GitHubAPI is the API root. Tests point it at a local server.
var GitHubAPI = "https://api.github.com"

// GitHubHost is the only host whose tokens can list repositories (v1).
const GitHubHost = "github.com"

const (
	githubPerPage  = 100
	githubMaxPages = 10 // 1000 repositories, most recently pushed first
	githubMaxBody  = 4 << 20
)

// ErrGitHubToken means GitHub refused the token (revoked, expired or
// without access to any repository).
var ErrGitHubToken = errors.New("github refused the token")

// GitHubRepo is one repository a token can read.
type GitHubRepo struct {
	FullName      string    `json:"full_name"`
	Description   string    `json:"description"`
	Private       bool      `json:"private"`
	DefaultBranch string    `json:"default_branch"`
	CloneURL      string    `json:"clone_url"`
	Language      string    `json:"language"`
	PushedAt      time.Time `json:"pushed_at"`
	Archived      bool      `json:"archived"`
}

// GitHubRepos lists the repositories the token can read, most recently
// pushed first; archived ones are left out (nothing deploys from them).
func GitHubRepos(ctx context.Context, token string) ([]GitHubRepo, error) {
	var out []GitHubRepo
	for page := 1; page <= githubMaxPages; page++ {
		q := url.Values{
			"per_page": {fmt.Sprint(githubPerPage)}, "page": {fmt.Sprint(page)},
			"sort": {"pushed"}, "affiliation": {"owner,collaborator,organization_member"},
		}
		var batch []GitHubRepo
		if err := githubGet(ctx, token, "/user/repos?"+q.Encode(), &batch); err != nil {
			return nil, err
		}
		for _, r := range batch {
			if r.Archived || !strings.HasPrefix(r.CloneURL, "https://") {
				continue
			}
			out = append(out, r)
		}
		if len(batch) < githubPerPage {
			break
		}
	}
	return out, nil
}

// GitHubBranches lists a repository's branches (up to 100), names only.
func GitHubBranches(ctx context.Context, token, fullName string) ([]string, error) {
	if !validFullName(fullName) {
		return nil, ErrPath
	}
	var batch []struct {
		Name string `json:"name"`
	}
	if err := githubGet(ctx, token, "/repos/"+fullName+"/branches?per_page=100", &batch); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(batch))
	for _, b := range batch {
		names = append(names, b.Name)
	}
	return names, nil
}

// validFullName accepts "owner/repo" with GitHub's characters only, so the
// value can never change the request path.
func validFullName(s string) bool {
	owner, repo, ok := strings.Cut(s, "/")
	if !ok || owner == "" || repo == "" || len(s) > 200 || repo == "." || repo == ".." {
		return false
	}
	return !strings.ContainsFunc(owner+repo, func(c rune) bool {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		return !alnum && c != '-' && c != '_' && c != '.'
	})
}

var githubClient = func() *http.Client {
	c := safeHTTPClient()
	c.Timeout = 20 * time.Second
	return c
}()

func githubGet(ctx context.Context, token, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubAPI+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "hangar")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := githubClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrGitHubToken
	case resp.StatusCode == http.StatusNotFound:
		return ErrAccess
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("github: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, githubMaxBody+1))
	if err != nil {
		return err
	}
	if len(body) > githubMaxBody {
		return errors.New("github: answer too large")
	}
	return json.Unmarshal(body, into)
}
