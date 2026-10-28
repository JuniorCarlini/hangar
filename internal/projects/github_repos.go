package projects

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// The new-service dialog lists the repositories a saved GitHub credential
// can read. Answers are cached for a few minutes per credential: opening
// the dialog again does not spend the token's API quota (5000 calls an
// hour), and replacing the token drops the cache (its UpdatedAt changes).

const reposTTL = 5 * time.Minute

type cachedRepos struct {
	at      time.Time
	updated int64
	repos   []gitsrc.GitHubRepo
}

// githubToken opens a credential the project may use, made for GitHub.
func (m *Manager) githubToken(ctx context.Context, projectSlug, credID string) (string, int64, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return "", 0, err
	}
	c, err := m.usableCredential(ctx, p.ID, "https://"+gitsrc.GitHubHost+"/", credID)
	if err != nil {
		return "", 0, err
	}
	b, err := m.box.Open(c.TokenEnc, credAD(c.ID))
	if err != nil {
		return "", 0, err
	}
	return string(b), c.UpdatedAt, nil
}

// GitHubRepos lists what the credential can read, most recently pushed
// first. fresh skips the cache: the token stays the same when its access is
// widened on GitHub, so only the person knows the list changed (the dialog's
// refresh button).
func (m *Manager) GitHubRepos(ctx context.Context, projectSlug, credID string, fresh bool) ([]gitsrc.GitHubRepo, error) {
	token, updated, err := m.githubToken(ctx, projectSlug, credID)
	if err != nil {
		return nil, err
	}
	m.reposMu.Lock()
	c, ok := m.repos[credID]
	m.reposMu.Unlock()
	if !fresh && ok && c.updated == updated && m.now().Sub(c.at) < reposTTL {
		return c.repos, nil
	}
	repos, err := gitsrc.GitHubRepos(ctx, token)
	if err != nil {
		return nil, githubError(err)
	}
	m.reposMu.Lock()
	if m.repos == nil {
		m.repos = map[string]cachedRepos{}
	}
	m.repos[credID] = cachedRepos{at: m.now(), updated: updated, repos: repos}
	m.reposMu.Unlock()
	return repos, nil
}

// GitHubBranches lists a repository's branches, read with the credential.
func (m *Manager) GitHubBranches(ctx context.Context, projectSlug, credID, fullName string) ([]string, error) {
	token, _, err := m.githubToken(ctx, projectSlug, credID)
	if err != nil {
		return nil, err
	}
	b, err := gitsrc.GitHubBranches(ctx, token, strings.TrimSpace(fullName))
	if err != nil {
		return nil, githubError(err)
	}
	return b, nil
}

func githubError(err error) error {
	switch {
	case errors.Is(err, gitsrc.ErrGitHubToken):
		return i18n.E("github.error.token")
	case errors.Is(err, gitsrc.ErrAccess), errors.Is(err, gitsrc.ErrPath):
		return gitsrc.ErrAccess
	default:
		return i18n.E("github.error.unreachable")
	}
}
