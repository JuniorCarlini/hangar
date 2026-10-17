package projects

import (
	"context"
	"errors"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// CheckGitHubAccount validates a GitHub token the operator is typing into the
// "new credential" dialog and returns whose profile it is. It never stores
// anything: it only confirms the token works so the dialog can show "profile
// found" before the credential is saved.
func (m *Manager) CheckGitHubAccount(ctx context.Context, token string) (gitsrc.GitHubAccount, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return gitsrc.GitHubAccount{}, i18n.E("gitcred.error.token_empty")
	}
	acc, err := gitsrc.GitHubWhoami(ctx, token)
	switch {
	case errors.Is(err, gitsrc.ErrGitHubToken):
		return gitsrc.GitHubAccount{}, i18n.E("gitcred.error.token_invalid")
	case err != nil:
		return gitsrc.GitHubAccount{}, i18n.E("gitcred.error.github_unreachable")
	}
	return acc, nil
}
