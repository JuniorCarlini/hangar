package gitsrc

import "context"

// GitHubAccount is the profile a token belongs to: who the panel found on
// GitHub when a credential was entered. The avatar is not used (the panel's
// CSP blocks external images); the GitHub mark plus the login is enough.
type GitHubAccount struct {
	Login   string `json:"login"`
	Name    string `json:"name"`
	Type    string `json:"type"` // "User" or "Organization"
	HTMLURL string `json:"html_url"`
}

// GitHubWhoami returns the account a token authenticates as (GET /user). It
// confirms the token works and names the profile the credential belongs to,
// so the "new credential" dialog can show "profile found" before saving.
func GitHubWhoami(ctx context.Context, token string) (GitHubAccount, error) {
	var a GitHubAccount
	if err := githubGet(ctx, token, "/user", &a); err != nil {
		return GitHubAccount{}, err
	}
	return a, nil
}
