package projects

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

func errKey(err error) string {
	var ie *i18n.Error
	if errors.As(err, &ie) {
		return ie.Key
	}
	return ""
}

func TestGitCredentialIsSharedBetweenServices(t *testing.T) {
	g := newGitFixture(t)
	ctx := context.Background()
	const token = "github_pat_11AAAAAAA0secret0token0one"
	c, err := g.m.CreateGitCredential(ctx, g.who, GitCredentialInput{Name: "GitHub", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "github.com" || c.Hint != "0one" || !c.Server() {
		t.Fatalf("credential: %+v", c)
	}
	if _, err := g.m.CreateGitCredential(ctx, g.who, GitCredentialInput{Name: "github", Token: token}); errKey(err) != "gitcred.error.name_taken" {
		t.Errorf("same name twice: %v", err)
	}

	// The token is in the build log only masked, and both services use it.
	g.b.echo = []string{"cloning with " + token}
	web := g.create(t, GitServiceInput{CredentialID: c.ID})
	g.create(t, GitServiceInput{ServiceInput: ServiceInput{Slug: "worker"}, CredentialID: c.ID})
	src, _, _ := g.m.GetGitSource(ctx, web)
	if src.CredentialID != c.ID || src.CredentialName != "GitHub" || src.HasToken {
		t.Fatalf("source: %+v", src)
	}
	deps, _ := g.m.Deployments(ctx, web, 1)
	if strings.Contains(deps[0].Log, token) {
		t.Errorf("token leaked into the build log:\n%s", deps[0].Log)
	}
	list, _ := g.m.ListGitCredentials(ctx)
	if len(list) != 1 || list[0].Uses != 2 || list[0].LastUsed.IsZero() {
		t.Fatalf("list: %+v", list)
	}

	// Replacing the token keeps the services on the credential.
	if err := g.m.ReplaceGitCredentialToken(ctx, g.who, c.ID, "github_pat_22BBBBBBB0secret0token0two"); err != nil {
		t.Fatal(err)
	}
	tok, err := g.m.credentialToken(ctx, "prj_any", g.repo, c.ID) // server-wide: any project
	if err != nil || tok != "github_pat_22BBBBBBB0secret0token0two" {
		t.Errorf("token after replace: %q", tok)
	}

	// In use: refused, naming the services.
	err = g.m.DeleteGitCredential(ctx, g.who, c.ID)
	if errKey(err) != "gitcred.error.in_use" {
		t.Fatalf("delete in use: %v", err)
	}
	if err := g.m.SetGitCredential(ctx, g.who, web, ""); err != nil {
		t.Fatal(err)
	}
	if src, _, _ := g.m.GetGitSource(ctx, web); src.CredentialID != "" {
		t.Errorf("service still on the credential: %+v", src)
	}
}

func TestGitCredentialScopeAndHost(t *testing.T) {
	g := newGitFixture(t)
	ctx := context.Background()
	if _, err := g.m.CreateProject(ctx, g.who, "outro", ""); err != nil {
		t.Fatal(err)
	}
	mine, err := g.m.CreateGitCredential(ctx, g.who, GitCredentialInput{ProjectSlug: "outro", Name: "Só do outro", Token: "github_pat_33CCCCCCCC0x"})
	if err != nil {
		t.Fatal(err)
	}
	// Another project cannot use it.
	if _, err := g.m.CreateGitService(ctx, g.who, "lab", GitServiceInput{
		ServiceInput: ServiceInput{Slug: "web"}, GitSourceInput: GitSourceInput{URL: g.repo}, CredentialID: mine.ID,
	}); errKey(err) != "gitcred.error.gone" {
		t.Errorf("other project's credential: %v", err)
	}
	// A GitHub token is never sent to another host.
	if _, err := g.m.CreateGitService(ctx, g.who, "outro", GitServiceInput{
		ServiceInput: ServiceInput{Slug: "web"}, GitSourceInput: GitSourceInput{URL: "https://gitlab.com/dono/repo"}, CredentialID: mine.ID,
	}); errKey(err) != "gitcred.error.host_mismatch" {
		t.Errorf("host mismatch: %v", err)
	}
	for _, bad := range []GitCredentialInput{{Name: "", Token: "x123456789"}, {Name: "a", Host: "http://x", Token: "x123456789"}, {Name: "a", Token: ""}} {
		if _, err := g.m.CreateGitCredential(ctx, g.who, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// Not in use: it goes.
	if err := g.m.DeleteGitCredential(ctx, g.who, mine.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := g.m.ListGitCredentials(ctx); len(list) != 0 {
		t.Errorf("left: %+v", list)
	}
}
