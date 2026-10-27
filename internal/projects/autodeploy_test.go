package projects

import (
	"context"
	"testing"
)

// With the switch on, a new commit on the branch is deployed at the next
// look; a look with nothing new deploys nothing, and turning it on never
// deploys what was already there.
func TestAutoDeployPollsTheBranch(t *testing.T) {
	g := newGitFixture(t)
	id := g.create(t, GitServiceInput{})
	ctx := context.Background()
	if err := g.m.SetAutoDeploy(ctx, g.who, id, true); err != nil {
		t.Fatal(err)
	}
	builds := g.b.buildCount()
	g.m.autoDeployOnce(ctx)
	g.m.Wait()
	if g.b.buildCount() != builds {
		t.Fatal("deployed with nothing new on the branch")
	}

	commitFiles(t, g.repoDir, "main", map[string]string{"README.md": "v2\n"}, "segunda versão")
	g.m.autoDeployOnce(ctx)
	g.m.Wait()
	deps, _ := g.m.Deployments(ctx, id, 5)
	if deps[0].Trigger != "auto" || deps[0].CommitMessage != "segunda versão" {
		t.Fatalf("the push was not deployed: %+v", deps[0])
	}
	builds = g.b.buildCount()
	g.m.autoDeployOnce(ctx)
	g.m.Wait()
	if g.b.buildCount() != builds {
		t.Error("the same commit was deployed twice")
	}

	if err := g.m.SetAutoDeploy(ctx, g.who, id, false); err != nil {
		t.Fatal(err)
	}
	commitFiles(t, g.repoDir, "main", map[string]string{"README.md": "v3\n"}, "terceira versão")
	g.m.autoDeployOnce(ctx)
	g.m.Wait()
	if g.b.buildCount() != builds {
		t.Error("deployed with the switch off")
	}
}
