//go:build integration

package docker

import (
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestRollingDeployKeepsOldUntilNewIsHealthy(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgr")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "web")
	t.Cleanup(func() { _ = l.Remove(ctx, project, "web"+nextSuffix) })

	web := spec(project, "web", "nginx:1.29-alpine")
	web.MemoryBytes = 128 << 20
	opt := node.DeployOptions{Strategy: node.StrategyRolling, Port: 80, HealthPath: "/", HealthTimeout: 20 * time.Second}
	first, err := l.Deploy(ctx, web, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first.ImageRef, "@sha256:") {
		t.Errorf("a pulled image must be pinned by digest: %q", first.ImageRef)
	}

	// A version that never becomes healthy: the old one must stay, untouched.
	broken := web
	broken.Deployment = "dep_broken"
	broken.Command = []string{"sh", "-c", "sleep 3600"}
	var log strings.Builder
	bopt := opt
	bopt.HealthTimeout = 5 * time.Second
	bopt.Progress = func(phase, line string) { log.WriteString(phase + " " + line + "\n") }
	if _, err := l.Deploy(ctx, broken, bopt); err == nil || !strings.Contains(err.Error(), "still live") {
		t.Fatalf("broken deploy: %v", err)
	}
	st, _ := l.Status(ctx, project, "web")
	if !st.Running || st.Deployment != "dep_1" {
		t.Errorf("the old version must keep serving: %+v", st)
	}
	if _, err := l.inspectManaged(ctx, node.ContainerName(project, "web")+nextSuffix); err == nil {
		t.Error("the failed new container must be removed")
	}
	if !strings.Contains(log.String(), "health") {
		t.Errorf("progress: %s", log.String())
	}

	// A good version replaces it and takes the service name.
	good := web
	good.Deployment = "dep_2"
	second, err := l.Deploy(ctx, good, opt)
	if err != nil {
		t.Fatal(err)
	}
	st, _ = l.Status(ctx, project, "web")
	if !st.Running || st.Deployment != "dep_2" || second.ContainerID == first.ContainerID {
		t.Errorf("after the switch: %+v", st)
	}
	// Rolling back to the pinned image works without the tag.
	back := web
	back.Deployment = "dep_3"
	back.Image = first.ImageRef
	if _, err := l.Deploy(ctx, back, opt); err != nil {
		t.Fatalf("deploy by digest: %v", err)
	}
}

func TestPreDeployRunsOnceAndAbortsOnFailure(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgp")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "app")
	app := spec(project, "app", "busybox:1.37", "sh", "-c", "sleep 3600")
	opt := node.DeployOptions{Strategy: node.StrategyRolling, HealthTimeout: 20 * time.Second}
	if _, err := l.Deploy(ctx, app, opt); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	opt.Progress = func(phase, line string) { log.WriteString(line + "\n") }
	opt.PreDeploy = []string{"sh", "-c", "echo migrating $HANGAR_TESTE; exit 3"}
	next := app
	next.Deployment = "dep_2"
	if _, err := l.Deploy(ctx, next, opt); err == nil || !strings.Contains(err.Error(), "exited with 3") {
		t.Fatalf("failing pre-deploy: %v", err)
	}
	if st, _ := l.Status(ctx, project, "app"); st.Deployment != "dep_1" {
		t.Errorf("a failed pre-deploy must not touch the live version: %+v", st)
	}
	if !strings.Contains(log.String(), "migrating 1") {
		t.Errorf("pre-deploy output (with the service variables) must reach the deploy log: %s", log.String())
	}
	opt.PreDeploy = []string{"sh", "-c", "echo ok"}
	if _, err := l.Deploy(ctx, next, opt); err != nil {
		t.Fatal(err)
	}
	if _, err := l.inspectManaged(ctx, node.ContainerName(project, "app")+preDeploySuffix); err == nil {
		t.Error("the pre-deploy container must be removed")
	}
}
