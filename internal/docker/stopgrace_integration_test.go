//go:build integration

package docker

import (
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// The grace period is kept on the container and every stop path uses it:
// a process that ignores SIGTERM is killed after it, not after the default.
func TestStopGracePeriodIsKeptOnTheContainer(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgs")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "srv")

	srv := spec(project, "srv", "busybox:1.37", "sh", "-c", `trap "" TERM; while true; do sleep 1; done`)
	srv.StopGrace = 3 * time.Second
	if _, err := l.Deploy(ctx, srv, node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	res, err := l.c.ContainerInspect(ctx, node.ContainerName(project, "srv"), client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st := res.Container.Config.StopTimeout; st == nil || *st != 3 {
		t.Fatalf("StopTimeout on the container: %v", st)
	}
	start := time.Now()
	if err := l.Stop(ctx, project, "srv"); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < 2*time.Second || took > 15*time.Second {
		t.Errorf("stop took %s, want about the 3 s grace period", took)
	}

	// The default when the service sets none.
	srv.StopGrace = 0
	srv.Deployment = "dep_2"
	if _, err := l.Deploy(ctx, srv, node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	res, err = l.c.ContainerInspect(ctx, node.ContainerName(project, "srv"), client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st := res.Container.Config.StopTimeout; st == nil || *st != 30 {
		t.Errorf("default StopTimeout: %v", st)
	}
}
