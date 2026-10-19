//go:build integration

package docker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
)

// Two panels on one Docker daemon with the same project and service names:
// neither may touch the other's container, network or volume.
func TestTwoPanelsOnOneDocker(t *testing.T) {
	a, ctx := setup(t)
	b, _ := setup(t)
	project := uniq("hgi")
	a.SetInstance("hgi_a", func(context.Context, string, string) bool { return false })
	b.SetInstance("hgi_b", func(context.Context, string, string) bool { return false })
	if err := a.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, a, project, "web")
	t.Cleanup(func() { _ = a.RemoveVolume(context.Background(), project, "web", "data") })

	web := spec(project, "web", "busybox:1.37", "sleep", "3600")
	web.Volumes = []node.Volume{{Name: "data", Path: "/data"}}
	if _, err := a.Deploy(ctx, web, node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}

	isOther := func(err error) bool {
		var ie *i18n.Error
		return errors.As(err, &ie) && ie.Key == "docker.error.other_instance"
	}
	if err := b.EnsureProjectNetwork(ctx, "prj_other", project); !isOther(err) {
		t.Errorf("network of another panel: %v", err)
	}
	theirs := web
	theirs.ProjectID, theirs.ServiceID = "prj_other", "svc_other"
	if _, err := b.Deploy(ctx, theirs, node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); !isOther(err) {
		t.Errorf("deploy over another panel's container: %v", err)
	}
	if _, err := b.Status(ctx, project, "web"); !isOther(err) {
		t.Errorf("status of another panel's container: %v", err)
	}
	for _, op := range []func(context.Context, string, string) error{b.Stop, b.Remove} {
		if err := op(ctx, project, "web"); !isOther(err) {
			t.Errorf("stop/remove another panel's container: %v", err)
		}
	}
	list, err := b.ListManaged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		if m.Project == project {
			t.Errorf("another panel's container is listed: %+v", m)
		}
	}
	st, err := a.Status(ctx, project, "web")
	if err != nil || !st.Running {
		t.Fatalf("the owner's container must be untouched: %+v %v", st, err)
	}

	// A container from before instance ids is adopted only by the panel
	// whose database knows its ids.
	legacy := &Local{c: a.c}
	if _, err := legacy.Deploy(ctx, spec(project, "old", "busybox:1.37", "sleep", "3600"), node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacy.Remove(context.Background(), project, "old") })
	a.SetInstance("hgi_a", func(_ context.Context, p, s string) bool { return p == "prj_"+project && (s == "" || s == "svc_old") })
	if _, err := a.Status(ctx, project, "old"); err != nil {
		t.Errorf("a panel must keep its containers from before the upgrade: %v", err)
	}
	if _, err := b.Status(ctx, project, "old"); !isOther(err) {
		t.Errorf("another panel adopted a container it does not know: %v", err)
	}
}
