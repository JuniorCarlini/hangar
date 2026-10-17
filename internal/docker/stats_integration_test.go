//go:build integration

package docker

import (
	"errors"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestContainerStatsAndDiskUsage(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgm")
	cleanup(t, l, project, "web")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Deploy(ctx, spec(project, "web", "busybox:1.37", "sleep", "300"), node.DeployOptions{Strategy: node.StrategyRecreate}); err != nil {
		t.Fatal(err)
	}
	list, err := l.ListManaged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, m := range list {
		if m.Name == node.ContainerName(project, "web") {
			id = m.ID
			if m.Project != project || m.Service != "web" || m.ServiceID != "svc_web" {
				t.Errorf("managed labels: %+v", m)
			}
		}
	}
	if id == "" {
		t.Fatal("deployed container not listed")
	}
	s, err := l.ContainerStats(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUTotal == 0 || s.SystemCPU == 0 || s.OnlineCPUs == 0 {
		t.Errorf("CPU counters missing: %+v", s)
	}
	if s.MemLimit != 64<<20 || s.MemUsed == 0 || s.MemUsed > s.MemLimit {
		t.Errorf("memory: used %d, limit %d (want the 64 MB limit)", s.MemUsed, s.MemLimit)
	}

	// A container Hangar did not create is not read.
	res, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: uniq("hgm-foreign"), Config: &container.Config{Image: "busybox:1.37", Cmd: []string{"sleep", "60"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = l.c.ContainerRemove(ctx, res.ID, client.ContainerRemoveOptions{Force: true})
	})
	if _, err := l.ContainerStats(ctx, res.ID); !errors.Is(err, ErrNotManaged) {
		t.Errorf("stats of a foreign container: %v", err)
	}

	du, err := l.DiskUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if du.Images <= 0 {
		t.Errorf("disk usage should count at least busybox: %+v", du)
	}
}
