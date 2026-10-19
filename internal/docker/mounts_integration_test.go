//go:build integration

package docker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// logsUntil waits until the service's log contains want.
func logsUntil(t *testing.T, l *Local, ctx context.Context, project, service, want string) string {
	t.Helper()
	var out string
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		var b strings.Builder
		_ = l.Logs(ctx, project, service, node.LogOptions{Tail: 50}, func(ln node.LogLine) error {
			b.WriteString(ln.Text + "\n")
			return nil
		})
		if out = b.String(); strings.Contains(out, want) {
			return out
		}
	}
	t.Fatalf("%s/%s never logged %q: %s", project, service, want, out)
	return out
}

// Two services of a project share one volume: it carries the owner's name
// and labels whichever deploys first, and what one writes the other reads.
func TestSharedVolume(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgsv")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "game", "panel")
	t.Cleanup(func() { _ = l.RemoveVolume(context.Background(), project, "game", "world") })

	game := spec(project, "game", "busybox:1.37", "sh", "-c", `echo hello > /world/level.dat; sleep 3600`)
	game.Volumes = []node.Volume{{Name: "world", Path: "/world"}}
	panel := spec(project, "panel", "busybox:1.37", "sh", "-c", `while [ ! -f /data/level.dat ]; do sleep 0.2; done; echo READ $(cat /data/level.dat); sleep 3600`)
	panel.Volumes = []node.Volume{{Name: "world", Path: "/data", ReadOnly: true, Service: "game", ServiceID: game.ServiceID}}

	// Created ahead of the deploys, as a template does.
	if err := l.EnsureVolumes(ctx, game); err != nil {
		t.Fatal(err)
	}
	// The sharer deploys first; the volume still is the owner's.
	if _, err := l.Deploy(ctx, panel, node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Deploy(ctx, game, node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	logsUntil(t, l, ctx, project, "panel", "READ hello")

	res, err := l.c.VolumeInspect(ctx, node.VolumeName(project, "game", "world"), client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if lb := res.Volume.Labels; lb[node.LabelServiceID] != game.ServiceID || lb[node.LabelService] != "game" {
		t.Errorf("volume labels: %v", lb)
	}
	if _, err := l.c.VolumeInspect(ctx, node.VolumeName(project, "panel", "world"), client.VolumeInspectOptions{}); err == nil {
		t.Error("the sharer got a volume of its own")
	}
}

func TestReadOnlyMount(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgro")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "app")
	t.Cleanup(func() { _ = l.RemoveVolume(context.Background(), project, "app", "site") })

	app := spec(project, "app", "busybox:1.37", "sh", "-c", `if touch /site/x 2>/dev/null; then echo WROTE; else echo REFUSED; fi; sleep 3600`)
	app.Volumes = []node.Volume{{Name: "site", Path: "/site", ReadOnly: true}}
	if _, err := l.Deploy(ctx, app, node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if out := logsUntil(t, l, ctx, project, "app", "REFUSED"); strings.Contains(out, "WROTE") {
		t.Errorf("wrote to a read-only mount: %s", out)
	}
}
