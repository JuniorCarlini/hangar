//go:build integration

package docker

import (
	"context"
	"strings"
	"testing"
	"time"

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
