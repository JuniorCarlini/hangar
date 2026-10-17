//go:build integration

package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// Runs against the real Docker: go test -tags integration ./internal/docker/

func setup(t *testing.T) (*Local, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	l, err := New(ctx, "")
	if err != nil {
		t.Skip("Docker unavailable:", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, ctx
}

func uniq(prefix string) string { return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()%1_000_000) }

func spec(project, service, image string, cmd ...string) node.ServiceSpec {
	return node.ServiceSpec{
		ProjectID: "prj_" + project, Project: project, ServiceID: "svc_" + service, Service: service,
		Deployment: "dep_1", Image: image, Command: cmd,
		Env:         map[string]string{"HANGAR_TESTE": "1"},
		MemoryBytes: 64 << 20, NanoCPUs: 500_000_000, PidsLimit: 128,
	}
}

func cleanup(t *testing.T, l *Local, project string, services ...string) {
	t.Cleanup(func() {
		ctx := context.Background()
		for _, s := range services {
			_ = l.Remove(ctx, project, s)
		}
		_ = l.RemoveProjectNetwork(ctx, project)
	})
}

// run executes a command inside a temporary test container in the project
// and returns its output.
func run(t *testing.T, l *Local, ctx context.Context, project, name string, cmd ...string) string {
	t.Helper()
	s := spec(project, name, "busybox:1.37", cmd...)
	// A one-shot probe exits on its own, which the deploy reports as "not
	// healthy"; only a failure to create it matters here.
	if res, err := l.Deploy(ctx, s, node.DeployOptions{Strategy: node.StrategyRecreate}); err != nil && res.ContainerID == "" {
		t.Fatal(err)
	}
	var out strings.Builder
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := l.Status(ctx, project, name)
		if !st.Running && st.State == "exited" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	// Stop it from restarting (unless-stopped) before reading.
	_ = l.Stop(ctx, project, name)
	_ = l.Logs(ctx, project, name, node.LogOptions{Tail: 50}, func(ln node.LogLine) error {
		out.WriteString(ln.Text + "\n")
		return nil
	})
	return out.String()
}

func TestDeployAppliesHardening(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgt")
	cleanup(t, l, project, "web")

	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Deploy(ctx, spec(project, "web", "nginx:1.29-alpine"), node.DeployOptions{}); err != nil {
		t.Fatal(err)
	}

	var st node.Status
	for range 40 {
		st, _ = l.Status(ctx, project, "web")
		if st.Running {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !st.Running {
		t.Fatalf("nginx did not come up: %+v", st)
	}

	res, err := l.c.ContainerInspect(ctx, node.ContainerName(project, "web"), client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hc := res.Container.HostConfig
	checks := []struct {
		name string
		ok   bool
	}{
		{"privileged off", !hc.Privileged},
		{"cap_drop ALL", len(hc.CapDrop) == 1 && hc.CapDrop[0] == "ALL"},
		{"no-new-privileges", strings.Contains(strings.Join(hc.SecurityOpt, ","), "no-new-privileges")},
		{"memory limit", hc.Memory == 64<<20},
		{"no swap", hc.MemorySwap == 64<<20},
		{"CPU limit", hc.NanoCPUs == 500_000_000},
		{"process limit", hc.PidsLimit != nil && *hc.PidsLimit == 128},
		{"local log with rotation", hc.LogConfig.Type == "local" && hc.LogConfig.Config["max-size"] == "50m"},
		{"unless-stopped restart", hc.RestartPolicy.Name == container.RestartPolicyUnlessStopped},
		{"no bind mounts", len(hc.Binds) == 0},
		{"no published ports", len(hc.PortBindings) == 0},
		{"init (zombie reaper)", hc.Init != nil && *hc.Init},
		{"Hangar label", res.Container.Config.Labels[node.LabelManaged] == "true"},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("missing protection: %s", c.name)
		}
	}

	// nginx may not have written its startup lines yet on a slow machine.
	var lines int
	for deadline := time.Now().Add(10 * time.Second); lines == 0 && time.Now().Before(deadline); {
		if err := l.Logs(ctx, project, "web", node.LogOptions{Tail: 20}, func(ln node.LogLine) error {
			if ln.Time.IsZero() {
				t.Errorf("line without timestamp: %+v", ln)
			}
			lines++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if lines == 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if lines == 0 {
		t.Error("no nginx log lines")
	}
}

func TestProjectsAreIsolated(t *testing.T) {
	l, ctx := setup(t)
	a, b := uniq("hga"), uniq("hgb")
	cleanup(t, l, a, "web", "probe")
	cleanup(t, l, b, "probe")

	for _, p := range []string{a, b} {
		if err := l.EnsureProjectNetwork(ctx, "prj_"+p, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Deploy(ctx, spec(a, "web", "nginx:1.29-alpine"), node.DeployOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)

	same := run(t, l, ctx, a, "probe", "sh", "-c", "wget -q -T 3 -O - http://web/ >/dev/null && echo REACHED || echo NOT_REACHED")
	if !strings.Contains(same, "REACHED") || strings.Contains(same, "NOT_REACHED") {
		t.Errorf("a service in the same project should reach web by name: %q", same)
	}
	byName := run(t, l, ctx, a, "probe", "sh", "-c", "wget -q -T 3 -O - http://"+node.ContainerName(a, "web")+"/ >/dev/null && echo REACHED || echo NOT_REACHED")
	if !strings.Contains(byName, "REACHED") || strings.Contains(byName, "NOT_REACHED") {
		t.Errorf("<project>_<service> should resolve inside the project: %q", byName)
	}
	other := run(t, l, ctx, b, "probe", "sh", "-c", "wget -q -T 3 -O - http://"+node.ContainerName(a, "web")+"/ >/dev/null && echo REACHED || echo NOT_REACHED")
	if !strings.Contains(other, "NOT_REACHED") {
		t.Errorf("another project must NOT reach web: %q", other)
	}
}

func TestRefusesForeignContainer(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgf")
	cleanup(t, l, project)
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	if err := l.pull(ctx, "busybox:1.37"); err != nil {
		t.Fatal(err)
	}
	name := node.ContainerName(project, "web")
	res, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name, Config: &container.Config{Image: "busybox:1.37", Cmd: []string{"sleep", "60"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = l.c.ContainerRemove(context.Background(), res.ID, client.ContainerRemoveOptions{Force: true})
	})

	if _, err := l.Deploy(ctx, spec(project, "web", "busybox:1.37", "sleep", "60"), node.DeployOptions{}); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("Deploy over a foreign container: %v", err)
	}
	if err := l.Remove(ctx, project, "web"); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("Remove of a foreign container: %v", err)
	}
	if _, err := l.c.ContainerInspect(ctx, res.ID, client.ContainerInspectOptions{}); err != nil {
		t.Fatal("the foreign container should still exist")
	}
}
