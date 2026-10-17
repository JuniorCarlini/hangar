//go:build integration

package docker

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestVolumeSurvivesRedeployAndHealthcheck(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgv")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "box")
	t.Cleanup(func() {
		_, _ = l.c.VolumeRemove(context.Background(), node.VolumeName(project, "box", "data"), client.VolumeRemoveOptions{})
	})

	s := spec(project, "box", "busybox:1.37", "sh", "-c", "test -f /data/x || date > /data/x; sleep 3600")
	s.Volumes = []node.Volume{{Name: "data", Path: "/data"}}
	s.Health = &node.Health{Test: []string{"CMD-SHELL", "test -f /data/x"}, Interval: time.Second, Retries: 3}
	if _, err := l.Deploy(ctx, s, node.DeployOptions{}); err != nil {
		t.Fatal(err)
	}
	var first bytes.Buffer
	waitHealthy(t, l, ctx, project, "box")
	if err := l.Exec(ctx, project, "box", []string{"cat", "/data/x"}, &first); err != nil {
		t.Fatal(err)
	}
	s.Deployment = "dep_2"
	if _, err := l.Deploy(ctx, s, node.DeployOptions{}); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	waitHealthy(t, l, ctx, project, "box")
	if err := l.Exec(ctx, project, "box", []string{"cat", "/data/x"}, &second); err != nil {
		t.Fatal(err)
	}
	if first.Len() == 0 || first.String() != second.String() {
		t.Errorf("the volume must keep its data across deploys: %q vs %q", first.String(), second.String())
	}
	if err := l.Exec(ctx, project, "box", []string{"sh", "-c", "echo oops >&2; exit 3"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "oops") {
		t.Errorf("a failing command must report its exit and stderr: %v", err)
	}
}

func waitHealthy(t *testing.T, l *Local, ctx context.Context, project, service string) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := l.Status(ctx, project, service); st.Health == "healthy" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s_%s never became healthy", project, service)
}

func TestPublishedPortsAndLinkedProjects(t *testing.T) {
	l, ctx := setup(t)
	a, b := uniq("hpa"), uniq("hpb")
	for _, p := range []string{a, b} {
		if err := l.EnsureProjectNetwork(ctx, "prj_"+p, p); err != nil {
			t.Fatal(err)
		}
	}
	cleanup(t, l, a, "web", "probe")
	cleanup(t, l, b, "probe")

	web := spec(a, "web", "nginx:1.29-alpine")
	web.MemoryBytes = 128 << 20
	web.Ports = []node.Port{{HostPort: 18081, ContainerPort: 80, Protocol: "tcp", HostIP: netip.MustParseAddr("127.0.0.1")}}
	if _, err := l.Deploy(ctx, web, node.DeployOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := l.c.ContainerInspect(ctx, node.ContainerName(a, "web"), client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var bound []string
	for port, bs := range res.Container.HostConfig.PortBindings {
		for _, bnd := range bs {
			bound = append(bound, port.String()+"@"+bnd.HostIP.String()+":"+bnd.HostPort)
		}
	}
	if len(bound) != 1 || bound[0] != "80/tcp@127.0.0.1:18081" {
		t.Errorf("port binding: %v", bound)
	}

	// Not linked: b cannot resolve a's container.
	name := node.ContainerName(a, "web")
	if out := run(t, l, ctx, b, "probe", "sh", "-c", "wget -qO- -T 3 http://"+name+"/ >/dev/null && echo REACHED || echo BLOCKED"); !strings.Contains(out, "BLOCKED") {
		t.Fatalf("projects must be isolated before linking: %s", out)
	}
	// Link: a's running container joins b's network; b now reaches it by name.
	if err := l.SetLinked(ctx, a, "web", []string{b}); err != nil {
		t.Fatal(err)
	}
	if out := run(t, l, ctx, b, "probe", "sh", "-c", "wget -qO- -T 3 http://"+name+"/ >/dev/null && echo REACHED || echo BLOCKED"); !strings.Contains(out, "REACHED") {
		t.Fatalf("linked projects must reach each other by name: %s", out)
	}
	// Unlink: back to isolated.
	if err := l.SetLinked(ctx, a, "web", nil); err != nil {
		t.Fatal(err)
	}
	if out := run(t, l, ctx, b, "probe", "sh", "-c", "wget -qO- -T 3 http://"+name+"/ >/dev/null && echo REACHED || echo BLOCKED"); !strings.Contains(out, "BLOCKED") {
		t.Fatalf("unlinking must isolate again: %s", out)
	}
}
