//go:build integration

package docker

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestRunTaskStdinScratchAndCleanup(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("e2e-bk-")
	cleanup(t, l, project, "box")

	task := node.TaskSpec{
		Image: "busybox:1.37", Scratch: "/scratch",
		Cmd:         []string{"sh", "-c", "cat > /scratch/in && wc -c < /scratch/in && touch /etc/nope 2>/dev/null; wget -q -T 2 http://1.1.1.1 >/dev/null 2>&1 && echo net || echo nonet"},
		MemoryBytes: 64 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
	}
	var out bytes.Buffer
	if err := l.RunTask(ctx, task, strings.NewReader(strings.Repeat("a", 100000)), &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(out.String()); len(got) != 2 || got[0] != "100000" || got[1] != "nonet" {
		t.Fatalf("task output %q: stdin must arrive whole and there is no network", out.String())
	}

	// A failing task reports its exit code and stderr.
	task.Cmd = []string{"sh", "-c", "echo quebrou >&2; exit 3"}
	if err := l.RunTask(ctx, task, nil, &out); err == nil || !strings.Contains(err.Error(), "exited with 3") || !strings.Contains(err.Error(), "quebrou") {
		t.Fatalf("failing task: %v", err)
	}

	// A task that fails before reading its input returns, even while the
	// caller keeps that input open (it waits for the task's output first).
	inR, inW := io.Pipe()
	defer func() { _ = inW.Close() }()
	done := make(chan error, 1)
	go func() { done <- l.RunTask(ctx, task, inR, &out) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "exited with 3") {
			t.Fatalf("early failure with open input: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("a task that ended early must not wait for its input to end")
	}

	// Nothing is left behind: no task container, no scratch volume.
	cs, _ := l.c.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: make(client.Filters).Add("label", LabelTask+"=true")})
	vs, _ := l.c.VolumeList(ctx, client.VolumeListOptions{Filters: make(client.Filters).Add("label", LabelTask+"=true")})
	if len(cs.Items) != 0 || len(vs.Items) != 0 {
		t.Fatalf("leftovers: %d containers, %d volumes", len(cs.Items), len(vs.Items))
	}

	// Mounting a volume Hangar did not create is refused.
	task.Mounts = []node.TaskMount{{Volume: "hangar_not_ours", Path: "/data"}}
	if err := l.RunTask(ctx, task, nil, nil); err == nil {
		t.Fatal("unknown volume must be refused")
	}

	// ExecIO feeds a running service's command.
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	s := spec(project, "box", "busybox:1.37", "sleep", "300")
	if _, err := l.Deploy(ctx, s, node.DeployOptions{Strategy: node.StrategyRecreate}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := l.Status(ctx, project, "box"); st.Running {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	out.Reset()
	if err := l.ExecIO(ctx, project, "box", []string{"sh", "-c", "cat > /tmp/x && md5sum < /tmp/x"}, strings.NewReader("restaurado"), &out); err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum([]byte("restaurado"))
	if !strings.HasPrefix(out.String(), hex.EncodeToString(sum[:])) {
		t.Fatalf("exec output %q", out.String())
	}
}
