//go:build integration

package docker

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// safeLog collects the deploy log from the deploy's goroutines.
type safeLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeLog) add(phase, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.WriteString("[" + phase + "] " + line + "\n")
}

func (s *safeLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// An app that migrates and uploads its static files for 2.5 minutes before
// it listens (a Django entrypoint running collectstatic to a bucket) is not
// a failed deploy: the startup grace covers it, the previous version
// serves meanwhile, and the deploy log shows the wait and the app's output.
func TestSlowStartingAppDeploysWithinTheGrace(t *testing.T) {
	l, _ := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	project := uniq("hgs")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "web")
	t.Cleanup(func() { _ = l.Remove(context.Background(), project, "web"+nextSuffix) })

	const serve = `mkdir -p /tmp/w && echo ok > /tmp/w/healthz && exec httpd -f -p 8000 -h /tmp/w`
	opt := node.DeployOptions{Strategy: node.StrategyRolling, Port: 8000, HealthPath: "/healthz", HealthTimeout: 20 * time.Second}
	if _, err := l.Deploy(ctx, spec(project, "web", "busybox:1.37", "sh", "-c", serve), opt); err != nil {
		t.Fatal(err)
	}

	slow := spec(project, "web", "busybox:1.37", "sh", "-c",
		`i=0; while [ $i -lt 150 ]; do echo "copying static file $i"; sleep 1; i=$((i+1)); done; `+serve)
	slow.Deployment = "dep_2"
	var log safeLog
	sopt := opt
	sopt.HealthTimeout = node.HealthWait(nil, 0, 15*time.Minute) // the default grace
	sopt.Progress = log.add
	done := make(chan error, 1)
	go func() {
		_, err := l.Deploy(ctx, slow, sopt)
		done <- err
	}()
	// Meanwhile the previous version keeps serving.
	time.Sleep(30 * time.Second)
	if st, _ := l.Status(ctx, project, "web"); !st.Running || st.Deployment != "dep_1" {
		t.Errorf("the previous version must serve while the new one starts: %+v", st)
	}
	start := time.Now()
	if err := <-done; err != nil {
		t.Fatalf("a slow start within the grace must deploy: %v\n%s", err, log.String())
	}
	t.Logf("deployed %s after the check above", time.Since(start).Round(time.Second))
	if st, _ := l.Status(ctx, project, "web"); !st.Running || st.Deployment != "dep_2" {
		t.Errorf("the new version must be live: %+v", st)
	}
	out := log.String()
	for _, want := range []string{"waiting for the app to answer GET /healthz on port 8000", "of 5m0s", "last output: copying static file"} {
		if !strings.Contains(out, want) {
			t.Errorf("deploy log without %q:\n%s", want, out)
		}
	}
}

// An app that exits on start fails the deploy at once (not after the
// whole grace), the error carries its last output, and the previous
// version stays live.
func TestCrashingAppFailsFastWithItsOutput(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgc")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "web")
	t.Cleanup(func() { _ = l.Remove(context.Background(), project, "web"+nextSuffix) })

	opt := node.DeployOptions{Strategy: node.StrategyRolling, Port: 8000, HealthPath: "/healthz", HealthTimeout: 20 * time.Second}
	live := spec(project, "web", "busybox:1.37", "sh", "-c", `mkdir -p /tmp/w && echo ok > /tmp/w/healthz && exec httpd -f -p 8000 -h /tmp/w`)
	if _, err := l.Deploy(ctx, live, opt); err != nil {
		t.Fatal(err)
	}

	crash := spec(project, "web", "busybox:1.37", "sh", "-c", `echo "Operations to perform: migrate"; echo "django.db.utils.OperationalError: could not connect to server" >&2; exit 3`)
	crash.Deployment = "dep_2"
	copt := opt
	copt.HealthTimeout = 5 * time.Minute
	start := time.Now()
	_, err := l.Deploy(ctx, crash, copt)
	if err == nil {
		t.Fatal("a crashing app must fail the deploy")
	}
	if took := time.Since(start); took > time.Minute {
		t.Errorf("a container that exits must fail at once, not wait the grace: %s", took)
	}
	msg := err.Error()
	first, rest, _ := strings.Cut(msg, "\n")
	if !strings.Contains(first, "exit code 3") || !strings.Contains(first, "still live") {
		t.Errorf("first line must say why and that the previous version is live: %q", first)
	}
	if !strings.Contains(rest, "OperationalError: could not connect to server") || !strings.Contains(rest, "Operations to perform") {
		t.Errorf("the error must carry the app's last output: %q", msg)
	}
	if st, _ := l.Status(ctx, project, "web"); !st.Running || st.Deployment != "dep_1" {
		t.Errorf("the previous version must stay live: %+v", st)
	}
}
