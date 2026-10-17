package projects

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// fakeNotifier records what the alert channels would hear.
type fakeNotifier struct {
	mu        sync.Mutex
	failed    []DeployFailure
	recovered []string
}

func (n *fakeNotifier) DeployFailed(_ context.Context, f DeployFailure) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.failed = append(n.failed, f)
}

func (n *fakeNotifier) DeploySucceeded(_ context.Context, serviceID, _ string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.recovered = append(n.recovered, serviceID)
}

func (n *fakeNotifier) last(t *testing.T) DeployFailure {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.failed) == 0 {
		t.Fatal("no failure was reported")
	}
	return n.failed[len(n.failed)-1]
}

func TestValidateCommandSettings(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t)
	if got := f.n.lastOpt(); len(got.Validate) != 0 {
		t.Errorf("no validation by default: %+v", got.Validate)
	}
	err := f.m.SetDeploySettings(ctx, f.who, id, DeploySettings{
		Validate: `python manage.py check --deploy`, ValidateTimeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []DeploySettings{
		{Validate: `sh -c 'oops`},
		{Validate: "true", ValidateTimeout: time.Second},
		{Validate: "true", ValidateTimeout: time.Hour},
	} {
		if err := f.m.SetDeploySettings(ctx, f.who, id, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	s, _ := f.m.q.GetServiceByID(ctx, id)
	ds := f.m.GetDeploySettings(s)
	if ds.Validate != "python manage.py check --deploy" || ds.ValidateTimeout != 2*time.Minute {
		t.Errorf("stored: %+v", ds)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	opt := f.n.lastOpt()
	if !reflect.DeepEqual(opt.Validate, []string{"python", "manage.py", "check", "--deploy"}) || opt.ValidateTimeout != 2*time.Minute {
		t.Errorf("options: %+v", opt)
	}
	// Clearing it with no timeout given falls back to the default.
	if err := f.m.SetDeploySettings(ctx, f.who, id, DeploySettings{}); err != nil {
		t.Fatal(err)
	}
	s, _ = f.m.q.GetServiceByID(ctx, id)
	if ds := f.m.GetDeploySettings(s); ds.Validate != "" || ds.ValidateTimeout != DefaultValidateTimeout {
		t.Errorf("cleared: %+v", ds)
	}
}

func TestFailedDeployIsReported(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	n := &fakeNotifier{}
	f.m.SetDeployNotifier(n)
	_, id := f.service(t)
	if len(n.recovered) != 1 {
		t.Errorf("a good deploy closes open deploy alerts: %v", n.recovered)
	}
	if err := f.m.SetEnv(ctx, f.who, id, "API_TOKEN", "tok-super-secreto-123", true); err != nil {
		t.Fatal(err)
	}

	// Recreate that failed validation and brought the old version back.
	f.n.failNext = errors.New("the validation command exited with 1: token tok-super-secreto-123 refused (the previous version is back live)")
	f.n.failRes = node.DeployResult{Previous: node.PreviousRestored}
	f.n.failPhases = []string{node.PhaseHealth, node.PhaseValidate, node.PhaseRestore}
	dep, err := f.m.Deploy(ctx, f.who, "lab", "web", "webhook")
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	got := n.last(t)
	if got.Phase != node.PhaseValidate || got.Previous != node.PreviousRestored || got.Trigger != "webhook" ||
		got.Service != "lab/web" || got.ServiceID != id || got.Deployment != dep {
		t.Errorf("failure: %+v", got)
	}
	if strings.Contains(got.Reason, "tok-super-secreto-123") || !strings.Contains(got.Reason, "••••") {
		t.Errorf("the reason must be masked: %q", got.Reason)
	}
	d, _ := f.m.q.GetDeployment(ctx, dbq.GetDeploymentParams{ID: dep, ServiceID: id})
	if d.Status != "failed" || !strings.Contains(d.Error.String, "back live") {
		t.Errorf("history: %+v", d)
	}

	// Left down: the node says so.
	f.n.failNext = errors.New("not healthy; the previous version did not come back either")
	f.n.failRes = node.DeployResult{Previous: node.PreviousDown}
	f.n.failPhases = []string{node.PhaseHealth, node.PhaseRestore}
	if _, err := f.m.Rebuild(ctx, f.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if got := n.last(t); got.Previous != node.PreviousDown || got.Phase != node.PhaseHealth || got.Trigger != "rebuild" {
		t.Errorf("down: %+v", got)
	}

	// A failure that never reached the node (or a node that does not say)
	// keeps the version that was live.
	f.n.failNext = errors.New("pull failed")
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if got := n.last(t); got.Previous != node.PreviousLive {
		t.Errorf("untouched: %+v", got)
	}
}

func TestFirstDeployFailureHasNoPrevious(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	n := &fakeNotifier{}
	f.m.SetDeployNotifier(n)
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	f.n.failNext = errors.New("image not found")
	if _, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "web", Image: "nginx:1.29-alpine"}); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if got := n.last(t); got.Previous != node.PreviousNone || got.Trigger != "create" {
		t.Errorf("first deploy: %+v", got)
	}
}

func TestRebuildSkipsCaches(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t)
	if f.n.lastOpt().Fresh {
		t.Error("a normal deploy must keep the cache")
	}
	if _, err := f.m.Rebuild(ctx, f.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if !f.n.lastOpt().Fresh {
		t.Error("rebuild must force the pull")
	}
	deps, _ := f.m.Deployments(ctx, id, 1)
	if deps[0].Trigger != "rebuild" || deps[0].Status != "live" {
		t.Errorf("history: %+v", deps[0])
	}
}

func TestGitRebuildBuildsWithoutCache(t *testing.T) {
	g := newGitFixture(t)
	g.create(t, GitServiceInput{})
	if _, err := g.m.Rebuild(context.Background(), g.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	g.m.Wait()
	g.b.bmu.Lock()
	defer g.b.bmu.Unlock()
	if len(g.b.builds) != 2 || g.b.builds[0].Fresh || !g.b.builds[1].Fresh {
		t.Errorf("builds: %+v", g.b.builds)
	}
}

func TestRestorePolicy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t)
	if got := f.n.lastOpt().Restore; got != node.RestoreAlways {
		t.Errorf("stateless app: %q", got)
	}
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	// First deploy of a database: nothing to compare with.
	if got := f.n.lastOpt().Restore; got != node.RestoreSameImage {
		t.Errorf("first database deploy: %q", got)
	}
	_, db, err := f.m.GetService(ctx, "lab", "db")
	if err != nil {
		t.Fatal(err)
	}
	setImage := func(image string) {
		t.Helper()
		if _, err := f.st.DB.ExecContext(ctx, "UPDATE services SET image = ? WHERE id = ?", image, db.ID); err != nil {
			t.Fatal(err)
		}
	}
	redeploy := func() string {
		t.Helper()
		if _, err := f.m.Deploy(ctx, f.who, "lab", "db", "manual"); err != nil {
			t.Fatal(err)
		}
		f.m.Wait()
		return f.n.lastOpt().Restore
	}
	setImage("postgres:18.1-alpine")
	if got := redeploy(); got != node.RestoreAlways {
		t.Errorf("same major (18 → 18.1): %q", got)
	}
	setImage("postgres:19-alpine")
	if got := redeploy(); got != node.RestoreSameImage {
		t.Errorf("new major (18 → 19): %q, the old binary may not read the converted data", got)
	}
	setImage("postgres:latest")
	redeploy()
	if got := redeploy(); got != node.RestoreSameImage {
		t.Errorf("latest says nothing about the major: %q", got)
	}
}

func TestSameMajor(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"postgres:16-alpine", "postgres:16.4-alpine", true},
		{"postgres:16", "docker.io/library/postgres:16.2", true},
		{"postgres:16", "postgres:17", false},
		{"postgres:16", "mysql:16", false},
		{"postgres:latest", "postgres:latest", false},
		{"postgres", "postgres", false},
		{"registry.local:5000/db:v2.1", "registry.local:5000/db:v2.3", true},
		{"postgres:16@sha256:abc", "postgres:16.1", true},
	}
	for _, c := range cases {
		if got := sameMajor(c.a, c.b); got != c.want {
			t.Errorf("sameMajor(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
