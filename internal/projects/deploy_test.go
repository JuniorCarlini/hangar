package projects

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

func (f *fakeNode) lastOpt() node.DeployOptions {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opts[len(f.opts)-1]
}

func TestStrategyFollowsWhatIsSafe(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t) // nginx, no volume, no port
	if got := f.n.lastOpt().Strategy; got != node.StrategyRolling {
		t.Errorf("stateless app: %s, want rolling (no downtime)", got)
	}
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if got := f.n.lastOpt().Strategy; got != node.StrategyRecreate {
		t.Errorf("database: %s, want recreate (two processes on one volume corrupt it)", got)
	}
	if err := f.m.AddPort(ctx, f.who, "lab", "web", PortInput{HostPort: 8080, ContainerPort: 80, Protocol: "tcp", Access: AccessAny}); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if got := f.n.lastOpt().Strategy; got != node.StrategyRecreate {
		t.Errorf("published port: %s, want recreate (two containers cannot bind it)", got)
	}
}

func TestPreDeployHealthAndLog(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t)
	err := f.m.SetDeploySettings(ctx, f.who, id, DeploySettings{PreDeploy: `python manage.py migrate --noinput`, HealthPath: "/healthz"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []DeploySettings{{HealthPath: "healthz"}, {HealthPath: "/a b"}, {PreDeploy: `sh -c 'oops`}} {
		if err := f.m.SetDeploySettings(ctx, f.who, id, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	dep, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual")
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	opt := f.n.lastOpt()
	if !reflect.DeepEqual(opt.PreDeploy, []string{"python", "manage.py", "migrate", "--noinput"}) || opt.HealthPath != "/healthz" || opt.Port != 80 {
		t.Errorf("options: %+v", opt)
	}
	d, _ := f.m.q.GetDeployment(ctx, dbq.GetDeploymentParams{ID: dep, ServiceID: id})
	if d.Status != "live" || d.ImageRef == "" || d.Phase != node.PhaseHealth || !strings.Contains(d.Log, "[pull] nginx:1.29-alpine") {
		t.Errorf("deployment record: %+v", d)
	}
}

func TestRollbackUsesThePinnedImage(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t) // deploy 1 → sha256:1
	first, _ := f.m.Deployments(ctx, id, 1)
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil { // deploy 2 → sha256:2
		t.Fatal(err)
	}
	f.m.Wait()
	deps, _ := f.m.Deployments(ctx, id, 5)
	live := deps[0]
	if _, err := f.m.Rollback(ctx, f.who, "lab", "web", live.ID); err == nil {
		t.Error("rolling back to the live version makes no sense")
	}
	targets := f.m.RollbackTargets(ctx, id, deps)
	if !targets[first[0].ID] || targets[live.ID] {
		t.Errorf("rollback targets: %v", targets)
	}
	if _, err := f.m.Rollback(ctx, f.who, "lab", "web", first[0].ID); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_web")
	if spec.Image != first[0].ImageRef {
		t.Errorf("rollback deployed %q, want the pinned %q", spec.Image, first[0].ImageRef)
	}
	deps, _ = f.m.Deployments(ctx, id, 1)
	if deps[0].Trigger != "rollback" {
		t.Errorf("trigger: %s", deps[0].Trigger)
	}

	// A failed deploy is never a rollback target.
	f.n.failNext = errors.New("unhealthy")
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	deps, _ = f.m.Deployments(ctx, id, 1)
	if _, err := f.m.Rollback(ctx, f.who, "lab", "web", deps[0].ID); err == nil {
		t.Error("rolled back to a failed deploy")
	}
}

func TestSplitCommand(t *testing.T) {
	cases := map[string][]string{
		"python manage.py migrate":         {"python", "manage.py", "migrate"},
		`sh -c 'migrate && seed'`:          {"sh", "-c", "migrate && seed"},
		`echo "a b" c`:                     {"echo", "a b", "c"},
		"":                                 nil,
		`node scripts/run.js --name="x y"`: {"node", "scripts/run.js", "--name=x y"},
	}
	for in, want := range cases {
		got, err := SplitCommand(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("SplitCommand(%q) = %q, %v", in, got, err)
		}
		if back, _ := SplitCommand(JoinCommand(got)); !reflect.DeepEqual(back, want) {
			t.Errorf("round trip of %q: %q", in, back)
		}
	}
}

func TestSetEnvBulk(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t)
	n, err := f.m.SetEnvBulk(ctx, f.who, id, "# comment\nexport A=1\r\nB=\"two words\"\n\nC='x=y'\n", false)
	if err != nil || n != 3 {
		t.Fatalf("bulk: %d %v", n, err)
	}
	env, _ := f.m.ListEnv(ctx, id)
	got := map[string]string{}
	for _, e := range env {
		got[e.Key] = e.Value
	}
	if got["A"] != "1" || got["B"] != "two words" || got["C"] != "x=y" {
		t.Errorf("parsed: %v", got)
	}
	// Saving the same file again writes only what changed.
	if n, err := f.m.SetEnvBulk(ctx, f.who, id, "A=1\nB=two words\nC=new\n", false); err != nil || n != 1 {
		t.Fatalf("resave: %d %v", n, err)
	}
	if _, err := f.m.SetEnvBulk(ctx, f.who, id, "OK=1\nbad line\n", false); err == nil {
		t.Error("an invalid line must reject the whole paste")
	}
	if env2, _ := f.m.ListEnv(ctx, id); len(env2) != 3 {
		t.Error("nothing may be written when a line is invalid")
	}
}

// The deploy waits as long as the service's own healthcheck may take: a
// server that loads for minutes is not removed by a recreate halfway.
func TestHealthWaitFollowsTheHealthcheck(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t)
	if got := f.n.lastOpt().HealthTimeout; got != node.DefaultHealthTimeout {
		t.Errorf("no healthcheck: %s, want %s", got, node.DefaultHealthTimeout)
	}
	set := func(h node.Health) {
		t.Helper()
		b, _ := json.Marshal(h)
		if _, err := f.st.DB.ExecContext(ctx, `UPDATE services SET health_json = ? WHERE id = ?`, string(b), id); err != nil {
			t.Fatal(err)
		}
		if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
			t.Fatal(err)
		}
		f.m.Wait()
	}
	set(node.Health{Test: []string{"CMD", "true"}, StartPeriod: 6 * time.Minute, Interval: 30 * time.Second, Timeout: 10 * time.Second, Retries: 3})
	if got, want := f.n.lastOpt().HealthTimeout, 7*time.Minute+40*time.Second; got != want {
		t.Errorf("slow start: %s, want %s", got, want)
	}
	set(node.Health{Test: []string{"CMD", "true"}, StartPeriod: 2 * time.Hour})
	if got := f.n.lastOpt().HealthTimeout; got != deployTimeout {
		t.Errorf("capped by the deploy timeout: %s, want %s", got, deployTimeout)
	}
}
