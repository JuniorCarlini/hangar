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

// progressLog collects the deploy progress as the deploy log would.
type progressLog struct{ b strings.Builder }

func (p *progressLog) fn(phase, line string) { p.b.WriteString("[" + phase + "] " + line + "\n") }
func (p *progressLog) String() string        { return p.b.String() }

func TestRecreateBringsThePreviousVersionBack(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgr")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "db", "db"+prevSuffix)

	db := spec(project, "db", "busybox:1.37", "sh", "-c", "echo v1 > /data/version; sleep 3600")
	db.Volumes = []node.Volume{{Name: "data", Path: "/data"}}
	t.Cleanup(func() {
		_, _ = l.c.VolumeRemove(context.Background(), node.VolumeName(project, "db", "data"), client.VolumeRemoveOptions{Force: true})
	})
	opt := node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}
	first, err := l.Deploy(ctx, db, opt)
	if err != nil {
		t.Fatal(err)
	}

	// A version that crashes: the old one comes back, with its volume.
	broken := db
	broken.Deployment = "dep_broken"
	broken.Command = []string{"sh", "-c", "echo crashing; exit 1"}
	var log progressLog
	bopt := opt
	bopt.Progress = log.fn
	res, err := l.Deploy(ctx, broken, bopt)
	if err == nil || !strings.Contains(err.Error(), "back live") || res.Previous != node.PreviousRestored {
		t.Fatalf("broken deploy: %+v %v", res, err)
	}
	st, _ := l.Status(ctx, project, "db")
	if !st.Running || st.Deployment != "dep_1" {
		t.Fatalf("the previous version must be serving again: %+v", st)
	}
	if !strings.Contains(log.String(), "[restore] the previous version is back live") || !strings.Contains(log.String(), "crashing") {
		t.Errorf("deploy log:\n%s", log.String())
	}
	if _, err := l.inspectManaged(ctx, node.ContainerName(project, "db")+prevSuffix); err == nil {
		t.Error("nothing may be left under the -prev name")
	}
	var out strings.Builder
	if err := l.Exec(ctx, project, "db", []string{"cat", "/data/version"}, &out); err != nil || strings.TrimSpace(out.String()) != "v1" {
		t.Errorf("the restored version must see its volume: %q %v", out.String(), err)
	}

	// A healthy version that fails its validation: same thing, and the
	// command's output (it sees the service's variables) reaches the log.
	log = progressLog{}
	invalid := db
	invalid.Deployment = "dep_invalid"
	vopt := bopt
	vopt.Progress = log.fn
	vopt.Validate = []string{"sh", "-c", "echo checking $HANGAR_TESTE; exit 4"}
	res, err = l.Deploy(ctx, invalid, vopt)
	if err == nil || !strings.Contains(err.Error(), "exited with 4") || res.Previous != node.PreviousRestored {
		t.Fatalf("invalid deploy: %+v %v", res, err)
	}
	if st, _ := l.Status(ctx, project, "db"); !st.Running || st.Deployment != "dep_1" {
		t.Fatalf("after a failed validation: %+v", st)
	}
	if !strings.Contains(log.String(), "[validate]") || !strings.Contains(log.String(), "checking 1") {
		t.Errorf("deploy log:\n%s", log.String())
	}

	// A database whose image changed: the previous one stays down, since
	// the new image may have converted its data.
	strict := opt
	strict.Restore = node.RestoreSameImage
	upgraded := broken
	upgraded.Image = "alpine:3.22"
	upgraded.Deployment = "dep_upgrade"
	res, err = l.Deploy(ctx, upgraded, strict)
	if err == nil || !strings.Contains(err.Error(), "service is down") || res.Previous != node.PreviousDown {
		t.Fatalf("upgrade: %+v %v", res, err)
	}
	if _, err := l.inspectManaged(ctx, node.ContainerName(project, "db")+prevSuffix); err == nil {
		t.Error("a previous version that may not come back must not linger")
	}

	// Same rule, same image (only the configuration changed): it comes back.
	if _, err := l.Deploy(ctx, db, opt); err != nil {
		t.Fatal(err)
	}
	res, err = l.Deploy(ctx, broken, strict)
	if err == nil || res.Previous != node.PreviousRestored {
		t.Fatalf("config change: %+v %v", res, err)
	}
	if st, _ := l.Status(ctx, project, "db"); !st.Running || st.Deployment != "dep_1" || st.Image != first.ImageRef {
		t.Errorf("after a bad config change: %+v", st)
	}
}

func TestRollingValidationKeepsTheOldVersion(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgv")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "app", "app"+nextSuffix)
	app := spec(project, "app", "busybox:1.37", "sh", "-c", "sleep 3600")
	opt := node.DeployOptions{Strategy: node.StrategyRolling, HealthTimeout: 20 * time.Second}
	if _, err := l.Deploy(ctx, app, opt); err != nil {
		t.Fatal(err)
	}
	var log progressLog
	opt.Progress = log.fn
	opt.Validate = []string{"sh", "-c", "echo running checks; echo 'FAILED: 1 test' >&2; exit 1"}
	next := app
	next.Deployment = "dep_2"
	res, err := l.Deploy(ctx, next, opt)
	if err == nil || !strings.Contains(err.Error(), "still live") || res.Previous != node.PreviousLive {
		t.Fatalf("failed validation: %+v %v", res, err)
	}
	if st, _ := l.Status(ctx, project, "app"); !st.Running || st.Deployment != "dep_1" {
		t.Errorf("the old version must keep serving: %+v", st)
	}
	if _, err := l.inspectManaged(ctx, node.ContainerName(project, "app")+nextSuffix); err == nil {
		t.Error("the new container must be discarded")
	}
	if !strings.Contains(log.String(), "running checks") || !strings.Contains(log.String(), "FAILED: 1 test") {
		t.Errorf("validation output:\n%s", log.String())
	}

	// A command that never ends is cut at the time limit.
	opt.Validate = []string{"sleep", "60"}
	opt.ValidateTimeout = 2 * time.Second
	if _, err := l.Deploy(ctx, next, opt); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("slow validation: %v", err)
	}

	opt.Validate, opt.ValidateTimeout = []string{"true"}, 0
	if _, err := l.Deploy(ctx, next, opt); err != nil {
		t.Fatal(err)
	}
	if st, _ := l.Status(ctx, project, "app"); st.Deployment != "dep_2" {
		t.Errorf("a passing validation switches: %+v", st)
	}
}

func TestRecoverDeployHandlesThePreviousVersion(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgc")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "app", "app"+prevSuffix)
	app := spec(project, "app", "busybox:1.37", "sh", "-c", "sleep 3600")
	opt := node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}
	res, err := l.Deploy(ctx, app, opt)
	if err != nil {
		t.Fatal(err)
	}
	name := node.ContainerName(project, "app")

	// The panel died right after stopping the old version.
	if err := l.stopAndKeep(ctx, res.ContainerID, name+prevSuffix); err != nil {
		t.Fatal(err)
	}
	if got, err := l.RecoverDeploy(ctx, project, "app"); err != nil || got != "restored-prev" {
		t.Fatalf("recover: %q %v", got, err)
	}
	if st, _ := l.Status(ctx, project, "app"); !st.Running || st.Deployment != "dep_1" {
		t.Errorf("restored: %+v", st)
	}

	// It died after the new one was created: the new one stays.
	if err := l.stopAndKeep(ctx, res.ContainerID, name+prevSuffix); err != nil {
		t.Fatal(err)
	}
	next := app
	next.Deployment = "dep_2"
	ref, err := l.imageRef(ctx, next.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.createContainer(ctx, next, name, ref); err != nil {
		t.Fatal(err)
	}
	if got, err := l.RecoverDeploy(ctx, project, "app"); err != nil || got != "removed-prev" {
		t.Fatalf("recover: %q %v", got, err)
	}
	if _, err := l.inspectManaged(ctx, name+prevSuffix); err == nil {
		t.Error("the stale previous version must go")
	}
}

func TestFreshDeployRefusesTheLocalCopy(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("hgf")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	cleanup(t, l, project, "app")
	if err := l.pull(ctx, "busybox:1.37"); err != nil {
		t.Fatal(err)
	}
	// An image no registry has: a normal deploy falls back on this copy.
	local := "hangar-test-local-only/" + project + ":1"
	if _, err := l.c.ImageTag(ctx, client.ImageTagOptions{Source: "busybox:1.37", Target: local}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = l.c.ImageRemove(context.Background(), local, client.ImageRemoveOptions{})
	})
	app := spec(project, "app", local, "sh", "-c", "sleep 3600")
	opt := node.DeployOptions{Strategy: node.StrategyRecreate, HealthTimeout: 20 * time.Second}
	if _, err := l.Deploy(ctx, app, opt); err != nil {
		t.Fatalf("normal deploy: %v", err)
	}
	opt.Fresh = true
	res, err := l.Deploy(ctx, app, opt)
	if err == nil || !strings.Contains(err.Error(), "pull image") || res.Previous != node.PreviousLive {
		t.Fatalf("fresh deploy must fail when the registry lacks the image: %+v %v", res, err)
	}
	if st, _ := l.Status(ctx, project, "app"); !st.Running {
		t.Errorf("a refused pull touches nothing: %+v", st)
	}
}
