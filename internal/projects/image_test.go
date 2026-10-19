package projects

import (
	"context"
	"errors"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestSplitImage(t *testing.T) {
	cases := map[string][2]string{
		"nginx:1.29-alpine":               {"nginx", "1.29-alpine"},
		"ghcr.io/org/app:2.0":             {"ghcr.io/org/app", "2.0"},
		"registry.local:5000/team/api":    {"registry.local:5000/team/api", ""},
		"registry.local:5000/team/api:v3": {"registry.local:5000/team/api", "v3"},
		"redis":                           {"redis", ""},
	}
	for in, want := range cases {
		if r, tag := SplitImage(in); r != want[0] || tag != want[1] {
			t.Errorf("SplitImage(%q) = %q, %q; want %q", in, r, tag, want)
		}
	}
}

// Only the tag changes; the deploy runs the new tag; a failed deploy puts
// the previous tag back (the previous version kept serving), and both
// steps are audited.
func TestChangeImageTag(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t) // nginx:1.29-alpine

	for tag, want := range map[string]error{
		"1.29-alpine":          ErrImageSame,
		"redis:8":              ErrImageTag,
		"../x":                 ErrImageTag,
		"":                     ErrImageTag,
		"1.31-alpine@sha256:x": ErrImageTag,
		"UPPER":                ErrImageTag,
	} {
		if _, err := f.m.ChangeImageTag(ctx, f.who, "lab", "web", tag); !errors.Is(err, want) {
			t.Errorf("tag %q: %v, want %v", tag, err, want)
		}
	}

	if _, err := f.m.ChangeImageTag(ctx, f.who, "lab", "web", "1.31-alpine"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if s, _ := f.n.spec(node.ContainerName("lab", "web")); s.Image != "nginx:1.31-alpine" {
		t.Errorf("deployed %q, want nginx:1.31-alpine", s.Image)
	}
	_, svc, _ := f.m.GetService(ctx, "lab", "web")
	if svc.Image != "nginx:1.31-alpine" {
		t.Errorf("service image = %q", svc.Image)
	}
	deps, _ := f.m.Deployments(ctx, id, 1)
	if deps[0].Trigger != "image" || deps[0].Status != "live" {
		t.Errorf("deploy = %+v", deps[0])
	}

	// The new version never becomes healthy: the old one keeps serving and
	// the service goes back to its tag.
	f.n.failNext = errors.New("health check failed")
	f.n.failRes = node.DeployResult{Previous: node.PreviousLive}
	if _, err := f.m.ChangeImageTag(ctx, f.who, "lab", "web", "1.32-alpine"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	_, svc, _ = f.m.GetService(ctx, "lab", "web")
	if svc.Image != "nginx:1.31-alpine" {
		t.Errorf("after a failed change the service runs %q, want the previous nginx:1.31-alpine", svc.Image)
	}
	var changes, reverts int
	_ = f.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'service.image.change'`).Scan(&changes)
	_ = f.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'service.image.revert'`).Scan(&reverts)
	if changes != 2 || reverts != 1 {
		t.Errorf("audit: %d changes, %d reverts; want 2 and 1", changes, reverts)
	}

	// A deploy already running: nothing changes.
	if _, err := f.st.DB.Exec(`UPDATE deployments SET status = 'running' WHERE id = (SELECT id FROM deployments ORDER BY started_at DESC LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.ChangeImageTag(ctx, f.who, "lab", "web", "1.33-alpine"); !errors.Is(err, ErrDeployRunning) {
		t.Errorf("change during a deploy: %v", err)
	}
	if _, svc, _ = f.m.GetService(ctx, "lab", "web"); svc.Image != "nginx:1.31-alpine" {
		t.Errorf("a refused change left the image at %q", svc.Image)
	}
}

func TestChangeImageTagRefusesGitServices(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, id := f.service(t)
	if _, err := f.st.DB.Exec(`INSERT INTO service_git (service_id, repo_url, branch, updated_at) VALUES (?, 'https://github.com/o/r', 'main', 1)`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.ChangeImageTag(ctx, f.who, "lab", "web", "1.31-alpine"); !errors.Is(err, ErrImageGit) {
		t.Errorf("git service: %v", err)
	}
}
