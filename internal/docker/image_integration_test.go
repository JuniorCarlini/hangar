//go:build integration

package docker

import (
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/node"
)

// TestImageScanOfARunningService exports the image a service runs and
// inventories it, the way the dependency monitor does.
func TestImageScanOfARunningService(t *testing.T) {
	l, ctx := setup(t)
	project := uniq("img")
	cleanup(t, l, project, "web")
	if err := l.EnsureProjectNetwork(ctx, "prj_"+project, project); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Deploy(ctx, spec(project, "web", "alpine:3.24.1", "sleep", "300"), node.DeployOptions{Strategy: node.StrategyRecreate}); err != nil {
		t.Fatal(err)
	}
	id, size, err := l.ContainerImage(ctx, node.ContainerName(project, "web"))
	if err != nil || !strings.HasPrefix(id, "sha256:") || size <= 0 {
		t.Fatalf("container image = %q %d %v", id, size, err)
	}
	if _, _, err := l.ContainerImage(ctx, "not-a-hangar-container"); err == nil {
		t.Error("a missing container has an image")
	}
	s := &deps.ImageScanner{Images: l, Dir: t.TempDir()}
	pkgs, err := s.ScanContainer(ctx, node.ContainerName(project, "web"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pkgs {
		if p.Ecosystem == "Alpine:v3.24" && p.Name == "busybox" {
			found = true
		}
	}
	if !found {
		t.Errorf("busybox not inventoried: %+v", pkgs)
	}
}
