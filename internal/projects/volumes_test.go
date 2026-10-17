package projects

import (
	"context"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestServiceVolumesSurviveAndRecreate(t *testing.T) {
	f := newFixture(t)
	f.service(t)
	ctx := context.Background()
	if err := f.m.AddServiceVolume(ctx, f.who, "lab", "web", "media", "/app/media/"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ name, path, key string }{
		{"Media", "/x", "volume.error.name"},
		{"x", "app/media", "volume.error.path"},
		{"x", "/", "volume.error.path"},
		{"x", "/etc/nginx", "volume.error.reserved"},
		{"x", "/app/../etc", "volume.error.path"},
		{"media", "/data", "volume.error.name_taken"},
		{"sub", "/app/media/thumbs", "volume.error.overlap"},
	} {
		if err := f.m.AddServiceVolume(ctx, f.who, "lab", "web", bad.name, bad.path); errKey(err) != bad.key {
			t.Errorf("%s %s: got %v, want %s", bad.name, bad.path, err, bad.key)
		}
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_web")
	if len(spec.Volumes) != 1 || spec.Volumes[0] != (node.Volume{Name: "media", Path: "/app/media"}) {
		t.Fatalf("deployed volumes: %+v", spec.Volumes)
	}
	if last := f.n.opts[len(f.n.opts)-1]; last.Strategy != node.StrategyRecreate {
		t.Errorf("a service with a disk must be recreated, got %s", last.Strategy)
	}
	if err := f.m.RemoveServiceVolume(ctx, f.who, "lab", "web", "media", false); err != nil {
		t.Fatal(err)
	}
	_, s, _ := f.m.GetService(ctx, "lab", "web")
	if vols, _ := f.m.ListServiceVolumes(ctx, "lab", s); len(vols) != 0 {
		t.Errorf("still attached: %+v", vols)
	}
}
