package projects

import (
	"context"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestComposeReadOnlyMounts(t *testing.T) {
	plan, err := ParseCompose([]byte(`
services:
  web:
    image: nginx:1.29-alpine
    volumes:
      - site:/usr/share/nginx/html:ro
      - cache:/var/cache/app:rw,z
      - type: volume
        source: conf
        target: /etc-app
        read_only: true
volumes:
  site:
  cache:
  conf:
`), false)
	if err != nil {
		t.Fatal(err)
	}
	web := svcByName(t, plan, "web")
	want := []node.Volume{
		{Name: "site", Path: "/usr/share/nginx/html", ReadOnly: true},
		{Name: "cache", Path: "/var/cache/app"},
		{Name: "conf", Path: "/etc-app", ReadOnly: true},
	}
	if len(web.Volumes) != len(want) {
		t.Fatalf("volumes: %+v", web.Volumes)
	}
	for i, v := range want {
		if web.Volumes[i].Name != v.Name || web.Volumes[i].Path != v.Path || web.Volumes[i].ReadOnly != v.ReadOnly {
			t.Errorf("volume %d: %+v, want %+v", i, web.Volumes[i], v)
		}
	}
	if !hasNote(web, NoteOK, "compose.note.volume_ro") || !hasNote(web, NoteInfo, "compose.note.volume_options") {
		t.Errorf("notes: %+v", web.Notes)
	}

	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	if plan, err = f.m.PlanCompose(ctx, "lab", []byte("services:\n  web:\n    image: nginx:1.29-alpine\n    volumes: [\"site:/usr/share/nginx/html:ro\"]\nvolumes:\n  site:\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateFromCompose(ctx, f.who, "lab", plan, nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_web")
	if len(spec.Volumes) != 1 || !spec.Volumes[0].ReadOnly {
		t.Errorf("deploy spec volumes: %+v", spec.Volumes)
	}
	_, s, err := f.m.GetService(ctx, "lab", "web")
	if err != nil {
		t.Fatal(err)
	}
	vols, err := f.m.ListServiceVolumes(ctx, "lab", s)
	if err != nil || len(vols) != 1 || !vols[0].ReadOnly {
		t.Errorf("the disks tab must say read-only: %+v %v", vols, err)
	}
}
