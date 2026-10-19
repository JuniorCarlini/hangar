package projects

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
)

// ensured records the volumes created ahead of the deploys
// (node.VolumeEnsurer), per fake node.
var ensured sync.Map // *fakeNode -> *[]node.ServiceSpec

func (f *fakeNode) EnsureVolumes(_ context.Context, spec node.ServiceSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	v, _ := ensured.LoadOrStore(f, &[]node.ServiceSpec{})
	f.mu.Lock()
	defer f.mu.Unlock()
	*v.(*[]node.ServiceSpec) = append(*v.(*[]node.ServiceSpec), spec)
	return nil
}

func ensuredBy(f *fakeNode) []node.ServiceSpec {
	v, ok := ensured.Load(f)
	if !ok {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]node.ServiceSpec(nil), *v.(*[]node.ServiceSpec)...)
}

func isKey(err error, key string) bool {
	var ie *i18n.Error
	return errors.As(err, &ie) && ie.Key == key
}

const sharedTemplate = `services:
  app:
    image: nginx:1.29-alpine
    volumes: ["world:/srv/world"]
    healthcheck:
      test: ["CMD", "true"]
      start_period: 5m
    deploy:
      resources:
        limits: { memory: 64M, cpus: "0.5" }
  tool:
    image: busybox:1.37
    volumes: ["world:/data:ro"]
    deploy:
      resources:
        limits: { memory: 32M, cpus: "0.1" }
volumes:
  world:
`

func TestTemplateSharedVolume(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.useTemplate(t, "shared", sharedTemplate)
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	created, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "shared", "game", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	app, tool := created[0], created[1]

	// Created once, ahead of the deploys, with the owner's identity.
	pre := ensuredBy(f.n)
	if len(pre) != 1 || pre[0].ServiceID != app.ID || len(pre[0].Volumes) != 1 || pre[0].Volumes[0].Name != "world" {
		t.Fatalf("volumes created ahead: %+v", pre)
	}
	owner, _ := f.n.spec("lab_game")
	sharer, _ := f.n.spec("lab_game-tool")
	if v := owner.Volumes[0]; v.Service != "" {
		t.Errorf("owner mounts its own volume: %+v", v)
	}
	if v := sharer.Volumes[0]; v.Service != "game" || v.ServiceID != app.ID || !v.ReadOnly || v.Path != "/data" {
		t.Errorf("sharer mounts the owner's volume: %+v", v)
	}
	if ownerSlug, _ := sharer.VolumeOwner(sharer.Volumes[0]); node.VolumeName("lab", ownerSlug, "world") != node.VolumeName("lab", "game", "world") {
		t.Error("both services must mount the same Docker volume")
	}

	// The disks tab says who shares what, with the one Docker name.
	ownerVols, err := f.m.ListServiceVolumes(ctx, "lab", app)
	if err != nil || len(ownerVols) != 1 || len(ownerVols[0].SharedWith) != 1 || ownerVols[0].SharedWith[0] != "game-tool" {
		t.Errorf("owner's disks: %+v %v", ownerVols, err)
	}
	toolVols, err := f.m.ListServiceVolumes(ctx, "lab", tool)
	if err != nil || len(toolVols) != 1 || toolVols[0].Owner != "game" || toolVols[0].Docker != ownerVols[0].Docker {
		t.Errorf("sharer's disks: %+v %v", toolVols, err)
	}

	// The owner stays while another service mounts its volume.
	if err := f.m.DeleteService(ctx, f.who, "lab", "game"); !isKey(err, "service.error.volume_shared") {
		t.Fatalf("deleting the owner: %v", err)
	}
	if _, _, err := f.m.GetService(ctx, "lab", "game"); err != nil {
		t.Fatal("the owner was deleted anyway")
	}
	if err := f.m.DeleteService(ctx, f.who, "lab", "game-tool"); err != nil {
		t.Fatalf("deleting the sharer: %v", err)
	}
	if err := f.m.DeleteService(ctx, f.who, "lab", "game"); err != nil {
		t.Fatalf("deleting the owner once alone: %v", err)
	}
}

func TestComposeSharedVolume(t *testing.T) {
	const file = `
services:
  web:
    image: ghcr.io/acme/site:1.0
    volumes: ["media:/app/media"]
  worker:
    image: ghcr.io/acme/site:1.0
    volumes: ["media:/app/media", "scratch:/tmp/work"]
  db:
    image: postgres:18-alpine
    volumes: ["media:/var/lib/postgresql/data"]
volumes:
  media:
  scratch:
`
	plan, err := ParseCompose([]byte(file), false)
	if err != nil {
		t.Fatal(err)
	}
	web, worker, db := svcByName(t, plan, "web"), svcByName(t, plan, "worker"), svcByName(t, plan, "db")
	if web.Volumes[0].Service != "" || !hasNote(web, NoteInfo, "compose.note.volume_owner") {
		t.Errorf("first service owns it: %+v %+v", web.Volumes, web.Notes)
	}
	if worker.Volumes[0].Service != "web" || worker.Volumes[1].Service != "" || !hasNote(worker, NoteOK, "compose.note.volume_shared") {
		t.Errorf("second mounts the first's: %+v %+v", worker.Volumes, worker.Notes)
	}
	if len(db.Volumes) != 0 {
		t.Errorf("a catalog database keeps its own disk: %+v", db.Volumes)
	}

	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	if plan, err = f.m.PlanCompose(ctx, "lab", []byte(file)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateFromCompose(ctx, f.who, "lab", plan, nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	w, _ := f.n.spec("lab_worker")
	_, webRow, _ := f.m.GetService(ctx, "lab", "web")
	if len(w.Volumes) != 2 || w.Volumes[0].Service != "web" || w.Volumes[0].ServiceID != webRow.ID {
		t.Errorf("worker spec: %+v", w.Volumes)
	}
	// The worker may detach its mount, never delete the web's data.
	if err := f.m.RemoveServiceVolume(ctx, f.who, "lab", "worker", "media", true); !isKey(err, "volume.error.shared_wipe") {
		t.Errorf("wiping another service's disk: %v", err)
	}
	if err := f.m.RemoveServiceVolume(ctx, f.who, "lab", "web", "media", false); !isKey(err, "volume.error.shared_owner") {
		t.Errorf("detaching a disk others use: %v", err)
	}
	if err := f.m.RemoveServiceVolume(ctx, f.who, "lab", "worker", "media", false); err != nil {
		t.Errorf("detaching the mount: %v", err)
	}
	if err := f.m.DeleteService(ctx, f.who, "lab", "web"); err != nil {
		t.Errorf("no one else mounts it now: %v", err)
	}
}
