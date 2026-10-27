package projects

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/volumes"
)

// The fake node's Docker volumes: name → the folder it binds to ("" for a
// plain volume), per fake node.
var fakeVolumes sync.Map // *fakeNode -> map[string]string

func (f *fakeNode) volumes() map[string]string {
	v, _ := fakeVolumes.LoadOrStore(f, map[string]string{})
	return v.(map[string]string)
}

func (f *fakeNode) VolumeDevice(_ context.Context, name string) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dev, ok := f.volumes()[name]
	return ok, dev, nil
}

func (f *fakeNode) SwitchVolume(_ context.Context, spec node.ServiceSpec, v node.Volume, device string) error {
	if !node.SlugRE.MatchString(spec.Project) || !node.SlugRE.MatchString(spec.Service) || spec.ServiceID == "" {
		return errors.New("switch without the owner's identity")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	owner, _ := spec.VolumeOwner(v)
	for c, s := range f.deployed {
		for _, sv := range s.Volumes {
			if o, _ := s.VolumeOwner(sv); o == owner && sv.Name == v.Name {
				return errors.New("in use by " + c)
			}
		}
	}
	f.volumes()[node.VolumeName(spec.Project, owner, v.Name)] = device
	return nil
}

func (f *fakeNode) RemoveVolume(_ context.Context, project, service, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.volumes(), node.VolumeName(project, service, name))
	return nil
}

// limits wires the volume limits to a temporary data directory, with the
// root unit "installed" (it answered once).
func (f *fixture) limits(t *testing.T, usage map[string]int64) volumes.Paths {
	t.Helper()
	w := volumes.NewWriter(t.TempDir())
	f.m.SetVolumeLimits(w, func(name string) (int64, bool) {
		n, ok := usage[name]
		return n, ok
	})
	if err := w.Write(nil, true); err != nil {
		t.Fatal(err)
	}
	if err := volumes.WriteApplied(w.Paths, nil); err != nil {
		t.Fatal(err)
	}
	return w.Paths
}

// unit plays the root unit: it answers every entry of the current desired
// state, successfully unless fail names the entry's op.
func (f *fixture) unit(t *testing.T, p volumes.Paths, fail map[string]string) []volumes.Entry {
	t.Helper()
	st := (&volumes.Writer{Paths: p}).Current()
	var res []volumes.Result
	for _, e := range st.Volumes {
		r := volumes.Result{Name: e.Name, Op: e.Op, OK: true, Size: e.Size}
		if e.Op == volumes.OpMount || e.Op == volumes.OpImport {
			r.Mounted, r.Used, r.Total = true, 1<<30, uint64(e.Size)
		}
		if msg, ok := fail[e.Op]; ok {
			r.OK, r.Error = false, msg
		}
		res = append(res, r)
	}
	if err := volumes.WriteApplied(p, res); err != nil {
		t.Fatal(err)
	}
	return st.Volumes
}

func (f *fixture) sync(t *testing.T) {
	t.Helper()
	f.m.syncVolumeLimits(context.Background(), false)
}

func (f *fixture) limitState(t *testing.T, name string) (string, string) {
	t.Helper()
	r, ok := f.m.limitOf(context.Background(), name)
	if !ok {
		return "", ""
	}
	return r.State, r.Step
}

func desiredOps(p volumes.Paths) map[string]string {
	out := map[string]string{}
	for _, e := range (&volumes.Writer{Paths: p}).Current().Volumes {
		out[e.Name] = e.Op
	}
	return out
}

const gib = volumes.GiB

func TestVolumeLimitNewDiskGrowAndWipe(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.limits(t, nil)
	f.service(t)
	if err := f.m.AddServiceVolume(ctx, f.who, "lab", "web", "media", "/app/media"); err != nil {
		t.Fatal(err)
	}
	const name = "hangar_lab_web_media"
	for _, size := range []int64{0, gib - 1, volumes.MaxSize + 1} {
		if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", size); !isKey(err, "volume.limit.error.size") {
			t.Errorf("size %d: %v", size, err)
		}
	}
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "nope", 2*gib); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown disk: %v", err)
	}
	// The volume does not exist on Docker yet: it is born on its image.
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 2*gib); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.limitState(t, name); st != limitNew {
		t.Fatalf("state = %s", st)
	}
	f.sync(t)
	if desiredOps(p)[name] != volumes.OpMount {
		t.Fatalf("desired = %v", desiredOps(p))
	}
	// Another limit request while this one is not in place.
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 3*gib); !isKey(err, "volume.limit.error.busy") {
		t.Errorf("second request: %v", err)
	}
	f.unit(t, p, nil)
	f.sync(t)
	if st, _ := f.limitState(t, name); st != limitActive {
		t.Fatalf("state after the unit answered = %s", st)
	}

	// Deploys bind the volume to the image.
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_web")
	i := slices.IndexFunc(spec.Volumes, func(v node.Volume) bool { return v.Name == "media" })
	if i < 0 || spec.Volumes[i].Device != p.Device(name) {
		t.Fatalf("deployed volumes: %+v", spec.Volumes)
	}

	// Growing: one write, applied live; never shrinking.
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 2*gib); !isKey(err, "volume.limit.error.shrink") {
		t.Errorf("same size: %v", err)
	}
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 5*gib); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	_, s, _ := f.m.GetService(ctx, "lab", "web")
	vols, _ := f.m.ListServiceVolumes(ctx, "lab", s)
	if l := vols[0].Limit; l == nil || l.Size != 5*gib || !l.Pending {
		t.Errorf("limit before the unit applied it: %+v", l)
	}
	f.unit(t, p, nil)
	f.sync(t)
	vols, _ = f.m.ListServiceVolumes(ctx, "lab", s)
	if l := vols[0].Limit; l == nil || l.Pending || l.Total != uint64(5*gib) || vols[0].Used != gib {
		t.Errorf("limit after: %+v (used %d)", l, vols[0].Used)
	}

	// Removing a limited disk keeps it until a deploy goes live without
	// it, then deletes its image.
	if err := f.m.RemoveServiceVolume(ctx, f.who, "lab", "web", "media", false); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.limitState(t, name); st != limitActive {
		t.Fatalf("state right after removing = %s", st)
	}
	f.n.mu.Lock()
	delete(f.n.deployed, "lab_web") // the deploy that dropped it
	f.n.mu.Unlock()
	proj, svc, _ := f.m.GetService(ctx, "lab", "web")
	f.m.emptyVolumeTrash(ctx, proj, svc)
	if st, _ := f.limitState(t, name); st != limitRemove {
		t.Fatalf("state after the deploy = %s", st)
	}
	f.sync(t)
	if desiredOps(p)[name] != volumes.OpRemove {
		t.Fatalf("desired = %v", desiredOps(p))
	}
	f.unit(t, p, nil)
	f.sync(t)
	if st, _ := f.limitState(t, name); st != "" {
		t.Errorf("row left after the image was removed: %s", st)
	}
	if len(desiredOps(p)) != 0 {
		t.Errorf("desired = %v", desiredOps(p))
	}
}

// existing gives the fixture's service a disk that already holds data.
func existing(t *testing.T, f *fixture) string {
	t.Helper()
	ctx := context.Background()
	f.service(t)
	if err := f.m.AddServiceVolume(ctx, f.who, "lab", "web", "media", "/app/media"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	f.n.mu.Lock()
	f.n.volumes()["hangar_lab_web_media"] = ""
	f.n.mu.Unlock()
	return "hangar_lab_web_media"
}

func TestVolumeLimitMovesExistingData(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.limits(t, map[string]int64{"hangar_lab_web_media": 3 * gib})
	name := existing(t, f)

	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 3*gib); !isKey(err, "volume.limit.error.too_small") {
		t.Errorf("a limit the data does not fit in: %v", err)
	}
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 6*gib); err != nil {
		t.Fatal(err)
	}
	if st, step := f.limitState(t, name); st != limitMigrate || step != stepMount {
		t.Fatalf("state = %s/%s", st, step)
	}
	f.sync(t) // mount asked
	f.unit(t, p, nil)
	f.sync(t) // mounted → stop
	if _, step := f.limitState(t, name); step != stepStop {
		t.Fatalf("step = %s", step)
	}
	f.sync(t) // stopped → import
	if _, ok := f.n.spec("lab_web"); ok {
		t.Fatal("the container still exists while its data moves")
	}
	if _, step := f.limitState(t, name); step != stepImport || desiredOps(p)[name] != volumes.OpImport {
		t.Fatalf("step = %s, desired %v", step, desiredOps(p))
	}
	// Nothing deploys while the data moves.
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); !errors.Is(err, ErrVolumeMoving) {
		t.Errorf("deploy while moving: %v", err)
	}
	if err := f.m.DeleteService(ctx, f.who, "lab", "web"); !isKey(err, "volume.limit.error.busy") {
		t.Errorf("delete while moving: %v", err)
	}
	f.unit(t, p, nil)
	f.sync(t) // imported → switch
	f.sync(t) // switched → active, deployed again
	f.m.Wait()
	if st, _ := f.limitState(t, name); st != limitActive {
		t.Fatalf("state = %s", st)
	}
	f.n.mu.Lock()
	dev := f.n.volumes()[name]
	f.n.mu.Unlock()
	if dev != p.Device(name) {
		t.Errorf("Docker volume binds to %q", dev)
	}
	spec, ok := f.n.spec("lab_web")
	if !ok {
		t.Fatal("not started again")
	}
	if i := slices.IndexFunc(spec.Volumes, func(v node.Volume) bool { return v.Name == "media" }); spec.Volumes[i].Device != p.Device(name) {
		t.Errorf("started on %+v", spec.Volumes[i])
	}
	if desiredOps(p)[name] != volumes.OpMount {
		t.Errorf("desired = %v", desiredOps(p))
	}

	// Taking the limit away moves the data back.
	if err := f.m.RemoveVolumeLimit(ctx, f.who, "lab", "web", "media"); err != nil {
		t.Fatal(err)
	}
	f.sync(t) // stop
	f.sync(t) // switch to a plain volume
	if _, step := f.limitState(t, name); step != stepExport || desiredOps(p)[name] != volumes.OpExport {
		t.Fatalf("step = %s, desired %v", step, desiredOps(p))
	}
	f.n.mu.Lock()
	dev = f.n.volumes()[name]
	f.n.mu.Unlock()
	if dev != "" {
		t.Errorf("not plain: %q", dev)
	}
	f.unit(t, p, nil)
	f.sync(t)
	f.m.Wait()
	if st, _ := f.limitState(t, name); st != "" {
		t.Errorf("limit left: %s", st)
	}
	spec, _ = f.n.spec("lab_web")
	if i := slices.IndexFunc(spec.Volumes, func(v node.Volume) bool { return v.Name == "media" }); i < 0 || spec.Volumes[i].Device != "" {
		t.Errorf("restarted with %+v", spec.Volumes)
	}
}

func TestVolumeLimitFailedCopyGoesBack(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.limits(t, map[string]int64{"hangar_lab_web_media": gib})
	name := existing(t, f)
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 4*gib); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	f.unit(t, p, nil)
	f.sync(t)
	f.sync(t) // stopped, import asked
	f.unit(t, p, map[string]string{volumes.OpImport: "not enough free space"})
	f.sync(t)
	f.m.Wait()
	st, step := f.limitState(t, name)
	if st != limitFailed || step != stepCleanup || desiredOps(p)[name] != volumes.OpRemove {
		t.Fatalf("state = %s/%s, desired %v", st, step, desiredOps(p))
	}
	// Back on its plain volume, untouched.
	spec, ok := f.n.spec("lab_web")
	if !ok || spec.Volumes[slices.IndexFunc(spec.Volumes, func(v node.Volume) bool { return v.Name == "media" })].Device != "" {
		t.Fatalf("not back on the plain volume: %+v", spec)
	}
	f.unit(t, p, nil)
	f.sync(t)
	_, s, _ := f.m.GetService(ctx, "lab", "web")
	vols, _ := f.m.ListServiceVolumes(ctx, "lab", s)
	if l := vols[0].Limit; l == nil || !l.Failed() || !l.Cleaned || l.Error != "not enough free space" {
		t.Fatalf("shown: %+v", l)
	}
	// Dismissed.
	if err := f.m.RemoveVolumeLimit(ctx, f.who, "lab", "web", "media"); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.limitState(t, name); st != "" {
		t.Errorf("still %s", st)
	}
}

func TestVolumeLimitGoesWithTheService(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.limits(t, nil)
	f.service(t)
	if err := f.m.AddServiceVolume(ctx, f.who, "lab", "web", "media", "/app/media"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 2*gib); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	f.unit(t, p, nil)
	f.sync(t)
	if err := f.m.DeleteService(ctx, f.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	if desiredOps(p)["hangar_lab_web_media"] != volumes.OpRemove {
		t.Fatalf("desired = %v", desiredOps(p))
	}
	// A new service with the same name waits for the old image to go.
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if err := f.m.AddServiceVolume(ctx, f.who, "lab", "web", "media", "/app/media"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); !errors.Is(err, ErrVolumeMoving) {
		t.Errorf("deploy onto a disk being deleted: %v (%s)", err, s.ID)
	}
	f.unit(t, p, nil)
	f.sync(t)
	if len(desiredOps(p)) != 0 {
		t.Errorf("desired = %v", desiredOps(p))
	}
}

func TestVolumeLimitUnavailableAndSilentUnit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t)
	if err := f.m.AddServiceVolume(ctx, f.who, "lab", "web", "media", "/app/media"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 2*gib); !isKey(err, "volume.limit.error.unavailable") {
		t.Errorf("without the writer: %v", err)
	}
	// A writer but the unit never ran (no applied.json): not offered.
	w := volumes.NewWriter(t.TempDir())
	f.m.SetVolumeLimits(w, nil)
	if f.m.VolumeLimitsAvailable() {
		t.Error("available before the unit answered")
	}
	p := f.limits(t, nil)
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", "web", "media", 2*gib); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	// The unit does not answer the write for minutes.
	f.m.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	f.sync(t)
	r, _ := f.m.limitOf(ctx, "hangar_lab_web_media")
	if r.Error == "" || r.State != limitNew {
		t.Errorf("silent unit: %+v", r)
	}
	_ = p
}

const limitTemplate = `services:
  app:
    image: nginx:1.29-alpine
    volumes: ["files:/srv/files"]
    healthcheck:
      test: ["CMD", "true"]
    deploy:
      resources:
        limits: { memory: 64M, cpus: "0.5" }
  tool:
    image: busybox:1.37
    volumes: ["files:/data:ro"]
    deploy:
      resources:
        limits: { memory: 32M, cpus: "0.1" }
volumes:
  files:
`

func TestVolumeLimitFromTemplate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.limits(t, nil)
	f.useTemplate(t, "lim", limitTemplate)
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	opt := TemplateOptions{Limits: map[string]int64{"files": 3 * gib}}
	if _, err := f.m.CreateFromTemplateWith(ctx, f.who, "lab", "lim", "store", nil, opt); !isKey(err, "volume.limit.error.sudo") {
		t.Fatalf("without sudo: %v", err)
	}
	sudo := f.who
	sudo.Sudo = true
	if _, err := f.m.CreateFromTemplateWith(ctx, sudo, "lab", "lim", "store", nil, TemplateOptions{Limits: map[string]int64{"other": 3 * gib}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown volume: %v", err)
	}
	volumePoll = 10 * time.Millisecond
	t.Cleanup(func() { volumePoll = time.Second })
	created, err := f.m.CreateFromTemplateWith(ctx, sudo, "lab", "lim", "store", nil, opt)
	if err != nil {
		t.Fatal(err)
	}
	name := "hangar_lab_store_files"
	if st, _ := f.limitState(t, name); st != limitNew {
		t.Fatalf("state = %s", st)
	}
	// The deploys wait for the image; the unit answers meanwhile.
	f.sync(t)
	f.unit(t, p, nil)
	f.sync(t)
	f.m.Wait()
	for _, s := range created {
		spec, ok := f.n.spec("lab_" + s.Slug)
		if !ok {
			t.Fatalf("%s not deployed", s.Slug)
		}
		if spec.Volumes[0].Device != p.Device(name) {
			t.Errorf("%s mounts %+v", s.Slug, spec.Volumes[0])
		}
	}
	// The sharer shows the owner's limit and cannot change it.
	tool := created[1]
	vols, _ := f.m.ListServiceVolumes(ctx, "lab", tool)
	if vols[0].Limit == nil || vols[0].Limit.Size != 3*gib {
		t.Errorf("sharer's view: %+v", vols[0])
	}
	if err := f.m.SetVolumeLimit(ctx, f.who, "lab", tool.Slug, "files", 5*gib); !isKey(err, "volume.limit.error.owner") {
		t.Errorf("limit from the sharer: %v", err)
	}
}
