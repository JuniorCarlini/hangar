//go:build unix

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeHost plays the commands the applier runs: mounting only records the
// mount point (the folder stays a plain folder of the test's disk), cp is
// the real one.
type fakeHost struct {
	t       *testing.T
	mounted map[string]string // mount point → loop device
	backing map[string]string // loop device → image
	calls   []string
	busy    map[string]bool // mount points umount refuses
	fail    map[string]error
	free    uint64 // what statfs reports available
	docker  map[string]DockerVolume
	root    string // where unmounted images keep their files
}

func newHost(t *testing.T) *fakeHost {
	return &fakeHost{
		t: t, mounted: map[string]string{}, backing: map[string]string{}, busy: map[string]bool{},
		fail: map[string]error{}, free: 100 * uint64(GiB), docker: map[string]DockerVolume{}, root: t.TempDir(),
	}
}

func (h *fakeHost) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	h.calls = append(h.calls, name+" "+strings.Join(args, " "))
	if err := h.fail[name]; err != nil {
		return []byte("boom"), err
	}
	switch name {
	case "mkfs.ext4":
		if _, err := os.Stat(args[len(args)-1]); err != nil {
			return nil, err
		}
	case "mount":
		img, mnt := args[len(args)-2], args[len(args)-1]
		dev := fmt.Sprintf("/dev/loop%d", len(h.backing))
		h.mounted[mnt], h.backing[dev] = dev, img
		h.move(h.stash(img), mnt) // the image's files come into view
	case "umount":
		mnt := args[0]
		if h.busy[mnt] {
			return []byte("target is busy"), errors.New("exit status 32")
		}
		h.move(mnt, h.stash(h.backing[h.mounted[mnt]])) // and leave it
		delete(h.mounted, mnt)
	case "losetup":
		if args[0] == "-n" {
			return []byte(h.backing[args[len(args)-1]] + "\n"), nil
		}
	case "cp":
		return exec.CommandContext(ctx, "cp", args...).CombinedOutput() //nolint:gosec // test
	}
	return nil, nil
}

// stash holds an image's files while it is not mounted.
func (h *fakeHost) stash(img string) string {
	d := filepath.Join(h.root, filepath.Base(img))
	if err := os.MkdirAll(d, 0o755); err != nil {
		h.t.Fatal(err)
	}
	return d
}

func (h *fakeHost) move(from, to string) {
	entries, _ := os.ReadDir(from)
	for _, e := range entries {
		if err := os.Rename(filepath.Join(from, e.Name()), filepath.Join(to, e.Name())); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *fakeHost) ProbeVolume(_ context.Context, name string) (DockerVolume, error) {
	return h.docker[name], nil
}

func (h *fakeHost) applier(dir string) *Applier {
	a := &Applier{
		Paths: Paths{Data: dir}, Run: h.run, NotRoot: true, Log: slog.New(slog.DiscardHandler),
		Docker: func(context.Context) (Docker, error) { return h, nil },
	}
	a.mounts = func() (map[string]string, error) { return h.mounted, nil }
	a.statfs = func(string) (uint64, uint64, uint64, error) { return 1 << 20, h.free + 1<<20, h.free, nil }
	return a
}

func dataDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func writeDesired(t *testing.T, dir string, entries ...Entry) State {
	t.Helper()
	w := NewWriter(dir)
	if err := w.Write(entries, true); err != nil {
		t.Fatal(err)
	}
	return w.Current()
}

func readApplied(t *testing.T, dir string) Applied {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "volumes", appliedFile))
	if err != nil {
		t.Fatal(err)
	}
	var a Applied
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestApplyCreatesSparseImageAndMounts(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	st := writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := Paths{Data: dir}
	fi, err := os.Stat(p.Image(vol))
	if err != nil || fi.Size() != 2*GiB {
		t.Fatalf("image: %v %v", fi, err)
	}
	if n, _ := allocated(p.Images()); n > 1<<20 {
		t.Errorf("the image takes %d bytes: it must be sparse", n)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("image mode %v", fi.Mode())
	}
	if d, err := os.Stat(p.Images()); err != nil || d.Mode().Perm() != 0o700 {
		t.Errorf("images folder: %v %v", d, err)
	}
	if h.mounted[p.Mount(vol)] == "" {
		t.Error("not mounted")
	}
	if fi, err := os.Stat(p.Device(vol)); err != nil || !fi.IsDir() {
		t.Error("no data folder in the image")
	}
	mkfs := slices.IndexFunc(h.calls, func(c string) bool { return strings.HasPrefix(c, "mkfs.ext4 -q -F -m 0") })
	if mkfs < 0 || !strings.HasSuffix(h.calls[mkfs], ".img.new") {
		t.Errorf("mkfs not run on the temporary image: %v", h.calls)
	}
	if !slices.ContainsFunc(h.calls, func(c string) bool { return strings.Contains(c, "-o loop,nodev,nosuid") }) {
		t.Errorf("mount options: %v", h.calls)
	}
	ap := readApplied(t, dir)
	if ap.Hash != st.hash() || len(ap.Volumes) != 1 || !ap.Volumes[0].OK || !ap.Volumes[0].Mounted || ap.Volumes[0].Size != 2*GiB {
		t.Errorf("applied = %+v", ap)
	}

	// Again: idempotent, no second mkfs or mount.
	h.calls = nil
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "mkfs") || strings.HasPrefix(c, "mount") {
			t.Errorf("second run did %q", c)
		}
	}
}

func TestApplyGrowsOnlineAndNeverShrinks(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := Paths{Data: dir}
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 3 * GiB})
	h.calls = nil
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p.Image(vol)); fi.Size() != 3*GiB {
		t.Errorf("size after growing = %d", fi.Size())
	}
	dev := h.mounted[p.Mount(vol)]
	for _, want := range []string{"losetup -c " + dev, "resize2fs " + dev} {
		if !slices.Contains(h.calls, want) {
			t.Errorf("missing %q in %v", want, h.calls)
		}
	}
	// Smaller: left alone (the panel refuses it; the unit never shrinks).
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p.Image(vol)); fi.Size() != 3*GiB {
		t.Errorf("shrunk to %d", fi.Size())
	}
	// A loop device backed by something else is never resized.
	h.backing[dev] = "/somewhere/else.img"
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 4 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err == nil {
		t.Error("grew a loop device backed by another file")
	}
}

func TestApplyRefusesLinks(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(dir, "volume-images")); err != nil {
		t.Fatal(err)
	}
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err == nil {
		t.Fatal("followed a link for the images folder")
	}
	if ap := readApplied(t, dir); ap.Error == "" {
		t.Error("the error is not reported")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("wrote through the link: %v", entries)
	}

	// An image that is a link.
	dir = dataDir(t)
	p := Paths{Data: dir}
	if err := os.MkdirAll(p.Images(), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p.Image(vol)); err != nil {
		t.Fatal(err)
	}
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	_ = h.applier(dir).Apply(context.Background())
	if ap := readApplied(t, dir); ap.Volumes[0].OK {
		t.Error("used an image that is a link")
	}
	if b, _ := os.ReadFile(target); string(b) != "x" {
		t.Error("the link's target changed")
	}
}

// makeVolume builds a plain Docker volume folder with a few kinds of
// entries.
func makeVolume(t *testing.T, root, name string) string {
	t.Helper()
	data := filepath.Join(root, "docker", "volumes", name, "_data")
	if err := os.MkdirAll(filepath.Join(data, "pg", "base"), 0o700); err != nil {
		t.Fatal(err)
	}
	for p, body := range map[string]string{"pg/PG_VERSION": "18\n", "pg/base/1": strings.Repeat("x", 9000), "readme": "hi"} {
		if err := os.WriteFile(filepath.Join(data, p), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("pg/PG_VERSION", filepath.Join(data, "version")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(data, 0o750); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestImportCopiesAndVerifies(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	src := makeVolume(t, dataDir(t), vol)
	h.docker[vol] = DockerVolume{Exists: true, Managed: true, Driver: "local", Mountpoint: src}
	writeDesired(t, dir, Entry{Name: vol, Op: OpImport, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	dst := Paths{Data: dir}.Device(vol)
	if err := verifyCopy(src, dst); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o750 {
		t.Errorf("top folder mode %v, want the volume's", fi.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(dst, "version")); l != "pg/PG_VERSION" {
		t.Errorf("link = %q", l)
	}
	if ap := readApplied(t, dir); !ap.Volumes[0].OK {
		t.Errorf("applied = %+v", ap)
	}
	// Leftovers of an earlier, interrupted copy are replaced.
	if err := os.WriteFile(filepath.Join(dst, "stale"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "stale")); err == nil {
		t.Error("an earlier copy's leftover survived")
	}
}

func TestImportRefusals(t *testing.T) {
	cases := map[string]func(h *fakeHost, src string){
		"in use": func(h *fakeHost, src string) {
			h.docker[vol] = DockerVolume{Exists: true, Managed: true, Driver: "local", Mountpoint: src, InUse: true}
		},
		"not hangar's": func(h *fakeHost, src string) {
			h.docker[vol] = DockerVolume{Exists: true, Driver: "local", Mountpoint: src}
		},
		"odd folder": func(h *fakeHost, src string) {
			h.docker[vol] = DockerVolume{Exists: true, Managed: true, Driver: "local", Mountpoint: filepath.Dir(src)}
		},
		"no disk space": func(h *fakeHost, src string) {
			h.docker[vol] = DockerVolume{Exists: true, Managed: true, Driver: "local", Mountpoint: src}
			h.free = 1 << 20
		},
		"other driver": func(h *fakeHost, src string) {
			h.docker[vol] = DockerVolume{Exists: true, Managed: true, Driver: "nfs", Mountpoint: src}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := dataDir(t)
			h := newHost(t)
			src := makeVolume(t, dataDir(t), vol)
			setup(h, src)
			writeDesired(t, dir, Entry{Name: vol, Op: OpImport, Size: 2 * GiB})
			if err := h.applier(dir).Apply(context.Background()); err == nil {
				t.Fatal("imported")
			}
			if ap := readApplied(t, dir); ap.Volumes[0].OK || ap.Volumes[0].Error == "" {
				t.Errorf("applied = %+v", ap)
			}
			if _, err := os.Stat(filepath.Join(src, "pg", "PG_VERSION")); err != nil {
				t.Error("the source changed")
			}
		})
	}
}

func TestImportAfterSwitchIsANoOp(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	p := Paths{Data: dir}
	// The volume already binds to the image (the panel switched it): the
	// copy must not run again (its "source" is the image itself).
	h.docker[vol] = DockerVolume{
		Exists: true, Managed: true, Driver: "local",
		Options: map[string]string{"type": "none", "o": "bind", "device": p.Device(vol)}, Mountpoint: "/x/" + vol + "/_data", InUse: true,
	}
	writeDesired(t, dir, Entry{Name: vol, Op: OpImport, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(h.calls, func(c string) bool { return strings.HasPrefix(c, "cp ") }) {
		t.Errorf("copied again: %v", h.calls)
	}
}

func TestExportCopiesBackAndDeletes(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	p := Paths{Data: dir}
	src := makeVolume(t, dataDir(t), vol)
	h.docker[vol] = DockerVolume{Exists: true, Managed: true, Driver: "local", Mountpoint: src}
	writeDesired(t, dir, Entry{Name: vol, Op: OpImport, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The panel recreated the plain volume, empty.
	plain := filepath.Join(dataDir(t), "docker", "volumes", vol, "_data")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	h.docker[vol] = DockerVolume{Exists: true, Managed: true, Driver: "local", Mountpoint: plain}
	writeDesired(t, dir, Entry{Name: vol, Op: OpExport})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := verifyCopy(src, plain); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.Image(vol)); !os.IsNotExist(err) {
		t.Error("image not deleted")
	}
	if _, ok := h.mounted[p.Mount(vol)]; ok {
		t.Error("still mounted")
	}
	// Again: the image is gone, so it was exported; nothing to do.
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A volume still bound to the image is not a target.
	dir2 := dataDir(t)
	writeDesired(t, dir2, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	_ = h.applier(dir2).Apply(context.Background())
	h.docker[vol] = DockerVolume{
		Exists: true, Managed: true, Driver: "local",
		Options: map[string]string{"device": Paths{Data: dir2}.Device(vol)}, Mountpoint: plain,
	}
	writeDesired(t, dir2, Entry{Name: vol, Op: OpExport})
	if err := h.applier(dir2).Apply(context.Background()); err == nil {
		t.Error("exported into the bound volume")
	}
	if _, err := os.Stat(Paths{Data: dir2}.Image(vol)); err != nil {
		t.Error("image deleted after a refused export")
	}
}

func TestRemoveUnmountsAndDeletesButNeverWhileBusy(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	p := Paths{Data: dir}
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.busy[p.Mount(vol)] = true
	writeDesired(t, dir, Entry{Name: vol, Op: OpRemove})
	if err := h.applier(dir).Apply(context.Background()); err == nil {
		t.Fatal("removed a busy image")
	}
	if _, err := os.Stat(p.Image(vol)); err != nil {
		t.Fatal("deleted the image of a busy mount")
	}
	delete(h.busy, p.Mount(vol))
	if err := h.applier(dir).Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.Image(vol), p.Mount(vol)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("%s left behind", path)
		}
	}
	if ap := readApplied(t, dir); !ap.Volumes[0].OK {
		t.Errorf("applied = %+v", ap)
	}
}

func TestApplyFailedMkfsLeavesNoImage(t *testing.T) {
	dir := dataDir(t)
	h := newHost(t)
	h.fail["mkfs.ext4"] = errors.New("exit status 1")
	writeDesired(t, dir, Entry{Name: vol, Op: OpMount, Size: 2 * GiB})
	if err := h.applier(dir).Apply(context.Background()); err == nil {
		t.Fatal("no error")
	}
	entries, _ := os.ReadDir(Paths{Data: dir}.Images())
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".img") || strings.HasSuffix(e.Name(), ".new") {
			t.Errorf("left %s", e.Name())
		}
	}
	ap := readApplied(t, dir)
	if ap.Volumes[0].OK || !strings.Contains(ap.Volumes[0].Error, "mkfs.ext4") {
		t.Errorf("applied = %+v", ap)
	}
}

func TestApplyBadDesiredIsReported(t *testing.T) {
	dir := dataDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "volumes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "volumes", desiredFile), []byte(`{"version":1,"volumes":[{"name":"../../etc","op":"remove"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHost(t)
	if err := h.applier(dir).Apply(context.Background()); err == nil {
		t.Fatal("accepted")
	}
	if ap := readApplied(t, dir); ap.Error == "" || len(h.calls) != 0 {
		t.Errorf("applied = %+v, calls %v", ap, h.calls)
	}
}
