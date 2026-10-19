//go:build unix

package volumes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// The root side. Everything here runs as root, started by
// hangar-volumes.service, on input written by the unprivileged panel: the
// desired file is validated again, every path is derived from a volume
// name that matches node.VolumeName, the folders must be root's and real
// folders (never symbolic links), and data is only ever copied between a
// volume no running container uses and a fresh image.

// Runner runs one fixed command (mkfs.ext4, mount, umount, losetup,
// resize2fs, cp); a test seam.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs the command for real.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed binaries, validated arguments
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return cmd.CombinedOutput()
}

// DockerVolume is what the root unit needs to know about a Docker volume.
type DockerVolume struct {
	Exists     bool
	Managed    bool // carries hangar.managed=true
	Driver     string
	Options    map[string]string
	Mountpoint string
	// InUse: a running container mounts it.
	InUse bool
}

// Docker reads Docker volumes for the root unit.
type Docker interface {
	ProbeVolume(ctx context.Context, name string) (DockerVolume, error)
}

// Applier applies the desired state (root side).
type Applier struct {
	Paths Paths
	Run   Runner
	// Docker connects to Docker when an entry needs it (copying data in or
	// out). At boot the unit runs before Docker: mounting needs no Docker.
	Docker func(ctx context.Context) (Docker, error)
	Log    *slog.Logger
	// NotRoot skips the "owned by root" checks (tests only).
	NotRoot bool

	mounts func() (map[string]string, error)
	statfs func(path string) (used, total, avail uint64, err error)
	now    func() time.Time
	docker Docker
	// done are the copies finished during this run: when the panel writes
	// again while one was copying, the next pass does not copy again.
	done map[string]bool
}

// reserve is kept free on the disk a copy writes to.
const reserve = 256 << 20

// Apply reads the desired state and applies it; the result, success or
// errors, goes to applied.json for the panel. When the panel wrote again
// while it worked, it applies the new state too.
func (a *Applier) Apply(ctx context.Context) error {
	a.defaults()
	if err := a.prepare(); err != nil {
		_ = a.report(State{Version: 1, Volumes: []Entry{}}, Applied{Error: err.Error()})
		return err
	}
	unlock, err := a.lock()
	if err != nil {
		return err
	}
	defer unlock()
	var last error
	for range 4 {
		raw, err := os.ReadFile(filepath.Join(a.Paths.Dir(), desiredFile)) //nolint:gosec // fixed path under the data dir
		if errors.Is(err, fs.ErrNotExist) {
			raw = []byte(`{"version":1,"written":0,"volumes":[]}`)
		} else if err != nil {
			return err
		}
		st, err := decodeState(raw)
		res := Applied{}
		if err != nil {
			res.Error = err.Error()
			last = err
		} else {
			last = nil
			for _, e := range st.Volumes {
				r := a.apply(ctx, e)
				if r.Error != "" {
					a.Log.Warn("volume", "name", e.Name, "op", e.Op, "error", r.Error)
					last = errors.New("some volumes failed: see applied.json")
				} else {
					a.Log.Info("volume", "name", e.Name, "op", e.Op, "size", r.Size)
				}
				res.Volumes = append(res.Volumes, r)
			}
		}
		if err := a.report(st, res); err != nil {
			return err
		}
		again, _ := os.ReadFile(filepath.Join(a.Paths.Dir(), desiredFile)) //nolint:gosec // fixed path under the data dir
		if bytes.Equal(again, raw) || len(again) == 0 {
			break
		}
	}
	return last
}

func (a *Applier) defaults() {
	if a.Run == nil {
		a.Run = ExecRunner
	}
	if a.Log == nil {
		a.Log = slog.Default()
	}
	if a.mounts == nil {
		a.mounts = readMounts
	}
	if a.statfs == nil {
		a.statfs = statfs
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.done == nil {
		a.done = map[string]bool{}
	}
}

func (a *Applier) report(st State, res Applied) error {
	a.defaults()
	res.Hash, res.At = st.hash(), a.now().UTC()
	if res.Volumes == nil {
		res.Volumes = []Result{}
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	return writeAtomic(a.Paths.Dir(), appliedFile, b)
}

// prepare checks the data directory and creates the folders: the panel's
// exchange folder (its owner's), the images (root only) and the mount
// points (readable, so the panel can measure them).
func (a *Applier) prepare() error {
	data := a.Paths.Data
	if !filepath.IsAbs(data) || filepath.Clean(data) != data {
		return fmt.Errorf("data directory %q must be an absolute, clean path", data)
	}
	fi, err := os.Lstat(data)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", data)
	}
	if _, err := os.Lstat(a.Paths.Dir()); errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(a.Paths.Dir(), 0o755); err != nil { //nolint:gosec // holds no secret
			return err
		}
		// The panel writes desired.json there: give it to the data
		// directory's owner.
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && !a.NotRoot {
			if err := os.Lchown(a.Paths.Dir(), int(st.Uid), int(st.Gid)); err != nil {
				return err
			}
		}
	}
	if err := a.secureDir(a.Paths.Images(), 0o700); err != nil {
		return err
	}
	if err := a.secureDir(a.Paths.Mounts(), 0o755); err != nil {
		return err
	}
	// An image half created by a run that was interrupted.
	if stale, _ := filepath.Glob(filepath.Join(a.Paths.Images(), "*.img.new")); len(stale) > 0 {
		for _, p := range stale {
			if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
				_ = os.Remove(p)
			}
		}
	}
	return nil
}

// secureDir makes path a real directory with mode, owned by root.
func (a *Applier) secureDir(path string, mode os.FileMode) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s must be a directory, not a link or a file", path)
	}
	if err := a.rootOwned(fi, path); err != nil {
		return err
	}
	if fi.Mode().Perm() != mode {
		return os.Chmod(path, mode)
	}
	return nil
}

func (a *Applier) rootOwned(fi fs.FileInfo, path string) error {
	if a.NotRoot {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return fmt.Errorf("%s must belong to root", path)
	}
	return nil
}

// lock keeps two runs (the unit and a manual one) apart.
func (a *Applier) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(a.Paths.Images(), ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // a file descriptor fits an int
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

func (a *Applier) apply(ctx context.Context, e Entry) Result {
	r := Result{Name: e.Name, Op: e.Op}
	var err error
	switch e.Op {
	case OpMount:
		err = a.ensure(ctx, e.Name, e.Size)
	case OpImport:
		if err = a.ensure(ctx, e.Name, e.Size); err == nil {
			err = a.importData(ctx, e.Name)
		}
	case OpExport:
		err = a.exportData(ctx, e.Name)
	case OpRemove:
		err = a.remove(ctx, e.Name)
	}
	if err != nil {
		r.Error = err.Error()
	} else {
		r.OK = true
	}
	if e.Op != OpRemove && e.Op != OpExport || err != nil {
		a.measure(&r)
	}
	return r
}

// measure fills in the image's size and its filesystem's usage.
func (a *Applier) measure(r *Result) {
	if fi, err := os.Lstat(a.Paths.Image(r.Name)); err == nil && fi.Mode().IsRegular() {
		r.Size = fi.Size()
	}
	mounts, err := a.mounts()
	if err != nil {
		return
	}
	if _, ok := mounts[a.Paths.Mount(r.Name)]; ok {
		r.Mounted = true
		if used, total, _, err := a.statfs(a.Paths.Mount(r.Name)); err == nil {
			r.Used, r.Total = used, total
		}
	}
}

// ensure makes the image exist with at least size bytes (size 0: as it is)
// and mounted, with the folder the Docker volume binds to.
func (a *Applier) ensure(ctx context.Context, name string, size int64) error {
	img, mnt := a.Paths.Image(name), a.Paths.Mount(name)
	fi, err := os.Lstat(img)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if size <= 0 {
			return fmt.Errorf("no image for %s", name)
		}
		if err := a.create(ctx, img, size); err != nil {
			return err
		}
		fi, err = os.Lstat(img)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", img)
	}
	if err := a.rootOwned(fi, img); err != nil {
		return err
	}
	if err := a.mountPoint(mnt); err != nil {
		return err
	}
	dev, err := a.mountedAt(mnt)
	if err != nil {
		return err
	}
	if dev == "" {
		if out, err := a.Run(ctx, "mount", "-t", "ext4", "-o", "loop,nodev,nosuid", img, mnt); err != nil {
			return cmdError("mount", err, out)
		}
		if dev, err = a.mountedAt(mnt); err != nil {
			return err
		}
		if dev == "" {
			return fmt.Errorf("%s did not mount", img)
		}
	}
	if size > fi.Size() {
		if err := a.grow(ctx, img, dev, size); err != nil {
			return err
		}
	}
	data := a.Paths.Device(name)
	dfi, err := os.Lstat(data)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(data, 0o755); err != nil { //nolint:gosec // the app's folder; the volume's owner is set later
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}
	if dfi.Mode()&fs.ModeSymlink != 0 || !dfi.IsDir() {
		return fmt.Errorf("%s must be a directory", data)
	}
	return nil
}

// create makes a sparse image (truncate, never fallocate: only what the
// app writes takes room on the server) and an ext4 filesystem in it,
// under a temporary name so an interrupted run leaves no half-made image.
func (a *Applier) create(ctx context.Context, img string, size int64) error {
	tmp := img + ".new"
	if fi, err := os.Lstat(tmp); err == nil && fi.Mode().IsRegular() {
		_ = os.Remove(tmp)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // derived from a validated name
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// -m 0: no blocks reserved for root, the whole size is the app's.
	if out, err := a.Run(ctx, "mkfs.ext4", "-q", "-F", "-m", "0", "-E", "lazy_itable_init=1,lazy_journal_init=1", tmp); err != nil {
		_ = os.Remove(tmp)
		return cmdError("mkfs.ext4", err, out)
	}
	return os.Rename(tmp, img)
}

var loopRE = regexp.MustCompile(`^/dev/loop[0-9]{1,4}$`)

// grow makes the image bigger while it is mounted: the file first, then
// the loop device's idea of its size, then the filesystem (ext4 grows
// online).
func (a *Applier) grow(ctx context.Context, img, dev string, size int64) error {
	if !loopRE.MatchString(dev) {
		return fmt.Errorf("%s is mounted from %q, not a loop device", img, dev)
	}
	out, err := a.Run(ctx, "losetup", "-n", "-O", "BACK-FILE", dev)
	if err != nil {
		return cmdError("losetup", err, out)
	}
	if back := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(string(out)), "(deleted)")); back != img {
		return fmt.Errorf("%s is backed by %q, not %s", dev, back, img)
	}
	f, err := os.OpenFile(img, os.O_WRONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // derived from a validated name
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if out, err := a.Run(ctx, "losetup", "-c", dev); err != nil {
		return cmdError("losetup -c", err, out)
	}
	if out, err := a.Run(ctx, "resize2fs", dev); err != nil {
		return cmdError("resize2fs", err, out)
	}
	return nil
}

func (a *Applier) mountPoint(mnt string) error {
	fi, err := os.Lstat(mnt)
	if errors.Is(err, fs.ErrNotExist) {
		return os.Mkdir(mnt, 0o755) //nolint:gosec // a mount point; the image's root decides access
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s must be a directory", mnt)
	}
	return nil
}

// mountedAt is the device mounted at mnt ("" when nothing is).
func (a *Applier) mountedAt(mnt string) (string, error) {
	m, err := a.mounts()
	if err != nil {
		return "", err
	}
	return m[mnt], nil
}

// dockerVolume reads the Docker volume name, which must be Hangar's.
func (a *Applier) dockerVolume(ctx context.Context, name string) (DockerVolume, error) {
	if a.docker == nil {
		if a.Docker == nil {
			return DockerVolume{}, errors.New("docker is not available")
		}
		d, err := a.Docker(ctx)
		if err != nil {
			return DockerVolume{}, fmt.Errorf("docker is not available: %w", err)
		}
		a.docker = d
	}
	dv, err := a.docker.ProbeVolume(ctx, name)
	if err != nil {
		return dv, err
	}
	if dv.Exists && !dv.Managed {
		return dv, fmt.Errorf("docker volume %s was not created by Hangar", name)
	}
	return dv, nil
}

// volumeFolder checks the folder Docker keeps a plain local volume's
// files in: …/volumes/<name>/_data, a real path, outside Hangar's folders.
func (a *Applier) volumeFolder(dv DockerVolume, name string) (string, error) {
	mp := dv.Mountpoint
	switch {
	case dv.Driver != "local" || len(dv.Options) > 0:
		return "", fmt.Errorf("docker volume %s is not a plain local volume", name)
	case !filepath.IsAbs(mp) || filepath.Clean(mp) != mp || filepath.Base(mp) != "_data" || filepath.Base(filepath.Dir(mp)) != name:
		return "", fmt.Errorf("docker volume %s: unexpected folder %q", name, mp)
	case strings.HasPrefix(mp, a.Paths.Data+string(filepath.Separator)):
		return "", fmt.Errorf("docker volume %s: folder %q is inside Hangar's data", name, mp)
	}
	real, err := filepath.EvalSymlinks(mp)
	if err != nil {
		return "", err
	}
	if real != mp {
		return "", fmt.Errorf("docker volume %s: folder %q goes through a link", name, mp)
	}
	return mp, nil
}

// importData copies the plain Docker volume name into its mounted image.
func (a *Applier) importData(ctx context.Context, name string) error {
	if a.done[OpImport+name] {
		return nil
	}
	dv, err := a.dockerVolume(ctx, name)
	if err != nil {
		return err
	}
	dst := a.Paths.Device(name)
	switch {
	case !dv.Exists:
		return nil // a new volume: nothing to bring in
	case dv.Options["device"] == dst:
		return nil // already switched to the image
	case dv.InUse:
		return fmt.Errorf("a running container still uses %s", name)
	}
	src, err := a.volumeFolder(dv, name)
	if err != nil {
		return err
	}
	if err := a.fits(src, a.Paths.Images(), a.Paths.Mount(name)); err != nil {
		return err
	}
	if err := a.copyTree(ctx, src, dst); err != nil {
		return err
	}
	a.done[OpImport+name] = true
	return nil
}

// exportData copies a volume's image back into the plain Docker volume of
// the same name (created empty by the panel) and deletes the image.
func (a *Applier) exportData(ctx context.Context, name string) error {
	if a.done[OpExport+name] {
		return nil
	}
	if _, err := os.Lstat(a.Paths.Image(name)); errors.Is(err, fs.ErrNotExist) {
		return nil // exported already
	}
	dv, err := a.dockerVolume(ctx, name)
	if err != nil {
		return err
	}
	switch {
	case !dv.Exists:
		return fmt.Errorf("docker volume %s does not exist yet", name)
	case dv.InUse:
		return fmt.Errorf("a running container still uses %s", name)
	}
	dst, err := a.volumeFolder(dv, name)
	if err != nil {
		return err
	}
	if err := a.ensure(ctx, name, 0); err != nil {
		return err
	}
	src := a.Paths.Device(name)
	if err := a.fits(src, dst, ""); err != nil {
		return err
	}
	if err := a.copyTree(ctx, src, dst); err != nil {
		return err
	}
	if err := a.remove(ctx, name); err != nil {
		return err
	}
	a.done[OpExport+name] = true
	return nil
}

// fits checks the files of src fit where they go: hostDir's disk (sparse
// images take room as they fill) and, when set, the image mounted at mnt.
func (a *Applier) fits(src, hostDir, mnt string) error {
	need, err := allocated(src)
	if err != nil {
		return err
	}
	_, _, avail, err := a.statfs(hostDir)
	if err != nil {
		return err
	}
	if need+reserve > avail {
		return fmt.Errorf("not enough free space on the server: the copy needs %s and %s is free", gib(need+reserve), gib(avail))
	}
	if mnt != "" {
		_, total, avail, err := a.statfs(mnt)
		if err != nil {
			return err
		}
		if need > avail {
			return fmt.Errorf("the data (%s) does not fit in the limit (%s)", gib(need), gib(total))
		}
	}
	return nil
}

// copyTree replaces what dst holds with a copy of src (owners, modes,
// links, extended attributes), then checks the copy entry by entry.
func (a *Applier) copyTree(ctx context.Context, src, dst string) error {
	if s, d := statOf(src), statOf(dst); s == nil || d == nil || os.SameFile(s, d) {
		return fmt.Errorf("cannot copy %s onto %s", src, dst)
	}
	if err := clearDir(dst); err != nil {
		return err
	}
	if out, err := a.Run(ctx, "cp", "-a", "--", src+"/.", dst); err != nil {
		return cmdError("cp", err, out)
	}
	if err := copyAttrs(src, dst); err != nil {
		return err
	}
	return verifyCopy(src, dst)
}

// remove unmounts and deletes a volume's image.
func (a *Applier) remove(ctx context.Context, name string) error {
	img, mnt := a.Paths.Image(name), a.Paths.Mount(name)
	dev, err := a.mountedAt(mnt)
	if err != nil {
		return err
	}
	if dev != "" {
		// Never lazily: while a container holds it the unmount fails and
		// nothing is deleted.
		if out, err := a.Run(ctx, "umount", mnt); err != nil {
			return cmdError("umount", err, out)
		}
		if dev, err := a.mountedAt(mnt); err != nil || dev != "" {
			return fmt.Errorf("%s is still mounted", mnt)
		}
	}
	if fi, err := os.Lstat(img); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", img)
		}
		if err := os.Remove(img); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if fi, err := os.Lstat(mnt); err == nil && fi.IsDir() && fi.Mode()&fs.ModeSymlink == 0 {
		if err := os.Remove(mnt); err != nil {
			return fmt.Errorf("mount point %s is not empty: %w", mnt, err)
		}
	}
	return nil
}

func cmdError(what string, err error, out []byte) error {
	msg := strings.TrimSpace(string(out))
	if len(msg) > 400 {
		msg = msg[:400]
	}
	if msg == "" {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s: %w: %s", what, err, msg)
}

func gib(b uint64) string {
	return fmt.Sprintf("%.1f GB", float64(b)/float64(GiB))
}

// readMounts maps each mount point to its source, from the kernel.
func readMounts() (map[string]string, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	return parseMountinfo(string(b)), nil
}

func parseMountinfo(s string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(s, "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 5 || len(f) < sep+3 {
			continue
		}
		out[unescapeMount(f[4])] = unescapeMount(f[sep+2])
	}
	return out
}

var mountEscapes = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)

func unescapeMount(s string) string { return mountEscapes.Replace(s) }
