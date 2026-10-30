package update

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/JuniorCarlini/hangar/internal/hostperms"
	"github.com/JuniorCarlini/hangar/internal/release"
)

// ReadyFile is written by hangard (data_dir/run/ready) with its version after
// migrating the database and starting to listen. It signals that the new
// version came up.
const ReadyFile = "run/ready"

// Service controls the panel service (systemd in production).
type Service interface {
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
}

// Systemd controls a unit through systemctl.
type Systemd struct{ Unit string }

func (s Systemd) Stop(ctx context.Context) error  { return systemctl(ctx, "stop", s.Unit) }
func (s Systemd) Start(ctx context.Context) error { return systemctl(ctx, "start", s.Unit) }

// Restarts returns how many times systemd restarted the unit (NRestarts).
func (s Systemd) Restarts(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", s.Unit, "-p", "NRestarts", "--value").Output() //nolint:gosec // unit from the configuration
	if err != nil {
		return 0, err
	}
	var n int
	_, err = fmt.Sscan(strings.TrimSpace(string(out)), &n)
	return n, err
}

// restartCounter is implemented by services that can count restarts; with
// it, a version stuck in a crash loop is detected in seconds.
type restartCounter interface {
	Restarts(ctx context.Context) (int, error)
}

// crashLoopRestarts is how many consecutive restarts mean the new version
// does not come up (about 10 seconds with RestartSec=3).
const crashLoopRestarts = 3

func systemctl(ctx context.Context, verb, unit string) error {
	out, err := exec.CommandContext(ctx, "systemctl", verb, unit).CombinedOutput() //nolint:gosec // verb and unit fixed in code/config
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w: %s", verb, unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Applier is the root side of the update.
type Applier struct {
	DataDir    string        // /var/lib/hangar
	BinaryPath string        // /usr/local/bin/hangard
	Service    Service       // hangard.service
	ReadyWait  time.Duration // how long to wait for the new version to come up
	// CurrentVersion reads the installed binary's version (default: runs
	// "<binary> version").
	CurrentVersion func(ctx context.Context, binary string) (string, error)
	// InstallUnits writes the systemd units embedded in the binary (default:
	// runs "<binary> system install-units"). This way a new version can ship
	// new units without a reinstall.
	InstallUnits func(ctx context.Context, binary string) error
	// ConfigPath is hangar.toml, for the preflight.
	ConfigPath string
	// Preflight runs the new binary before the panel is stopped (default:
	// "system fix-perms" as root, then "system check-start" as the service
	// user). If the new version could not read its config or master key,
	// the update does not start and the panel stays up.
	Preflight func(ctx context.Context, binary string) error
	// FreeSpace reports the bytes still writable on the filesystem holding
	// path (default: statfs). The disk check runs before the panel stops.
	FreeSpace func(path string) (uint64, error)
	Now       func() time.Time

	// root is DataDir, opened for the duration of Apply. DataDir and
	// everything in it belong to the hangar user, so every path the applier
	// (root) touches there goes through it: a symlink planted anywhere on
	// the way (releases/, backups/, update/, a file) can never make root
	// read, write or delete outside DataDir.
	root *os.Root
}

// keepBackups is how many pre-update copies (and pre-migration copies) are
// kept; older ones are deleted after a successful update.
const keepBackups = 3

// Paths inside DataDir, relative to the applier's root.
const (
	updateRel   = "update"
	releasesRel = "releases"
	backupsRel  = "backups"
	// releasePrefix is the name of every kept binary; pruning never deletes
	// anything else.
	releasePrefix = "hangard-v"
)

func (a *Applier) updateDir() string { return filepath.Join(a.DataDir, updateRel) }

// Apply runs the pending request, if any. It never leaves the panel without a
// binary that starts: any failure after stopping the service rolls
// everything back.
func (a *Applier) Apply(ctx context.Context) (*Status, error) {
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.CurrentVersion == nil {
		a.CurrentVersion = binaryVersion
	}
	if a.ReadyWait == 0 {
		a.ReadyWait = 90 * time.Second
	}
	if a.InstallUnits == nil {
		a.InstallUnits = installUnits
	}
	if a.Preflight == nil {
		a.Preflight = func(ctx context.Context, binary string) error { return preflight(ctx, binary, a.ConfigPath) }
	}
	if a.FreeSpace == nil {
		a.FreeSpace = freeSpace
	}

	root, err := os.OpenRoot(a.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	a.root = root
	defer func() { a.root = nil }()

	reqPath := path.Join(updateRel, requestFile)
	raw, err := readRegular(root, reqPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		_ = root.Remove(reqPath)
		return nil, err
	}
	// Remove the request before anything else: a broken request must not make
	// the applier loop.
	if err := root.Remove(reqPath); err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return a.finish("failed", "", "", "invalid request: "+err.Error())
	}

	current, err := a.CurrentVersion(ctx, a.BinaryPath)
	if err != nil {
		return a.finish("failed", req.Version, "", "read installed version: "+err.Error())
	}
	// Say so at once: the request is gone and the checks below take a
	// while, and the panel shows the update as on its way only while it
	// sees the request or this status (otherwise it offers the button again
	// and stops waiting for the new version).
	if _, err := a.finish("applying", req.Version, current, ""); err != nil {
		return nil, err
	}

	// Verify everything again without trusting the unprivileged process that
	// staged it. The binary is copied somewhere only root can write before its
	// hash is checked, so nobody can swap it between the check and the
	// install.
	newBin, err := a.verifiedCopy(req.Version, current)
	if err != nil {
		return a.finish("failed", req.Version, current, err.Error())
	}
	defer func() { _ = os.Remove(newBin) }()

	if err := a.checkDisk(newBin); err != nil {
		return a.finish("failed", req.Version, current, "preflight: "+err.Error()+" (the panel was not stopped)")
	}
	if err := a.Preflight(ctx, newBin); err != nil {
		return a.finish("failed", req.Version, current, "preflight (the panel was not stopped): "+err.Error())
	}

	// current was parsed as a version by verifiedCopy, so it holds no path
	// separator.
	backupDir := path.Join(backupsRel, "pre-update-"+current+"-"+a.Now().UTC().Format("20060102T150405Z"))
	oldBin := path.Join(releasesRel, "hangard-"+current)

	if err := a.Service.Stop(ctx); err != nil {
		return a.finish("failed", req.Version, current, "stop the panel: "+err.Error())
	}
	if err := a.backupDB(backupDir); err != nil {
		return a.rollback(ctx, req.Version, current, "", "", "copy database: "+err.Error())
	}
	if err := a.keepBinary(oldBin); err != nil {
		return a.rollback(ctx, req.Version, current, "", "", "keep current binary: "+err.Error())
	}
	if err := installBinary(newBin, a.BinaryPath); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, "install: "+err.Error())
	}
	if err := a.InstallUnits(ctx, a.BinaryPath); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, "systemd units: "+err.Error())
	}
	_ = root.Remove(ReadyFile)
	if err := a.Service.Start(ctx); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, "start new version: "+err.Error())
	}
	if err := a.waitReady(ctx, req.Version); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, err.Error())
	}

	_ = root.RemoveAll(path.Join(updateRel, stagingDir))
	pruneReleases(root, releasesRel, keepBackups)
	pruneOldest(root, backupsRel, "pre-update-", keepBackups)
	return a.finish("ok", req.Version, current, "")
}

func (a *Applier) verifiedCopy(version, current string) (string, error) {
	if ok, err := release.IsUpgrade(current, version); err != nil || !ok {
		return "", fmt.Errorf("%s is not an upgrade of %s", version, current)
	}
	// IsUpgrade parsed version: it is a plain "vX.Y.Z", no path in it.
	dir := path.Join(updateRel, stagingDir, version)
	manifest, err := readRegular(a.root, path.Join(dir, "release.json"))
	if err != nil {
		return "", err
	}
	sig, err := readRegular(a.root, path.Join(dir, "release.json.sig"))
	if err != nil {
		return "", err
	}
	m, err := release.VerifyManifest(manifest, string(sig))
	if err != nil {
		return "", err
	}
	if m.Version != version {
		return "", fmt.Errorf("manifest is for %s, request was %s", m.Version, version)
	}

	name := release.AssetName(runtime.GOARCH)
	tmp, err := os.CreateTemp(filepath.Dir(a.BinaryPath), ".hangard-verificado-")
	if err != nil {
		return "", err
	}
	src, err := openRegular(a.root, path.Join(dir, name))
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	_, err = io.Copy(tmp, io.LimitReader(src, maxBinaryBytes+1))
	_ = src.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		var f *os.File
		if f, err = os.Open(tmp.Name()); err == nil {
			err = m.CheckFile(name, f)
			_ = f.Close()
		}
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func installUnits(ctx context.Context, binary string) error {
	out, err := exec.CommandContext(ctx, binary, "system", "install-units").CombinedOutput() //nolint:gosec // freshly verified binary
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// checkDisk refuses to start when the disk cannot hold what the update
// writes: in DataDir the database copy, the copy the new version makes
// before migrating, and the kept old binary; next to the binary, the copy a
// rollback puts back. Running out of space halfway would leave the panel
// down or the database half restored.
func (a *Applier) checkDisk(newBin string) error {
	var dbSize uint64
	for _, f := range dbFiles {
		if info, err := os.Stat(filepath.Join(a.DataDir, f)); err == nil {
			dbSize += uint64(info.Size()) //nolint:gosec // file sizes are not negative
		}
	}
	var binSize uint64
	for _, b := range []string{a.BinaryPath, newBin} {
		if info, err := os.Stat(b); err == nil && uint64(info.Size()) > binSize { //nolint:gosec // file sizes are not negative
			binSize = uint64(info.Size()) //nolint:gosec // file sizes are not negative
		}
	}
	checks := []struct {
		dir  string
		need uint64
	}{
		{a.DataDir, 2*dbSize + binSize},
		{filepath.Dir(a.BinaryPath), binSize},
	}
	for _, c := range checks {
		free, err := a.FreeSpace(c.dir)
		if err != nil {
			return fmt.Errorf("measure free disk in %s: %w", c.dir, err)
		}
		if free < c.need {
			return fmt.Errorf("not enough disk in %s: %d MiB free, %d MiB needed", c.dir, free>>20, (c.need+(1<<20)-1)>>20)
		}
	}
	return nil
}

// preflight checks that the new binary will start, before anything stops:
// it puts the files' owners back (root) and then reads the config and the
// master key as the service user, like the service will.
func preflight(ctx context.Context, binary, configPath string) error {
	if configPath == "" {
		configPath = "/etc/hangar/hangar.toml"
	}
	// The verified copy is root-only (0600); the service user must run it.
	if err := os.Chmod(binary, 0o755); err != nil { //nolint:gosec // a root-owned binary in a root-owned directory
		return err
	}
	if out, err := exec.CommandContext(ctx, binary, "system", "fix-perms", "-config", configPath).CombinedOutput(); err != nil { //nolint:gosec // freshly verified binary
		return fmt.Errorf("fix-perms: %w: %s", err, strings.TrimSpace(string(out)))
	}
	uid, gid, err := hostperms.SystemLookup("hangar")
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, binary, "system", "check-start", "-config", configPath)                     //nolint:gosec // freshly verified binary
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}} //nolint:gosec // ids from /etc/passwd
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("check-start as hangar: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// rollback restores binary and database and starts the previous version.
func (a *Applier) rollback(ctx context.Context, version, current, oldBin, backupDir, reason string) (*Status, error) {
	var errs []string
	if oldBin != "" {
		_ = a.Service.Stop(ctx)
		if err := a.installCopy(oldBin); err != nil {
			errs = append(errs, "restore binary: "+err.Error())
		} else if err := a.InstallUnits(ctx, a.BinaryPath); err != nil {
			errs = append(errs, "restore units: "+err.Error())
		}
	}
	if backupDir != "" {
		if err := a.restoreDB(backupDir); err != nil {
			errs = append(errs, "restore database: "+err.Error())
		}
	}
	_ = a.root.Remove(ReadyFile)
	if err := a.Service.Start(ctx); err != nil {
		errs = append(errs, "start previous version: "+err.Error())
	} else if err := a.waitReady(ctx, current); err != nil {
		// Only "rolled_back" when the old version is really serving again.
		errs = append(errs, "previous version did not come back: "+err.Error())
	}
	msg := reason
	if len(errs) > 0 {
		msg += " | " + strings.Join(errs, "; ")
		return a.finish("failed", version, current, msg)
	}
	return a.finish("rolled_back", version, current, msg)
}

func (a *Applier) waitReady(ctx context.Context, version string) error {
	deadline := a.Now().Add(a.ReadyWait)
	counter, canCount := a.Service.(restartCounter)
	base := 0
	if canCount {
		base, _ = counter.Restarts(ctx)
	}
	for {
		b, err := readRegular(a.root, ReadyFile)
		if err == nil && strings.TrimSpace(string(b)) == version {
			return nil
		}
		if canCount {
			if n, err := counter.Restarts(ctx); err == nil && n-base >= crashLoopRestarts {
				return fmt.Errorf("version %s crashed %d times in a row on start", version, n-base)
			}
		}
		if a.Now().After(deadline) {
			return fmt.Errorf("version %s was not ready within %s", version, a.ReadyWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

var dbFiles = []string{"hangar.db", "hangar.db-wal", "hangar.db-shm"}

// backupDB copies the database with the service stopped, keeping owner and
// permissions.
func (a *Applier) backupDB(dir string) error {
	if err := mkdirAllNoFollow(a.root, dir, 0o700); err != nil {
		return err
	}
	for _, f := range dbFiles {
		err := copyPreserving(a.root, f, path.Join(dir, f))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Applier) restoreDB(dir string) error {
	for _, f := range dbFiles {
		err := restoreFile(a.root, path.Join(dir, f), f)
		if errors.Is(err, os.ErrNotExist) {
			_ = a.root.Remove(f) // the new version's -wal/-shm must not be left behind
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// restoreFile puts src at dst (both inside root) through a temporary file in
// dst's directory and a rename: if the copy fails halfway (disk full, the
// applier killed), dst is still the whole file it was, never a truncated
// database. The backup's mode and owner come along.
func restoreFile(root *os.Root, src, dst string) error {
	if err := copyPreserving(root, src, dst); err != nil {
		return err
	}
	return syncDir(root, path.Dir(dst))
}

// syncDir makes a rename in dir durable.
func syncDir(root *os.Root, dir string) error {
	d, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func (a *Applier) finish(state, version, from, msg string) (*Status, error) {
	s := &Status{State: state, Version: version, From: from, Message: truncate(msg, 2000), At: a.Now().UTC()}
	b, _ := json.Marshal(s)
	if err := mkdirAllNoFollow(a.root, updateRel, 0o750); err != nil {
		return s, err
	}
	if err := writeIn(a.root, path.Join(updateRel, statusFile), bytes.NewReader(b), 0o644, -1, -1); err != nil {
		return s, err
	}
	if state == "failed" || state == "rolled_back" {
		return s, errors.New(msg)
	}
	return s, nil
}

func binaryVersion(ctx context.Context, binary string) (string, error) {
	out, err := exec.CommandContext(ctx, binary, "version").Output() //nolint:gosec // binary path comes from the configuration
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// installBinary swaps the binary with rename (atomic on the same filesystem):
// there is never an instant without a complete binary in place.
func installBinary(src, dst string) error {
	if err := os.Chmod(src, 0o755); err != nil { //nolint:gosec // executable binary
		return err
	}
	return os.Rename(src, dst)
}

// keepBinary copies the installed binary (a root-owned path) to rel inside
// DataDir, so a rollback can put it back.
func (a *Applier) keepBinary(rel string) error {
	in, err := os.Open(a.BinaryPath)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if err := mkdirAllNoFollow(a.root, path.Dir(rel), 0o750); err != nil {
		return err
	}
	return writeIn(a.root, rel, in, 0o755, -1, -1)
}

// installCopy puts the kept binary rel (inside DataDir) back in place of
// BinaryPath, through a temporary file and a rename next to it.
func (a *Applier) installCopy(rel string) error {
	in, err := openRegular(a.root, rel)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	binRoot, err := os.OpenRoot(filepath.Dir(a.BinaryPath))
	if err != nil {
		return err
	}
	defer func() { _ = binRoot.Close() }()
	return writeIn(binRoot, filepath.Base(a.BinaryPath), in, 0o755, -1, -1)
}

// errNotRegular refuses symlinks and anything else that is not a plain file
// (or, for directories, a plain directory) where the applier expects one.
var errNotRegular = errors.New("not a regular file or directory (symlink?)")

// openRegular opens name inside root for reading, refusing a symlink or
// anything that is not a regular file. root itself keeps every lookup
// inside DataDir; the Lstat and the SameFile check also refuse a link that
// stays inside it, or a swap between the check and the open.
func openRegular(root *os.Root, name string) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, errNotRegular)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", name, errNotRegular)
	}
	return f, nil
}

// readRegular reads a small file through openRegular.
func readRegular(root *os.Root, name string) ([]byte, error) {
	f, err := openRegular(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxManifestBytes))
}

// mkdirAllNoFollow creates dir (relative to root) one component at a time,
// refusing any component that exists as something other than a real
// directory: a releases/ or backups/ swapped for a symlink makes the step
// fail instead of being followed.
func mkdirAllNoFollow(root *os.Root, dir string, perm os.FileMode) error {
	cur := ""
	for part := range strings.SplitSeq(path.Clean(dir), "/") {
		if part == "." || part == "" {
			continue
		}
		cur = path.Join(cur, part)
		info, err := root.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(cur, perm); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = root.Lstat(cur)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s: %w", cur, errNotRegular)
		}
	}
	return nil
}

// copyPreserving copies src to dst, both inside root, keeping permissions
// and owner (the database belongs to the hangar user; a root-owned copy
// would leave the panel unable to open it).
func copyPreserving(root *os.Root, src, dst string) error {
	in, err := openRegular(root, src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	uid, gid := -1, -1
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(st.Uid), int(st.Gid)
	}
	return writeIn(root, dst, in, info.Mode().Perm(), uid, gid)
}

// writeIn writes r to dst inside root, as root, without following a
// symlink: the data goes to a fresh temporary file (O_EXCL, random name),
// gets its mode and owner through the open descriptor, and is renamed into
// place; rename replaces a link itself, never what it points at. uid/gid -1
// keep root's.
func writeIn(root *os.Root, dst string, r io.Reader, perm os.FileMode, uid, gid int) error {
	tmp := path.Join(path.Dir(dst), "."+path.Base(dst)+"."+rand.Text())
	out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	if _, err := io.Copy(out, r); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(perm); err != nil {
		_ = out.Close()
		return err
	}
	if uid >= 0 {
		if err := out.Chown(uid, gid); err != nil && !errors.Is(err, os.ErrPermission) {
			_ = out.Close()
			return err
		}
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return root.Rename(tmp, dst)
}

// readDirNoFollow lists dir inside root, refusing a dir that is a symlink.
func readDirNoFollow(root *os.Root, dir string) ([]os.DirEntry, error) {
	info, err := root.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: %w", dir, errNotRegular)
	}
	d, err := root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	return d.ReadDir(-1)
}

// pruneNewest deletes from dir (inside root) every entry accepted by match
// except the keep most recently modified ones. Names end in a version or a
// timestamp that does not sort, so age is the modification time. Entries are
// listed without following links (DirEntry.Type comes from lstat).
func pruneNewest(root *os.Root, dir string, keep int, match func(os.DirEntry) bool, remove func(string) error) {
	entries, err := readDirNoFollow(root, dir)
	if err != nil {
		return
	}
	type aged struct {
		name string
		mod  time.Time
	}
	var found []aged
	for _, e := range entries {
		if !match(e) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		found = append(found, aged{e.Name(), info.ModTime()})
	}
	if len(found) <= keep {
		return
	}
	sort.Slice(found, func(i, j int) bool { return found[i].mod.After(found[j].mod) })
	for _, f := range found[keep:] {
		_ = remove(path.Join(dir, f.name))
	}
}

// pruneOldest keeps the keep newest entries of dir whose name starts with
// prefix and deletes the rest (files or directories, never a symlink).
func pruneOldest(root *os.Root, dir, prefix string, keep int) {
	pruneNewest(root, dir, keep, func(e os.DirEntry) bool {
		return strings.HasPrefix(e.Name(), prefix) && e.Type()&os.ModeSymlink == 0
	}, root.RemoveAll)
}

// pruneReleases keeps only the keep most recent old binaries. Only regular
// files named like a kept binary are candidates: nothing else that ends up
// in releases/ is ever deleted.
func pruneReleases(root *os.Root, dir string, keep int) {
	pruneNewest(root, dir, keep, func(e os.DirEntry) bool {
		return strings.HasPrefix(e.Name(), releasePrefix) && e.Type().IsRegular()
	}, root.Remove)
}
