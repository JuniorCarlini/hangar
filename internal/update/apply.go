package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
}

// keepBackups is how many pre-update copies (and pre-migration copies) are
// kept; older ones are deleted after a successful update.
const keepBackups = 3

func (a *Applier) updateDir() string { return filepath.Join(a.DataDir, "update") }

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

	reqPath := filepath.Join(a.updateDir(), requestFile)
	raw, err := os.ReadFile(reqPath) //nolint:gosec // fixed path
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Remove the request before anything else: a broken request must not make
	// the applier loop.
	if err := os.Remove(reqPath); err != nil {
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

	backupDir := filepath.Join(a.DataDir, "backups", "pre-update-"+current+"-"+a.Now().UTC().Format("20060102T150405Z"))
	oldBin := filepath.Join(a.DataDir, "releases", "hangard-"+current)

	if err := a.Service.Stop(ctx); err != nil {
		return a.finish("failed", req.Version, current, "stop the panel: "+err.Error())
	}
	if err := a.backupDB(backupDir); err != nil {
		return a.rollback(ctx, req.Version, current, "", "", "copy database: "+err.Error())
	}
	if err := copyFile(a.BinaryPath, oldBin, 0o755); err != nil {
		return a.rollback(ctx, req.Version, current, "", "", "keep current binary: "+err.Error())
	}
	if err := installBinary(newBin, a.BinaryPath); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, "install: "+err.Error())
	}
	if err := a.InstallUnits(ctx, a.BinaryPath); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, "systemd units: "+err.Error())
	}
	_ = os.Remove(filepath.Join(a.DataDir, ReadyFile))
	if err := a.Service.Start(ctx); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, "start new version: "+err.Error())
	}
	if err := a.waitReady(ctx, req.Version); err != nil {
		return a.rollback(ctx, req.Version, current, oldBin, backupDir, err.Error())
	}

	_ = os.RemoveAll(filepath.Join(a.updateDir(), stagingDir))
	pruneReleases(filepath.Join(a.DataDir, "releases"), 3)
	pruneOldest(filepath.Join(a.DataDir, "backups"), "pre-update-", keepBackups)
	return a.finish("ok", req.Version, current, "")
}

func (a *Applier) verifiedCopy(version, current string) (string, error) {
	if ok, err := release.IsUpgrade(current, version); err != nil || !ok {
		return "", fmt.Errorf("%s is not an upgrade of %s", version, current)
	}
	dir := filepath.Join(a.updateDir(), stagingDir, version)
	manifest, err := os.ReadFile(filepath.Join(dir, "release.json")) //nolint:gosec // path inside data_dir
	if err != nil {
		return "", err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "release.json.sig")) //nolint:gosec // path inside data_dir
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
	src, err := os.Open(filepath.Join(dir, name)) //nolint:gosec // path inside data_dir
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
		if err := installCopy(oldBin, a.BinaryPath); err != nil {
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
	_ = os.Remove(filepath.Join(a.DataDir, ReadyFile))
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
	ready := filepath.Join(a.DataDir, ReadyFile)
	counter, canCount := a.Service.(restartCounter)
	base := 0
	if canCount {
		base, _ = counter.Restarts(ctx)
	}
	for {
		b, err := os.ReadFile(ready) //nolint:gosec // fixed path
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range dbFiles {
		src := filepath.Join(a.DataDir, f)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := copyPreserving(src, filepath.Join(dir, f)); err != nil {
			return err
		}
	}
	return nil
}

func (a *Applier) restoreDB(dir string) error {
	for _, f := range dbFiles {
		dst := filepath.Join(a.DataDir, f)
		src := filepath.Join(dir, f)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(dst) // the new version's -wal/-shm must not be left behind
			continue
		}
		if err := restoreFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

// restoreFile puts src at dst through a temporary file in dst's directory
// and a rename: if the copy fails halfway (disk full, the applier killed),
// dst is still the whole file it was, never a truncated database.
func restoreFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".restoring-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	if err := copyPreserving(src, tmpName); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// CreateTemp makes 0600; give back the backup's mode.
	if err := os.Chmod(tmpName, info.Mode().Perm()); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // the applier's own paths
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func (a *Applier) finish(state, version, from, msg string) (*Status, error) {
	s := &Status{State: state, Version: version, From: from, Message: truncate(msg, 2000), At: a.Now().UTC()}
	b, _ := json.Marshal(s)
	if err := os.MkdirAll(a.updateDir(), 0o750); err != nil {
		return s, err
	}
	if err := writeFileAtomic(filepath.Join(a.updateDir(), statusFile), b, 0o644); err != nil {
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

func installCopy(src, dst string) error {
	tmp := dst + ".restaurando"
	if err := copyFile(src, tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func copyFile(src, dst string, perm os.FileMode) error {
	return copyTo(src, dst, perm, -1, -1)
}

// copyPreserving copies keeping permissions and owner (the database belongs
// to the hangar user; a root-owned copy would leave the panel unable to open
// it).
func copyPreserving(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	uid, gid := -1, -1
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(st.Uid), int(st.Gid)
	}
	return copyTo(src, dst, info.Mode().Perm(), uid, gid)
}

// copyTo copies src to dst as root without following a symlink at either
// end: these paths live in directories the hangar user owns, and a link
// planted there would otherwise make root read or overwrite (and chown) any
// file on the host. The copy goes to a fresh temporary file, gets its mode
// and owner through the open descriptor, and is renamed into place; rename
// replaces a link itself, never what it points at. uid/gid -1 keep root's.
func copyTo(src, dst string, perm os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the applier's own paths
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if st, err := in.Stat(); err != nil {
		return err
	} else if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*")
	if err != nil {
		return err
	}
	tmp := out.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := io.Copy(out, in); err != nil {
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
	return os.Rename(tmp, dst)
}

// pruneOldest keeps the keep newest entries of dir whose name starts with
// prefix and deletes the rest (files or directories). Names end in a UTC
// timestamp, but what comes before it (a version) does not sort, so age is
// the modification time.
func pruneOldest(dir, prefix string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type aged struct {
		name string
		mod  time.Time
	}
	var match []aged
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		match = append(match, aged{e.Name(), info.ModTime()})
	}
	if len(match) <= keep {
		return
	}
	sort.Slice(match, func(i, j int) bool { return match[i].mod.After(match[j].mod) })
	for _, m := range match[keep:] {
		_ = os.RemoveAll(filepath.Join(dir, m.name))
	}
}

// pruneReleases keeps only the keep most recent old binaries.
func pruneReleases(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= keep {
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		ii, _ := entries[i].Info()
		jj, _ := entries[j].Info()
		return ii.ModTime().After(jj.ModTime())
	})
	for _, e := range entries[keep:] {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}
