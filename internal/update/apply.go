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
	Now          func() time.Time
}

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

	// Verify everything again without trusting the unprivileged process that
	// staged it. The binary is copied somewhere only root can write before its
	// hash is checked, so nobody can swap it between the check and the
	// install.
	newBin, err := a.verifiedCopy(req.Version, current)
	if err != nil {
		return a.finish("failed", req.Version, current, err.Error())
	}
	defer func() { _ = os.Remove(newBin) }()

	if _, err := a.finish("applying", req.Version, current, ""); err != nil {
		return nil, err
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
	if err := a.Service.Start(ctx); err != nil {
		errs = append(errs, "start previous version: "+err.Error())
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
		if err := copyPreserving(src, dst); err != nil {
			return err
		}
	}
	return nil
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
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src) //nolint:gosec // the applier's own paths
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) //nolint:gosec // the applier's own paths
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// copyPreserving copies keeping permissions and owner (the database belongs
// to the hangar user; a root-owned copy would leave the panel unable to open
// it).
func copyPreserving(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := copyFile(src, dst, info.Mode().Perm()); err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Chown(dst, int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, os.ErrPermission) {
			return err
		}
	}
	return nil
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
