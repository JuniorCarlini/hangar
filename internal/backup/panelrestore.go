package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
)

// PanelSource is where `hangard restore` reads the panel backup from (the
// bucket, through a read-only credential).
type PanelSource interface {
	List(ctx context.Context, prefix string) ([]archive.Listed, error)
	Open(ctx context.Context, key string) (io.ReadCloser, map[string]string, error)
}

// PanelRestoreOptions say where the restored files go.
type PanelRestoreOptions struct {
	DataDir       string
	MasterKeyFile string
	ConfigFile    string
	// Force replaces an existing database (moved aside, never deleted).
	Force bool
	Now   func() time.Time
}

// PanelRestored describes what was put back.
type PanelRestored struct {
	Key        string
	Manifest   Manifest
	ConfigCopy string // where the old hangar.toml was written, if any
	Aside      []string
}

// ErrPanelExists means the server already has a panel database.
var ErrPanelExists = errors.New("this server already has a panel database (use -force to move it aside)")

// RestorePanel brings the panel database, master key, configuration and
// certificates back from the newest panel backup taken before at (docs/09
// step 2). The current files, if any, are moved aside, never deleted. The
// panel must be stopped.
func RestorePanel(ctx context.Context, src PanelSource, ids []age.Identity, at time.Time, o PanelRestoreOptions) (PanelRestored, error) {
	var out PanelRestored
	if o.Now == nil {
		o.Now = time.Now
	}
	if at.IsZero() {
		at = o.Now()
	}
	objs, err := src.List(ctx, archive.PanelPrefix)
	if err != nil {
		return out, err
	}
	var best archive.Listed
	for _, l := range objs {
		if p, ok := archive.ParseKey(l.Key); ok && p.Kind == archive.KindPanel && !l.LastModified.After(at) && l.LastModified.After(best.LastModified) {
			best = l
		}
	}
	if best.Key == "" {
		return out, errors.New("no panel backup in the bucket before that moment")
	}
	out.Key = best.Key
	dbPath := filepath.Join(o.DataDir, PanelDB)
	if _, err := os.Stat(dbPath); err == nil && !o.Force {
		return out, ErrPanelExists
	}
	if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
		return out, err
	}
	stamp := o.Now().UTC().Format(archive.TimeFormat)
	stage := filepath.Join(o.DataDir, ".restore-"+stamp)
	defer func() { _ = os.RemoveAll(stage) }()

	rc, _, err := src.Open(ctx, best.Key)
	if err != nil {
		return out, err
	}
	plain, err := archive.Open(rc, ids, archive.DefaultLimits)
	if err != nil {
		_ = rc.Close()
		return out, err
	}
	err = archive.Extract(plain, stage, archive.DefaultTarLimits)
	_ = plain.Close()
	_ = rc.Close()
	if err != nil {
		return out, err
	}
	raw, err := os.ReadFile(filepath.Join(stage, PanelManifest)) //nolint:gosec // inside our own staging dir
	if err != nil {
		return out, fmt.Errorf("manifest: %w", err)
	}
	if err := json.Unmarshal(raw, &out.Manifest); err != nil {
		return out, fmt.Errorf("manifest: %w", err)
	}
	key, err := os.ReadFile(filepath.Join(stage, PanelKey)) //nolint:gosec // inside our own staging dir
	if err != nil || len(key) != 32 {
		return out, errors.New("the backup has no valid master key")
	}
	head := make([]byte, 16)
	if f, err := os.Open(filepath.Join(stage, PanelDB)); err == nil { //nolint:gosec // inside our own staging dir
		_, _ = io.ReadFull(f, head)
		_ = f.Close()
	}
	if !bytes.HasPrefix(head, []byte("SQLite format 3")) {
		return out, errors.New("the backup has no valid panel database")
	}

	aside := func(path string) error {
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		dest := path + ".before-restore-" + stamp
		out.Aside = append(out.Aside, dest)
		return os.Rename(path, dest)
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm", o.MasterKeyFile} {
		if err := aside(p); err != nil {
			return out, err
		}
	}
	if err := os.Rename(filepath.Join(stage, PanelDB), dbPath); err != nil {
		return out, err
	}
	if err := os.MkdirAll(filepath.Dir(o.MasterKeyFile), 0o700); err != nil {
		return out, err
	}
	if err := os.WriteFile(o.MasterKeyFile, key, 0o400); err != nil { //nolint:gosec // the configured master key path
		return out, err
	}
	if o.ConfigFile != "" {
		if b, err := os.ReadFile(filepath.Join(stage, PanelConfig)); err == nil { //nolint:gosec // inside our own staging dir
			out.ConfigCopy = o.ConfigFile + ".restaurado"
			if err := os.WriteFile(out.ConfigCopy, b, 0o600); err != nil { //nolint:gosec // next to the configured hangar.toml
				return out, err
			}
		}
	}
	certs := filepath.Join(o.DataDir, "edge", "data")
	if entries, err := os.ReadDir(certs); err != nil || len(entries) == 0 {
		if _, err := os.Stat(filepath.Join(stage, "certs")); err == nil {
			_ = os.RemoveAll(certs)
			if err := os.MkdirAll(filepath.Dir(certs), 0o700); err != nil {
				return out, err
			}
			if err := os.Rename(filepath.Join(stage, "certs"), certs); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}
