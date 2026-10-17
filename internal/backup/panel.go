package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// PanelLabel names the panel's own runs.
const PanelLabel = "painel"

// Panel backup layout: one tar with these names.
const (
	PanelManifest = "manifest.json"
	PanelDB       = "hangar.db"
	PanelKey      = "master.key"
	PanelConfig   = "hangar.toml"
	PanelCerts    = "certs/"
)

// Manifest describes a panel backup.
type Manifest struct {
	Version       string    `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	DataDir       string    `json:"data_dir"`
	MasterKeyFile string    `json:"master_key_file"`
	ConfigFile    string    `json:"config_file"`
}

// settingPanelAudit is the last audit id a panel backup covered.
const settingPanelAudit = "backup.panel_audit_id"

// backupPanel copies the panel database (VACUUM INTO: consistent, without
// stopping), the master key, the configuration and the certificates into
// one encrypted file. The master key goes inside so one private key (the
// operator's) recovers everything (docs/04).
func (m *Manager) backupPanel(ctx context.Context, a Actor, trigger string) (string, error) {
	unlock := m.lock(PanelLabel)
	defer unlock()
	ts, err := m.targets(ctx)
	if err != nil {
		return "", err
	}
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return "", err
	}
	runID, err := m.startRun(ctx, a, "", PanelLabel, archive.KindPanel, trigger, "")
	if err != nil {
		return "", err
	}
	res := runResult{}
	err = func() error {
		dbCopy := filepath.Join(m.opt.StagingDir, "panel-"+runID+".db")
		defer func() { _ = os.Remove(dbCopy) }()
		if _, err := m.db.ExecContext(ctx, "VACUUM INTO ?", dbCopy); err != nil {
			return fmt.Errorf("copy database: %w", err)
		}
		f, err := m.stagingFile("panel-*.age")
		if err != nil {
			return err
		}
		defer removeFile(f)
		sf := &sealedFile{f: f, sha: sha256.New()}
		sealer, err := archive.Seal(io.MultiWriter(f, sf.sha, &sf.size), rcpts, true)
		if err != nil {
			return err
		}
		tw := tar.NewWriter(sealer)
		man, _ := json.MarshalIndent(Manifest{
			Version: m.opt.Version, CreatedAt: m.now().UTC(), DataDir: filepath.Dir(m.opt.DBPath),
			MasterKeyFile: m.opt.MasterKeyFile, ConfigFile: m.opt.ConfigFile,
		}, "", "  ")
		files := 0
		if err := tarBytes(tw, PanelManifest, man, 0o600); err != nil {
			return err
		}
		for _, x := range []struct{ name, path string }{{PanelDB, dbCopy}, {PanelKey, m.opt.MasterKeyFile}, {PanelConfig, m.opt.ConfigFile}} {
			if x.path == "" {
				continue
			}
			if err := tarFile(tw, x.name, x.path); err != nil {
				if x.name == PanelConfig && errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return fmt.Errorf("%s: %w", x.name, err)
			}
			files++
		}
		if m.opt.CertsDir != "" {
			if err := tarDir(tw, PanelCerts, m.opt.CertsDir); err != nil {
				return fmt.Errorf("certificates: %w", err)
			}
		}
		if err := tw.Close(); err != nil {
			return err
		}
		if err := sealer.Close(); err != nil {
			return err
		}
		res.verified, res.check, res.size, res.sha = true, map[string]any{"files": files}, sf.size.n, sf.hexSum()
		res.key = archive.PanelKey(m.now())
		res.uploads, err = m.sendFile(ctx, ts, res.key, "painel", f, res.size, res.sha, map[string]string{
			"hangar-kind": archive.KindPanel, "hangar-version": m.opt.Version,
		})
		return err
	}()
	m.finishRun(ctx, runID, res, err)
	m.record(ctx, a, "backup.run", "panel", "", outcomeOf(err), map[string]any{"kind": archive.KindPanel, "trigger": trigger, "run": runID, "size": res.size})
	if err == nil {
		// After our own audit record: only other actions count as changes.
		if id, qerr := m.q.MaxAuditID(ctx); qerr == nil {
			_ = m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingPanelAudit, ValueJson: strconv.FormatInt(id, 10)})
		}
	} else {
		m.log.Warn("backup failed", "kind", archive.KindPanel, "error", err)
	}
	return runID, err
}

// panelChanged reports whether anything was audited since the last panel
// backup (a configuration change: docs/09 backs the panel up on changes).
func (m *Manager) panelChanged(ctx context.Context) bool {
	last, err := m.q.GetSetting(ctx, settingPanelAudit)
	if err != nil {
		return true
	}
	n, _ := strconv.ParseInt(last, 10, 64)
	cur, err := m.q.MaxAuditID(ctx)
	return err == nil && cur > n
}

func tarBytes(tw *tar.Writer, name string, b []byte, mode int64) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), Typeflag: tar.TypeReg, ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func tarFile(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path) //nolint:gosec // paths come from the configuration
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: st.Size(), Typeflag: tar.TypeReg, ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, io.LimitReader(f, st.Size()))
	return err
}

func tarDir(tw *tar.Writer, prefix, dir string) error {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil // directories are implied; sockets and links are skipped
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 16<<20 {
			return nil // certificates and keys are small; anything else is not ours to keep
		}
		f, err := root.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		if err := tw.WriteHeader(&tar.Header{Name: prefix + p, Mode: 0o600, Size: info.Size(), Typeflag: tar.TypeReg, ModTime: info.ModTime()}); err != nil {
			return err
		}
		_, err = io.Copy(tw, io.LimitReader(f, info.Size()))
		return err
	})
}
