package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// How backups are encrypted. With the kit, only who holds a recovery kit
// opens them, not even someone who takes the server. In the simple mode
// the server keeps its own key (sealed with the master key): backups are
// still encrypted in the bucket, and the panel opens them itself to
// restore and download, with no kit to keep or upload.
const (
	ModeSimple = "simple"
	ModeKit    = "kit"
)

const settingMode = "backup.mode"

const serverKeyAD = "backup_server_key|server|identity"

// Mode is how backups are encrypted. Unset, an install that already
// confirmed a kit keeps it; a new one starts simple.
func (m *Manager) Mode(ctx context.Context) string {
	if v, err := m.q.GetSetting(ctx, settingMode); err == nil {
		var s string
		if json.Unmarshal([]byte(v), &s) == nil && (s == ModeSimple || s == ModeKit) {
			return s
		}
	}
	rs, _ := m.Recipients(ctx)
	for _, r := range rs {
		if r.Confirmed {
			return ModeKit
		}
	}
	return ModeSimple
}

// SetMode switches between the simple mode and the recovery kit. The kit
// needs a confirmed key first, or no backup could be made.
func (m *Manager) SetMode(ctx context.Context, a Actor, mode string) error {
	switch mode {
	case ModeKit:
		rs, err := m.Recipients(ctx)
		if err != nil {
			return err
		}
		confirmed := false
		for _, r := range rs {
			confirmed = confirmed || r.Confirmed
		}
		if !confirmed {
			return i18n.E("backup.error.mode_kit")
		}
	case ModeSimple:
		if _, err := m.serverIdentity(ctx, true); err != nil {
			return err
		}
	default:
		return i18n.E("backup.error.mode")
	}
	raw, _ := json.Marshal(mode)
	if err := m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingMode, ValueJson: string(raw)}); err != nil {
		return err
	}
	m.record(ctx, a, "backup.mode", "settings", settingMode, audit.OK, map[string]any{"mode": mode})
	return nil
}

// serverIdentity is the server's own backup key, made the first time it
// is needed when create is set (nil, nil when there is none yet).
func (m *Manager) serverIdentity(ctx context.Context, create bool) (*age.X25519Identity, error) {
	sealed, err := m.q.GetBackupServerKey(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		if !create {
			return nil, nil
		}
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
		enc, err := m.box.Seal([]byte(id.String()), serverKeyAD)
		if err != nil {
			return nil, err
		}
		if err := m.q.CreateBackupServerKey(ctx, dbq.CreateBackupServerKeyParams{IdentityEnc: enc, CreatedAt: m.now().Unix()}); err != nil {
			return nil, err
		}
		// Another request may have made one first: use what was stored.
		return m.serverIdentity(ctx, false)
	}
	if err != nil {
		return nil, err
	}
	raw, err := m.box.Open(sealed, serverKeyAD)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Identity(strings.TrimSpace(string(raw)))
}

// ServerKey is the server's key as text (AGE-SECRET-KEY-…), for whoever
// wants to keep a copy off the server: without it, backups made in the
// simple mode cannot be opened once the server is gone.
func (m *Manager) ServerKey(ctx context.Context, a Actor) (string, error) {
	id, err := m.serverIdentity(ctx, true)
	if err != nil {
		return "", err
	}
	m.record(ctx, a, "backup.server_key.reveal", "settings", settingMode, audit.OK, nil)
	return id.String(), nil
}

// withServerIdentity adds the server's key to the ones a restore tries:
// in the simple mode it is the only one, and it also opens backups made
// while the server held it.
func (m *Manager) withServerIdentity(ctx context.Context, ids []age.Identity) []age.Identity {
	if id, err := m.serverIdentity(ctx, false); err == nil && id != nil {
		ids = append(ids, id)
	}
	return ids
}

// OpenRun decrypts an older backup for download in the simple mode: the
// panel holds the key, so the file arrives ready to use. It returns the
// content and the file name without the encryption's extension.
func (m *Manager) OpenRun(ctx context.Context, a Actor, runID string) (io.ReadCloser, string, error) {
	r, err := m.q.GetBackupRun(ctx, runID)
	if err != nil || r.ObjectKey == "" || r.Status != "ok" {
		return nil, "", projects.ErrNotFound
	}
	ids := m.withServerIdentity(ctx, nil)
	if len(ids) == 0 {
		return nil, "", i18n.E("backup.error.kit")
	}
	ts, err := m.targets(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, t := range ts {
		src, _, err := t.store.Get(ctx, t.Prefix+r.ObjectKey)
		if err != nil {
			continue
		}
		plain, err := archive.Open(src, ids, archive.DefaultLimits)
		if err != nil {
			_ = src.Close()
			return nil, "", err
		}
		m.record(ctx, a, "backup.download", "backup_run", runID, audit.OK, map[string]any{"label": r.Label, "kind": r.Kind, "target": t.Name})
		name := strings.TrimSuffix(strings.TrimSuffix(path.Base(r.ObjectKey), ".age"), ".zst")
		if r.Label != "" {
			name = strings.ReplaceAll(r.Label, "/", "_") + "-" + name
		}
		return readCloser{plain, src}, name, nil
	}
	return nil, "", errors.New("the backup is in no destination anymore")
}

// readCloser closes the decrypted stream and the object under it.
type readCloser struct {
	io.ReadCloser
	under io.Closer
}

func (r readCloser) Close() error {
	err := r.ReadCloser.Close()
	if cerr := r.under.Close(); err == nil {
		err = cerr
	}
	return err
}
