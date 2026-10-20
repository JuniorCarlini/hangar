package backup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// DownloadTTL is how long a prepared download waits (docs/09: single-use
// link valid for 5 minutes).
const DownloadTTL = 5 * time.Minute

var randRead = rand.Read

// download is an encrypted dump waiting to be fetched once.
type download struct {
	Token     string
	UserID    string
	ServiceID string
	Label     string
	FileName  string
	Path      string
	Size      int64
	Ready     bool
	Error     string
	Expires   time.Time
	Started   time.Time
}

// Download is what the UI shows about a prepared download.
type Download struct {
	Token    string
	FileName string
	Size     int64
	Ready    bool
	Error    string
	Expires  time.Time
}

// PrepareDownload makes an encrypted, tested dump for the browser (docs/09
// "Baixar backup agora"): pg_dump, test restore, encrypted to the kit's
// public keys. It runs in the background (a big database takes longer than
// a request may last); PendingDownload shows it until it is ready.
func (m *Manager) PrepareDownload(ctx context.Context, a Actor, projectSlug, serviceSlug string) error {
	s, err := m.ref(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if _, err := m.recipients(ctx); err != nil {
		return err
	}
	if !m.running(ctx, s) {
		return ErrNotRunning
	}
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return err
	}
	d := &download{
		Token: hex.EncodeToString(b), UserID: a.UserID, ServiceID: s.ID, Label: s.label(),
		FileName: s.Project + "_" + s.Service + "-" + m.now().UTC().Format(archive.TimeFormat) + archive.ExtDump,
		Started:  m.now(), Expires: m.now().Add(time.Hour),
	}
	m.dlMu.Lock()
	for _, old := range m.downloads {
		// Still being prepared: a second click waits for that one instead
		// of starting another dump and throwing the first away.
		if old.UserID == a.UserID && old.ServiceID == s.ID && !old.Ready && old.Error == "" {
			m.dlMu.Unlock()
			return nil
		}
	}
	for k, old := range m.downloads {
		if old.UserID == a.UserID && old.ServiceID == s.ID {
			m.dropLocked(k)
		}
	}
	m.downloads[d.Token] = d
	m.dlMu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreTimeout)
		defer cancel()
		unlock := m.lock(s.label())
		sf, check, err := m.dumpAndVerify(bg, s)
		unlock()
		m.dlMu.Lock()
		defer m.dlMu.Unlock()
		if _, ok := m.downloads[d.Token]; !ok {
			if sf != nil {
				removeFile(sf.f)
			}
			return
		}
		if err != nil {
			d.Error = i18n.Message("en", err)
			m.record(bg, a, "service.backup.download", "service", s.ID, outcomeOf(err), map[string]any{"service": s.label(), "error": d.Error})
			return
		}
		_ = sf.f.Close()
		d.Path, d.Size, d.Ready, d.Expires = sf.f.Name(), sf.size.n, true, m.now().Add(DownloadTTL)
		m.record(bg, a, "service.backup.prepare", "service", s.ID, outcomeOf(nil), map[string]any{"service": s.label(), "rows": check.Rows, "tables": check.Tables})
	}()
	return nil
}

// PendingDownload is the user's prepared (or preparing) download of a
// service, if any.
func (m *Manager) PendingDownload(userID, serviceID string) (Download, bool) {
	m.dlMu.Lock()
	defer m.dlMu.Unlock()
	m.expireLocked()
	for _, d := range m.downloads {
		if d.UserID == userID && d.ServiceID == serviceID {
			return Download{Token: d.Token, FileName: d.FileName, Size: d.Size, Ready: d.Ready, Error: d.Error, Expires: d.Expires}, true
		}
	}
	return Download{}, false
}

// TakeDownload hands the file over once: the token is gone afterwards.
// The caller removes the file with the returned function after sending.
func (m *Manager) TakeDownload(ctx context.Context, a Actor, token string) (*os.File, string, func(), error) {
	m.dlMu.Lock()
	defer m.dlMu.Unlock()
	m.expireLocked()
	var d *download
	for k, x := range m.downloads {
		if subtle.ConstantTimeCompare([]byte(k), []byte(token)) == 1 {
			d = x
		}
	}
	if d == nil || !d.Ready || d.UserID != a.UserID {
		return nil, "", nil, projects.ErrNotFound
	}
	delete(m.downloads, d.Token)
	f, err := os.Open(d.Path)
	if err != nil {
		_ = os.Remove(d.Path)
		return nil, "", nil, err
	}
	m.record(ctx, a, "service.backup.download", "service", d.ServiceID, outcomeOf(nil), map[string]any{"service": d.Label, "size": d.Size, "encrypted": true})
	return f, d.FileName, func() { _ = f.Close(); _ = os.Remove(d.Path) }, nil
}

func (m *Manager) expireLocked() {
	now := m.now()
	for k, d := range m.downloads {
		if now.After(d.Expires) {
			m.dropLocked(k)
		}
	}
}

func (m *Manager) dropLocked(token string) {
	if d, ok := m.downloads[token]; ok {
		if d.Path != "" {
			_ = os.Remove(d.Path)
		}
		delete(m.downloads, token)
	}
}

// RunDownloadURL returns a short-lived signed link to an older backup in
// the first destination that has it (docs/09: "do bucket direto").
func (m *Manager) RunDownloadURL(ctx context.Context, a Actor, runID string) (string, error) {
	r, err := m.q.GetBackupRun(ctx, runID)
	if err != nil || r.ObjectKey == "" || r.Status != "ok" {
		return "", projects.ErrNotFound
	}
	ts, err := m.targets(ctx)
	if err != nil {
		return "", err
	}
	for _, t := range ts {
		if _, err := t.store.Head(ctx, t.Prefix+r.ObjectKey); err == nil {
			m.record(ctx, a, "backup.download_link", "backup_run", runID, outcomeOf(nil), map[string]any{"label": r.Label, "kind": r.Kind, "target": t.Name})
			return t.store.PresignGet(t.Prefix+r.ObjectKey, DownloadTTL), nil
		}
	}
	return "", errors.New("the backup is in no destination anymore")
}
