package backup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// DownloadTTL is how long a prepared download waits (docs/09: single-use
// link valid for 5 minutes).
const DownloadTTL = 5 * time.Minute

var randRead = rand.Read

// download is an encrypted backup (a dump and the roles of its server, or
// a copy of volumes) waiting to be fetched once as one bundle
// (archive.WriteBundle).
type download struct {
	Token     string
	UserID    string
	ServiceID string
	Label     string
	FileName  string
	Base      string // name of the files in the bundle, without extension
	Readme    string
	Files     []dlFile // in the bundle's order, after the README
	Size      int64
	Ready     bool
	Error     string
	Expires   time.Time
	Started   time.Time
	// Open: the simple mode's server holds the key, so the files go out
	// decrypted (a copy of volumes: encrypted only while it waits here).
	Open bool
}

// dlFile is a staged file of a download and its name in the bundle.
type dlFile struct {
	Name string
	Path string
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
	if s.Method == projects.BackupPGDump && !m.running(ctx, s) {
		return ErrNotRunning
	}
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return err
	}
	base := archive.BundleName(s.Project, s.Service, m.now())
	readme := BundleReadme(ctx, base, s.DBName, true)
	open := false
	if s.Method == projects.BackupVolume {
		// The copy is made here, then sent: the services are paused only
		// for the copy, not for as long as the browser takes.
		open = m.Mode(ctx) == ModeSimple
		readme = VolumesReadme(ctx, base, s.label(), volumeList(s), !open)
	}
	d := &download{
		Token: hex.EncodeToString(b), UserID: a.UserID, ServiceID: s.ID, Label: s.label(),
		FileName: base + archive.ExtBundle, Base: base, Readme: readme, Open: open,
		Started: m.now(), Expires: m.now().Add(time.Hour),
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
		files, summary, err := m.prepareFiles(bg, s, base)
		unlock()
		m.dlMu.Lock()
		defer m.dlMu.Unlock()
		if _, ok := m.downloads[d.Token]; !ok {
			for _, f := range files {
				_ = os.Remove(f.Path)
			}
			return
		}
		if err != nil {
			d.Error = i18n.Message("en", err)
			m.record(bg, a, "service.backup.download", "service", s.ID, outcomeOf(err), map[string]any{"service": s.label(), "error": d.Error})
			return
		}
		d.Files = files
		for _, f := range files {
			if st, err := os.Stat(f.Path); err == nil {
				d.Size += st.Size()
			}
		}
		d.Ready, d.Expires = true, m.now().Add(DownloadTTL)
		summary["service"] = s.label()
		m.record(bg, a, "service.backup.prepare", "service", s.ID, outcomeOf(nil), summary)
	}()
	return nil
}

// prepareFiles makes the tested, encrypted files of a download in the
// staging dir: the roles and the dump of a database, or a copy of the
// volumes (kept consistent as the policy says).
func (m *Manager) prepareFiles(ctx context.Context, s svcRef, base string) ([]dlFile, map[string]any, error) {
	if s.Method == projects.BackupVolume {
		v, err := m.archiveVolumes(ctx, s, m.consistency(ctx, s))
		if err != nil {
			return nil, nil, err
		}
		_ = v.file.f.Close()
		return []dlFile{{Name: base + archive.ExtVolumes, Path: v.file.f.Name()}},
			map[string]any{"files": v.check.Files, "bytes": v.check.Bytes, "pause_ms": v.check.PauseMS}, nil
	}
	dd, err := m.dumpAndVerify(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	_ = dd.dump.f.Close()
	_ = dd.roles.f.Close()
	return []dlFile{{Name: base + archive.ExtRoles, Path: dd.roles.f.Name()}, {Name: base + archive.ExtDump, Path: dd.dump.f.Name()}},
		map[string]any{"rows": dd.check.Rows, "tables": dd.check.Tables}, nil
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

// Bundle writes a download (archive.WriteBundle) to w.
type Bundle func(w io.Writer) error

// TakeDownload hands the bundle over once: the token is gone afterwards.
// The caller removes the files with the returned function after sending.
func (m *Manager) TakeDownload(ctx context.Context, a Actor, token string) (Bundle, string, func(), error) {
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
	var opened []io.Closer
	done := func() {
		for _, f := range opened {
			_ = f.Close()
		}
		for _, f := range d.Files {
			_ = os.Remove(f.Path)
		}
	}
	files := []archive.BundleFile{archive.TextFile(ReadmeName, d.Readme)}
	var ids []age.Identity
	if d.Open {
		if ids = m.withServerIdentity(ctx, nil); len(ids) == 0 {
			done()
			return nil, "", nil, i18n.E("backup.error.kit")
		}
	}
	for _, df := range d.Files {
		f, err := os.Open(df.Path)
		if err != nil {
			done()
			return nil, "", nil, err
		}
		opened = append(opened, f)
		bf := archive.BundleFile{Name: df.Name, Body: f}
		if d.Open {
			plain, err := archive.Open(f, ids, archive.LimitsFor(df.Name))
			if err != nil {
				done()
				return nil, "", nil, err
			}
			opened = append(opened, plain)
			bf = archive.BundleFile{Name: strings.TrimSuffix(strings.TrimSuffix(df.Name, ".age"), ".zst"), Body: plain}
		}
		files = append(files, bf)
	}
	m.record(ctx, a, "service.backup.download", "service", d.ServiceID, outcomeOf(nil), map[string]any{"service": d.Label, "size": d.Size, "encrypted": !d.Open, "files": len(d.Files)})
	bundle := func(w io.Writer) error { return archive.WriteBundle(w, m.now(), files...) }
	return bundle, d.FileName, done, nil
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
		for _, f := range d.Files {
			_ = os.Remove(f.Path)
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
