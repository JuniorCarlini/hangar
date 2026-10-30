package backup

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Restoring a project backup (docs/09 "Restaurar projeto") always makes a
// new project, never touching one that exists: the services are created
// from their configuration, each one's data goes back with the restore a
// service's own backup uses (the files come from the uploaded .zip instead
// of a destination), then the other services start. The fixed domains stay
// off, so the copy takes no traffic from the original. A restore that
// fails removes the services it created; the empty project stays with the
// error on it.

// projectRestoreTimeout bounds a whole project's restore.
const projectRestoreTimeout = 2 * restoreTimeout

// Limits of what a restore reads into memory from the uploaded file.
const (
	maxManifest   = 4 << 20
	maxConfigFile = 8 << 20
	// maxZipEntries bounds the files in an uploaded backup: a manifest,
	// the project's file and a handful per service.
	maxZipEntries = 10_000
)

// DefaultMaxRestoreUpload bounds an uploaded project backup when the
// configuration does not ([backup] max_restore_upload_gb).
const DefaultMaxRestoreUpload int64 = 100 << 30

// Errors of a project restore the UI translates.
var (
	ErrProjectFile   = &i18n.Error{Key: "project.restore.error.file"}
	ErrProjectFormat = &i18n.Error{Key: "project.restore.error.format"}
	// ErrUploadTooLarge is an upload over the limit (an HTTP 413).
	ErrUploadTooLarge = errors.New("the uploaded project backup is over the limit")
)

// maxUpload is the most a project backup upload may hold.
func (m *Manager) maxUpload() int64 {
	if m.opt.MaxRestoreUpload > 0 {
		return m.opt.MaxRestoreUpload
	}
	return DefaultMaxRestoreUpload
}

// uploadTooLarge is ErrUploadTooLarge with the message the user reads.
func (m *Manager) uploadTooLarge() error {
	return fmt.Errorf("%w: %w", ErrUploadTooLarge, i18n.E("project.restore.error.too_large", "max", gbText(m.maxUpload())))
}

// ProjectRestoreRequest is the "Novo projeto → A partir de um backup" form.
type ProjectRestoreRequest struct {
	// Name is the new project's name.
	Name string
	// File is the uploaded backup in the staging dir (StageUpload); the
	// restore removes it when it ends, or right away when it does not start.
	File     string
	FileName string
	// Identities are the kit's private keys, in memory for this restore
	// only (none in the simple mode).
	Identities []age.Identity
}

// ProjectRestoreNotes is what a restore left for the owner to decide.
type ProjectRestoreNotes struct {
	// Domains are the original's fixed domains, left off ("service: host").
	Domains []string `json:"domains,omitempty"`
	// Public are the endpoints the original had on the internet.
	Public []string `json:"public,omitempty"`
	// Linked are the connections to other projects made again; Unlinked,
	// the ones whose project is not on this server.
	Linked   []string `json:"linked,omitempty"`
	Unlinked []string `json:"unlinked,omitempty"`
	// NoGitAccess are Git services that need a credential to build.
	NoGitAccess []string `json:"no_git_access,omitempty"`
	// NoLogin are roles created without a password ("service: roles").
	NoLogin []string `json:"no_login,omitempty"`
	// NotStarted are services with no data of their own that did not
	// start ("service: error"): the data is back, they can be fixed.
	NotStarted []string `json:"not_started,omitempty"`
	// Cleanup says what happened to the services of a failed restore.
	Cleanup string `json:"cleanup,omitempty"`
}

// ProjectRestore is a project's restore as the UI shows it.
type ProjectRestore struct {
	ID         string
	Source     string
	FileName   string
	Status     string
	Step       string
	Error      string
	StartedAt  time.Time
	FinishedAt time.Time
	Notes      ProjectRestoreNotes
}

// LatestProjectRestore is the restore that made a project, if any.
func (m *Manager) LatestProjectRestore(ctx context.Context, projectID string) (ProjectRestore, bool) {
	r, err := m.q.LatestProjectRestore(ctx, projectID)
	if err != nil {
		return ProjectRestore{}, false
	}
	out := ProjectRestore{
		ID: r.ID, Source: r.Source, FileName: r.FileName, Status: r.Status, Step: r.Step, Error: r.Error.String,
		StartedAt: time.Unix(r.StartedAt, 0),
	}
	if r.FinishedAt.Valid {
		out.FinishedAt = time.Unix(r.FinishedAt.Int64, 0)
	}
	_ = json.Unmarshal([]byte(r.NotesJson), &out.Notes)
	return out, true
}

// StageUpload writes an uploaded project backup of size bytes (-1 when
// unknown) into the staging dir, refusing one over the upload limit
// (ErrUploadTooLarge, also once more than that has arrived) or one the
// server's disk cannot hold with room to spare. It returns the file's
// path.
func (m *Manager) StageUpload(r io.Reader, size int64) (string, error) {
	limit := m.maxUpload()
	if size > limit+1<<20 { // size is the whole request: the form fields and the kit come along
		return "", m.uploadTooLarge()
	}
	if free, ok := freeSpace(m.opt.StagingDir); ok && size > 0 && free < size+stagingReserve {
		return "", i18n.E("backup.error.no_room", "need", gbText(size+stagingReserve), "free", gbText(free))
	}
	f, err := m.stagingFile("upload-*.zip")
	if err != nil {
		return "", err
	}
	n, err := io.Copy(&roomWriter{w: f, dir: m.opt.StagingDir}, io.LimitReader(r, limit+1))
	if err == nil && n > limit {
		err = m.uploadTooLarge()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// projectFile is an uploaded project backup, open.
type projectFile struct {
	zr     *zip.ReadCloser
	byName map[string]*zip.File
	man    ProjectManifest
	// ids open its sealed files: the kit's (never the server's own key,
	// see StartProjectRestore) and eph, which seals its open files on the
	// way to the restore (localSource).
	ids []age.Identity
	eph *age.X25519Identity
}

func (pf *projectFile) close() { _ = pf.zr.Close() }

// openProjectFile opens the .zip at path and checks its manifest. ids are
// the keys from the kit (if any).
func openProjectFile(path string, ids []age.Identity) (*projectFile, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, ErrProjectFile
	}
	pf := &projectFile{zr: zr, byName: map[string]*zip.File{}}
	ok := false
	defer func() {
		if !ok {
			pf.close()
		}
	}()
	if len(zr.File) > maxZipEntries {
		return nil, fmt.Errorf("%w: %d files", ErrProjectFile, len(zr.File))
	}
	for _, f := range zr.File {
		if _, dup := pf.byName[f.Name]; dup {
			return nil, fmt.Errorf("%w: %s twice", ErrProjectFile, f.Name)
		}
		pf.byName[f.Name] = f
	}
	mf, found := pf.byName[ManifestName]
	if !found {
		return nil, ErrProjectFile
	}
	raw, err := readZip(mf, maxManifest)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &pf.man); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProjectFile, err)
	}
	if err := pf.check(); err != nil {
		return nil, err
	}
	if pf.eph, err = age.GenerateX25519Identity(); err != nil {
		return nil, err
	}
	pf.ids = append(slices.Clone(ids), pf.eph)
	ok = true
	return pf, nil
}

// readZip reads a whole (small) file of the .zip.
func readZip(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProjectFile, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProjectFile, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s is too large", ErrProjectFile, f.Name)
	}
	return b, nil
}

// check validates the manifest against the .zip: a known format, valid
// and unique service names, each file present once, where it belongs,
// encrypted or not as the manifest says, and what each method needs.
func (pf *projectFile) check() error {
	man := pf.man
	if man.Format != ProjectFormat {
		return ErrProjectFormat
	}
	if len(man.Services) == 0 {
		return fmt.Errorf("%w: no services", ErrProjectFile)
	}
	seen := map[string]bool{}
	part := func(p ManifestPart, dir string) error {
		clean := path.Clean(p.Path)
		switch {
		case clean != p.Path, strings.HasPrefix(p.Path, "/"), strings.Contains(p.Path, ".."), seen[p.Path]:
			return fmt.Errorf("%w: path %q", ErrProjectFile, p.Path)
		case dir != "" && !strings.HasPrefix(p.Path, dir), dir == "" && strings.Contains(p.Path, "/"):
			return fmt.Errorf("%w: %q out of place", ErrProjectFile, p.Path)
		case pf.byName[p.Path] == nil:
			return fmt.Errorf("%w: %q missing", ErrProjectFile, p.Path)
		case p.Size < 0 || uint64(p.Size) != pf.byName[p.Path].UncompressedSize64:
			// The zip and the manifest agree on every size; reading a file
			// then stops at that size (archive/zip and verify).
			return fmt.Errorf("%w: %q size", ErrProjectFile, p.Path)
		case p.Role == partData || p.Role == partConfig || p.Role == partRoles:
			if strings.HasSuffix(p.Path, ".age") != man.Encrypted {
				return fmt.Errorf("%w: %q encrypted or not, against the manifest", ErrProjectFile, p.Path)
			}
		}
		seen[p.Path] = true
		return nil
	}
	if _, ok := manifestConfig(man.Parts); !ok {
		return fmt.Errorf("%w: no %s", ErrProjectFile, ProjectFile)
	}
	for _, p := range man.Parts {
		if err := part(p, ""); err != nil {
			return err
		}
	}
	names := map[string]bool{}
	for _, s := range man.Services {
		if !node.SlugRE.MatchString(s.Service) || names[s.Service] {
			return fmt.Errorf("%w: service %q", ErrProjectFile, s.Service)
		}
		names[s.Service] = true
		for _, p := range s.Parts {
			if err := part(p, projectServices+s.Service+"/"); err != nil {
				return err
			}
		}
		if _, ok := s.part(partConfig); !ok {
			return fmt.Errorf("%w: %s has no %s", ErrProjectFile, s.Service, ServiceFile)
		}
		_, data := s.part(partData)
		switch s.Method {
		case "":
		case projects.BackupPGDump:
			if _, roles := s.part(partRoles); !data || !roles {
				return fmt.Errorf("%w: %s has no dump and roles", ErrProjectFile, s.Service)
			}
		case projects.BackupRecipe:
			if !data {
				return fmt.Errorf("%w: %s has no data", ErrProjectFile, s.Service)
			}
		case projects.BackupVolume:
			if _, ok := archive.ParseVolumeMeta(s.Volumes); !data || !ok {
				return fmt.Errorf("%w: %s has no copy of its volumes", ErrProjectFile, s.Service)
			}
		default:
			return fmt.Errorf("%w: %s: method %q", ErrProjectFile, s.Service, s.Method)
		}
	}
	return nil
}

func manifestConfig(parts []ManifestPart) (ManifestPart, bool) {
	for _, p := range parts {
		if p.Role == partConfig {
			return p, true
		}
	}
	return ManifestPart{}, false
}

// readConfig reads a configuration file of the backup (decrypted).
func (pf *projectFile) readConfig(p ManifestPart, v any) error {
	f := pf.byName[p.Path]
	if !pf.man.Encrypted {
		raw, err := readZip(f, maxConfigFile)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, v)
	}
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProjectFile, err)
	}
	defer func() { _ = rc.Close() }()
	plain, err := archive.Open(rc, pf.ids, archive.DefaultLimits)
	if errors.Is(err, archive.ErrWrongKey) {
		return i18n.E("project.restore.error.wrong_key")
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProjectFile, err)
	}
	defer func() { _ = plain.Close() }()
	raw, err := io.ReadAll(io.LimitReader(plain, maxConfigFile+1))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProjectFile, err)
	}
	if len(raw) > maxConfigFile {
		return fmt.Errorf("%w: %s is too large", ErrProjectFile, p.Path)
	}
	return json.Unmarshal(raw, v)
}

// verify checks every file of the backup against its size and SHA-256 in
// the manifest, before anything is restored from it.
func (pf *projectFile) verify(ctx context.Context) error {
	all := slices.Clone(pf.man.Parts)
	for _, s := range pf.man.Services {
		all = append(all, s.Parts...)
	}
	for _, p := range all {
		if err := ctx.Err(); err != nil {
			return err
		}
		rc, err := pf.byName[p.Path].Open()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrProjectFile, err)
		}
		sum := sha256.New()
		n, err := io.Copy(sum, io.LimitReader(rc, p.Size+1))
		_ = rc.Close()
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrProjectFile, p.Path, err)
		}
		if n != p.Size || hex.EncodeToString(sum.Sum(nil)) != p.SHA256 {
			return i18n.E("project.restore.error.corrupt", "file", p.Path)
		}
	}
	return nil
}

// localKey names a service's data in localSource as the bucket would, so
// the restores pick the same limits and find the roles next to a dump.
func localKey(s ManifestService) string {
	base := "upload/" + s.Service + "/" + s.Taken.UTC().Format(archive.TimeFormat)
	switch s.Method {
	case projects.BackupVolume:
		return base + archive.ExtVolumes
	case projects.BackupRecipe:
		return base + archive.ExtRecipe
	}
	return base + archive.ExtDump
}

// source maps the data of the backup to the keys the restores read.
func (pf *projectFile) source() *localSource {
	src := &localSource{parts: map[string]localPart{}, eph: pf.eph.Recipient()}
	for _, s := range pf.man.Services {
		if s.Method == "" {
			continue
		}
		key := localKey(s)
		meta := map[string]string{}
		if s.Volumes != "" {
			meta["hangar-volumes"] = s.Volumes
		}
		if s.DB != "" {
			meta["hangar-db-name"] = s.DB
		}
		if p, ok := s.part(partData); ok {
			src.parts[key] = localPart{f: pf.byName[p.Path], sealed: pf.man.Encrypted, meta: meta}
		}
		if p, ok := s.part(partRoles); ok {
			src.parts[archive.RolesKey(key)] = localPart{f: pf.byName[p.Path], sealed: pf.man.Encrypted}
		}
	}
	return src
}

// localSource serves the files of an uploaded backup to the restores in
// place of a destination (fetch, loadRoles). An open file is sealed on the
// way, to a key made for this restore alone, so every restore reads what
// it always reads: an age file.
type localSource struct {
	parts map[string]localPart
	eph   age.Recipient
}

type localPart struct {
	f      *zip.File
	sealed bool
	meta   map[string]string
}

type localKeyCtx struct{}

func withLocal(ctx context.Context, src *localSource) context.Context {
	return context.WithValue(ctx, localKeyCtx{}, src)
}

func localFrom(ctx context.Context) *localSource {
	src, _ := ctx.Value(localKeyCtx{}).(*localSource)
	return src
}

// errNoPart: the backup has no such file (a not found, for loadRoles).
var errNoPart = errors.New("no such file in the backup")

func (l *localSource) get(key string) (io.ReadCloser, s3.ObjectInfo, error) {
	p, ok := l.parts[key]
	if !ok {
		return nil, s3.ObjectInfo{}, errNoPart
	}
	info := s3.ObjectInfo{Key: key, Size: int64(min(p.f.UncompressedSize64, 1<<62)), Metadata: p.meta} //nolint:gosec // bounded
	rc, err := p.f.Open()
	if err != nil {
		return nil, info, err
	}
	if p.sealed {
		return rc, info, nil
	}
	pr, pw := io.Pipe()
	go func() {
		w, err := archive.Seal(pw, []age.Recipient{l.eph}, false)
		if err == nil {
			// verify checked every file against its size before this.
			_, err = io.Copy(w, io.LimitReader(rc, archive.VolumeLimits.MaxBytes))
			if cerr := w.Close(); err == nil {
				err = cerr
			}
		}
		_ = rc.Close()
		_ = pw.CloseWithError(err)
	}()
	return pr, info, nil
}

// StartProjectRestore opens the uploaded backup, checks it and the kit,
// creates the new project with its services (no data yet) and restores
// the rest in the background. It returns the new project's slug. The
// uploaded file is removed when the restore ends (or right away when it
// does not start).
func (m *Manager) StartProjectRestore(ctx context.Context, a Actor, req ProjectRestoreRequest) (slug string, err error) {
	started := false
	defer func() {
		if !started {
			_ = os.Remove(req.File)
		}
	}()
	if _, _, err := m.tasker(); err != nil {
		return "", err
	}
	// Only the uploaded kit opens an uploaded file, never the server's own
	// key: that key opens the panel's backups made in the simple mode
	// (master key, every secret), and a file sealed to it, dropped into a
	// bundle, would be decrypted and handed to a container the bundle
	// names. Hangar's own bundles never need it: in the simple mode they
	// leave the server open, with the kit they are sealed to the kit.
	pf, err := openProjectFile(req.File, req.Identities)
	if err != nil {
		return "", err
	}
	defer func() {
		if !started {
			pf.close()
		}
	}()
	if pf.man.Encrypted && len(pf.ids) == 1 {
		return "", i18n.E("backup.error.kit")
	}
	cfg, _ := manifestConfig(pf.man.Parts)
	var ps projects.ProjectSnapshot
	if err := pf.readConfig(cfg, &ps); err != nil {
		return "", err
	}
	snaps := make([]projects.ServiceSnapshot, 0, len(pf.man.Services))
	for _, s := range pf.man.Services {
		p, _ := s.part(partConfig)
		var snap projects.ServiceSnapshot
		if err := pf.readConfig(p, &snap); err != nil {
			return "", err
		}
		if snap.Service != s.Service {
			return "", fmt.Errorf("%w: %s holds %q", ErrProjectFile, p.Path, snap.Service)
		}
		// The data goes back the way it was backed up: this server must
		// back the service up the same way (its template, here).
		if got := m.projects.SnapshotMethod(snap); got != s.Method {
			return "", i18n.E("project.restore.error.method", "service", s.Service)
		}
		snaps = append(snaps, snap)
	}
	res, err := m.projects.CreateFromSnapshots(ctx, a, req.Name, ps, snaps)
	if err != nil {
		return "", err
	}
	notes := ProjectRestoreNotes{
		Domains: res.Domains, Public: res.Public, Linked: res.Linked, Unlinked: res.Unlinked, NoGitAccess: res.NoGitAccess,
	}
	id := ids.New("prr_")
	if err := m.q.CreateProjectRestore(ctx, dbq.CreateProjectRestoreParams{
		ID: id, ProjectID: res.Project.ID, Source: pf.man.Project, FileName: truncate(req.FileName, 200), Step: "verify",
		CreatedBy: nullStr(a.UserID), StartedAt: m.now().Unix(),
	}); err != nil {
		_ = m.projects.RemoveRestoredServices(context.WithoutCancel(ctx), a, res.Project.Slug)
		return "", err
	}
	m.setNotes(ctx, id, notes)
	m.record(ctx, a, "project.restore.start", "project", res.Project.ID, outcomeOf(nil), map[string]any{
		"project": res.Project.Slug, "source": pf.man.Project, "file": req.FileName, "services": len(snaps),
		"encrypted": pf.man.Encrypted, "private_key_used": len(req.Identities) > 0, "restore": id,
	})
	started = true
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() { _ = os.Remove(req.File) }()
		defer pf.close()
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), projectRestoreTimeout)
		defer cancel()
		err := m.runProjectRestore(rctx, a, id, pf, res.Project, &notes)
		pf.ids = nil // the kit's keys are dropped as soon as the restore ends
		status, errText := "ok", sql.NullString{}
		if err != nil {
			status = "failed"
			errText = sql.NullString{String: truncate(i18n.Message("en", err), 2000), Valid: true}
			m.log.Warn("project restore failed", "project", res.Project.Slug, "restore", id, "error", err)
			notes.Cleanup = CleanupRemoved
			if rerr := m.projects.RemoveRestoredServices(context.WithoutCancel(ctx), a, res.Project.Slug); rerr != nil {
				notes.Cleanup = CleanupKept
				m.log.Warn("remove the services of a failed project restore", "project", res.Project.Slug, "error", rerr)
			}
		}
		m.setNotes(rctx, id, notes)
		_ = m.q.FinishProjectRestore(context.WithoutCancel(ctx), dbq.FinishProjectRestoreParams{
			Status: status, Error: errText, FinishedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: id,
		})
		m.record(rctx, a, "project.restore", "project", res.Project.ID, outcomeOf(err), map[string]any{
			"project": res.Project.Slug, "source": pf.man.Project, "restore": id, "error": errText.String,
			"domains_off": len(notes.Domains), "not_started": notes.NotStarted,
		})
	}()
	return res.Project.Slug, nil
}

func (m *Manager) setNotes(ctx context.Context, id string, n ProjectRestoreNotes) {
	b, _ := json.Marshal(n)
	_ = m.q.SetProjectRestoreNotes(context.WithoutCancel(ctx), dbq.SetProjectRestoreNotesParams{NotesJson: string(b), ID: id})
}

func (m *Manager) projectStep(ctx context.Context, id, step string) {
	_ = m.q.SetProjectRestoreStep(context.WithoutCancel(ctx), dbq.SetProjectRestoreStepParams{Step: step, ID: id})
}

// runProjectRestore checks the whole file, then brings each service with
// data up and puts its data back (databases and copies first, so apps
// start against their data), then starts the others. A service with data
// that fails fails the restore; one without data that does not start is
// noted (its data is back, it can be fixed).
func (m *Manager) runProjectRestore(ctx context.Context, a Actor, id string, pf *projectFile, p dbq.Project, notes *ProjectRestoreNotes) error {
	m.projectStep(ctx, id, "verify")
	if err := pf.verify(ctx); err != nil {
		return err
	}
	lctx := withLocal(ctx, pf.source())
	for _, s := range pf.man.Services {
		if s.Method == "" {
			continue
		}
		m.projectStep(ctx, id, "restore:"+s.Service)
		roles, err := m.restoreProjectService(lctx, a, p.Slug, s, pf.ids)
		if len(roles) > 0 {
			notes.NoLogin = append(notes.NoLogin, s.Service+": "+strings.Join(roles, ", "))
			m.setNotes(ctx, id, *notes)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", s.Service, err)
		}
	}
	for _, s := range pf.man.Services {
		if s.Method != "" {
			continue
		}
		m.projectStep(ctx, id, "start:"+s.Service)
		t := svcRef{Project: p.Slug, Service: s.Service}
		if _, sv, err := m.projects.GetService(ctx, p.Slug, s.Service); err == nil {
			t.ID = sv.ID
		}
		if err := m.deployAndWait(ctx, a, t, "create"); err != nil {
			notes.NotStarted = append(notes.NotStarted, s.Service+": "+truncate(err.Error(), 300))
			m.setNotes(ctx, id, *notes)
		}
	}
	m.projectStep(ctx, id, "done")
	return nil
}

// restoreProjectService deploys the new service t of a project restore
// (so its disks exist) and puts its data back from the backup, the way a
// restore of the service's own backup into a new service does. It returns
// the roles it created without a password.
func (m *Manager) restoreProjectService(ctx context.Context, a Actor, project string, s ManifestService, keys []age.Identity) ([]string, error) {
	t, err := m.ref(ctx, project, s.Service)
	if err != nil {
		return nil, err
	}
	if t.Method != s.Method {
		return nil, i18n.E("project.restore.error.method", "service", s.Service)
	}
	unlock := m.lock("restore:" + t.label())
	defer unlock()
	if err := m.deployAndWait(ctx, a, t, "create"); err != nil {
		return nil, err
	}
	// Read again: the deploy created the disks.
	if t, err = m.ref(ctx, project, s.Service); err != nil {
		return nil, err
	}
	key := localKey(s)
	switch s.Method {
	case projects.BackupVolume:
		_, err = m.restoreVolumes(ctx, a, "", t, key, keys)
		return nil, err
	case projects.BackupRecipe:
		return nil, m.restoreRecipe(ctx, "", t, key, keys)
	}
	roles, err := m.restoreDump(ctx, "", t, key, keys)
	return roles.NoLogin, err
}
