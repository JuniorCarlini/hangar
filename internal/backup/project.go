package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgroles"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A project backup (docs/09 "Backup do projeto") is one .zip with every
// service of a project, whole: README.txt, project.json (the project's own
// configuration: its connections to other projects), a folder per service
// laid out as the service's own download (README, data, roles, its
// service.json), and manifest.json last, which says what each file is and
// its SHA-256. A service's data is its newest tested backup in a
// destination, as it is (the service is not touched); one with no backup
// yet is backed up now, the way Hangar always backs it up. Files are
// encrypted to the kit, or open in the simple mode, as a service's
// download is.

// ProjectFormat is the version of a project backup's manifest.
const ProjectFormat = 1

// Names in a project backup.
const (
	ManifestName = "manifest.json"
	ProjectFile  = "project.json"
	// ExtProject is the extension of a project backup.
	ExtProject = ".hangar.zip"
	// projectServices is the folder of the services.
	projectServices = "services/"
)

// What each file of a project backup is.
const (
	partData         = "data"
	partRoles        = "roles"
	partRolesRestore = "roles_restore"
	partConfig       = "config"
	partReadme       = "readme"
)

// Where a service's data in a project backup came from.
const (
	SourceBackup = "backup" // its newest tested backup in a destination
	SourceNow    = "now"    // backed up for this download
)

// ProjectManifest is manifest.json.
type ProjectManifest struct {
	Format    int       `json:"format"`
	Hangar    string    `json:"hangar_version"`
	Created   time.Time `json:"created_at"`
	Project   string    `json:"project"`
	Name      string    `json:"name"`
	Encrypted bool      `json:"encrypted"`
	// Parts are the project's own files (README, project.json).
	Parts    []ManifestPart    `json:"parts"`
	Services []ManifestService `json:"services"`
}

// ManifestService is a service of a project backup.
type ManifestService struct {
	Service  string `json:"service"`
	Template string `json:"template,omitempty"`
	// Method is how its data is backed up (projects.BackupPGDump,
	// BackupRecipe, BackupVolume); "" for a service with no data, which
	// only carries its configuration.
	Method string    `json:"method,omitempty"`
	Source string    `json:"source,omitempty"`
	Taken  time.Time `json:"taken_at,omitzero"`
	// Volumes is what a copy of volumes holds (archive.VolumeManifest's
	// metadata); DB, a dump's database.
	Volumes string         `json:"volumes,omitempty"`
	DB      string         `json:"db,omitempty"`
	Parts   []ManifestPart `json:"parts"`
}

// ManifestPart is one file of a project backup.
type ManifestPart struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// part returns the service's file with role, if any.
func (s ManifestService) part(role string) (ManifestPart, bool) {
	for _, p := range s.Parts {
		if p.Role == role {
			return p, true
		}
	}
	return ManifestPart{}, false
}

// projectBundle is what a prepared project backup sends.
type projectBundle struct {
	manifest ProjectManifest
	readme   string
	config   dlFile
	services []bundleService
}

// bundleService is a service's folder in a project backup.
type bundleService struct {
	meta   ManifestService
	readme string
	files  []dlFile // data, roles, config
}

// ProjectBundleName is the name of a project backup made at t.
func ProjectBundleName(project string, t time.Time) string {
	return project + "-" + t.UTC().Format(archive.TimeFormat) + ExtProject
}

// PrepareProjectDownload makes a backup of a whole project for the
// browser in the background (docs/09 "Baixar backup do projeto");
// PendingProjectDownload shows it until it is ready.
func (m *Manager) PrepareProjectDownload(ctx context.Context, a Actor, projectSlug string) error {
	p, err := m.projects.GetProject(ctx, projectSlug)
	if err != nil {
		return err
	}
	svcs, err := m.projects.ListServices(ctx, p.ID)
	if err != nil {
		return err
	}
	if len(svcs) == 0 {
		return i18n.E("project.backup.error.empty")
	}
	if _, err := m.recipients(ctx); err != nil {
		return err
	}
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return err
	}
	now := m.now()
	d := &download{
		Token: hex.EncodeToString(b), UserID: a.UserID, ServiceID: p.ID, Label: p.Slug,
		FileName: ProjectBundleName(p.Slug, now), Open: m.Mode(ctx) == ModeSimple,
		Started: now, Expires: now.Add(restoreTimeout), Project: &projectBundle{},
	}
	m.dlMu.Lock()
	for _, old := range m.downloads {
		if old.UserID == a.UserID && old.ServiceID == p.ID && !old.Ready && old.Error == "" {
			m.dlMu.Unlock()
			return nil
		}
	}
	for k, old := range m.downloads {
		if old.UserID == a.UserID && old.ServiceID == p.ID {
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
		pb, err := m.prepareProject(bg, p, svcs, d.Open)
		m.dlMu.Lock()
		defer m.dlMu.Unlock()
		files := pb.allFiles()
		if _, ok := m.downloads[d.Token]; !ok {
			removeAll(files)
			return
		}
		summary := map[string]any{"project": p.Slug}
		if err != nil {
			removeAll(files)
			d.Error = i18n.Message("en", err)
			summary["error"] = d.Error
			m.record(bg, a, "project.backup.download", "project", p.ID, outcomeOf(err), summary)
			return
		}
		d.Project, d.Files = pb, files
		for _, f := range files {
			if st, err := os.Stat(f.Path); err == nil {
				d.Size += st.Size()
			}
		}
		d.Ready, d.Expires = true, m.now().Add(DownloadTTL)
		var from []string
		for _, s := range pb.services {
			if s.meta.Method != "" {
				from = append(from, s.meta.Service+":"+s.meta.Source)
			}
		}
		summary["services"], summary["data"] = len(pb.services), from
		m.record(bg, a, "project.backup.prepare", "project", p.ID, outcomeOf(nil), summary)
	}()
	return nil
}

// PendingProjectDownload is the user's prepared (or preparing) backup of
// a project, if any.
func (m *Manager) PendingProjectDownload(userID, projectID string) (Download, bool) {
	m.dlMu.Lock()
	defer m.dlMu.Unlock()
	m.expireLocked()
	for _, d := range m.downloads {
		if d.UserID == userID && d.ServiceID == projectID && d.Project != nil {
			return Download{Token: d.Token, FileName: d.FileName, Size: d.Size, Ready: d.Ready, Error: d.Error, Expires: d.Expires}, true
		}
	}
	return Download{}, false
}

func (pb *projectBundle) allFiles() []dlFile {
	if pb == nil {
		return nil
	}
	var out []dlFile
	if pb.config.Path != "" {
		out = append(out, pb.config)
	}
	for _, s := range pb.services {
		out = append(out, s.files...)
	}
	return out
}

func removeAll(files []dlFile) {
	for _, f := range files {
		_ = os.Remove(f.Path)
	}
}

// prepareProject gathers the files of a project backup in the staging
// dir. On error, the files made so far are in the result for the caller
// to remove.
func (m *Manager) prepareProject(ctx context.Context, p dbq.Project, svcs []dbq.Service, open bool) (*projectBundle, error) {
	pb := &projectBundle{manifest: ProjectManifest{
		Format: ProjectFormat, Hangar: m.opt.Version, Created: m.now().UTC(), Project: p.Slug, Name: p.Name, Encrypted: !open,
	}}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Slug < svcs[j].Slug })
	snap, err := m.projects.SnapshotProject(ctx, p.Slug)
	if err != nil {
		return pb, err
	}
	raw, err := indentJSON(snap)
	if err != nil {
		return pb, err
	}
	if pb.config, err = m.sealedJSON(ctx, ProjectFile, raw); err != nil {
		return pb, err
	}
	pb.readme = ProjectReadme(ctx, p.Slug, !open)
	for _, s := range svcs {
		bs := bundleService{meta: ManifestService{Service: s.Slug, Template: s.Template}}
		r, err := m.toRef(ctx, p, s)
		switch {
		case errors.Is(err, ErrUnsupported):
			// No data of its own: its configuration is all it takes.
			r = svcRef{ID: s.ID, Project: p.Slug, Service: s.Slug}
			bs.readme = strings.TrimLeft(ServiceReadme(ctx, !open), "\n")
		case err != nil:
			return pb, err
		default:
			if err := m.serviceData(ctx, r, open, &bs); err != nil {
				pb.services = append(pb.services, bs)
				return pb, fmt.Errorf("%s: %w", s.Slug, err)
			}
		}
		cf, err := m.configFile(ctx, r)
		if err != nil {
			pb.services = append(pb.services, bs)
			return pb, err
		}
		bs.files = append(bs.files, cf)
		pb.services = append(pb.services, bs)
	}
	return pb, nil
}

// serviceData puts r's data in bs: its newest tested backup in a
// destination, or a new one when there is none (or it cannot be used).
func (m *Manager) serviceData(ctx context.Context, r svcRef, open bool, bs *bundleService) error {
	bs.meta.Method = r.Method
	files, err := m.stageLatest(ctx, r, open, &bs.meta)
	if err != nil {
		return err
	}
	if files == nil {
		if r.online() && !m.running(ctx, r) {
			return i18n.E("project.backup.error.not_running", "service", r.Service)
		}
		bs.meta.Source, bs.meta.Taken, bs.meta.DB = SourceNow, m.now().UTC(), r.DBName
		base := archive.BundleName(r.Project, r.Service, bs.meta.Taken)
		unlock := m.lock(r.label())
		files, _, bs.meta.Volumes, err = m.prepareData(ctx, r, base)
		unlock()
		if err != nil {
			return err
		}
	}
	base := archive.BundleName(r.Project, r.Service, bs.meta.Taken)
	bs.files, bs.readme = files, m.readmeFor(ctx, r, base, !open)
	return nil
}

// errUnusable: an object in a destination this download cannot carry (a
// key that cannot open it, a copy that does not match its sum).
var errUnusable = errors.New("the backup in the destination cannot be used here")

// stageLatest copies r's newest tested backup from a destination into the
// staging dir. It returns no files (and no error) when there is none, or
// when it cannot be used: the caller backs the service up instead.
func (m *Manager) stageLatest(ctx context.Context, r svcRef, open bool, meta *ManifestService) (files []dlFile, err error) {
	run, err := m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: r.label(), Kind: r.kind()})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && run.ObjectKey == "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o, ok := archive.ParseKey(run.ObjectKey)
	if !ok {
		return nil, nil
	}
	if _, err := m.targets(ctx); err != nil {
		return nil, nil //nolint:nilerr // no destination: back it up now
	}
	defer func() {
		if err != nil || files == nil {
			removeAll(files)
			files = nil
		}
		if errors.Is(err, errUnusable) {
			m.log.Info("project backup: making a new backup instead of the one in the destination", "service", r.label(), "key", run.ObjectKey, "error", err)
			err = nil
		}
	}()
	base := archive.BundleName(r.Project, r.Service, o.Time)
	var keys []dlFile
	switch r.Method {
	case projects.BackupPGDump:
		rk := archive.RolesKey(run.ObjectKey)
		if rk == "" {
			return nil, nil
		}
		keys = []dlFile{{Name: base + archive.ExtRoles, Path: rk, Role: partRoles}, {Name: base + archive.ExtDump, Path: run.ObjectKey, Role: partData}}
	case projects.BackupRecipe:
		if r.Recipe == nil {
			return nil, nil
		}
		keys = []dlFile{{Name: base + "." + r.Recipe.FileExt() + ".zst.age", Path: run.ObjectKey, Role: partData}}
	default:
		keys = []dlFile{{Name: base + archive.ExtVolumes, Path: run.ObjectKey, Role: partData}}
	}
	if free, ok := freeSpace(m.opt.StagingDir); ok && free < 2*run.SizeBytes+stagingReserve {
		return nil, i18n.E("backup.error.no_room", "need", gbText(2*run.SizeBytes+stagingReserve), "free", gbText(free))
	}
	for _, k := range keys {
		want := ""
		if k.Role == partData {
			want = run.Sha256
		}
		path, info, err := m.stageObject(ctx, k.Path, open, want)
		if err != nil {
			return files, err
		}
		files = append(files, dlFile{Name: k.Name, Path: path, Role: k.Role})
		if k.Role != partData {
			continue
		}
		meta.Volumes, meta.DB = info["hangar-volumes"], info["hangar-db-name"]
		if r.Method == projects.BackupVolume {
			if _, ok := archive.ParseVolumeMeta(meta.Volumes); !ok {
				return files, fmt.Errorf("%w: the copy does not say which volumes it holds", errUnusable)
			}
		}
	}
	meta.Source, meta.Taken = SourceBackup, o.Time.UTC()
	return files, nil
}

// stageObject copies key from a destination into a staging file and
// checks it against want (its SHA-256, when known). The file must open
// with the key that will open it: the server's own in the simple mode. A
// file the server's key opens is encrypted again to the current keys with
// the kit (it may have been made before the kit, for the server alone).
func (m *Manager) stageObject(ctx context.Context, key string, open bool, want string) (string, map[string]string, error) {
	rc, info, err := m.fetch(ctx, key)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", errUnusable, err)
	}
	defer func() { _ = rc.Close() }()
	f, err := m.stagingFile("project-*.age")
	if err != nil {
		return "", nil, err
	}
	ok := false
	defer func() {
		if !ok {
			removeFile(f)
		}
	}()
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(&roomWriter{w: f, dir: m.opt.StagingDir}, sum), rc); err != nil {
		return "", nil, err
	}
	if want != "" && hex.EncodeToString(sum.Sum(nil)) != want {
		return "", nil, fmt.Errorf("%w: the copy does not match its SHA-256", errUnusable)
	}
	sid, _ := m.serverIdentity(ctx, false)
	opens := false
	if sid != nil {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", nil, err
		}
		_, derr := age.Decrypt(f, sid)
		opens = derr == nil
	}
	switch {
	case open && !opens:
		return "", nil, fmt.Errorf("%w: the server's key does not open it", errUnusable)
	case !open && opens:
		path, err := m.reseal(ctx, f, key, sid)
		if err != nil {
			return "", nil, err
		}
		removeFile(f)
		ok = true
		return path, info.Metadata, nil
	}
	_ = f.Close()
	ok = true
	return f.Name(), info.Metadata, nil
}

// reseal encrypts the file f (which id opens) again to the current keys.
func (m *Manager) reseal(ctx context.Context, f *os.File, key string, id age.Identity) (string, error) {
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	plain, err := archive.Open(f, []age.Identity{id}, archive.LimitsFor(key))
	if err != nil {
		return "", err
	}
	defer func() { _ = plain.Close() }()
	out, err := m.stagingFile("project-*.age")
	if err != nil {
		return "", err
	}
	w, err := archive.Seal(&roomWriter{w: out, dir: m.opt.StagingDir}, rcpts, strings.Contains(key, ".zst."))
	if err == nil {
		_, err = io.Copy(w, plain)
		if cerr := w.Close(); err == nil {
			err = cerr
		}
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}

// ProjectReadme is the README at the root of a project backup.
func ProjectReadme(ctx context.Context, project string, sealed bool) string {
	text := i18n.T(ctx, "backup.project.readme_plain", "project", project, "manifest", ManifestName, "config", ProjectFile)
	if sealed {
		text = i18n.T(ctx, "backup.project.readme_sealed", "project", project, "manifest", ManifestName, "config", ProjectFile)
	}
	return strings.TrimLeft(text, "\n")
}

// hashingReader counts and hashes what is read through it.
type hashingReader struct {
	r   io.Reader
	sum hash.Hash
	n   int64
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.sum.Write(p[:n])
	h.n += int64(n)
	return n, err
}

// lazyReader reads what fn returns, called on the first read: the
// manifest is made once every file before it was written.
type lazyReader struct {
	fn func() (io.Reader, error)
	r  io.Reader
}

func (l *lazyReader) Read(p []byte) (int, error) {
	if l.r == nil {
		r, err := l.fn()
		if err != nil {
			return 0, err
		}
		l.r = r
	}
	return l.r.Read(p)
}

// plainName is a file's name once decrypted (and decompressed).
func plainName(name string) string {
	return strings.TrimSuffix(strings.TrimSuffix(name, ".age"), ".zst")
}

// takeProject hands a prepared project backup over (TakeDownload).
func (m *Manager) takeProject(ctx context.Context, a Actor, d *download) (Bundle, string, func(), error) {
	pb := d.Project
	var opened []io.Closer
	done := func() {
		for _, c := range opened {
			_ = c.Close()
		}
		removeAll(d.Files)
	}
	var ids []age.Identity
	if d.Open {
		if ids = m.withServerIdentity(ctx, nil); len(ids) == 0 {
			done()
			return nil, "", nil, i18n.E("backup.error.kit")
		}
	}
	man := pb.manifest
	man.Services = make([]ManifestService, len(pb.services))
	var files []archive.BundleFile
	// add puts a file in the bundle and its entry in parts once written.
	add := func(parts *[]ManifestPart, role, name string, body io.Reader, text bool) {
		hr := &hashingReader{r: body, sum: sha256.New()}
		i := len(*parts)
		*parts = append(*parts, ManifestPart{Role: role, Path: name})
		files = append(files, archive.BundleFile{Name: name, Body: &doneReader{r: hr, done: func() {
			(*parts)[i].Size, (*parts)[i].SHA256 = hr.n, hex.EncodeToString(hr.sum.Sum(nil))
		}}, Text: text})
	}
	// file adds a staged file, decrypted in the simple mode; the roles of
	// a PostgreSQL also get the script that recreates only the missing
	// ones, as a service's download has.
	file := func(parts *[]ManifestPart, dir string, f dlFile) error {
		fh, err := os.Open(f.Path)
		if err != nil {
			return err
		}
		opened = append(opened, fh)
		if !d.Open {
			add(parts, f.Role, dir+f.Name, fh, false)
			return nil
		}
		plain, err := archive.Open(fh, ids, archive.LimitsFor(f.Name))
		if err != nil {
			return err
		}
		opened = append(opened, plain)
		if f.Role != partRoles {
			add(parts, f.Role, dir+plainName(f.Name), plain, f.Role == partConfig)
			return nil
		}
		rolesSQL, err := io.ReadAll(io.LimitReader(plain, pgroles.MaxGlobals+1))
		if err == nil && len(rolesSQL) > pgroles.MaxGlobals {
			err = errors.New("the roles of the backup are too large")
		}
		if err != nil {
			return err
		}
		restore, err := RestoreScript(rolesSQL)
		if err != nil {
			return err
		}
		base := strings.TrimSuffix(f.Name, archive.ExtRoles)
		add(parts, partRoles, dir+base+ExtRolesSQL, strings.NewReader(string(rolesSQL)), true)
		add(parts, partRolesRestore, dir+base+ExtRolesRestore, strings.NewReader(string(restore)), true)
		return nil
	}
	fail := func(err error) (Bundle, string, func(), error) {
		done()
		return nil, "", nil, err
	}
	add(&man.Parts, partReadme, ReadmeName, strings.NewReader(pb.readme), true)
	if err := file(&man.Parts, "", pb.config); err != nil {
		return fail(err)
	}
	for i, s := range pb.services {
		man.Services[i] = s.meta
		man.Services[i].Parts = nil
		dir := projectServices + s.meta.Service + "/"
		add(&man.Services[i].Parts, partReadme, dir+ReadmeName, strings.NewReader(s.readme), true)
		for _, f := range s.files {
			if err := file(&man.Services[i].Parts, dir, f); err != nil {
				return fail(err)
			}
		}
	}
	files = append(files, archive.BundleFile{Name: ManifestName, Text: true, Body: &lazyReader{fn: func() (io.Reader, error) {
		b, err := indentJSON(man)
		return strings.NewReader(string(b)), err
	}}})
	m.record(ctx, a, "project.backup.download", "project", d.ServiceID, outcomeOf(nil), map[string]any{
		"project": d.Label, "size": d.Size, "encrypted": !d.Open, "services": len(pb.services),
	})
	bundle := func(w io.Writer) error { return archive.WriteBundle(w, m.now(), files...) }
	return bundle, d.FileName, done, nil
}

// doneReader calls done once r reaches its end.
type doneReader struct {
	r    io.Reader
	done func()
	once bool
}

func (d *doneReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if errors.Is(err, io.EOF) && !d.once {
		d.once = true
		d.done()
	}
	return n, err
}
