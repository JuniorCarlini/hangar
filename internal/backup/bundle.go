package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgroles"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// A downloaded database backup is one .zip (archive.WriteBundle) that
// restores elsewhere on its own: the pg_dump, the roles of its server and a
// README with the commands. Encrypted backups keep their .age files as
// they are (the server cannot open them); open ones also carry the script
// that recreates only the missing roles (pgroles ApplyScript).

// ReadmeName is the README of a bundle.
const ReadmeName = "README.txt"

// The open files of a bundle: pg_dumpall's output, the script that
// recreates only the missing roles, and the dump.
const (
	ExtRolesSQL     = archive.ExtRolesSQL
	ExtRolesRestore = archive.ExtRolesRestore
	extDumpPlain    = ".dump"
)

// BundleReadme is the README of a bundle whose files are named base.
func BundleReadme(ctx context.Context, base, db string, sealed bool) string {
	text := i18n.T(ctx, "backup.bundle.readme_plain", "base", base, "db", db)
	if sealed {
		text = i18n.T(ctx, "backup.bundle.readme_sealed", "base", base, "db", db)
	}
	return strings.TrimLeft(text, "\n")
}

// RecipeReadme is the README of a bundle with the backup a template's
// recipe made of service: what it holds and the commands that put it back.
func RecipeReadme(ctx context.Context, base, service, template string, r *templates.Recipe, sealed bool) string {
	ext, restore := "backup", ""
	if r != nil {
		ext, restore = r.FileExt(), shellJoin(r.Restore)
	}
	args := []any{"base", base, "service", service, "template", template, "file", base + "." + ext, "restore", restore}
	text := i18n.T(ctx, "backup.bundle.readme_recipe_plain", args...)
	if sealed {
		text = i18n.T(ctx, "backup.bundle.readme_recipe_sealed", args...)
	}
	return strings.TrimLeft(text, "\n")
}

// ServiceReadme is the part of every README about service.json.
func ServiceReadme(ctx context.Context, sealed bool) string {
	if sealed {
		return i18n.T(ctx, "backup.bundle.readme_service_sealed", "file", ServiceFile)
	}
	return i18n.T(ctx, "backup.bundle.readme_service_plain", "file", ServiceFile)
}

// VolumesReadme is the README of a bundle with a copy of the volumes of
// service (volumes says which, and where they were mounted).
func VolumesReadme(ctx context.Context, base, service, volumes string, sealed bool) string {
	text := i18n.T(ctx, "backup.bundle.readme_volumes_plain", "base", base, "service", service, "volumes", volumes, "image", VolumeHelperImage)
	if sealed {
		text = i18n.T(ctx, "backup.bundle.readme_volumes_sealed", "base", base, "service", service, "volumes", volumes, "image", VolumeHelperImage)
	}
	return strings.TrimLeft(text, "\n")
}

// volumeList says which volumes a copy of s holds: "data (/data), ...".
func volumeList(s svcRef) string {
	parts := make([]string, 0, len(s.Vols))
	for _, v := range s.Vols {
		parts = append(parts, v.Name+" ("+v.Path+")")
	}
	return strings.Join(parts, ", ")
}

// RestoreScript is pgroles.RestoreScript.
func RestoreScript(rolesSQL []byte) ([]byte, error) { return pgroles.RestoreScript(rolesSQL) }

// DownloadPlain streams an open (not encrypted) bundle of a database for
// the browser: used when there is no key to encrypt to (simple mode, or no
// destination yet). The roles are read first, then pg_dump streams into
// the zip as it runs.
func (m *Manager) DownloadPlain(ctx context.Context, a Actor, projectSlug, serviceSlug string, w io.Writer) (err error) {
	s, err := m.ref(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if s.Method != projects.BackupPGDump {
		// A copy of volumes is made first, then sent (PrepareDownload).
		return ErrUnsupported
	}
	n, _, err := m.tasker()
	if err != nil {
		return err
	}
	defer func() {
		m.record(ctx, a, "service.backup.download", "service", s.ID, outcomeOf(err), map[string]any{"service": s.label(), "encrypted": false, "roles": true})
	}()
	rolesSQL, _, err := captureRoles(ctx, n, s)
	if err != nil {
		return err
	}
	restore, err := RestoreScript(rolesSQL)
	if err != nil {
		return err
	}
	cfg, err := m.serviceJSON(ctx, s)
	if err != nil {
		return err
	}
	base := archive.BundleName(s.Project, s.Service, m.now())
	pr, pw := io.Pipe()
	go func() {
		_ = pw.CloseWithError(n.Exec(ctx, s.Project, s.Service, pgDumpCmd, pw))
	}()
	defer func() { _ = pr.Close() }()
	return archive.WriteBundle(w, m.now(),
		archive.TextFile(ReadmeName, m.readmeFor(ctx, s, base, false)),
		archive.BundleFile{Name: base + ExtRolesSQL, Body: strings.NewReader(string(rolesSQL)), Text: true},
		archive.BundleFile{Name: base + ExtRolesRestore, Body: strings.NewReader(string(restore)), Text: true},
		archive.BundleFile{Name: ServiceFile, Body: strings.NewReader(string(cfg)), Text: true},
		archive.BundleFile{Name: base + extDumpPlain, Body: pr})
}

// runBundle finds a dump run and its roles in the destinations. ok is
// false for anything else (a dump made before roles were saved, a base
// backup, the panel): those download as they always did.
func (m *Manager) runBundle(ctx context.Context, runID string) (dbq.BackupRun, target, bool, error) {
	r, err := m.q.GetBackupRun(ctx, runID)
	if err != nil || r.ObjectKey == "" || r.Status != "ok" {
		return r, target{}, false, projects.ErrNotFound
	}
	if r.Kind != archive.KindDump || archive.RolesKey(r.ObjectKey) == "" {
		return r, target{}, false, nil
	}
	ts, err := m.targets(ctx)
	if err != nil {
		return r, target{}, false, err
	}
	for _, t := range ts {
		if _, err := t.store.Head(ctx, t.Prefix+archive.RolesKey(r.ObjectKey)); err == nil {
			if _, err := t.store.Head(ctx, t.Prefix+r.ObjectKey); err == nil {
				return r, t, true, nil
			}
		}
	}
	return r, target{}, false, nil
}

// OpenRunBundle streams an older dump with its roles as one bundle. In
// the simple mode (open, when open is set) the server decrypts both and
// adds the script that recreates the missing roles; otherwise the .age
// files go as they are. ok is false when the run has no saved roles: the
// caller sends the backup the way it did before.
func (m *Manager) OpenRunBundle(ctx context.Context, a Actor, runID string, open bool) (io.ReadCloser, string, bool, error) {
	if r, err := m.q.GetBackupRun(ctx, runID); err == nil && (r.Kind == archive.KindVolume || r.Kind == archive.KindRecipe) {
		return m.fileRunBundle(ctx, a, r, open)
	}
	r, t, ok, err := m.runBundle(ctx, runID)
	if err != nil || !ok {
		return nil, "", ok, err
	}
	o, _ := archive.ParseKey(r.ObjectKey)
	base := archive.BundleName(o.Project, o.Service, o.Time)
	get := func(key string) (io.ReadCloser, error) {
		rc, _, err := t.store.Get(ctx, t.Prefix+key)
		return rc, err
	}
	var files []archive.BundleFile
	var closers []io.Closer
	closeAll := func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
	rolesRC, err := get(archive.RolesKey(r.ObjectKey))
	if err != nil {
		return nil, "", true, err
	}
	closers = append(closers, rolesRC)
	dumpRC, err := get(r.ObjectKey)
	if err != nil {
		closeAll()
		return nil, "", true, err
	}
	closers = append(closers, dumpRC)
	db := ""
	if info, err := t.store.Head(ctx, t.Prefix+r.ObjectKey); err == nil {
		db = info.Metadata["hangar-db-name"]
	}
	if open {
		ids := m.withServerIdentity(ctx, nil)
		if len(ids) == 0 {
			closeAll()
			return nil, "", true, i18n.E("backup.error.kit")
		}
		rolesPlain, err := archive.Open(rolesRC, ids, archive.DefaultLimits)
		if err != nil {
			closeAll()
			return nil, "", true, err
		}
		rolesSQL, err := io.ReadAll(io.LimitReader(rolesPlain, pgroles.MaxGlobals+1))
		_ = rolesPlain.Close()
		if err == nil && len(rolesSQL) > pgroles.MaxGlobals {
			err = errors.New("the roles of the backup are too large")
		}
		if err != nil {
			closeAll()
			return nil, "", true, err
		}
		restore, err := RestoreScript(rolesSQL)
		if err != nil {
			closeAll()
			return nil, "", true, err
		}
		dumpPlain, err := archive.Open(dumpRC, ids, archive.DefaultLimits)
		if err != nil {
			closeAll()
			return nil, "", true, err
		}
		closers = append(closers, dumpPlain)
		files = []archive.BundleFile{
			archive.TextFile(ReadmeName, BundleReadme(ctx, base, db, false)),
			{Name: base + ExtRolesSQL, Body: strings.NewReader(string(rolesSQL)), Text: true},
			{Name: base + ExtRolesRestore, Body: strings.NewReader(string(restore)), Text: true},
			{Name: base + extDumpPlain, Body: dumpPlain},
		}
	} else {
		files = []archive.BundleFile{
			archive.TextFile(ReadmeName, BundleReadme(ctx, base, db, true)),
			{Name: base + archive.ExtRoles, Body: rolesRC},
			{Name: base + archive.ExtDump, Body: dumpRC},
		}
	}
	m.record(ctx, a, "backup.download", "backup_run", runID, audit.OK, map[string]any{"label": r.Label, "kind": r.Kind, "target": t.Name, "encrypted": !open, "roles": true})
	pr, pw := io.Pipe()
	go func() {
		err := archive.WriteBundle(pw, m.now(), files...)
		closeAll()
		_ = pw.CloseWithError(err)
	}()
	return pr, base + archive.ExtBundle, true, nil
}

// fileRunBundle streams an older copy of volumes, or a recipe's backup, as
// one bundle with its README: decrypted in the simple mode (open), else
// the .age file as it is.
func (m *Manager) fileRunBundle(ctx context.Context, a Actor, r dbq.BackupRun, open bool) (io.ReadCloser, string, bool, error) {
	if r.ObjectKey == "" || r.Status != "ok" {
		return nil, "", true, projects.ErrNotFound
	}
	o, ok := archive.ParseKey(r.ObjectKey)
	if !ok {
		return nil, "", true, projects.ErrNotFound
	}
	var ids []age.Identity
	if open {
		if ids = m.withServerIdentity(ctx, nil); len(ids) == 0 {
			return nil, "", true, i18n.E("backup.error.kit")
		}
	}
	rc, info, err := m.fetch(ctx, r.ObjectKey)
	if err != nil {
		return nil, "", true, err
	}
	base := archive.BundleName(o.Project, o.Service, o.Time)
	var readme, sealedName, plainName string
	if r.Kind == archive.KindRecipe {
		tpl := info.Metadata["hangar-template"]
		var recipe *templates.Recipe
		if t, ok := m.projects.Template(tpl); ok {
			recipe = t.Recipe
		}
		readme = RecipeReadme(ctx, base, r.Label, tpl, recipe, !open)
		ext := "backup"
		if recipe != nil {
			ext = recipe.FileExt()
		}
		sealedName, plainName = base+"."+ext+".zst.age", base+"."+ext
	} else {
		man, _ := archive.ParseVolumeMeta(info.Metadata["hangar-volumes"])
		readme = VolumesReadme(ctx, base, r.Label, strings.Join(man.Names(), ", "), !open)
		sealedName, plainName = base+archive.ExtVolumes, base+archive.ExtVolumesTar
	}
	file := archive.BundleFile{Name: sealedName, Body: rc}
	closers := []io.Closer{rc}
	if open {
		plain, err := archive.Open(rc, ids, archive.LimitsFor(r.ObjectKey))
		if err != nil {
			_ = rc.Close()
			return nil, "", true, err
		}
		closers = append(closers, plain)
		file = archive.BundleFile{Name: plainName, Body: plain}
	}
	m.record(ctx, a, "backup.download", "backup_run", r.ID, audit.OK, map[string]any{"label": r.Label, "kind": r.Kind, "encrypted": !open})
	pr, pw := io.Pipe()
	go func() {
		err := archive.WriteBundle(pw, m.now(), archive.TextFile(ReadmeName, readme), file)
		for _, c := range closers {
			_ = c.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	return pr, base + archive.ExtBundle, true, nil
}

// loadRoles reads the roles saved with the dump key. ok is false when the
// dump has none (made before roles were saved): no destination has the
// object. Any other failure is an error, never a silent fallback.
func (m *Manager) loadRoles(ctx context.Context, key string, ids []age.Identity) (pgroles.Globals, bool, error) {
	var g pgroles.Globals
	rk := archive.RolesKey(key)
	if rk == "" {
		return g, false, nil
	}
	if src := localFrom(ctx); src != nil {
		rc, _, err := src.get(rk)
		if errors.Is(err, errNoPart) {
			return g, false, nil
		}
		if err != nil {
			return g, false, err
		}
		return readRoles(rc, ids)
	}
	ts, err := m.targets(ctx)
	if err != nil {
		return g, false, err
	}
	var errs []error
	for _, t := range ts {
		rc, _, err := t.store.Get(ctx, t.Prefix+rk)
		if err != nil {
			if !s3.IsNotFound(err) {
				errs = append(errs, err)
			}
			continue
		}
		return readRoles(rc, ids)
	}
	if len(errs) > 0 {
		return g, false, fmt.Errorf("read the roles of the backup: %w", errors.Join(errs...))
	}
	return g, false, nil
}

// readRoles decrypts and parses the roles saved with a dump, and closes rc.
func readRoles(rc io.ReadCloser, ids []age.Identity) (pgroles.Globals, bool, error) {
	var g pgroles.Globals
	defer func() { _ = rc.Close() }()
	plain, err := archive.Open(rc, ids, archive.DefaultLimits)
	if err != nil {
		return g, false, err
	}
	raw, err := io.ReadAll(io.LimitReader(plain, pgroles.MaxGlobals+1))
	_ = plain.Close()
	if err != nil {
		return g, false, err
	}
	g, err = pgroles.ParseGlobals(string(raw))
	return g, err == nil, err
}
