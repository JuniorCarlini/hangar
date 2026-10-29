package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// projectLab is lab with a PostgreSQL (db), a service with a volume
// (files) and an app (web) that references the database three ways: a
// reference, the container by name and a reference naming the project.
// web has a fixed domain.
func (f *fixture) projectLab(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	f.postgres(t)
	if _, err := f.pm.CreateService(ctx, f.who, "lab", projects.ServiceInput{Name: "files", Image: "nginx:1.29"}); err != nil {
		t.Fatal(err)
	}
	if err := f.pm.AddServiceVolume(ctx, f.who, "lab", "files", "data", "/data"); err != nil {
		t.Fatal(err)
	}
	web, err := f.pm.CreateService(ctx, f.who, "lab", projects.ServiceInput{Name: "web", Image: "nginx:1.29", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	f.pm.Wait()
	for k, v := range map[string]string{
		"DATABASE_URL": "${{db.DATABASE_URL}}",
		"DB_HOST":      "lab_db",
		"DB_USER":      "${{lab.db.USER}}",
		"OTHER":        "${{elsewhere.db.USER}} lab_dbx",
	} {
		if err := f.pm.SetEnv(ctx, f.who, web.ID, k, v, k == "DATABASE_URL"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.m.q.CreateDomain(ctx, dbq.CreateDomainParams{ID: "dom_1", ServiceID: web.ID, Hostname: "app.example.com", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	f.ready(t)
	f.n.volTar = sampleTar(t)
}

// takeProject prepares lab's backup and returns the .zip.
func (f *fixture) takeProject(t *testing.T) []byte {
	t.Helper()
	ctx := context.Background()
	if err := f.m.PrepareProjectDownload(ctx, f.who, "lab"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	p, _ := f.pm.GetProject(ctx, "lab")
	d, ok := f.m.PendingProjectDownload(f.who.UserID, p.ID)
	if !ok || !d.Ready {
		t.Fatalf("pending: %+v", d)
	}
	if !strings.HasPrefix(d.FileName, "lab-") || !strings.HasSuffix(d.FileName, ExtProject) {
		t.Fatalf("file name %q", d.FileName)
	}
	bundle, _, done, err := f.m.TakeDownload(ctx, f.who, d.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	var out bytes.Buffer
	if err := bundle(&out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func unzip(t *testing.T, b []byte) (map[string][]byte, []string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	var order []string
	for _, zf := range zr.File {
		rc, _ := zf.Open()
		out[zf.Name], _ = io.ReadAll(rc)
		_ = rc.Close()
		order = append(order, zf.Name)
	}
	return out, order
}

func manifestOf(t *testing.T, files map[string][]byte) ProjectManifest {
	t.Helper()
	var man ProjectManifest
	if err := json.Unmarshal(files[ManifestName], &man); err != nil {
		t.Fatal(err)
	}
	return man
}

func (man ProjectManifest) service(name string) ManifestService {
	for _, s := range man.Services {
		if s.Service == name {
			return s
		}
	}
	return ManifestService{}
}

// rezip rebuilds a .zip with edit applied to each file (nil drops it).
func rezip(t *testing.T, b []byte, edit func(name string, data []byte) []byte) []byte {
	t.Helper()
	files, order := unzip(t, b)
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, name := range order {
		data := edit(name, files[name])
		if data == nil {
			continue
		}
		w, _ := zw.Create(name)
		_, _ = w.Write(data)
	}
	_ = zw.Close()
	return out.Bytes()
}

// One file with every service: the database's newest tested backup as it
// is in the destination, a new copy of the volumes of the service that had
// no backup, the app's configuration alone, the project's own file, and a
// manifest whose sums match every file.
func TestProjectBackupPackagesEveryService(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.projectLab(t)
	s, _ := f.m.ref(ctx, "lab", "db")
	runID, err := f.m.backupDump(ctx, f.who, s, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	files, order := unzip(t, f.takeProject(t))
	man := manifestOf(t, files)
	if order[0] != ReadmeName || order[len(order)-1] != ManifestName {
		t.Fatalf("README first and the manifest last: %v", order)
	}
	if man.Format != ProjectFormat || man.Project != "lab" || !man.Encrypted || man.Hangar != "test" || len(man.Services) != 3 {
		t.Fatalf("manifest: %+v", man)
	}
	all := slices.Clone(man.Parts)
	for _, s := range man.Services {
		all = append(all, s.Parts...)
	}
	for _, p := range all {
		sum := sha256.Sum256(files[p.Path])
		if files[p.Path] == nil || int64(len(files[p.Path])) != p.Size || hex.EncodeToString(sum[:]) != p.SHA256 {
			t.Errorf("%s does not match the manifest", p.Path)
		}
	}
	if len(all)+1 != len(files) {
		t.Errorf("%d files, the manifest lists %d", len(files), len(all))
	}

	db := man.service("db")
	data, _ := db.part(partData)
	roles, _ := db.part(partRoles)
	if db.Method != projects.BackupPGDump || db.Source != SourceBackup || !strings.HasPrefix(data.Path, "services/db/") || roles.Path == "" {
		t.Fatalf("db: %+v", db)
	}
	if !bytes.Equal(files[data.Path], f.store.objects["lab/"+run.ObjectKey]) {
		t.Fatal("the database's data must be its tested backup, as it is in the destination")
	}
	vol := man.service("files")
	if vol.Method != projects.BackupVolume || vol.Source != SourceNow || vol.Volumes == "" {
		t.Fatalf("files: %+v", vol)
	}
	vd, _ := vol.part(partData)
	plain, err := archive.Open(bytes.NewReader(files[vd.Path]), []age.Identity{f.id}, archive.VolumeLimits)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(plain); !bytes.Equal(got, f.n.volTar) {
		t.Fatal("the copy of the volumes opens to something else")
	}
	web := man.service("web")
	cfg, _ := web.part(partConfig)
	if web.Method != "" || len(web.Parts) != 2 || cfg.Path != "services/web/"+ServiceFile+".age" {
		t.Fatalf("web: %+v", web)
	}
	plain, err = archive.Open(bytes.NewReader(files[cfg.Path]), []age.Identity{f.id}, archive.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	var snap projects.ServiceSnapshot
	raw, _ := io.ReadAll(plain)
	if err := json.Unmarshal(raw, &snap); err != nil || snap.Service != "web" || len(snap.Domains) != 1 {
		t.Fatalf("web's configuration: %s", raw)
	}
	if files[ProjectFile+".age"] == nil || !bytes.Contains(files[ReadmeName], []byte("lab")) {
		t.Fatal("the project's own file and README")
	}
}

// In the simple mode the file goes out open. A backup in the destination
// the server's key cannot open (made with the kit alone) is not carried:
// the database is backed up again for the file.
func TestProjectBackupSimpleModeIsOpen(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.projectLab(t)
	s, _ := f.m.ref(ctx, "lab", "db")
	if _, err := f.m.backupDump(ctx, f.who, s, TriggerManual); err != nil {
		t.Fatal(err)
	}
	if err := f.m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingMode, ValueJson: `"simple"`}); err != nil {
		t.Fatal(err)
	}
	files, _ := unzip(t, f.takeProject(t))
	man := manifestOf(t, files)
	db := man.service("db")
	data, _ := db.part(partData)
	restore, _ := db.part(partRolesRestore)
	if man.Encrypted || db.Source != SourceNow || !bytes.Equal(files[data.Path], f.n.dumpData) || restore.Path == "" {
		t.Fatalf("simple mode: %+v", db)
	}
	cfg, _ := man.service("web").part(partConfig)
	if !bytes.Contains(files[cfg.Path], []byte(`"DATABASE_URL"`)) || !bytes.Contains(files[ProjectFile], []byte(`"project": "lab"`)) {
		t.Fatal("the configuration must be open")
	}
}

// startRestore uploads b and restores it as the project "Cópia".
func (f *fixture) startRestore(t *testing.T, b []byte, keys ...age.Identity) (string, string, error) {
	t.Helper()
	path, err := f.m.StageUpload(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	slug, err := f.m.StartProjectRestore(context.Background(), f.who, ProjectRestoreRequest{
		Name: "Cópia", File: path, FileName: "lab.hangar.zip", Identities: keys,
	})
	return slug, path, err
}

func (f *fixture) finished(t *testing.T, slug string) ProjectRestore {
	t.Helper()
	// The restore's goroutine ends after its deploys went live; their own
	// goroutines end right after.
	f.m.Wait()
	f.pm.Wait()
	p, err := f.pm.GetProject(context.Background(), slug)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := f.m.LatestProjectRestore(context.Background(), p.ID)
	if !ok {
		t.Fatal("no restore recorded")
	}
	return r
}

func (f *fixture) envOf(t *testing.T, project, service string) map[string]string {
	t.Helper()
	_, s, err := f.pm.GetService(context.Background(), project, service)
	if err != nil {
		t.Fatal(err)
	}
	vars, _ := f.pm.ListEnvValues(context.Background(), s.ID)
	out := map[string]string{}
	for _, v := range vars {
		out[v.Key] = v.Value
	}
	return out
}

// The file becomes a new project: every service, the data of each put back
// by its own restore, references and container names pointed at the copy,
// the domains left off (and listed), the endpoints internal. The original
// is not touched.
func TestProjectRestoreIntoNewProject(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.projectLab(t)
	s, _ := f.m.ref(ctx, "lab", "db")
	if _, err := f.m.backupDump(ctx, f.who, s, TriggerManual); err != nil {
		t.Fatal(err)
	}
	zipped := f.takeProject(t)
	f.n.restoreIn, f.n.volIn = nil, nil

	if _, _, err := f.startRestore(t, zipped); err == nil {
		t.Fatal("a file made with the kit must ask for the kit")
	}
	slug, path, err := f.startRestore(t, zipped, f.id)
	if err != nil {
		t.Fatal(err)
	}
	r := f.finished(t, slug)
	if slug != "copia" || r.Status != "ok" || r.Source != "lab" {
		t.Fatalf("restore %s: %+v", slug, r)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("the uploaded file must be removed when the restore ends")
	}
	p, _ := f.pm.GetProject(ctx, "copia")
	svcs, _ := f.pm.ListServices(ctx, p.ID)
	if len(svcs) != 3 {
		t.Fatalf("services: %+v", svcs)
	}
	if !bytes.Equal(f.n.restoreIn, f.n.dumpData) || !bytes.Equal(f.n.volIn, f.n.volTar) {
		t.Fatal("the data of the database and of the volumes must be put back")
	}
	env := f.envOf(t, "copia", "web")
	want := map[string]string{
		"DATABASE_URL": "${{db.DATABASE_URL}}", "DB_HOST": "copia_db", "DB_USER": "${{db.USER}}",
		"OTHER": "${{elsewhere.db.USER}} lab_dbx",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	_, db, _ := f.pm.GetService(ctx, "copia", "db")
	exps, _ := f.m.q.ListExports(ctx, db.ID)
	for _, e := range exps {
		if e.Key == "HOST" {
			v, _ := f.pm.RevealExport(ctx, f.who, db.ID, "HOST")
			if v != "copia_db" {
				t.Errorf("the database's HOST export is %q", v)
			}
		}
	}
	if len(r.Notes.Domains) != 1 || r.Notes.Domains[0] != "web: app.example.com" {
		t.Fatalf("domains left off: %+v", r.Notes)
	}
	_, web, _ := f.pm.GetService(ctx, "copia", "web")
	if doms, _ := f.pm.ListDomains(ctx, web.ID); len(doms) != 0 {
		t.Fatal("the copy must take no domain of the original")
	}
	eps, _ := f.pm.ListEndpoints(ctx, web.ID)
	if len(eps) != 1 || eps[0].Public {
		t.Fatalf("the copy's endpoints are internal: %+v", eps)
	}
	_, orig, _ := f.pm.GetService(ctx, "lab", "web")
	if doms, _ := f.pm.ListDomains(ctx, orig.ID); len(doms) != 1 {
		t.Fatal("the original keeps its domain")
	}
}

// The simple mode's open file restores without a kit.
func TestProjectRestoreOpenFile(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.projectLab(t)
	if err := f.m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingMode, ValueJson: `"simple"`}); err != nil {
		t.Fatal(err)
	}
	zipped := f.takeProject(t)
	f.n.restoreIn = nil
	slug, _, err := f.startRestore(t, zipped)
	if err != nil {
		t.Fatal(err)
	}
	if r := f.finished(t, slug); r.Status != "ok" || !bytes.Equal(f.n.restoreIn, f.n.dumpData) {
		t.Fatalf("restore: %+v", r)
	}
}

// What is not a good file is refused before anything is made; a file that
// turns out damaged once the restore runs fails it and takes its services
// away, leaving the empty project with the reason.
func TestProjectRestoreRefusesBadFiles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.projectLab(t)
	zipped := f.takeProject(t)
	count := func() int {
		ps, _ := f.pm.ListProjects(ctx)
		return len(ps)
	}
	before := count()
	editManifest := func(edit func(*ProjectManifest)) []byte {
		return rezip(t, zipped, func(name string, data []byte) []byte {
			if name != ManifestName {
				return data
			}
			var man ProjectManifest
			_ = json.Unmarshal(data, &man)
			edit(&man)
			b, _ := json.Marshal(man)
			return b
		})
	}
	other, _ := age.GenerateX25519Identity()
	cases := []struct {
		name string
		file []byte
		keys []age.Identity
		want string
	}{
		{"wrong kit", zipped, []age.Identity{other}, "project.restore.error.wrong_key"},
		{"newer format", editManifest(func(m *ProjectManifest) { m.Format = 99 }), []age.Identity{f.id}, "project.restore.error.format"},
		{"path outside", editManifest(func(m *ProjectManifest) { m.Services[0].Parts[0].Path = "../escape" }), []age.Identity{f.id}, "project.restore.error.file"},
		{"no manifest", rezip(t, zipped, func(name string, data []byte) []byte {
			if name == ManifestName {
				return nil
			}
			return data
		}), []age.Identity{f.id}, "project.restore.error.file"},
		{"another method", editManifest(func(m *ProjectManifest) {
			for i := range m.Services {
				if m.Services[i].Service == "files" {
					m.Services[i].Method = projects.BackupRecipe
				}
			}
		}), []age.Identity{f.id}, "project.restore.error.method"},
		{"not a zip", []byte("hello"), nil, "project.restore.error.file"},
	}
	for _, c := range cases {
		_, path, err := f.startRestore(t, c.file, c.keys...)
		var ie *i18n.Error
		if !errors.As(err, &ie) || ie.Key != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
		if _, serr := os.Stat(path); !errors.Is(serr, os.ErrNotExist) {
			t.Errorf("%s: the uploaded file stayed", c.name)
		}
		if count() != before {
			t.Fatalf("%s: a refused file created a project", c.name)
		}
	}

	// A damaged data file passes the manifest but not its sum.
	man := manifestOf(t, func() map[string][]byte { m, _ := unzip(t, zipped); return m }())
	bad, _ := man.service("files").part(partData)
	damaged := rezip(t, zipped, func(name string, data []byte) []byte {
		if name == bad.Path {
			data = slices.Clone(data)
			data[len(data)/2] ^= 0xff
		}
		return data
	})
	slug, _, err := f.startRestore(t, damaged, f.id)
	if err != nil {
		t.Fatal(err)
	}
	r := f.finished(t, slug)
	if r.Status != "failed" || !strings.Contains(r.Error, bad.Path) || r.Notes.Cleanup != CleanupRemoved {
		t.Fatalf("damaged file: %+v", r)
	}
	p, _ := f.pm.GetProject(ctx, slug)
	if svcs, _ := f.pm.ListServices(ctx, p.ID); len(svcs) != 0 {
		t.Fatalf("a failed restore must take its services away: %+v", svcs)
	}
}

// LatestProjectRestore is empty for a project that no restore made.
func TestLatestProjectRestoreNone(t *testing.T) {
	f := newFixture(t)
	if _, ok := f.m.LatestProjectRestore(context.Background(), "prj_none"); ok {
		t.Fatal("no restore")
	}
}
