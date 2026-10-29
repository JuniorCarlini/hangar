package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// fakeRecipe is a database template whose recipe is the fake node's
// fake-* commands.
func fakeRecipe(t *testing.T) *templates.Template {
	t.Helper()
	tpl, err := templates.Parse("fakedb", map[string][]byte{
		templates.FileMeta: []byte(`id = "fakedb"
version = 1
category = "database"
main = "db"
name = { en = "FakeDB", "pt-BR" = "FakeDB" }
description = { en = "A database.", "pt-BR" = "Um banco." }

[variables.root_password]
generate = "secret"

[backup]
method = "recipe"
extension = "sql"
env = ["ROOT_PASSWORD"]
serve = ["fake-serve", "--empty"]
ready = ["fake-ready"]
dump = ["fake-dump"]
restore = ["fake-restore"]
verify = ["fake-verify"]
`),
		templates.FileCompose: []byte(`services:
  db:
    image: fakedb:1
    environment:
      ROOT_PASSWORD: ${root_password}
      OTHER: "x"
    volumes:
      - data:/var/lib/fakedb
    expose: ["5000"]
    healthcheck:
      test: ["CMD", "fake-ready"]
    deploy:
      resources:
        limits: { memory: 256M, cpus: "0.5" }
volumes:
  data:
`),
		templates.FileLogo: []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

// recipeService creates a project with a FakeDB service, backups ready.
func (f *fixture) recipeService(t *testing.T) svcRef {
	t.Helper()
	ctx := context.Background()
	f.pm.SetTemplates(templates.NewRegistry(templates.Merge(templates.Builtin(), []*templates.Template{fakeRecipe(t)})))
	if _, err := f.pm.CreateProject(ctx, f.who, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pm.CreateFromTemplate(ctx, f.who, "lab", "fakedb", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.pm.Wait()
	f.ready(t)
	f.n.recipeData = []byte("CREATE TABLE orders;" + strings.Repeat(" INSERT INTO orders VALUES (1);", 400) + " CREATE USER app IDENTIFIED BY PASSWORD '*AB';")
	f.n.recipeVerify = "HANGAR-CHECK tables=1 rows=400 users=1\n"
	f.n.recipeCheck = "some log line\nHANGAR-CHECK tables=1 rows=400 users=1\n"
	s, err := f.m.ref(ctx, "lab", "db")
	if err != nil {
		t.Fatal(err)
	}
	if s.Method != projects.BackupRecipe || s.Recipe == nil || !s.Stop {
		t.Fatalf("ref: %+v", s)
	}
	return s
}

// The dump streams to the throwaway instance and, encrypted, to the
// bucket at once; the instance gets only the variables the recipe names,
// keeps its data where the service does, and the backup is called tested
// only once it holds what the service holds.
func TestRecipeBackupStreamsTestsAndUploads(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.recipeService(t)
	runID, err := f.m.backupRecipe(ctx, f.who, s, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	if run.Status != "ok" || run.Verified != 1 || run.Kind != archive.KindRecipe {
		t.Fatalf("run: %+v", run)
	}
	var c RecipeCheck
	if err := json.Unmarshal([]byte(run.CheckJson), &c); err != nil || c.Restored["rows"] != 400 || c.Source["users"] != 1 || c.Bytes != int64(len(f.n.recipeData)) {
		t.Fatalf("check: %s", run.CheckJson)
	}
	if !bytes.Equal(f.n.recipeTestIn, f.n.recipeData) {
		t.Fatal("the test instance got something else than the dump")
	}
	spec := f.n.recipeSpec
	if spec.Image != "fakedb:1" || spec.Scratch != "/var/lib/fakedb" || len(spec.Env) != 1 || spec.Env["ROOT_PASSWORD"] == "" {
		t.Fatalf("test spec: %+v", spec)
	}
	for _, want := range []string{"( exec 'fake-serve' '--empty' )", "( 'fake-ready' )", "( 'fake-restore' )", "( 'fake-verify' ) </dev/null"} {
		if !strings.Contains(spec.Cmd[2], want) {
			t.Errorf("test script lacks %q", want)
		}
	}
	if o, ok := archive.ParseKey(run.ObjectKey); !ok || o.Kind != archive.KindRecipe || !strings.HasSuffix(run.ObjectKey, archive.ExtRecipe) {
		t.Fatalf("key %q", run.ObjectKey)
	}
	raw := f.store.objects["lab/"+run.ObjectKey]
	if bytes.Contains(raw, []byte("INSERT")) {
		t.Fatal("the backup must be encrypted")
	}
	if got := f.open(t, "lab/"+run.ObjectKey); !bytes.Equal(got, f.n.recipeData) {
		t.Fatal("the backup opens to something else")
	}
	if meta := f.store.opts["lab/"+run.ObjectKey].Metadata; meta["hangar-template"] != "fakedb" || meta["hangar-kind"] != archive.KindRecipe {
		t.Fatalf("metadata: %v", meta)
	}
	if staged, _ := os.ReadDir(f.m.opt.StagingDir); len(staged) != 0 {
		t.Fatalf("staging not cleaned: %v", staged)
	}
	// Nothing was stopped or paused: a dump runs with the service up.
	if ev := f.n.eventList(); slices.ContainsFunc(ev, func(e string) bool { return strings.HasPrefix(e, "stop") || strings.HasPrefix(e, "pause") }) {
		t.Fatalf("the service was held: %v", ev)
	}
}

// A test copy that lost what the service holds, or that did not come up,
// fails the backup; nothing is uploaded and no hash leaks into the error.
func TestRecipeBackupRefusesABadTest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.recipeService(t)
	f.n.recipeCheck = "HANGAR-CHECK tables=1 rows=0 users=1\n"
	if _, err := f.m.backupRecipe(ctx, f.who, s, TriggerManual); err == nil || !strings.Contains(err.Error(), "rows 400 -> 0") {
		t.Fatalf("an empty copy: %v", err)
	}
	f.n.recipeCheck = "HANGAR-CHECK tables=1 rows=400\n"
	if _, err := f.m.backupRecipe(ctx, f.who, s, TriggerManual); err == nil || !strings.Contains(err.Error(), "users 1 -> 0") {
		t.Fatalf("a copy without users: %v", err)
	}
	f.n.recipeCheck = ""
	_, err := f.m.backupRecipe(ctx, f.who, s, TriggerManual)
	if err == nil || strings.Contains(err.Error(), "0123456789ABCDEF") || !strings.Contains(err.Error(), "test restore") {
		t.Fatalf("a failed test restore: %v", err)
	}
	f.n.recipeCheck = "HANGAR-CHECK tables=1 rows=400 users=1\n"
	f.n.recipeDumpErr = errors.New("fake-dump exited with 2: lost connection")
	if _, err := f.m.backupRecipe(ctx, f.who, s, TriggerManual); err == nil || !strings.Contains(err.Error(), "dump") {
		t.Fatalf("a failed dump: %v", err)
	}
	if keys := f.store.keys("lab/diario/"); len(keys) != 0 {
		t.Fatalf("nothing may be uploaded: %v", keys)
	}
	if staged, _ := os.ReadDir(f.m.opt.StagingDir); len(staged) != 0 {
		t.Fatalf("staging not cleaned: %v", staged)
	}
}

func TestParseFingerprintAndCompare(t *testing.T) {
	fp, ok := parseFingerprint("noise\nHANGAR-CHECK tables=1 rows=2\nHANGAR-CHECK tables=3 rows=40 users=2\n")
	if !ok || fp["tables"] != 3 || fp["rows"] != 40 || fp["users"] != 2 || len(fp) != 3 {
		t.Fatalf("fingerprint: %v %v", fp, ok)
	}
	for _, bad := range []string{"", "HANGAR-CHECK", "HANGAR-CHECK rows=-1", "HANGAR-CHECK Rows=1", "HANGAR-CHECK rows=1 x"} {
		if _, ok := parseFingerprint(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	ok1 := RecipeCheck{Source: map[string]int64{"rows": 10, "users": 0}, Restored: map[string]int64{"rows": 9, "users": 0}}
	if err := ok1.compare(); err != nil {
		t.Errorf("a live dump may differ: %v", err)
	}
	if err := (RecipeCheck{Restored: map[string]int64{"rows": 0}}).compare(); err != nil {
		t.Errorf("no source counts, an empty database: %v", err)
	}
	if err := (RecipeCheck{}).compare(); err == nil {
		t.Error("no counts at all must fail")
	}
}

func TestRedactSecrets(t *testing.T) {
	for in, leak := range map[string]string{
		"near 'IDENTIFIED BY PASSWORD '*0123456789ABCDEF0123456789ABCDEF01234567''": "0123456789ABCDEF",
		"CREATE USER x IDENTIFIED WITH 'caching_sha2_password' AS 0x24412430303524": "0x2441",
		"ALTER USER x IDENTIFIED BY 's3cr3t pw'":                                    "s3cr3t",
		"SET PASSWORD FOR x = PASSWORD('hunter2')":                                  "hunter2",
		"ACL SETUSER app on >topsecret":                                             "",
	} {
		out := redactSecrets(in)
		if leak != "" && strings.Contains(out, leak) {
			t.Errorf("%q leaks: %q", in, out)
		}
	}
	if got := redactSecrets("table orders is missing"); got != "table orders is missing" {
		t.Errorf("plain text changed: %q", got)
	}
}

// Restoring into a new service clones it (same variables), deploys it
// empty and loads the backup with the recipe's restore. Overwriting backs
// up the current state, empties the volumes, redeploys and loads; when
// that fails, the backup made just before goes back the same way.
func TestRecipeRestore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.recipeService(t)
	runID, err := f.m.backupRecipe(ctx, f.who, s, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	later(f)
	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{Project: "lab", Service: "db", Mode: ModeDump, Key: run.ObjectKey, Destination: DestNew, NewService: "db-copy", Identities: []age.Identity{f.id}})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if r := f.waitRestore(t, s.ID, id); r.Status != "ok" {
		t.Fatalf("restore: %+v", r)
	}
	if !bytes.Equal(f.n.recipeIn, f.n.recipeData) {
		t.Fatal("the restore got something else than the backup")
	}
	if _, c, err := f.pm.GetService(ctx, "lab", "db-copy"); err != nil || c.Template != "fakedb" {
		t.Fatalf("the clone: %+v %v", c, err)
	}

	// Overwrite, failing: rolled back from the backup made just before.
	f.n.events = nil
	f.n.setRestoreErr(errors.New("fake-restore exited with 1: ERROR at line 3"))
	id, err = f.m.StartRestore(ctx, f.who, RestoreRequest{Project: "lab", Service: "db", Mode: ModeDump, Key: run.ObjectKey, Destination: DestOverwrite, Confirm: "db", Identities: []age.Identity{f.id}})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	r := f.waitRestore(t, s.ID, id)
	if r.Status != "failed" || !strings.Contains(r.Error, "the service is back as it was before the restore") {
		t.Fatalf("restore: %+v", r)
	}
	ev := f.n.eventList()
	if !slices.Equal(ev, []string{"stop db", "wipe data", "recipe-restore", "stop db", "wipe data", "recipe-restore"}) {
		t.Fatalf("events: %v", ev)
	}
	runs, _ := f.m.ServiceRuns(ctx, s.ID, 5)
	if len(runs) < 2 || runs[0].Trigger != TriggerPreRestore || runs[0].Kind != archive.KindRecipe || runs[0].Status != "ok" {
		t.Fatalf("the current state must be backed up first: %+v", runs)
	}
}

// The download is the whole service: the recipe's backup and service.json,
// encrypted with the kit; decrypted in the simple mode.
func TestRecipeDownloadBundle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.recipeService(t)
	take := func() map[string][]byte {
		t.Helper()
		if err := f.m.PrepareDownload(ctx, f.who, "lab", "db"); err != nil {
			t.Fatal(err)
		}
		f.m.Wait()
		d, ok := f.m.PendingDownload(f.who.UserID, s.ID)
		if !ok || !d.Ready {
			t.Fatalf("pending: %+v", d)
		}
		bundle, _, done, err := f.m.TakeDownload(ctx, f.who, d.Token)
		if err != nil {
			t.Fatal(err)
		}
		var zipped bytes.Buffer
		if err := bundle(&zipped); err != nil {
			t.Fatal(err)
		}
		done()
		zr, err := zip.NewReader(bytes.NewReader(zipped.Bytes()), int64(zipped.Len()))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]byte{}
		for _, zf := range zr.File {
			rc, _ := zf.Open()
			out[zf.Name], _ = io.ReadAll(rc)
			_ = rc.Close()
		}
		return out
	}
	files := take()
	var data, cfg []byte
	for name, b := range files {
		switch {
		case strings.HasSuffix(name, ".sql.zst.age"):
			data = b
		case name == ServiceFile+".age":
			cfg = b
		}
	}
	if len(files) != 3 || data == nil || cfg == nil || !bytes.Contains(files[ReadmeName], []byte("'fake-restore'")) {
		t.Fatalf("kit bundle: %v", slices.Collect(mapsKeys(files)))
	}
	if bytes.Contains(cfg, []byte("ROOT_PASSWORD")) || bytes.Contains(data, []byte("INSERT")) {
		t.Fatal("with the kit, everything is encrypted")
	}

	if err := f.m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingMode, ValueJson: `"simple"`}); err != nil {
		t.Fatal(err)
	}
	files = take()
	var snap projects.ServiceSnapshot
	for name, b := range files {
		switch {
		case strings.HasSuffix(name, ".sql"):
			data = b
		case name == ServiceFile:
			if err := json.Unmarshal(b, &snap); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !bytes.Equal(data, f.n.recipeData) || snap.Service != "db" || snap.Image != "fakedb:1" || len(snap.Vols) != 1 || snap.Vols[0].Path != "/var/lib/fakedb" {
		t.Fatalf("simple bundle: %v %+v", slices.Collect(mapsKeys(files)), snap)
	}
	found := false
	for _, v := range snap.Env {
		found = found || (v.Key == "ROOT_PASSWORD" && v.Value != "" && v.Secret)
	}
	if !found {
		t.Fatalf("service.json lacks the variables: %+v", snap.Env)
	}
}

// Every stateful service is listed on the backups page, with a routine or
// not; a service created from a template gets the daily one by itself.
func TestCoverageAndDefaultRoutine(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.pm.SetTemplateCreated(f.m.DefaultRoutines)
	s := f.recipeService(t)
	if _, err := f.pm.CreateFromTemplate(ctx, f.who, "lab", "adminer", "adm", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pm.CreateService(ctx, f.who, "lab", projects.ServiceInput{Name: "files", Image: "nginx:1.29"}); err != nil {
		t.Fatal(err)
	}
	if err := f.pm.AddServiceVolume(ctx, f.who, "lab", "files", "data", "/data"); err != nil {
		t.Fatal(err)
	}
	f.pm.Wait()
	p, ok := f.m.ServicePolicy(ctx, s.ID)
	if !ok || !p.Enabled || p.EveryHours != 24 || p.AtMinute != 180 {
		t.Fatalf("the template's database has no daily routine: %+v %v", p, ok)
	}
	o, err := f.m.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]Row{}
	for _, r := range o.Services {
		rows[r.Service] = r
	}
	if r, ok := rows["db"]; !ok || !r.Covered() || r.Kind != archive.KindRecipe {
		t.Errorf("db: %+v", r)
	}
	// An image service with a volume keeps data: listed, not covered.
	if r, ok := rows["files"]; !ok || r.Covered() || r.Kind != archive.KindVolume {
		t.Errorf("files: %+v", r)
	}
	if _, ok := rows["adm"]; ok {
		t.Error("a service that keeps no data is not listed")
	}
	// An existing routine is never replaced.
	if err := f.m.SetServicePolicy(ctx, f.who, "lab", "db", PolicyInput{Enabled: true, EveryHours: 6, AtMinute: 60}); err != nil {
		t.Fatal(err)
	}
	_, svc, _ := f.pm.GetService(ctx, "lab", "db")
	f.m.DefaultRoutines(ctx, f.who, []dbq.Service{svc})
	if p, _ := f.m.ServicePolicy(ctx, s.ID); p.EveryHours != 6 {
		t.Fatalf("the routine was replaced: %+v", p)
	}
}
