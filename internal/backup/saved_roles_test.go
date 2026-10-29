package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // PostgreSQL's md5(), as the check
	"encoding/hex"
	"io"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// appRolesSQL is pg_dumpall --roles-only of a server with an app user
// (LOGIN, password, BYPASSRLS) besides its bootstrap superuser.
const appRolesSQL = bootstrapOnly +
	"CREATE ROLE app_rw;\nALTER ROLE app_rw WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION BYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:YWJj$ZGVm:Z2hp';\n" +
	"GRANT postgres TO app_rw GRANTED BY postgres;\n"

const appHash = "SCRAM-SHA-256$4096:YWJj$ZGVm:Z2hp"

func stateLine(js string) string { return "HANGAR-STATE " + hex.EncodeToString([]byte(js)) + "\n" }

func md5hex(s string) string {
	h := md5.Sum([]byte(s)) //nolint:gosec // as above
	return hex.EncodeToString(h[:])
}

// A dump saved with the roles of its server restores as a clone: the
// roles first (only the missing ones, as they were), then the data with
// owners, then the database's own settings; the roles are recorded by
// name and the hashes never leave the scripts.
func TestRestoreRecreatesSavedRoles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.n.rolesSQL = appRolesSQL
	// The test restore recreates app_rw and reports it as in the file.
	f.n.checkOut = "HANGAR-SAVED " + hex.EncodeToString([]byte("app_rw")) + "\n" +
		stateLine(`[{"name":"app_rw","inherit":true,"login":true,"bypassrls":true,"connlimit":-1,"pw":"`+md5hex(appHash)+`","member_of":["postgres"]}]`) +
		"HANGAR-CHECK tables=3 restored=3 rows=42\n"
	s, key := f.dumpKey(t)
	f.n.mu.Lock()
	taskIn := string(f.n.taskIn)
	f.n.mu.Unlock()
	if !strings.Contains(taskIn, "CREATE ROLE app_rw") || !strings.HasSuffix(taskIn, string(f.n.dumpData)) {
		t.Fatalf("the test restore must get the roles script, then the dump: %.200q", taskIn)
	}
	run, err := f.m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: "lab/db", Kind: archive.KindDump})
	if err != nil || !strings.Contains(run.CheckJson, `"saved_roles":["app_rw"]`) {
		t.Fatalf("check: %s %v", run.CheckJson, err)
	}
	// The roles are next to the dump, encrypted, and open to the file.
	if raw := f.store.objects["lab/"+archive.RolesKey(key)]; len(raw) == 0 || strings.Contains(string(raw), "SCRAM") {
		t.Fatal("the roles must be stored encrypted next to the dump")
	}
	if got := f.open(t, "lab/"+archive.RolesKey(key)); string(got) != appRolesSQL {
		t.Fatalf("roles object: %q", got)
	}
	f.n.schemaSQL = "-- Name: lab; Type: DATABASE PROPERTIES; Schema: -; Owner: postgres\n--\n\nALTER DATABASE lab SET work_mem TO '8MB';\n"
	f.n.saved = []string{"app_rw"}

	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "db", Mode: ModeDump, Key: key, Destination: DestNew, NewService: "db-clone",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.waitRestore(t, s.ID, id)
	if r.Status != "ok" || !slices.Equal(r.SavedRoles, []string{"app_rw"}) || len(r.CreatedRoles) != 0 {
		t.Fatalf("restore: %+v", r)
	}
	f.n.mu.Lock()
	defer f.n.mu.Unlock()
	if !strings.Contains(f.n.rolesScript, "BYPASSRLS PASSWORD ''SCRAM") || strings.Contains(f.n.rolesScript, "GRANTED BY") {
		t.Errorf("roles script:\n%s", f.n.rolesScript)
	}
	if strings.Contains(f.n.restoreCmd, "--no-owner") {
		t.Errorf("a clone keeps the owners: %s", f.n.restoreCmd)
	}
	if !strings.Contains(f.n.dbScript, `ALTER DATABASE :"hangar_db" SET work_mem TO '8MB';`) {
		t.Errorf("database script:\n%s", f.n.dbScript)
	}
	var order []string
	for _, e := range f.n.execs {
		switch {
		case strings.Contains(e, "pg_restore --create --schema-only"):
			order = append(order, "schema")
		case strings.Contains(e, "hangar_db="):
			order = append(order, "database")
		case strings.Contains(e, "pg_restore"):
			order = append(order, "restore")
		}
	}
	if !slices.Equal(order, []string{"schema", "restore", "database"}) {
		t.Errorf("order: %v", order)
	}
}

// With no key to encrypt to, the download is an open .zip: README, the
// roles, the script that recreates only the missing ones, the dump.
func TestDownloadPlainBundle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.n.rolesSQL = appRolesSQL
	f.postgres(t)
	var b bytes.Buffer
	if err := f.m.DownloadPlain(ctx, f.who, "lab", "db", &b); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var names []string
	for _, zf := range zr.File {
		rc, _ := zf.Open()
		body, _ := io.ReadAll(rc)
		_ = rc.Close()
		ext := strings.TrimPrefix(zf.Name, strings.SplitN(zf.Name, ".", 2)[0])
		names = append(names, ext)
		got[ext] = string(body)
	}
	if !slices.Equal(names, []string{".txt", ".roles.sql", ".roles-restore.sql", ".json", ".dump"}) {
		t.Fatalf("bundle: %q", names)
	}
	if got[".roles.sql"] != appRolesSQL || got[".dump"] != string(f.n.dumpData) ||
		!strings.Contains(got[".roles-restore.sql"], "CREATE ROLE app_rw") || !strings.Contains(got[".txt"], "pg_restore") ||
		!strings.Contains(got[".json"], `"POSTGRES_PASSWORD"`) || !strings.Contains(got[".txt"], ServiceFile) {
		t.Fatalf("bundle contents: %q", got)
	}
}

// A test restore whose roles did not come back as saved fails the backup,
// without the hash in the message, and nothing is uploaded.
func TestCheckFailsWhenRolesDiffer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.n.rolesSQL = appRolesSQL
	f.n.checkOut = "HANGAR-SAVED " + hex.EncodeToString([]byte("app_rw")) + "\n" +
		stateLine(`[{"name":"app_rw","inherit":true,"login":true,"bypassrls":false,"connlimit":-1,"pw":"x"}]`) +
		"HANGAR-CHECK tables=3 restored=3 rows=42\n"
	f.postgres(t)
	f.ready(t)
	s, _ := f.m.ref(ctx, "lab", "db")
	_, err := f.m.backupDump(ctx, f.who, s, TriggerManual)
	if err == nil || !strings.Contains(err.Error(), `"app_rw" has other attributes`) || strings.Contains(err.Error(), "SCRAM") {
		t.Fatalf("backup: %v", err)
	}
	if keys := f.store.keys("lab/diario/"); len(keys) != 0 {
		t.Fatalf("nothing is uploaded: %v", keys)
	}
}
