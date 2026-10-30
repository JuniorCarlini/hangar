//go:build integration

package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/cofre"
)

// appRoles are the roles the test database's app made, as on the Lobot
// VPS: an owner of the app's schema, an app user that logs in with a
// password, a system user that bypasses row-level security, a reader
// group.
var appRoles = []string{"App Reader", "app_rw", "app_system", "dono"}

// cloneQueries describe a database the way a copy must match it: roles
// with their attributes, password hashes, memberships and settings, the
// database's owner, settings and GRANTs, object owners, extensions,
// comments, sequences, policies, default privileges and the data.
var cloneQueries = []string{
	`select string_agg(rolname || ':' || rolsuper || rolinherit || rolcreaterole || rolcreatedb || rolcanlogin || rolreplication || rolbypassrls || ':' || rolconnlimit || ':' || coalesce(md5(rolpassword), '-') || ':' || coalesce((select array_to_string(setconfig, ';') from pg_db_role_setting where setdatabase = 0 and setrole = pg_authid.oid), ''), ',' order by rolname) from pg_authid where rolname in ('App Reader', 'app_rw', 'app_system', 'dono')`,
	`select string_agg(r.rolname || '>' || m.rolname || ':' || a.admin_option || a.inherit_option || a.set_option, ',' order by r.rolname, m.rolname) from pg_auth_members a join pg_roles r on r.oid = a.roleid join pg_roles m on m.oid = a.member where m.rolname in ('App Reader', 'app_rw', 'app_system', 'dono')`,
	`select pg_get_userbyid(datdba) || ':' || coalesce(datacl::text, '-') || ':' || coalesce(shobj_description(oid, 'pg_database'), '-') from pg_database where datname = current_database()`,
	`select string_agg(coalesce(r.rolname, '*') || '=' || array_to_string(s.setconfig, ';'), ',' order by r.rolname nulls first) from pg_db_role_setting s join pg_database d on d.oid = s.setdatabase left join pg_roles r on r.oid = s.setrole where d.datname = current_database()`,
	`select string_agg(n.nspname || '.' || c.relname || ':' || c.relkind::text || ':' || pg_get_userbyid(c.relowner) || ':' || c.relrowsecurity || c.relforcerowsecurity || ':' || coalesce(c.relacl::text, '-') || ':' || coalesce(obj_description(c.oid, 'pg_class'), '-'), ',' order by n.nspname, c.relname) from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'app'`,
	`select string_agg(nspname || ':' || pg_get_userbyid(nspowner) || ':' || coalesce(nspacl::text, '-'), ',' order by nspname) from pg_namespace where nspname in ('app', 'public')`,
	`select string_agg(p.proname || ':' || pg_get_userbyid(p.proowner), ',') from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'app'`,
	`select string_agg(extname, ',' order by extname) from pg_extension`,
	`select last_value || ':' || is_called from app.contador`,
	`select string_agg(policyname || ':' || cmd || ':' || array_to_string(roles, '|') || ':' || coalesce(qual, '-'), ',' order by policyname) from pg_policies where schemaname = 'app'`,
	`select string_agg(pg_get_userbyid(defaclrole) || ':' || defaclobjtype::text || ':' || defaclacl::text, ',') from pg_default_acl`,
	`select count(*) || ':' || sum(valor) from app.pedidos`,
}

// snapshot runs cloneQueries in service.
func (e *realEnv) snapshot(t *testing.T, ctx context.Context, service string) []string {
	t.Helper()
	out := make([]string, len(cloneQueries))
	for i, q := range cloneQueries {
		out[i] = e.psql(t, ctx, service, q)
	}
	return out
}

func sameSnapshot(t *testing.T, what string, want, got []string) {
	t.Helper()
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("%s differs from the original:\n  query: %s\n  original: %q\n  copy:     %q", what, cloneQueries[i], want[i], got[i])
		}
	}
}

// loginScript connects over the container's own network address, where
// the official image asks for a password (loopback is trusted).
const loginScript = `PGPASSWORD="$3" exec psql -h "$(hostname -i | cut -d' ' -f1)" -AtX -v ON_ERROR_STOP=1 -U "$2" -d "$POSTGRES_DB" -c "$1"`

// asRole runs sql logged in over TCP as role with password, the way the
// app connects, and returns the output (or the error, as text).
func (e *realEnv) asRole(ctx context.Context, service, role, password, sql string) (string, error) {
	var out bytes.Buffer
	cmd := []string{"sh", "-c", loginScript, "sh", sql, role, password}
	err := e.pm.Node().Exec(ctx, e.project, service, cmd, &out)
	return strings.TrimSpace(out.String()), err
}

// Apps create roles of their own and grant them their schema. A pg_dump
// carries none of the roles, so the backup also keeps the server's roles
// (pg_dumpall --roles-only) next to it, and a restore is a clone: the
// roles come back as they were (same passwords, attributes, memberships,
// settings), objects keep their owners, the database its settings and
// GRANTs. The check proves it before calling the backup tested; an
// overwrite only adds roles that went missing; hangar-cofre does the
// same on a computer; a dump saved before roles were kept still restores,
// with the roles created without a password.
func TestDumpWithAppRolesRestoresIntoNewService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E roles"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateFromTemplate(ctx, e.who, e.project, "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	e.waitLive(t, ctx, "db")
	for _, q := range []string{
		`create role dono login password 'dono-senha' createdb`,
		`create role app_rw login password 'rw-senha' connection limit 20`,
		`create role app_system login password 'sys-senha' bypassrls`,
		`create role "App Reader" nologin`,
		`grant "App Reader" to app_rw`,
		`grant app_rw to app_system with admin option`,
		`alter role app_rw set statement_timeout = '5s'`,
		`alter role app_rw set search_path = app, public`,
		`do $$ begin execute format('alter role app_rw in database %I set work_mem = %L', current_database(), '8MB'); end $$`,
		`do $$ begin execute format('alter database %I set timezone = %L', current_database(), 'America/Sao_Paulo'); end $$`,
		`do $$ begin execute format('revoke connect, temporary on database %I from public', current_database()); end $$`,
		`do $$ begin execute format('grant connect on database %I to app_rw, app_system, dono', current_database()); end $$`,
		`do $$ begin execute format('comment on database %I is %L', current_database(), 'banco do app'); end $$`,
		`create extension pgcrypto`,
		`create schema app authorization dono`,
		`create table app.pedidos (id serial primary key, tenant int not null, valor int not null, segredo bytea default gen_random_bytes(4))`,
		`insert into app.pedidos (tenant, valor) select g % 3, g from generate_series(1, 300) g`,
		`create sequence app.contador`,
		`select setval('app.contador', 777)`,
		`comment on table app.pedidos is 'pedidos do app'`,
		`create function app.um() returns int language sql as 'select 1'`,
		`alter table app.pedidos owner to dono`,
		`alter sequence app.contador owner to dono`,
		`alter function app.um() owner to dono`,
		`alter table app.pedidos enable row level security`,
		`alter table app.pedidos force row level security`,
		`create policy por_tenant on app.pedidos for select to app_rw, "App Reader" using (tenant = coalesce(nullif(current_setting('app.tenant', true), ''), '0')::int)`,
		`create policy sistema on app.pedidos to app_system using (true) with check (true)`,
		`grant usage on schema app to app_rw, app_system, "App Reader"`,
		`grant select, insert on app.pedidos to app_rw`,
		`grant all on app.pedidos to app_system`,
		`grant select (id, valor) on app.pedidos to "App Reader"`,
		`grant usage on sequence app.pedidos_id_seq to app_rw`,
		`alter default privileges for role dono in schema app grant select on tables to "App Reader"`,
	} {
		e.psql(t, ctx, "db", q)
	}
	original := e.snapshot(t, ctx, "db")
	s, _ := e.m.ref(ctx, e.project, "db")

	// 1. The check recreates the roles from the saved ones, checks they
	// are as in the original and restores with owners and permissions.
	runID, err := e.m.backupDump(ctx, e.who, s, TriggerManual)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	run, _ := e.m.q.GetBackupRun(ctx, runID)
	if run.Verified != 1 || !strings.Contains(run.CheckJson, `"rows":300`) {
		t.Fatalf("check: %+v", run)
	}
	for _, r := range appRoles {
		if !strings.Contains(run.CheckJson, `"`+r+`"`) {
			t.Errorf("the check must list role %q as recreated: %s", r, run.CheckJson)
		}
	}
	// The roles are in the bucket next to the dump, encrypted.
	root, err := s3.New(e.minio.Root, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc, _, err := root.Get(ctx, archive.RolesKey(run.ObjectKey))
	if err != nil {
		t.Fatalf("roles next to the dump: %v", err)
	}
	sealed, _ := io.ReadAll(rc)
	_ = rc.Close()
	if bytes.Contains(sealed, []byte("SCRAM")) || bytes.Contains(sealed, []byte("app_rw")) {
		t.Fatal("the roles must be stored encrypted")
	}

	// 2. Into a new service: a clone.
	rid, err := e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "db", Mode: ModeDump, Key: run.ObjectKey, Destination: DestNew, NewService: "db-novo",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := e.waitRestore(t, ctx, s.ID, rid)
	if r.Status != "ok" {
		t.Fatalf("restore into a new service: %+v", r)
	}
	got := slices.Clone(r.SavedRoles)
	slices.Sort(got)
	if !slices.Equal(got, appRoles) || len(r.CreatedRoles) != 0 {
		t.Fatalf("recreated roles %q (without a password: %q), want %q", got, r.CreatedRoles, appRoles)
	}
	sameSnapshot(t, "the new service", original, e.snapshot(t, ctx, "db-novo"))
	// The app logs in with its own password, as in production, and the
	// policies hold: its tenant for app_rw, everything for the BYPASSRLS
	// system user.
	if out, err := e.asRole(ctx, "db-novo", "app_rw", "rw-senha", `set app.tenant = '1'; select count(*) from app.pedidos`); err != nil || !strings.HasSuffix(out, "100") {
		t.Errorf("app_rw with its password: %q %v", out, err)
	}
	if out, err := e.asRole(ctx, "db-novo", "app_system", "sys-senha", `select count(*) from app.pedidos`); err != nil || out != "300" {
		t.Errorf("app_system (BYPASSRLS) with its password: %q %v", out, err)
	}
	if out, err := e.asRole(ctx, "db-novo", "app_rw", "outra-senha", `select 1`); err == nil {
		t.Errorf("a wrong password must not log in: %q", out)
	}
	if out, err := e.asRole(ctx, "db-novo", "app_rw", "rw-senha", `show statement_timeout`); err != nil || out != "5s" {
		t.Errorf("app_rw's settings: %q %v", out, err)
	}
	_, c, err := e.pm.GetService(ctx, e.project, "db-novo")
	if err != nil {
		t.Fatal(err)
	}
	if rs, _ := e.m.ServiceRestores(ctx, e.project, c, 10); len(rs) != 1 || len(rs[0].SavedRoles) != 4 {
		t.Fatalf("the copy's restores: %+v", rs)
	}

	// 3. Overwrite in place: roles that exist are left alone (a password
	// changed after the backup stays), a role dropped since comes back.
	e.psql(t, ctx, "db", `alter role app_rw password 'nova-senha'`)
	e.psql(t, ctx, "db", `drop owned by "App Reader"`)
	e.psql(t, ctx, "db", `drop role "App Reader"`)
	rid, err = e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "db", Mode: ModeDump, Key: run.ObjectKey, Destination: DestOverwrite, Confirm: "db",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" || !slices.Equal(r.SavedRoles, []string{"App Reader"}) || len(r.CreatedRoles) != 0 {
		t.Fatalf("overwrite: %+v", r)
	}
	if _, err := e.asRole(ctx, "db", "app_rw", "nova-senha", `select 1`); err != nil {
		t.Errorf("an existing role must not be changed: %v", err)
	}
	// The recreated role gets its members back, and the grants come back.
	if got := e.psql(t, ctx, "db", `select has_column_privilege('App Reader', 'app.pedidos', 'valor', 'SELECT') and has_table_privilege('app_rw', 'app.pedidos', 'INSERT') and pg_has_role('app_rw', 'App Reader', 'MEMBER')`); got != "t" {
		t.Fatalf("overwrite must bring the role, its members and the grants back: %s", got)
	}

	// 4. hangar-cofre, on a computer with a fresh PostgreSQL: the drill
	// and restore-local make the same clone.
	reader, err := cofre.NewBucket(cofre.Config{
		Endpoint: e.minio.Endpoint, Region: "us-east-1", Bucket: e.minio.Bucket,
		AccessKey: e.minio.Reader.AccessKey, SecretKey: e.minio.Reader.SecretKey, PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	v := cofre.New(reader, []age.Identity{e.id})
	results, err := v.Test(ctx, e.project+"/db")
	if err != nil || len(results) != 1 || !results[0].OK || results[0].Rows != 300 {
		t.Fatalf("hangar-cofre test: %+v %v", results, err)
	}
	// The dump of step 1: the overwrite made a newer one (of the state
	// before it) on its way.
	o, _ := archive.ParseKey(run.ObjectKey)
	lr, err := v.RestoreLocal(ctx, cofre.RestoreOptions{Project: e.project, Service: "db", Dump: true, At: o.Time.Add(time.Second), Port: freePort(t)})
	defer v.Remove(ctx, lr)
	if err != nil {
		t.Fatalf("restore-local: %v", err)
	}
	got = slices.Clone(lr.Saved)
	slices.Sort(got)
	if lr.Mode != "dump" || !slices.Equal(got, appRoles) || len(lr.Roles) != 0 {
		t.Fatalf("restore-local: %+v", lr)
	}
	local := make([]string, len(cloneQueries))
	for i, q := range cloneQueries {
		var out bytes.Buffer
		if err := cofre.DockerCLI(ctx, nil, &out, "exec", lr.Container, "psql", "-AtX", "-v", "ON_ERROR_STOP=1", "-U", lr.User, "-d", lr.DB, "-c", q); err != nil {
			t.Fatal(err)
		}
		local[i] = strings.TrimSpace(out.String())
	}
	sameSnapshot(t, "restore-local", original, local)
	var who bytes.Buffer
	if err := cofre.DockerCLI(ctx, nil, &who, "exec", lr.Container, "sh", "-c", loginScript, "sh", "select count(*) from app.pedidos", "app_system", "sys-senha"); err != nil || strings.TrimSpace(who.String()) != "300" {
		t.Errorf("restore-local, app_system with its password: %q %v", who.String(), err)
	}

	// 5. hangar-cofre decrypt of a synced dump writes the roles next to
	// it, with the script that recreates only the missing ones.
	dir := t.TempDir()
	if _, err := v.Sync(ctx, reader, dir); err != nil {
		t.Fatal(err)
	}
	written, err := v.DecryptBackup(filepath.Join(dir, filepath.FromSlash(run.ObjectKey)), "")
	if err != nil || len(written) != 3 {
		t.Fatalf("decrypt: %+v %v", written, err)
	}
	restoreSQL, _ := os.ReadFile(written[2].Path)
	if !strings.HasSuffix(written[2].Path, archive.ExtRolesRestore) || !bytes.Contains(restoreSQL, []byte("app_system")) {
		t.Fatalf("decrypt wrote %+v", written)
	}

	// 6. The download is one .zip with the dump, the roles and a README.
	if err := e.m.PrepareDownload(ctx, e.who, e.project, "db"); err != nil {
		t.Fatal(err)
	}
	var dl Download
	for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		if d, ok := e.m.PendingDownload(e.who.UserID, s.ID); ok && (d.Ready || d.Error != "") {
			dl = d
			break
		}
	}
	if !dl.Ready {
		t.Fatalf("download: %+v", dl)
	}
	bundle, name, done, err := e.m.TakeDownload(ctx, e.who, dl.Token)
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), name)
	zf, err := os.Create(zipPath) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle(zf); err != nil {
		t.Fatal(err)
	}
	done()
	_ = zf.Close()
	zr, err := zip.OpenReader(zipPath)
	if err != nil || len(zr.File) != 4 || zr.File[3].Name != ServiceFile+".age" {
		t.Fatalf("bundle (README, roles, dump, service.json): %v", err)
	}
	_ = zr.Close()
	out, err := v.DecryptBackup(zipPath, "")
	if err != nil || len(out) != 5 {
		t.Fatalf("decrypt the bundle: %+v %v", out, err)
	}

	// 7. A dump saved before roles were kept (no roles next to it)
	// restores as it always did: roles created without a password,
	// objects owned by whoever restores.
	old := archive.DumpKey(archive.ClassDaily, e.project, "db", time.Now().Add(time.Minute))
	src, _, err := root.Get(ctx, run.ObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(src)
	_ = src.Close()
	if err := root.Put(ctx, old, bytes.NewReader(raw), int64(len(raw)), s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	// Planted by hand, it has no record nor MAC (SEC-005): refused until
	// the owner accepts a backup the panel cannot confirm.
	velho := RestoreRequest{
		Project: e.project, Service: "db", Mode: ModeDump, Key: old, Destination: DestNew, NewService: "db-velho",
		Identities: []age.Identity{e.id},
	}
	if _, err := e.m.StartRestore(ctx, e.who, velho); !errors.Is(err, errUnverified) {
		t.Fatalf("an object the panel did not make: %v", err)
	}
	velho.AllowUnverified = true
	rid, err = e.m.StartRestore(ctx, e.who, velho)
	if err != nil {
		t.Fatal(err)
	}
	r = e.waitRestore(t, ctx, s.ID, rid)
	got = slices.Clone(r.CreatedRoles)
	slices.Sort(got)
	if r.Status != "ok" || len(r.SavedRoles) != 0 || !slices.Equal(got, appRoles) {
		t.Fatalf("restore of a dump without roles: %+v", r)
	}
	if got := e.psql(t, ctx, "db-velho", `select string_agg(rolname || ':' || rolcanlogin || ':' || rolbypassrls, ',' order by rolname) from pg_roles where rolname in ('app_rw', 'app_system')`); got != "app_rw:false:false,app_system:false:false" {
		t.Errorf("roles of a dump without roles: %s", got)
	}
	if got := e.psql(t, ctx, "db-velho", `select count(*) from app.pedidos`); got != "300" {
		t.Errorf("data of a dump without roles: %s", got)
	}
}
