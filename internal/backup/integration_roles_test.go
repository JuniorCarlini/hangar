//go:build integration

package backup

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/cofre"
)

// Apps create roles of their own (an app user, a BYPASSRLS one) and grant
// them tables, sequences and row-level security policies. Roles are not in
// a pg_dump, so a restore into a fresh PostgreSQL used to fail on the
// first GRANT, while the backup check (restoring with --no-acl) called the
// backup tested. Now the check restores the permissions too, and a restore
// into a new service creates the missing roles (NOLOGIN, no password)
// first; an overwrite keeps working as before.
func TestDumpWithAppRolesRestoresIntoNewService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
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
		`create role app_rw login password 'x'`,
		`create role app_system nologin bypassrls`,
		`create role "App Reader" nologin`,
		`create table pedidos (id serial primary key, tenant int not null, valor int not null)`,
		`insert into pedidos (tenant, valor) select g % 3, g from generate_series(1, 300) g`,
		`alter table pedidos enable row level security`,
		`create policy por_tenant on pedidos for select to app_rw, "App Reader" using (tenant = coalesce(nullif(current_setting('app.tenant', true), ''), '0')::int)`,
		`create policy sistema on pedidos to app_system using (true) with check (true)`,
		`grant usage on schema public to app_rw, app_system, "App Reader"`,
		`grant select, insert on pedidos to app_rw`,
		`grant all on pedidos to app_system`,
		`grant select (id, valor) on pedidos to "App Reader"`,
		`grant usage on sequence pedidos_id_seq to app_rw`,
		`alter default privileges in schema public grant select on tables to "App Reader"`,
	} {
		e.psql(t, ctx, "db", q)
	}
	s, _ := e.m.ref(ctx, e.project, "db")

	// 1. The check restores with the permissions, creating the roles a
	// fresh server lacks, and lists them.
	runID, err := e.m.backupDump(ctx, e.who, s, TriggerManual)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	run, _ := e.m.q.GetBackupRun(ctx, runID)
	if run.Verified != 1 || !strings.Contains(run.CheckJson, `"rows":300`) {
		t.Fatalf("check: %+v", run)
	}
	for _, r := range []string{"app_rw", "app_system", "App Reader"} {
		if !strings.Contains(run.CheckJson, `"`+r+`"`) {
			t.Errorf("the check must list role %q: %s", r, run.CheckJson)
		}
	}

	// 2. Into a new service: roles first, then the data and permissions.
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
	got := slices.Clone(r.CreatedRoles)
	slices.Sort(got)
	if want := []string{"App Reader", "app_rw", "app_system"}; !slices.Equal(got, want) {
		t.Fatalf("created roles %q, want %q", got, want)
	}
	for q, want := range map[string]string{
		"select count(*) from pedidos": "300",
		// Created without login (no password), BYPASSRLS not copied.
		`select string_agg(rolname || ':' || rolcanlogin || ':' || rolbypassrls, ',' order by rolname) from pg_roles where rolname in ('app_rw', 'app_system', 'App Reader')`:         "App Reader:false:false,app_rw:false:false,app_system:false:false",
		`select has_table_privilege('app_rw', 'pedidos', 'SELECT') and has_table_privilege('app_rw', 'pedidos', 'INSERT') and not has_table_privilege('app_rw', 'pedidos', 'DELETE')`: "t",
		`select has_table_privilege('app_system', 'pedidos', 'DELETE')`:                                                                                                                         "t",
		`select has_column_privilege('App Reader', 'pedidos', 'valor', 'SELECT') and not has_column_privilege('App Reader', 'pedidos', 'tenant', 'SELECT')`:                                     "t",
		`select has_sequence_privilege('app_rw', 'pedidos_id_seq', 'USAGE')`:                                                                                                                    "t",
		`select string_agg(policyname || '=' || (select string_agg(x, '|' order by x collate "C") from unnest(roles) x), ',' order by policyname) from pg_policies where tablename = 'pedidos'`: "por_tenant=App Reader|app_rw,sistema=app_system",
		`select relrowsecurity from pg_class where relname = 'pedidos'`:                                                                                                                         "t",
		`select count(*) from pg_default_acl`: "1",
	} {
		if got := e.psql(t, ctx, "db-novo", q); got != want {
			t.Errorf("%s: %q, want %q", q, got, want)
		}
	}
	// The policies hold for the restored roles: the app sees its tenant.
	out := e.psql(t, ctx, "db-novo", `set role app_rw; set app.tenant = '1'; select count(*) from pedidos`)
	if lines := strings.Split(out, "\n"); lines[len(lines)-1] != "100" {
		t.Errorf("row-level security as app_rw: %q, want 100 rows", out)
	}
	// The copy lists the restore that created it, with the roles to fix.
	_, c, err := e.pm.GetService(ctx, e.project, "db-novo")
	if err != nil {
		t.Fatal(err)
	}
	if rs, _ := e.m.ServiceRestores(ctx, e.project, c, 10); len(rs) != 1 || len(rs[0].CreatedRoles) != 3 {
		t.Fatalf("the copy's restores: %+v", rs)
	}

	// 3. Overwrite in place: the roles are there, none is created or
	// changed, and the permissions stay.
	rid, err = e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "db", Mode: ModeDump, Key: run.ObjectKey, Destination: DestOverwrite, Confirm: "db",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" || len(r.CreatedRoles) != 0 {
		t.Fatalf("overwrite: %+v", r)
	}
	if got := e.psql(t, ctx, "db", `select rolcanlogin::text || rolbypassrls::text from pg_roles where rolname = 'app_rw'`); got != "truefalse" {
		t.Fatalf("an existing role must not be changed: %s", got)
	}
	if got := e.psql(t, ctx, "db", `select has_table_privilege('app_rw', 'pedidos', 'INSERT')`); got != "t" {
		t.Fatal("overwrite must keep the grants")
	}

	// 4. hangar-cofre, on a computer with a fresh PostgreSQL: the drill
	// and restore-local create the roles too.
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
	lr, err := v.RestoreLocal(ctx, cofre.RestoreOptions{Project: e.project, Service: "db", Port: freePort(t)})
	defer v.Remove(ctx, lr)
	if err != nil {
		t.Fatalf("restore-local: %v", err)
	}
	var cnt bytes.Buffer
	if err := cofre.DockerCLI(ctx, nil, &cnt, "exec", lr.Container, "psql", "-AtX", "-U", lr.User, "-d", lr.DB, "-c", "select count(*) from pg_policies"); err != nil {
		t.Fatal(err)
	}
	if lr.Mode != "dump" || len(lr.Roles) != 3 || strings.TrimSpace(cnt.String()) != "2" {
		t.Fatalf("restore-local: %+v policies=%s", lr, cnt.String())
	}
}
