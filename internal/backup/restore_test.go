package backup

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
)

// waitRestore waits for a restore started on the fake to end.
func (f *fixture) waitRestore(t *testing.T, serviceID, id string) Restore {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		// No f.pm.Wait() while polling: the restore may start a deploy
		// (WaitGroup.Add) at any moment, and Add racing a Wait at zero is
		// the race detector's complaint. Its deploys are over once the
		// restore is no longer running, so the wait goes there.
		rs, _ := f.m.Restores(context.Background(), serviceID, 10)
		for _, r := range rs {
			if r.ID == id && r.Status != "running" {
				f.pm.Wait()
				return r
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("restore did not finish")
	return Restore{}
}

// dumpKey takes a backup of lab/db on the fake and returns its key.
func (f *fixture) dumpKey(t *testing.T) (svcRef, string) {
	t.Helper()
	ctx := context.Background()
	f.postgres(t)
	f.ready(t)
	s, err := f.m.ref(ctx, "lab", "db")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := f.m.backupDump(ctx, f.who, s, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	return s, run.ObjectKey
}

func (f *fixture) execsWith(sub string) int {
	f.n.mu.Lock()
	defer f.n.mu.Unlock()
	n := 0
	for _, e := range f.n.execs {
		if strings.Contains(e, sub) {
			n++
		}
	}
	return n
}

// dropRoles removes the roles saved next to a dump: what a dump made
// before roles were saved looks like.
func (f *fixture) dropRoles(key string) {
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	delete(f.store.objects, "lab/"+archive.RolesKey(key))
}

// A dump saved without the roles of its server (made before they were
// saved), restored into a new service, still brings its permissions: the
// roles they name are created first (no password), the restore keeps the
// ACLs, and the roles created are recorded for the owner, on both services.
func TestRestoreIntoNewServiceCreatesMissingRoles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, key := f.dumpKey(t)
	f.dropRoles(key)
	f.n.schemaSQL = aclScript
	f.n.created = []string{"lobot_app", `Weird "Role"`} // lobot already exists there

	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "db", Mode: ModeDump, Key: key, Destination: DestNew, NewService: "db-restaurado",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.waitRestore(t, s.ID, id)
	if r.Status != "ok" || !slices.Equal(r.CreatedRoles, f.n.created) || r.Cleanup != "" {
		t.Fatalf("restore: %+v", r)
	}
	// The roles come from the dump itself, PUBLIC left out, and only the
	// missing ones are created, without a password.
	for _, want := range []string{"'lobot_app'", `'Weird "Role"'`, "NOLOGIN", "NOT EXISTS"} {
		if !strings.Contains(f.n.script, want) {
			t.Errorf("role script lacks %s:\n%s", want, f.n.script)
		}
	}
	if strings.Contains(strings.ToLower(f.n.script), "'public'") || strings.Contains(f.n.script, "'lobot'") || strings.Contains(f.n.script, "PASSWORD") {
		t.Errorf("role script:\n%s", f.n.script)
	}
	// Roles before the data; the data restore keeps the permissions.
	f.n.mu.Lock()
	var order []string
	for _, e := range f.n.execs {
		switch {
		case strings.Contains(e, "pg_restore --schema-only"):
			order = append(order, "schema")
		case strings.Contains(e, "psql -qAtX") && strings.Contains(e, "-f -"):
			order = append(order, "roles")
		case strings.Contains(e, "pg_restore"):
			order = append(order, "restore")
			if strings.Contains(e, "--no-acl") || !strings.Contains(e, "--single-transaction") || !strings.Contains(e, "--no-owner") {
				t.Errorf("restore command: %s", e)
			}
		}
	}
	restored := string(f.n.restoreIn)
	f.n.mu.Unlock()
	if !slices.Equal(order, []string{"schema", "roles", "restore"}) {
		t.Fatalf("order: %v", order)
	}
	if restored != string(f.n.dumpData) {
		t.Fatal("pg_restore must receive the whole dump")
	}
	// The copy lists the restore that created it, with where it came from.
	_, c, err := f.pm.GetService(ctx, "lab", "db-restaurado")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := f.m.ServiceRestores(ctx, "lab", c, 10)
	if err != nil || len(rs) != 1 || rs[0].ID != id || rs[0].Source != "lab/db" {
		t.Fatalf("copy's restores: %+v %v", rs, err)
	}
}

// A failed restore into a new service removes the service it created
// (never the original), says so, and shows on the backups page.
func TestFailedRestoreIntoNewServiceIsRemovedAndReported(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, key := f.dumpKey(t)
	f.n.setRestoreErr(errors.New(`sh exited with 1: pg_restore: error: could not execute query: ERROR:  role "x" does not exist`))

	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "db", Mode: ModeDump, Key: key, Destination: DestNew, NewService: "db-copia",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.waitRestore(t, s.ID, id)
	if r.Status != "failed" || !strings.Contains(r.Error, `role "x" does not exist`) || r.Cleanup != CleanupRemoved {
		t.Fatalf("restore: %+v", r)
	}
	if _, _, err := f.pm.GetService(ctx, "lab", "db-copia"); err == nil {
		t.Fatal("the new service of a failed restore must be removed")
	}
	if _, _, err := f.pm.GetService(ctx, "lab", "db"); err != nil {
		t.Fatal("the original must stay")
	}
	o, err := f.m.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range o.Alerts {
		found = found || (a.Kind == AlertRestore && a.Label == "lab/db" && strings.Contains(a.Info, "does not exist"))
	}
	if !found {
		t.Fatalf("a failed restore must raise an alert: %+v", o.Alerts)
	}

	// The name is free again, and a working retry clears the alert.
	f.n.setRestoreErr(nil)
	id, err = f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "db", Mode: ModeDump, Key: key, Destination: DestNew, NewService: "db-copia",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := f.waitRestore(t, s.ID, id); r.Status != "ok" {
		t.Fatalf("retry: %+v", r)
	}
	o, _ = f.m.Overview(ctx)
	for _, a := range o.Alerts {
		if a.Kind == AlertRestore {
			t.Fatalf("a later restore that worked clears the alert: %+v", a)
		}
	}
}

// The overwrite keeps its behavior: nothing to create when the roles are
// there, and a failure never removes the service.
func TestFailedOverwriteKeepsTheService(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s, key := f.dumpKey(t)
	f.n.setRestoreErr(errors.New("boom"))
	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "db", Mode: ModeDump, Key: key, Destination: DestOverwrite, Confirm: "db",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.waitRestore(t, s.ID, id)
	if r.Status != "failed" || r.Cleanup != "" || len(r.CreatedRoles) != 0 {
		t.Fatalf("restore: %+v", r)
	}
	if _, _, err := f.pm.GetService(ctx, "lab", "db"); err != nil {
		t.Fatal("an overwrite that fails keeps the service")
	}
	if f.execsWith("psql -qAtX") != 0 {
		t.Fatal("no role named in the dump: nothing to create")
	}
}
