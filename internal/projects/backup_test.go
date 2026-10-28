package projects

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

func setWAL(t *testing.T, f *fixture, serviceID string, on bool) {
	t.Helper()
	wal := int64(0)
	if on {
		wal = 1
	}
	if err := f.m.q.UpsertBackupPolicy(context.Background(), dbq.UpsertBackupPolicyParams{
		ID: "bp_" + serviceID, ServiceID: sql.NullString{String: serviceID, Valid: true}, Enabled: 1,
		EveryHours: 24, AtMinute: 180, Wal: wal, NextRunAt: 1, Consistency: "pause", CreatedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

// Continuous WAL archiving is added to the command at deploy time, shows
// as a pending change, and leaves the stored command alone.
func TestWALArchivingAddsServerOptions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t)
	svcs, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	db := svcs[0]
	if pending, _ := f.m.PendingChanges(ctx, db.ID); pending {
		t.Fatal("fresh service should have nothing pending")
	}
	setWAL(t, f, db.ID, true)
	if pending, _ := f.m.PendingChanges(ctx, db.ID); !pending {
		t.Fatal("turning WAL on must show as pending until a deploy")
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "db", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_db")
	cmd := strings.Join(spec.Command, " ")
	if spec.Command[0] != "postgres" || !strings.Contains(cmd, "archive_mode=on") || !strings.Contains(cmd, "archive_timeout=60") ||
		!strings.Contains(cmd, "/var/lib/postgresql/hangar-wal/%f") {
		t.Fatalf("archiving options missing: %v", spec.Command)
	}
	stored, _ := f.m.q.GetServiceByID(ctx, db.ID)
	if strings.Contains(stored.CommandJson, "archive") {
		t.Error("the stored command must stay as the user left it")
	}

	// A service whose command is not the postgres server is left alone.
	webID := ""
	for _, s := range mustServices(t, f) {
		if s.Slug == "web" {
			webID = s.ID
		}
	}
	setWAL(t, f, webID, true)
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if web, _ := f.n.spec("lab_web"); len(web.Command) != 0 {
		t.Errorf("nginx got a command: %v", web.Command)
	}
}

func mustServices(t *testing.T, f *fixture) []dbq.Service {
	t.Helper()
	p, err := f.m.GetProject(context.Background(), "lab")
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := f.m.ListServices(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	return svcs
}

func TestCloneServiceCopiesWithoutDeploying(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t)
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	c, err := f.m.CloneService(ctx, f.who, "lab", "db", "db-restaurado")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.n.spec("lab_db-restaurado"); ok {
		t.Fatal("clone must not deploy by itself")
	}
	vols, _ := f.m.q.ListVolumes(ctx, c.ID)
	if len(vols) != 1 || vols[0].Path != "/var/lib/postgresql" {
		t.Errorf("volumes: %+v", vols)
	}
	env, _, err := f.m.envFor(ctx, c)
	if err != nil || env["POSTGRES_DB"] != "app" || env["POSTGRES_PASSWORD"] == "" {
		t.Errorf("env: %v %v", env, err)
	}
	_, src, _ := f.m.GetService(ctx, "lab", "db")
	orig, _, _ := f.m.envFor(ctx, src)
	if env["POSTGRES_PASSWORD"] != orig["POSTGRES_PASSWORD"] {
		t.Error("the copy must keep the password: the restored data has the original roles")
	}
	url, err := f.m.RevealExport(ctx, f.who, c.ID, "DATABASE_URL")
	if err != nil || !strings.Contains(url, "@lab_db-restaurado:5432") {
		t.Errorf("exports must point at the copy: %q %v", url, err)
	}
	if _, err := f.m.CloneService(ctx, f.who, "lab", "db", "db-restaurado"); err == nil {
		t.Error("a second copy with the same name must fail")
	}
	if _, err := f.m.CloneService(ctx, f.who, "lab", "db", "Bad_Name"); err == nil {
		t.Error("invalid name accepted")
	}
}
