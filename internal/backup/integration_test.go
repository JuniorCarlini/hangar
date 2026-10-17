//go:build integration

package backup

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/backuptest"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/cofre"
	"github.com/JuniorCarlini/hangar/internal/docker"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
)

// realEnv is the engine wired to the real Docker and a throwaway MinIO.
type realEnv struct {
	m       *Manager
	pm      *projects.Manager
	id      *age.X25519Identity
	who     Actor
	project string
	minio   *backuptest.MinIO
}

func newRealEnv(t *testing.T, ctx context.Context) *realEnv {
	t.Helper()
	mio := backuptest.StartMinIO(ctx, t)
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	st, err := store.Open(ctx, filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	d, err := docker.New(ctx, "")
	if err != nil {
		t.Skip("Docker unavailable:", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{9}, 32))
	al := audit.New(st.DB)
	pm := projects.New(st.DB, box, d, al, log)
	m, err := New(st.DB, box, pm, al, log, Options{
		StagingDir: filepath.Join(dir, "staging"), AllowPrivateEndpoints: true,
		DBPath: filepath.Join(dir, "h.db"), MasterKeyFile: writeFile(t, dir, "master.key", strings.Repeat("k", 32)), Version: "it",
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &realEnv{m: m, pm: pm, who: Actor{UserID: "usr_it"}, project: backuptest.RandName("e2e-bk-"), minio: mio}
	e.id, _ = age.GenerateX25519Identity()
	t.Cleanup(func() { removeProject(e.project) })

	code := archive.ConfirmCode(e.id)
	rid, err := m.AddRecipient(ctx, e.who, "Teste", e.id.Recipient().String(), archive.CodeHash(code))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfirmRecipient(ctx, e.who, rid, code); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddTarget(ctx, e.who, TargetInput{
		Name: "MinIO", Provider: "custom", LockMode: s3.Compliance, LockDays: 1,
		Config: TargetConfig{Endpoint: mio.Endpoint, Region: "us-east-1", Bucket: mio.Bucket, AccessKey: mio.Writer.AccessKey, SecretKey: mio.Writer.SecretKey, PathStyle: true},
	}); err != nil {
		t.Fatalf("destination with the write-only credential: %v", err)
	}
	return e
}

// removeProject deletes everything Docker has for the test project.
func removeProject(project string) {
	for _, kind := range []string{"container", "volume", "network"} {
		args := []string{kind, "ls", "-q", "--filter", "label=hangar.project=" + project}
		if kind == "container" {
			args = []string{kind, "ls", "-aq", "--filter", "label=hangar.project=" + project}
		}
		out, _ := exec.Command("docker", args...).Output() //nolint:gosec // test cleanup with fixed arguments
		ids := strings.Fields(string(out))
		if len(ids) == 0 {
			continue
		}
		rm := append([]string{kind, "rm", "-f"}, ids...)
		if kind == "network" {
			rm = append([]string{kind, "rm"}, ids...)
		}
		_ = exec.Command("docker", rm...).Run() //nolint:gosec // test cleanup
	}
}

func (e *realEnv) psql(t *testing.T, ctx context.Context, service, sql string) string {
	t.Helper()
	n := e.pm.Node()
	var out bytes.Buffer
	cmd := []string{"sh", "-c", `psql -AtX -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "$1"`, "sh", sql}
	if err := n.Exec(ctx, e.project, service, cmd, &out); err != nil {
		t.Fatalf("psql %q: %v", sql, err)
	}
	return strings.TrimSpace(out.String())
}

func (e *realEnv) waitLive(t *testing.T, ctx context.Context, service string) {
	t.Helper()
	s, err := e.m.ref(ctx, e.project, service)
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.m.waitReady(ctx, s, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
}

func (e *realEnv) waitRestore(t *testing.T, ctx context.Context, serviceID, id string) Restore {
	t.Helper()
	deadline := time.Now().Add(8 * time.Minute)
	for time.Now().Before(deadline) {
		rs, _ := e.m.Restores(ctx, serviceID, 10)
		for _, r := range rs {
			if r.ID == id && r.Status != "running" {
				return r
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("restore did not finish")
	return Restore{}
}

// The Etapa 9 promise end to end: a tested, encrypted, locked dump; WAL
// shipped continuously; and the database brought back to the moment
// before a destructive DELETE, into a new service, with the kit.
func TestPostgresBackupAndPointInTimeRestore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E backups"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateFromTemplate(ctx, e.who, e.project, "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	e.waitLive(t, ctx, "db")
	e.psql(t, ctx, "db", "create table pedidos (id serial primary key, valor int not null, criado timestamptz default now())")
	e.psql(t, ctx, "db", "insert into pedidos (valor) select g from generate_series(1, 1000) g")
	s, _ := e.m.ref(ctx, e.project, "db")

	// 1. Logical backup: tested in a throwaway database, then uploaded.
	runID, err := e.m.backupDump(ctx, e.who, s, TriggerManual)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	run, _ := e.m.q.GetBackupRun(ctx, runID)
	if run.Verified != 1 || !strings.Contains(run.CheckJson, `"rows":1000`) || !strings.Contains(run.CheckJson, `"tables":1`) {
		t.Fatalf("the test restore must count the table and its rows: %+v", run)
	}
	writer := backuptest.Client(t, e.minio.Writer)
	if err := writer.Delete(ctx, run.ObjectKey, ""); !s3.IsAccessDenied(err) {
		t.Fatalf("the server credential deleted a backup: %v", err)
	}

	// 2. Continuous WAL: turn it on, redeploy, base backup.
	if err := e.m.SetServicePolicy(ctx, e.who, e.project, "db", PolicyInput{Enabled: true, EveryHours: 24, AtMinute: 180, WAL: true}); err != nil {
		t.Fatal(err)
	}
	if pending, _ := e.pm.PendingChanges(ctx, s.ID); !pending {
		t.Fatal("turning WAL on must ask for a redeploy")
	}
	if err := e.m.deployAndWait(ctx, e.who, s, "manual"); err != nil {
		t.Fatal(err)
	}
	e.waitLive(t, ctx, "db")
	if !e.m.archivingActive(ctx, s) {
		t.Fatal("archive_mode should be on after the redeploy")
	}
	if _, err := e.m.backupBase(ctx, e.who, s, TriggerWALStart); err != nil {
		t.Fatalf("base backup: %v", err)
	}

	// 3. More orders, the moment to go back to, then the disaster.
	e.psql(t, ctx, "db", "insert into pedidos (valor) select g from generate_series(1001, 1500) g")
	time.Sleep(1500 * time.Millisecond)
	target := time.Now()
	time.Sleep(1500 * time.Millisecond)
	e.psql(t, ctx, "db", "delete from pedidos")
	e.psql(t, ctx, "db", "select pg_switch_wal()")
	deadline := time.Now().Add(time.Minute)
	for {
		if err := e.m.shipWAL(ctx, s); err != nil {
			t.Fatalf("ship WAL: %v", err)
		}
		w := e.m.ServiceWAL(ctx, s.ID)
		if w != nil && w.LastName != "" && w.Pending == 0 && w.LastAt.After(target) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("WAL not shipped: %+v", w)
		}
		time.Sleep(time.Second)
	}
	if n := e.psql(t, ctx, "db", "select count(*) from pedidos"); n != "0" {
		t.Fatalf("the delete happened: %s", n)
	}

	// 4. Point-in-time restore into a new service, with the kit.
	if _, err := e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "db", Mode: ModePITR, At: target, Destination: DestNew, NewService: "db-restaurado",
		Identities: []age.Identity{mustKey(t)},
	}); err == nil {
		t.Fatal("a key that is not in the kit must be refused before anything starts")
	}
	rid, err := e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "db", Mode: ModePITR, At: target, Destination: DestNew, NewService: "db-restaurado",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := e.waitRestore(t, ctx, s.ID, rid)
	if r.Status != "ok" {
		t.Fatalf("restore: %+v", r)
	}
	if n := e.psql(t, ctx, "db-restaurado", "select count(*) from pedidos"); n != "1500" {
		t.Fatalf("restored to %v: %s orders, want 1500", target, n)
	}
	if ro := e.psql(t, ctx, "db-restaurado", "select pg_is_in_recovery()"); ro != "f" {
		t.Fatal("the restored database must accept writes")
	}
	e.psql(t, ctx, "db-restaurado", "insert into pedidos (valor) values (1)")

	// 5. The logical dump restores too (into another new service).
	rid, err = e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "db", Mode: ModeDump, Key: run.ObjectKey, Destination: DestNew, NewService: "db-dump",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" {
		t.Fatalf("dump restore: %+v", r)
	}
	if n := e.psql(t, ctx, "db-dump", "select count(*) from pedidos"); n != "1000" {
		t.Fatalf("dump restore has %s orders, want 1000", n)
	}

	// 6. Overwrite in place goes back too, after backing the current state up.
	rid, err = e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "db", Mode: ModePITR, At: target, Destination: DestOverwrite, Confirm: "db",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" {
		t.Fatalf("overwrite restore: %+v", r)
	}
	if n := e.psql(t, ctx, "db", "select count(*) from pedidos"); n != "1500" {
		t.Fatalf("overwritten service has %s orders, want 1500", n)
	}
	runs, _ := e.m.ServiceRuns(ctx, s.ID, 20)
	pre := 0
	for _, r := range runs {
		if r.Trigger == TriggerPreRestore && r.Status == "ok" {
			pre++
		}
	}
	if pre != 1 {
		t.Fatalf("overwrite must back up the current state first (%d pre-restore backups)", pre)
	}
	t.Logf("restored to %s: 1500 orders", target.Format(time.RFC3339))

	// 7. hangar-cofre on "the operator's computer": read-only credential,
	// the kit, the local Docker. The panel backup goes in too.
	if _, err := e.m.backupPanel(ctx, e.who, TriggerManual); err != nil {
		t.Fatalf("panel backup: %v", err)
	}
	reader, err := cofre.NewBucket(cofre.Config{
		Endpoint: e.minio.Endpoint, Region: "us-east-1", Bucket: e.minio.Bucket,
		AccessKey: e.minio.Reader.AccessKey, SecretKey: e.minio.Reader.SecretKey, PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	v := cofre.New(reader, []age.Identity{e.id})
	results, err := v.Test(ctx, "")
	if err != nil {
		t.Fatalf("hangar-cofre test: %v", err)
	}
	for _, r := range results {
		if !r.OK {
			t.Fatalf("hangar-cofre test %s: %v", r.Label, r.Err)
		}
	}
	if len(results) != 2 || results[0].Tables != 1 || results[1].Label != "painel" {
		t.Fatalf("drill results: %+v", results)
	}

	// Copy everything to "the external disk" and bring the database up
	// from there, offline, at the same minute.
	disk := t.TempDir()
	st, err := v.Sync(ctx, reader, disk)
	if err != nil || st.New == 0 {
		t.Fatalf("sync: %+v %v", st, err)
	}
	if again, _ := v.Sync(ctx, reader, disk); again.New != 0 {
		t.Fatal("a second sync must copy nothing new")
	}
	offline := cofre.New(cofre.Dir{Root: disk}, []age.Identity{e.id})
	lr, err := offline.RestoreLocal(ctx, cofre.RestoreOptions{Project: e.project, Service: "db", At: target, Port: freePort(t)})
	defer offline.Remove(ctx, lr)
	if err != nil {
		t.Fatalf("restore-local: %v", err)
	}
	var out bytes.Buffer
	if err := cofre.DockerCLI(ctx, nil, &out, "exec", lr.Container, "psql", "-AtX", "-U", lr.User, "-d", lr.DB, "-c", "select count(*) from pedidos"); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); lr.Mode != "pitr" || got != "1500" {
		t.Fatalf("restore-local (%s) has %s orders, want 1500", lr.Mode, got)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func mustKey(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
