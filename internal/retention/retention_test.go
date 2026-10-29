package retention

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

var now = time.Date(2027, 6, 15, 12, 0, 0, 0, time.UTC)

func newJanitor(t *testing.T) *Janitor {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(dir, "hangar.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	j := New(st, dir, log)
	j.now = func() time.Time { return now }
	j.pause = 0
	return j
}

func (j *Janitor) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := j.st.DB.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func (j *Janitor) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := j.st.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (j *Janitor) run(t *testing.T) Report {
	t.Helper()
	rep, err := j.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func ago(d time.Duration) int64 { return now.Add(-d).Unix() }

const day = 24 * time.Hour

func (j *Janitor) service(t *testing.T, id string) {
	t.Helper()
	j.exec(t, `INSERT OR IGNORE INTO projects (id, slug, name, created_at, updated_at) VALUES ('p1', 'p1', 'p1', 0, 0)`)
	j.exec(t, `INSERT INTO services (id, project_id, slug, image, memory_bytes, nano_cpus, pids_limit, created_at, updated_at)
		VALUES (?, 'p1', ?, 'nginx', 0, 0, 0, 0, 0)`, id, id)
}

func TestMetricsKeepMinutesTwoDaysAndHoursNinety(t *testing.T) {
	j := newJanitor(t)
	put := func(key, res string, at int64) {
		j.exec(t, `INSERT INTO metrics (key, resolution, ts, cpu_pct, mem_bytes, mem_limit, net_rx, net_tx) VALUES (?, ?, ?, 0, 0, 0, 0, 0)`, key, res, at)
	}
	for _, key := range []string{"host", "svc"} {
		put(key, "1m", ago(48*time.Hour+time.Minute)) // gone
		put(key, "1m", ago(48*time.Hour-time.Minute)) // stays
		put(key, "1h", ago(90*day+time.Hour))         // gone
		put(key, "1h", ago(90*day-time.Hour))         // stays
	}
	rep := j.run(t)
	if rep.Removed["metrics"] != 4 {
		t.Fatalf("removed %d metric rows, want 4", rep.Removed["metrics"])
	}
	if n := j.count(t, `SELECT count(*) FROM metrics`); n != 4 {
		t.Fatalf("%d rows left, want 4", n)
	}
}

func TestDeniedAsksGoAfterAWeekApprovalsStay(t *testing.T) {
	j := newJanitor(t)
	hour := now.Unix() / 3600
	put := func(host, decision string, h int64) {
		j.exec(t, `INSERT INTO tls_ask_log (hostname, decision, reason, hour, last_at) VALUES (?, ?, 'x', ?, 0)`, host, decision, h)
	}
	put("bad-old.example", "deny", hour-7*24-1)
	put("bad-new.example", "deny", hour-7*24+1)
	put("ok-old.example", "allow", hour-180*24-1)
	put("ok.example", "allow", hour-100*24)
	j.run(t)
	if n := j.count(t, `SELECT count(*) FROM tls_ask_log WHERE hostname IN ('bad-new.example', 'ok.example')`); n != 2 {
		t.Fatal("recent denial and approval within 180 days must stay")
	}
	if n := j.count(t, `SELECT count(*) FROM tls_ask_log`); n != 2 {
		t.Fatalf("%d rows left, want 2", n)
	}
}

func TestAlertsKeepWhatIsStillFiring(t *testing.T) {
	j := newJanitor(t)
	put := func(key, category string, resolved int, last int64) {
		j.exec(t, `INSERT INTO alerts (kind, severity, category, dedup_key, resolved, created_at, last_at) VALUES ('k', 'warning', ?, ?, ?, ?, ?)`,
			category, key, resolved, last, last)
	}
	put("disk", "server", 0, ago(200*day)) // firing, newest of its key: stays
	put("cpu", "server", 0, ago(100*day))  // fired…
	put("cpu", "server", 1, ago(99*day))   // …and resolved: both go
	put("mem", "server", 0, ago(400*day))  // stuck past a year: goes
	put("ip", "security", 0, ago(91*day))  // security ages out
	put("fresh", "server", 1, ago(89*day)) // within 90 days: stays
	j.exec(t, `INSERT INTO alert_deliveries (channel_name, channel_kind, kind, status, created_at) VALUES ('c', 'email', 'k', 'sent', ?), ('c', 'email', 'k', 'sent', ?)`,
		ago(31*day), ago(29*day))
	j.run(t)
	if n := j.count(t, `SELECT count(*) FROM alerts`); n != 2 {
		t.Fatalf("%d alerts left, want 2 (disk still firing, fresh)", n)
	}
	if n := j.count(t, `SELECT count(*) FROM alerts WHERE dedup_key IN ('disk', 'fresh')`); n != 2 {
		t.Fatal("wrong alerts kept")
	}
	if n := j.count(t, `SELECT count(*) FROM alert_deliveries`); n != 1 {
		t.Fatalf("%d deliveries left, want 1", n)
	}
}

func TestDeploymentsKeepNewestPerServiceAndLogsOfFewer(t *testing.T) {
	j := newJanitor(t)
	j.policy.DeploysPerSvc, j.policy.DeployLogsPerSvc = 5, 2
	j.service(t, "a")
	j.service(t, "b")
	for i := range 8 {
		status := "superseded"
		switch i {
		case 0:
			status = "live" // the oldest is still live: never removed
		case 7:
			status = "running"
		}
		j.exec(t, `INSERT INTO deployments (id, service_id, status, image, env_hash, trigger, started_at, log) VALUES (?, 'a', ?, 'x', '', 'manual', ?, 'build log')`,
			"a"+string(rune('0'+i)), status, int64(1000+i))
	}
	j.exec(t, `INSERT INTO deployments (id, service_id, status, image, env_hash, trigger, started_at, log) VALUES ('b0', 'b', 'failed', 'x', '', 'manual', 1, 'log')`)
	j.run(t)

	if n := j.count(t, `SELECT count(*) FROM deployments WHERE service_id = 'a'`); n != 6 {
		t.Fatalf("service a has %d deploys, want 5 newest + the live one", n)
	}
	if n := j.count(t, `SELECT count(*) FROM deployments WHERE id = 'a0'`); n != 1 {
		t.Fatal("the live deploy must stay")
	}
	if n := j.count(t, `SELECT count(*) FROM deployments WHERE service_id = 'a' AND log != ''`); n != 2 {
		t.Fatalf("%d deploys of a keep their log, want 2", n)
	}
	if n := j.count(t, `SELECT count(*) FROM deployments WHERE id = 'b0' AND log != ''`); n != 1 {
		t.Fatal("another service's history is counted on its own")
	}
}

func TestBackupRunsFollowTheBucketLifecycle(t *testing.T) {
	j := newJanitor(t)
	put := func(id, label, kind, class, status string, started int64) {
		j.exec(t, `INSERT INTO backup_runs (id, label, kind, trigger, class, status, started_at) VALUES (?, ?, ?, 'schedule', ?, ?, ?)`,
			id, label, kind, class, status, started)
	}
	// Daily objects live 7 days: the record 7 + 30.
	put("d-old", "db", "pg_dump", "daily", "ok", ago(38*day))
	put("d-kept", "db", "pg_dump", "daily", "ok", ago(36*day))
	put("m-kept", "db", "pg_dump", "monthly", "ok", ago(420*day))
	put("m-old", "db", "pg_dump", "monthly", "ok", ago(431*day))
	put("f-old", "db", "pg_dump", "daily", "failed", ago(91*day))
	put("latest", "db", "pg_dump", "daily", "ok", ago(day))
	// The only run of a label stays whatever its age: it is "last backup".
	put("only", "gone", "pg_dump", "daily", "ok", ago(900*day))
	put("panel-old", "painel", "panel", "", "ok", ago(66*day))
	put("panel", "painel", "panel", "", "ok", ago(day))
	j.run(t)
	for id, want := range map[string]int{"d-old": 0, "d-kept": 1, "m-kept": 1, "m-old": 0, "f-old": 0, "latest": 1, "only": 1, "panel-old": 0, "panel": 1} {
		if n := j.count(t, `SELECT count(*) FROM backup_runs WHERE id = ?`, id); n != want {
			t.Errorf("run %s: %d, want %d", id, n, want)
		}
	}
}

func TestSmallTablesAgeOut(t *testing.T) {
	j := newJanitor(t)
	j.exec(t, `INSERT INTO users (id, email, password_hash, role, created_at, updated_at) VALUES ('u', 'u@x', 'h', 'owner', 0, 0)`)
	j.exec(t, `INSERT INTO login_ips (user_id, ip, first_at, last_at) VALUES ('u', '1.1.1.1', 0, ?), ('u', '2.2.2.2', 0, ?)`, ago(181*day), ago(179*day))
	j.exec(t, `INSERT INTO invites (id, token_hash, email, role, created_at, expires_at, used_at) VALUES
		('i1', 't1', 'a@x', 'viewer', 0, ?, NULL), ('i2', 't2', 'b@x', 'viewer', 0, ?, NULL), ('i3', 't3', 'c@x', 'viewer', 0, ?, ?)`,
		ago(31*day), now.Add(day).Unix(), now.Add(day).Unix(), ago(31*day))
	j.service(t, "s")
	j.exec(t, `INSERT INTO log_marks (id, service_id, at, user_id, user_name) VALUES ('m1', 's', ?, 'u', 'u'), ('m2', 's', ?, 'u', 'u')`,
		now.Add(-31*day).UnixNano(), now.Add(-29*day).UnixNano())
	j.exec(t, `INSERT INTO dependency_findings (id, service_id, ecosystem, package, current_version, severity, level, kind, first_seen_at, last_seen_at, resolved_at)
		VALUES ('f1', 's', 'npm', 'a', '1', 'high', 'security', 'vuln', 0, 0, ?), ('f2', 's', 'npm', 'b', '1', 'high', 'security', 'vuln', 0, 0, ?), ('f3', 's', 'npm', 'c', '1', 'high', 'security', 'vuln', 0, 0, NULL)`,
		ago(181*day), ago(179*day))
	j.exec(t, `INSERT INTO backup_restores (id, label, mode, point, destination, status, started_at) VALUES ('r1', 'x', 'dump', 'p', 'new', 'ok', ?), ('r2', 'x', 'dump', 'p', 'new', 'running', ?)`,
		ago(401*day), ago(500*day))
	j.run(t)
	checks := map[string]int{
		`SELECT count(*) FROM login_ips`:                     1,
		`SELECT count(*) FROM invites`:                       1,
		`SELECT count(*) FROM log_marks`:                     1,
		`SELECT count(*) FROM dependency_findings`:           2,
		`SELECT count(*) FROM backup_restores WHERE id='r2'`: 1, // running: never
		`SELECT count(*) FROM backup_restores`:               1,
	}
	for q, want := range checks {
		if n := j.count(t, q); n != want {
			t.Errorf("%s = %d, want %d", q, n, want)
		}
	}
}

func TestDrainWorksInBatches(t *testing.T) {
	j := newJanitor(t)
	j.batch = 7
	for i := range 30 {
		j.exec(t, `INSERT INTO alert_deliveries (channel_name, channel_kind, kind, status, created_at) VALUES ('c', 'email', 'k', 'sent', ?)`, ago(40*day)+int64(i))
	}
	calls := 0
	n, err := j.drain(context.Background(), func(lim int64) (int64, error) {
		calls++
		if lim != 7 {
			t.Fatalf("batch of %d, want 7", lim)
		}
		return j.q.PruneAlertDeliveryRows(context.Background(), dbq.PruneAlertDeliveryRowsParams{Before: ago(30 * day), Lim: lim})
	})
	if err != nil || n != 30 {
		t.Fatalf("drained %d (%v), want 30", n, err)
	}
	if calls != 5 { // 7+7+7+7+2
		t.Fatalf("%d batches, want 5", calls)
	}
}

func TestDrainStopsAtMaxBatches(t *testing.T) {
	j := newJanitor(t)
	calls := 0
	n, err := j.drain(context.Background(), func(lim int64) (int64, error) {
		calls++
		return lim, nil // always a full batch: a backlog bigger than one run
	})
	if err != nil || calls != MaxBatches || n != int64(MaxBatches)*j.batch {
		t.Fatalf("calls=%d n=%d err=%v; want %d full batches", calls, n, err, MaxBatches)
	}
}

func TestAuditArchivedAndChainVerifies(t *testing.T) {
	j := newJanitor(t)
	l := audit.New(j.st.DB)
	for _, at := range []time.Time{now.Add(-500 * day), now.Add(-450 * day), now} {
		l.WithClock(func() time.Time { return at })
		if err := l.Record(context.Background(), audit.Entry{Action: "x", Outcome: audit.OK}); err != nil {
			t.Fatal(err)
		}
	}
	rep := j.run(t)
	if rep.Removed["audit_log"] != 2 {
		t.Fatalf("archived %d, want 2", rep.Removed["audit_log"])
	}
	if n, err := audit.Verify(context.Background(), j.st.Q); err != nil || n != 3 {
		t.Fatalf("verify = %d, %v", n, err)
	}
}

func TestTempFilesOlderThanADayGo(t *testing.T) {
	j := newJanitor(t)
	dir := filepath.Join(j.dataDir, "tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, age := range map[string]time.Duration{"old": 25 * time.Hour, "new": time.Hour} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	j.run(t)
	if _, err := os.Stat(filepath.Join(dir, "old")); !os.IsNotExist(err) {
		t.Error("a day-old leftover should be removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "new")); err != nil {
		t.Error("a scan in progress must stay")
	}
}

func TestRunOnceReclaimsSpace(t *testing.T) {
	j := newJanitor(t)
	big := make([]byte, 8<<10)
	for i := range 300 {
		j.exec(t, `INSERT INTO alert_deliveries (channel_name, channel_kind, kind, status, error, created_at) VALUES ('c', 'email', 'k', 'failed', ?, ?)`, string(big), ago(60*day)+int64(i))
	}
	before, _ := j.st.Stats(context.Background())
	rep := j.run(t)
	if rep.Stats.SizeBytes >= before.SizeBytes/2 {
		t.Fatalf("size %d → %d: space not returned", before.SizeBytes, rep.Stats.SizeBytes)
	}
}
