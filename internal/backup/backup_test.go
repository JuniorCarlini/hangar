package backup

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRecipientsNeedConfirmation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	code := archive.ConfirmCode(f.id)
	rid, err := f.m.AddRecipient(ctx, f.who, "Junior", f.id.Recipient().String(), archive.CodeHash(code))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.recipients(ctx); !errors.Is(err, ErrNotReady) {
		t.Fatal("an unconfirmed key must not be used")
	}
	if err := f.m.ConfirmRecipient(ctx, f.who, rid, "AAAA-BBBB-CCCC"); err == nil {
		t.Fatal("a wrong code must be refused")
	}
	if err := f.m.ConfirmRecipient(ctx, f.who, rid, strings.ToLower(code)); err != nil {
		t.Fatalf("typed in lowercase: %v", err)
	}
	if rs, err := f.m.recipients(ctx); err != nil || len(rs) != 1 {
		t.Fatalf("confirmed key: %v", err)
	}
	if err := f.m.DeleteRecipient(ctx, f.who, rid); err == nil {
		t.Fatal("the last confirmed key cannot be removed")
	}
	if _, err := f.m.AddRecipient(ctx, f.who, "Repetida", f.id.Recipient().String(), archive.CodeHash(code)); err == nil {
		t.Fatal("the same key twice must fail")
	}
	if _, err := f.m.AddRecipient(ctx, f.who, "Ruim", "age1naovale", archive.CodeHash(code)); err == nil {
		t.Fatal("an invalid public key must fail")
	}
}

func TestAddTargetChecksLockAndDeletePermission(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.store.canDelete = true
	if _, err := f.m.AddTarget(ctx, f.who, validTarget()); err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("a credential that can delete must be refused: %v", err)
	}
	// A key that may only add delete markers (B2's writeFiles) is fine:
	// the versions stay.
	f.store.canDelete, f.store.canHide = false, true
	hid, err := f.m.AddTarget(ctx, f.who, validTarget())
	if err != nil {
		t.Fatalf("a credential that can only hide must pass: %v", err)
	}
	if err := f.m.DeleteTarget(ctx, f.who, hid); err != nil {
		t.Fatal(err)
	}
	f.store.canHide, f.store.noLock = false, true
	if _, err := f.m.AddTarget(ctx, f.who, validTarget()); err == nil || !strings.Contains(strings.ToLower(err.Error()), "lock") {
		t.Fatalf("a bucket without Object Lock must be refused: %v", err)
	}
	f.store.noLock = false
	bad := validTarget()
	bad.Config.Bucket = "Bucket_Invalido"
	if _, err := f.m.AddTarget(ctx, f.who, bad); err == nil {
		t.Fatal("invalid bucket name accepted")
	}
	id, err := f.m.AddTarget(ctx, f.who, validTarget())
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := f.m.Targets(ctx)
	if len(ts) != 1 || ts[0].ID != id || !ts[0].Primary || ts[0].Prefix != "lab/" {
		t.Fatalf("targets: %+v", ts)
	}
	// The probe went in with the lock, under the prefix.
	locked := 0
	for _, k := range f.store.keys("lab/hangar-check/") {
		if f.store.opts[k].LockMode == s3.Compliance {
			locked++
		}
	}
	if locked == 0 {
		t.Fatalf("probe: %v", f.store.keys("lab/hangar-check/"))
	}
	// The credential is encrypted in the database.
	row, _ := f.m.q.GetBackupTarget(ctx, id)
	if bytes.Contains(row.ConfigEnc, []byte("backblazeb2")) {
		t.Fatal("destination config stored in clear")
	}
	if _, err := f.m.q.GetBackupPolicy(ctx, PanelPolicyID); err != nil {
		t.Fatal("the panel's own backup must be scheduled once a destination exists")
	}
}

func TestDumpIsTestedEncryptedAndLocked(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.postgres(t)
	if _, err := f.m.ref(ctx, "lab", "db"); err != nil {
		t.Fatal(err)
	}
	s, _ := f.m.ref(ctx, "lab", "db")
	if _, err := f.m.backupDump(ctx, f.who, s, TriggerManual); !errors.Is(err, ErrNotReady) {
		t.Fatalf("without kit and destination: %v", err)
	}
	f.ready(t)

	runID, err := f.m.backupDump(ctx, f.who, s, TriggerSchedule)
	if err != nil {
		t.Fatal(err)
	}
	// The test restore gets the roles script (none to recreate here: only
	// the bootstrap superuser) and then the whole dump.
	if !bytes.Equal(f.n.taskIn, append([]byte("0\n"), f.n.dumpData...)) {
		t.Fatalf("the test restore must receive the roles script and the whole dump: %.40q", f.n.taskIn)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	if run.Status != "ok" || run.Verified != 1 || run.Class != archive.ClassMonthly || !strings.HasPrefix(run.ObjectKey, "mensal/lab/db/") {
		t.Fatalf("run: %+v", run)
	}
	key := "lab/" + run.ObjectKey
	if bytes.Contains(f.store.objects[key], []byte("pedido")) {
		t.Fatal("the bucket got plaintext")
	}
	if got := f.open(t, key); !bytes.Equal(got, f.n.dumpData) {
		t.Fatal("the kit does not open the backup back to the dump")
	}
	o := f.store.opts[key]
	if o.LockMode != s3.Compliance || o.Metadata["hangar-sha256"] != run.Sha256 || o.RetainUntil.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("upload options: %+v", o)
	}
	if staged, _ := os.ReadDir(f.m.opt.StagingDir); len(staged) != 0 {
		t.Fatalf("staging not cleaned: %v", staged)
	}

	// Second scheduled run in the same week: daily, with a 7-day lock.
	runID, err = f.m.backupDump(ctx, f.who, s, TriggerSchedule)
	if err != nil {
		t.Fatal(err)
	}
	run, _ = f.m.q.GetBackupRun(ctx, runID)
	if run.Class != archive.ClassDaily || f.store.opts["lab/"+run.ObjectKey].RetainUntil.After(time.Now().Add(8*24*time.Hour)) {
		t.Fatalf("daily run: %+v", run)
	}

	// A failing test restore stops the upload.
	before := len(f.store.keys("lab/diario/"))
	f.n.checkOut = ""
	if _, err := f.m.backupDump(ctx, f.who, s, TriggerManual); err == nil {
		t.Fatal("a failed test restore must fail the backup")
	}
	if len(f.store.keys("lab/diario/")) != before {
		t.Fatal("a backup that failed its test must not be uploaded")
	}
	f.n.checkOut = "HANGAR-CHECK tables=5 restored=3 rows=1"
	if _, err := f.m.backupDump(ctx, f.who, s, TriggerManual); err == nil {
		t.Fatal("missing tables in the test restore must fail")
	}
}

func TestSizeWarning(t *testing.T) {
	prev := dbq.BackupRun{ID: "x", SizeBytes: 100 << 20, CheckJson: `{"rows":100000}`}
	for _, c := range []struct {
		size, rows int64
		want       string
	}{
		{100 << 20, 100000, ""},
		{40 << 20, 100000, "shrank"},
		{400 << 20, 100000, "grew"},
		{90 << 20, 10000, "rows_dropped"},
	} {
		if got := sizeWarning(prev, c.size, c.rows); got != c.want {
			t.Errorf("size %d rows %d: %q, want %q", c.size, c.rows, got, c.want)
		}
	}
	if sizeWarning(dbq.BackupRun{}, 1, 1) != "" {
		t.Error("first backup has nothing to compare")
	}
}

func TestShipWALMovesOutboxToBucket(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.postgres(t)
	f.ready(t)
	s, _ := f.m.ref(ctx, "lab", "db")
	seg := bytes.Repeat([]byte{1, 2, 3}, 1000)
	f.n.outbox = map[string][]byte{
		"000000010000000000000002":     seg,
		"000000010000000000000001":     seg,
		"000000010000000000000003.tmp": seg, // still being copied by PostgreSQL
		"evil;rm -rf":                  seg,
	}
	if err := f.m.shipWAL(ctx, s); err != nil {
		t.Fatal(err)
	}
	keys := f.store.keys("lab/wal/lab/db/seg/")
	if len(keys) != 2 || !strings.HasSuffix(keys[0], "000000010000000000000001.zst.age") {
		t.Fatalf("uploaded: %v", keys)
	}
	if got := f.open(t, keys[1]); !bytes.Equal(got, seg) {
		t.Fatal("WAL does not round-trip")
	}
	if strings.Join(f.n.removed, ",") != "000000010000000000000001,000000010000000000000002" {
		t.Fatalf("removed from the outbox: %v", f.n.removed)
	}
	for _, e := range f.n.execs {
		if strings.Contains(e, "evil") {
			t.Fatalf("an unexpected outbox name reached a command: %q", e)
		}
	}
	st, _ := f.m.q.GetWALStatus(ctx, s.ID)
	if st.LastArchivedWal != "000000010000000000000002" || st.Pending != 0 || st.LastError != "" {
		t.Fatalf("status: %+v", st)
	}
	// archive_mode off: the database still needs its restart.
	f.n.archive = "off|0|0|0"
	_ = f.m.shipWAL(ctx, s)
	if st, _ := f.m.q.GetWALStatus(ctx, s.ID); st.LastError != WALRestartNeeded {
		t.Fatalf("restart needed: %+v", st)
	}
}

func TestPanelBackupHoldsDatabaseKeyAndConfig(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.ready(t)
	runID, err := f.m.backupPanel(ctx, f.who, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	if !strings.HasPrefix(run.ObjectKey, "painel/") {
		t.Fatalf("key %q", run.ObjectKey)
	}
	tr := tar.NewReader(bytes.NewReader(f.open(t, "lab/"+run.ObjectKey)))
	got := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[h.Name], _ = io.ReadAll(tr)
	}
	if string(got[PanelKey]) != "0123456789abcdef0123456789abcdef" || !strings.HasPrefix(string(got[PanelDB]), "SQLite format 3") || len(got[PanelConfig]) == 0 || len(got[PanelManifest]) == 0 {
		t.Fatalf("panel backup entries: %v", keysOf(got))
	}
	if f.m.panelChanged(ctx) {
		t.Fatal("the backup's own audit record must not count as a change")
	}
	f.m.record(ctx, f.who, "project.create", "project", "p", "ok", nil)
	if !f.m.panelChanged(ctx) {
		t.Fatal("a new audited action is a change")
	}
}

// memSource reads the fake bucket as `hangard restore` reads the real one.
type memSource struct {
	s      *memStore
	prefix string
}

func (m memSource) List(ctx context.Context, prefix string) ([]archive.Listed, error) {
	var out []archive.Listed
	err := m.s.List(ctx, m.prefix+prefix, func(o s3.ObjectInfo) error {
		out = append(out, archive.Listed{Key: strings.TrimPrefix(o.Key, m.prefix), Size: o.Size, LastModified: o.LastModified})
		return nil
	})
	return out, err
}

func (m memSource) Open(ctx context.Context, key string) (io.ReadCloser, map[string]string, error) {
	rc, info, err := m.s.Get(ctx, m.prefix+key)
	return rc, info.Metadata, err
}

// Disaster recovery, step 2: the panel database, master key and config
// come back from the bucket with the kit; what was there is moved aside.
func TestRestorePanelFromBucket(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.ready(t)
	if _, err := f.m.backupPanel(ctx, f.who, TriggerManual); err != nil {
		t.Fatal(err)
	}
	server := t.TempDir()
	o := PanelRestoreOptions{
		DataDir: filepath.Join(server, "data"), MasterKeyFile: filepath.Join(server, "etc", "master.key"),
		ConfigFile: filepath.Join(server, "etc", "hangar.toml"),
	}
	src := memSource{s: f.store, prefix: "lab/"}
	if _, err := RestorePanel(ctx, src, []age.Identity{newKeyFor(t)}, time.Time{}, o); err == nil {
		t.Fatal("a stranger's kit must not restore the panel")
	}
	res, err := RestorePanel(ctx, src, []age.Identity{f.id}, time.Time{}, o)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(o.MasterKeyFile)
	st, _ := os.Stat(o.MasterKeyFile)
	if string(key) != "0123456789abcdef0123456789abcdef" || st.Mode().Perm() != 0o400 {
		t.Fatalf("master key: %q %v", key, st.Mode())
	}
	if db, _ := os.ReadFile(filepath.Join(o.DataDir, PanelDB)); !bytes.HasPrefix(db, []byte("SQLite format 3")) {
		t.Fatal("panel database not restored")
	}
	if res.ConfigCopy == "" || res.Manifest.Version != "test" {
		t.Fatalf("result: %+v", res)
	}
	// A second restore refuses without -force, and with it keeps the
	// current files aside.
	if _, err := RestorePanel(ctx, src, []age.Identity{f.id}, time.Time{}, o); !errors.Is(err, ErrPanelExists) {
		t.Fatalf("existing panel: %v", err)
	}
	o.Force = true
	res, err = RestorePanel(ctx, src, []age.Identity{f.id}, time.Time{}, o)
	if err != nil || len(res.Aside) < 2 {
		t.Fatalf("forced restore: %+v %v", res, err)
	}
}

func newKeyFor(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestNextRun(t *testing.T) {
	loc := time.FixedZone("BRT", -3*3600)
	now := time.Date(2026, 10, 16, 10, 30, 0, 0, loc)
	cases := []struct {
		every, at int
		want      time.Time
	}{
		{24, 180, time.Date(2026, 10, 17, 3, 0, 0, 0, loc)},
		{6, 180, time.Date(2026, 10, 16, 15, 0, 0, 0, loc)},
		{1, 15, time.Date(2026, 10, 16, 11, 15, 0, 0, loc)},
		{12, 600, time.Date(2026, 10, 16, 22, 0, 0, 0, loc)},
	}
	for _, c := range cases {
		if got := nextRun(now, c.every, c.at); !got.Equal(c.want) {
			t.Errorf("every %dh at %d: %v, want %v", c.every, c.at, got, c.want)
		}
	}
}

func TestDownloadIsEncryptedAndSingleUse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.postgres(t)
	f.ready(t)
	if err := f.m.PrepareDownload(ctx, f.who, "lab", "db"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	s, _ := f.m.ref(ctx, "lab", "db")
	d, ok := f.m.PendingDownload(f.who.UserID, s.ID)
	if !ok || !d.Ready || !strings.HasSuffix(d.FileName, ".zip") {
		t.Fatalf("pending: %+v %v", d, ok)
	}
	if _, _, _, err := f.m.TakeDownload(ctx, Actor{UserID: "usr_outro"}, d.Token); err == nil {
		t.Fatal("another user must not take the download")
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
	// One .zip: a README, the roles and the dump, both encrypted.
	zr, err := zip.NewReader(bytes.NewReader(zipped.Bytes()), int64(zipped.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, zf := range zr.File {
		names = append(names, zf.Name)
		rc, _ := zf.Open()
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		switch {
		case strings.HasSuffix(zf.Name, ".age"):
			if bytes.Contains(b, []byte("pedido")) || bytes.Contains(b, []byte("SCRAM")) || !bytes.HasPrefix(b, []byte("age-encryption.org/v1")) {
				t.Fatalf("%s must be encrypted", zf.Name)
			}
			plain, err := archive.Open(bytes.NewReader(b), []age.Identity{f.id}, archive.DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(plain)
			want := f.n.dumpData
			if strings.HasSuffix(zf.Name, archive.ExtRoles) {
				want = []byte(f.n.rolesSQL)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s opens to something else", zf.Name)
			}
		case zf.Name == ReadmeName:
			if !bytes.Contains(b, []byte("pg_restore")) || !bytes.Contains(b, []byte("hangar-cofre decrypt")) {
				t.Errorf("README: %s", b)
			}
		}
	}
	if len(names) != 3 || names[0] != ReadmeName || !strings.HasSuffix(names[1], archive.ExtRoles) || !strings.HasSuffix(names[2], archive.ExtDump) {
		t.Fatalf("bundle: %v", names)
	}
	if staged, _ := os.ReadDir(f.m.opt.StagingDir); len(staged) != 0 {
		t.Fatalf("staging not cleaned: %v", staged)
	}
	if _, _, _, err := f.m.TakeDownload(ctx, f.who, d.Token); err == nil {
		t.Fatal("the link must work only once")
	}
}

func TestAlerts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	o, _ := f.m.Overview(ctx)
	if !hasAlert(o.Alerts, AlertNoKit) || !hasAlert(o.Alerts, AlertNoTarget) {
		t.Fatalf("fresh panel: %+v", o.Alerts)
	}
	f.postgres(t)
	f.ready(t)
	if err := f.m.SetServicePolicy(ctx, f.who, "lab", "db", PolicyInput{Enabled: true, EveryHours: 24, AtMinute: 180, WAL: true}); err != nil {
		t.Fatal(err)
	}
	s, _ := f.m.ref(ctx, "lab", "db")
	// Pretend the policy is two days old with no backup at all.
	f.m.now = func() time.Time { return time.Now().Add(50 * time.Hour) }
	_ = f.m.q.UpsertWALStatus(ctx, dbq.UpsertWALStatusParams{ServiceID: s.ID, Pending: 3, OldestPendingAt: sql.NullInt64{Int64: time.Now().Unix(), Valid: true}, CheckedAt: time.Now().Unix()})
	o, _ = f.m.Overview(ctx)
	if !hasAlert(o.Alerts, AlertStale) || !hasAlert(o.Alerts, AlertWALLag) || hasAlert(o.Alerts, AlertNoKit) {
		t.Fatalf("alerts: %+v", o.Alerts)
	}
}

func hasAlert(as []Alert, kind string) bool {
	for _, a := range as {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

// Every few months the owner is asked to prove the kit is still kept; typing
// the code again restarts the count.
func TestKitCheckComesBackEveryFewMonths(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now()
	f.m.now = func() time.Time { return now }
	code := archive.ConfirmCode(f.id)
	rid, err := f.m.AddRecipient(ctx, f.who, "Junior", f.id.Recipient().String(), archive.CodeHash(code))
	if err != nil {
		t.Fatal(err)
	}
	if f.m.KitCheckDue(ctx) {
		t.Fatal("an unconfirmed key is not a reminder: it has its own warning")
	}
	if err := f.m.ConfirmRecipient(ctx, f.who, rid, code); err != nil {
		t.Fatal(err)
	}
	now = now.Add(KitCheckEvery - time.Hour)
	if f.m.KitCheckDue(ctx) {
		t.Fatal("asked before the time")
	}
	now = now.Add(time.Hour)
	if !f.m.KitCheckDue(ctx) {
		t.Fatal("no reminder after the period")
	}
	if err := f.m.ConfirmRecipient(ctx, f.who, rid, code); err != nil {
		t.Fatal(err)
	}
	if f.m.KitCheckDue(ctx) {
		t.Error("confirming again must restart the count")
	}
}

func TestManualBackupIsQueuedOnce(t *testing.T) {
	m := &Manager{jobs: make(chan job, 8)}
	if err := m.pushManual("svc_1", job{kind: archive.KindDump, service: "svc_1"}, job{kind: archive.KindBase, service: "svc_1"}); err != nil {
		t.Fatal(err)
	}
	if !m.Queued("svc_1") {
		t.Fatal("the backup should show as queued")
	}
	if err := m.pushManual("svc_1", job{kind: archive.KindDump, service: "svc_1"}); !errors.Is(err, ErrQueued) {
		t.Fatalf("a second click while queued: %v, want ErrQueued", err)
	}
	if err := m.pushManual("", job{kind: archive.KindPanel}); err != nil {
		t.Fatalf("the panel's backup is independent: %v", err)
	}
	m.doneManual("svc_1")
	if !m.Queued("svc_1") {
		t.Fatal("the base backup of the same click still waits")
	}
	m.doneManual("svc_1")
	if m.Queued("svc_1") {
		t.Fatal("both jobs ran: nothing queued")
	}
	if err := m.pushManual("svc_1", job{kind: archive.KindDump, service: "svc_1"}); err != nil {
		t.Fatalf("after it finished a new one is accepted: %v", err)
	}
}
