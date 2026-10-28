package backup

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// volumeTask plays the helpers of volume backups: the copy writes volTar
// after "go", the test of the copy counts what it got, the restore keeps
// what it got.
func (f *fakeNode) volumeTask(spec node.TaskSpec, stdin io.Reader, stdout io.Writer) error {
	script, names := spec.Cmd[2], spec.Cmd[min(4, len(spec.Cmd)):]
	switch script {
	case volumeCopyScript:
		f.mu.Lock()
		data, extra := f.volTar, f.sourceExtra
		f.mu.Unlock()
		f.event("copy " + strings.Join(names, ","))
		if _, err := io.WriteString(stdout, "HANGAR-READY\n"); err != nil {
			return err
		}
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if line != "go\n" {
			return errors.New("the copy did not get its go")
		}
		f.event("tar")
		e, b := countTar(data)
		if _, err := fmt.Fprintf(stdout, "HANGAR-SOURCE entries=%d bytes=%d\n", e+extra, b); err != nil {
			return err
		}
		_, err := stdout.Write(data)
		return err
	case volumeVerifyScript:
		if _, err := io.WriteString(stdout, "HANGAR-READY\n"); err != nil {
			return err
		}
		in, _ := io.ReadAll(stdin)
		e, b := countTar(in)
		f.mu.Lock()
		if f.verifyLies {
			e++
		}
		f.mu.Unlock()
		_, err := fmt.Fprintf(stdout, "HANGAR-VERIFY entries=%d bytes=%d sha256=%x\n", e, b, sha256.Sum256(in))
		return err
	case volumeRestoreScript:
		in, _ := io.ReadAll(stdin)
		f.mu.Lock()
		f.volIn, f.volMounts = in, spec.Mounts
		fail := f.restoreErr
		f.restoreErr = nil
		f.mu.Unlock()
		f.event("restore " + strings.Join(names, ","))
		if fail != nil {
			return fail
		}
		e, b := countTar(in)
		_, err := fmt.Fprintf(stdout, "HANGAR-RESTORED entries=%d bytes=%d\n", e, b)
		return err
	}
	return fmt.Errorf("unexpected volume script")
}

// countTar counts entries and file bytes as GNU tar would.
func countTar(b []byte) (entries, bytes int64) {
	tr := tar.NewReader(strings.NewReader(string(b)))
	for {
		h, err := tr.Next()
		if err != nil {
			return
		}
		entries++
		if h.Typeflag == tar.TypeReg {
			bytes += h.Size
		}
	}
}

type tarEntry struct {
	name, body, link string
	typ              byte
	mode             int64
	uid              int
}

func makeTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Uid: e.uid, Linkname: e.link, Format: tar.FormatPAX, ModTime: time.Unix(1700000000, 0)}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	// GNU tar pads to whole records.
	buf.Write(make([]byte, 10240-buf.Len()%10240))
	return buf.Bytes()
}

// sampleTar is a volume "data" with a file, a folder, an empty folder and
// a symlink out of the volume (apps keep those).
func sampleTar(t *testing.T) []byte {
	return makeTar(t,
		tarEntry{name: "data/", typ: tar.TypeDir, mode: 0o755, uid: 1000},
		tarEntry{name: "data/.rustfs.sys/", typ: tar.TypeDir, mode: 0o700},
		tarEntry{name: "data/.rustfs.sys/iam.json", typ: tar.TypeReg, body: `{"users":["app"]}`, mode: 0o600, uid: 1000},
		tarEntry{name: "data/bucket/", typ: tar.TypeDir},
		tarEntry{name: "data/bucket/photo.jpg", typ: tar.TypeReg, body: strings.Repeat("jpeg", 3000)},
		tarEntry{name: "data/empty/", typ: tar.TypeDir},
		tarEntry{name: "data/current", typ: tar.TypeSymlink, link: "/data/bucket"},
	)
}

// volumeService creates lab/files, an image service with the volume
// "data", ready to back up.
func (f *fixture) volumeService(t *testing.T) svcRef {
	t.Helper()
	ctx := context.Background()
	if _, err := f.pm.CreateProject(ctx, f.who, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pm.CreateService(ctx, f.who, "lab", projects.ServiceInput{Name: "files", Image: "nginx:1.29"}); err != nil {
		t.Fatal(err)
	}
	if err := f.pm.AddServiceVolume(ctx, f.who, "lab", "files", "data", "/data"); err != nil {
		t.Fatal(err)
	}
	f.ready(t)
	f.n.volTar = sampleTar(t)
	s, err := f.m.ref(ctx, "lab", "files")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Which services are backed up how: templates opt in, PostgreSQL keeps
// pg_dump, a database without a method gets nothing, and a service of its
// own (image or Git) is backed up as volumes once it owns one.
func TestBackupMethod(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.pm.CreateProject(ctx, f.who, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	for _, tpl := range []struct{ id, name string }{{"postgres", "db"}, {"rustfs", "s3"}, {"mariadb", "maria"}} {
		if _, err := f.pm.CreateFromTemplate(ctx, f.who, "lab", tpl.id, tpl.name, nil); err != nil {
			t.Fatal(tpl.id, err)
		}
	}
	f.pm.Wait()
	if _, err := f.pm.CreateService(ctx, f.who, "lab", projects.ServiceInput{Name: "app", Image: "nginx:1.29"}); err != nil {
		t.Fatal(err)
	}
	method := func(slug string) string {
		_, s, err := f.pm.GetService(ctx, "lab", slug)
		if err != nil {
			t.Fatal(err)
		}
		return f.pm.BackupMethod(ctx, s)
	}
	for slug, want := range map[string]string{"db": projects.BackupPGDump, "s3": projects.BackupVolume, "maria": "", "app": ""} {
		if got := method(slug); got != want {
			t.Errorf("%s: %q, want %q", slug, got, want)
		}
	}
	if err := f.pm.AddServiceVolume(ctx, f.who, "lab", "app", "uploads", "/app/uploads"); err != nil {
		t.Fatal(err)
	}
	if got := method("app"); got != projects.BackupVolume {
		t.Errorf("an app with a volume: %q", got)
	}
}

// A copy of volumes: the service is paused only between the helpers being
// ready and the end of the tar, the copy is tested by a second helper,
// encrypted (zstd + age), locked in the daily folder next to the dumps
// and verified in the bucket.
func TestVolumeBackupPausesTestsAndUploads(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	runID, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, "")
	if err != nil {
		t.Fatal(err)
	}
	if ev := f.n.eventList(); !slices.Equal(ev, []string{"copy data", "pause files", "tar", "unpause files"}) {
		t.Fatalf("events: %v", ev)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	o, ok := archive.ParseKey(run.ObjectKey)
	if run.Status != "ok" || run.Verified != 1 || run.Kind != archive.KindVolume || !ok || o.Kind != archive.KindVolume || o.Class != archive.ClassDaily {
		t.Fatalf("run: %+v %+v", run, o)
	}
	var c VolumeCheck
	if err := json.Unmarshal([]byte(run.CheckJson), &c); err != nil || c.Files != 7 || c.Mode != ConsistencyPause || !slices.Equal(c.Paused, []string{"files"}) {
		t.Fatalf("check: %s", run.CheckJson)
	}
	info, err := f.store.Head(ctx, "lab/"+run.ObjectKey)
	if err != nil || info.LockMode == "" || info.Metadata["hangar-kind"] != archive.KindVolume {
		t.Fatalf("object: %+v %v", info, err)
	}
	if man, ok := archive.ParseVolumeMeta(info.Metadata["hangar-volumes"]); !ok || man.Entries != 7 || man.Volumes[0].Name != "data" {
		t.Fatalf("metadata: %q", info.Metadata["hangar-volumes"])
	}
	raw := f.store.objects["lab/"+run.ObjectKey]
	if bytes.Contains(raw, []byte("rustfs")) {
		t.Fatal("the copy must be encrypted")
	}
	if got := f.open(t, "lab/"+run.ObjectKey); !bytes.Equal(got, f.n.volTar) {
		t.Fatal("the copy opens to something else")
	}
	if staged, _ := os.ReadDir(f.m.opt.StagingDir); len(staged) != 0 {
		t.Fatalf("staging not cleaned: %v", staged)
	}
}

// A copy is called tested only when every count agrees: what the volumes
// held, what was encrypted, what the second helper read back.
func TestVolumeBackupRefusesACopyThatDoesNotAddUp(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	f.n.verifyLies = true
	if _, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, ""); err == nil || !strings.Contains(err.Error(), "test of the copy") {
		t.Fatalf("a test that disagrees: %v", err)
	}
	f.n.verifyLies = false
	f.n.sourceExtra = 1
	if _, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, ""); err == nil || !strings.Contains(err.Error(), "the volumes had") {
		t.Fatalf("a copy short of what the volumes held: %v", err)
	}
	if keys := f.store.keys("lab/diario/"); len(keys) != 0 {
		t.Fatalf("nothing may be uploaded: %v", keys)
	}
	// Live, files come and go during the copy: only the test counts. And
	// nothing is paused.
	f.n.events = nil
	if _, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, ConsistencyLive); err != nil {
		t.Fatal(err)
	}
	if ev := f.n.eventList(); slices.ContainsFunc(ev, func(e string) bool { return strings.HasPrefix(e, "pause") }) {
		t.Fatalf("live paused: %v", ev)
	}
	// Every pause was undone, whatever happened.
	if err := f.m.SetServicePolicy(ctx, f.who, "lab", "files", PolicyInput{Enabled: true, EveryHours: 24, AtMinute: 180, Consistency: ConsistencyStop}); err != nil {
		t.Fatal(err)
	}
	f.n.events = nil
	f.n.sourceExtra = 0
	if _, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, ""); err != nil {
		t.Fatal(err)
	}
	if ev := f.n.eventList(); !slices.Equal(ev, []string{"copy data", "stop files", "tar", "start files"}) {
		t.Fatalf("stop mode: %v", ev)
	}
}

// The consistency is a choice of the routine; WAL is PostgreSQL's alone.
func TestVolumePolicy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.volumeService(t)
	var ie *i18n.Error
	if err := f.m.SetServicePolicy(ctx, f.who, "lab", "files", PolicyInput{Enabled: true, EveryHours: 24, Consistency: "snapshot"}); !errors.As(err, &ie) || ie.Key != "backup.error.consistency" {
		t.Fatalf("unknown consistency: %v", err)
	}
	if err := f.m.SetServicePolicy(ctx, f.who, "lab", "files", PolicyInput{Enabled: true, EveryHours: 24, WAL: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("WAL on volumes: %v", err)
	}
	if err := f.m.SetServicePolicy(ctx, f.who, "lab", "files", PolicyInput{Enabled: true, EveryHours: 6, AtMinute: 60}); err != nil {
		t.Fatal(err)
	}
	s, _ := f.m.ref(ctx, "lab", "files")
	p, ok := f.m.ServicePolicy(ctx, s.ID)
	if !ok || p.Consistency != ConsistencyPause || p.EveryHours != 6 {
		t.Fatalf("policy: %+v", p)
	}
	// Due: the scheduler queues a copy of the volumes.
	_ = f.m.q.SetBackupPolicyNextRun(ctx, dbq.SetBackupPolicyNextRunParams{NextRunAt: 1, ID: p.ID})
	f.m.schedule(ctx)
	for queued := true; queued; {
		select {
		case j := <-f.m.jobs:
			if j.kind == archive.KindVolume && j.service == s.ID {
				return
			}
		default:
			queued = false
		}
	}
	t.Fatal("no copy of the volumes queued")
}

// Overwriting: a copy of the current state first, then the services stop,
// the volume is filled from the copy and the service is deployed again.
func TestVolumeRestoreOverwrite(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	runID, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, "")
	if err != nil {
		t.Fatal(err)
	}
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	want := f.n.volTar
	f.n.volTar = makeTar(t, tarEntry{name: "data/", typ: tar.TypeDir}, tarEntry{name: "data/other", typ: tar.TypeReg, body: "now"})
	f.n.events = nil
	later(f)
	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "files", Mode: ModeDump, Key: run.ObjectKey, Destination: DestOverwrite, Confirm: "files",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.waitRestore(t, s.ID, id)
	if r.Status != "ok" {
		t.Fatalf("restore: %+v", r)
	}
	if !bytes.Equal(f.n.volIn, want) {
		t.Fatal("the volume did not get the copy")
	}
	if len(f.n.volMounts) != 1 || f.n.volMounts[0].Volume != "hangar_lab_files_data" || f.n.volMounts[0].ReadOnly {
		t.Fatalf("mounts: %+v", f.n.volMounts)
	}
	ev := f.n.eventList()
	if i, j := slices.Index(ev, "stop files"), slices.Index(ev, "restore data"); i < 0 || j < i || !slices.Contains(ev, "pause files") {
		t.Fatalf("events: %v", ev)
	}
	pre, _ := f.m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: "lab/files", Kind: archive.KindVolume})
	if pre.Trigger != TriggerPreRestore {
		t.Fatalf("no copy of the current state first: %+v", pre)
	}
}

// When the restore fails once the volume was touched, the copy made just
// before goes back in.
func TestVolumeRestoreRollsBack(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	runID, _ := f.m.backupVolume(ctx, f.who, s, TriggerManual, "")
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	later(f)
	current := makeTar(t, tarEntry{name: "data/", typ: tar.TypeDir}, tarEntry{name: "data/today", typ: tar.TypeReg, body: "today"})
	f.n.volTar = current
	f.n.setRestoreErr(errors.New("tar: disk full"))
	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "files", Mode: ModeDump, Key: run.ObjectKey, Destination: DestOverwrite, Confirm: "files",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.waitRestore(t, s.ID, id)
	if r.Status != "failed" || !strings.Contains(r.Error, "disk full") || !strings.Contains(r.Error, "back as they were") {
		t.Fatalf("restore: %+v", r)
	}
	if !bytes.Equal(f.n.volIn, current) {
		t.Fatal("the state before the restore was not put back")
	}
}

// Into a new service: a copy of the service with volumes of its own,
// deployed, then filled; the original is never touched.
func TestVolumeRestoreIntoNewService(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	runID, _ := f.m.backupVolume(ctx, f.who, s, TriggerManual, "")
	run, _ := f.m.q.GetBackupRun(ctx, runID)
	id, err := f.m.StartRestore(ctx, f.who, RestoreRequest{
		Project: "lab", Service: "files", Mode: ModeDump, Key: run.ObjectKey, Destination: DestNew, NewService: "files-copy",
		Identities: []age.Identity{f.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := f.waitRestore(t, s.ID, id); r.Status != "ok" {
		t.Fatalf("restore: %+v", r)
	}
	if !bytes.Equal(f.n.volIn, f.n.volTar) || f.n.volMounts[0].Volume != "hangar_lab_files-copy_data" {
		t.Fatalf("the new service did not get the copy: %+v", f.n.volMounts)
	}
	// A pg_dump point or a minute is not a copy of volumes.
	if _, err := f.m.StartRestore(ctx, f.who, RestoreRequest{Project: "lab", Service: "files", Mode: ModePITR, At: time.Now(), Destination: DestNew, NewService: "x-y", Identities: []age.Identity{f.id}}); err == nil {
		t.Fatal("a point-in-time restore of volumes")
	}
}

// A restore is refused before anything changes when the copy has a volume
// the target lacks or one its disk cannot hold.
func TestCheckVolumesFit(t *testing.T) {
	t1 := svcRef{Service: "s3", Vols: []projects.OwnedVolume{{Name: "data", Limit: 1 << 30}}}
	man := archive.VolumeManifest{Volumes: []archive.VolumeStat{{Name: "data", Need: 512 << 20}}}
	if err := checkVolumesFit(t1, man); err != nil {
		t.Fatal(err)
	}
	var ie *i18n.Error
	man.Volumes[0].Need = 2 << 30
	if err := checkVolumesFit(t1, man); !errors.As(err, &ie) || ie.Key != "backup.error.volume_too_big" {
		t.Fatalf("too big: %v", err)
	}
	t1.Vols[0].Limit = 0 // no limit: the server's disk
	if err := checkVolumesFit(t1, man); err != nil {
		t.Fatal(err)
	}
	man.Volumes = append(man.Volumes, archive.VolumeStat{Name: "uploads"})
	if err := checkVolumesFit(t1, man); !errors.As(err, &ie) || ie.Key != "backup.error.volume_missing" {
		t.Fatalf("missing volume: %v", err)
	}
}

// The staging dir must hold the copy and leave room on the server.
func TestVolumeBackupChecksRoom(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	s.Vols[0].Used = 10 << 30
	old := freeSpace
	t.Cleanup(func() { freeSpace = old })
	freeSpace = func(string) (int64, bool) { return 5 << 30, true }
	var ie *i18n.Error
	if _, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, ""); !errors.As(err, &ie) || ie.Key != "backup.error.no_room" {
		t.Fatalf("no room: %v", err)
	}
	if ev := f.n.eventList(); len(ev) != 0 {
		t.Fatalf("nothing may start: %v", ev)
	}
}

// "Baixar backup" of a service with volumes is made first and fetched
// once: encrypted with the kit, the plain tar in the simple mode.
func TestVolumeDownload(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	take := func() map[string][]byte {
		t.Helper()
		if err := f.m.PrepareDownload(ctx, f.who, "lab", "files"); err != nil {
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
	base := ""
	for name := range files {
		if b, ok := strings.CutSuffix(name, archive.ExtVolumes); ok {
			base = b
		}
	}
	if len(files) != 2 || base == "" || !bytes.Contains(files[ReadmeName], []byte("hangar-cofre decrypt")) {
		t.Fatalf("kit bundle: %v", slices.Collect(mapsKeys(files)))
	}
	plain, err := archive.Open(bytes.NewReader(files[base+archive.ExtVolumes]), []age.Identity{f.id}, archive.VolumeLimits)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(plain); !bytes.Equal(got, f.n.volTar) {
		t.Fatal("the encrypted copy opens to something else")
	}
	if err := f.m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingMode, ValueJson: `"simple"`}); err != nil {
		t.Fatal(err)
	}
	files = take()
	var tarName string
	for name := range files {
		if strings.HasSuffix(name, archive.ExtVolumesTar) {
			tarName = name
		}
	}
	if tarName == "" || !bytes.Equal(files[tarName], f.n.volTar) || !bytes.Contains(files[ReadmeName], []byte("NÃO está cifrado")) && !bytes.Contains(files[ReadmeName], []byte("NOT encrypted")) {
		t.Fatalf("simple bundle: %v", slices.Collect(mapsKeys(files)))
	}
}

// later moves the clock on: two backups in the same second would share a
// key (in a bucket with versions, one hides the other).
func later(f *fixture) {
	f.m.now = func() time.Time { return time.Now().Add(5 * time.Second) }
}

func mapsKeys(m map[string][]byte) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// Backups of volumes take part in the backups page: the row, the stale
// alert, and the alert for a copy that lost half its files.
func TestVolumeAlerts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.volumeService(t)
	if err := f.m.SetServicePolicy(ctx, f.who, "lab", "files", PolicyInput{Enabled: true, EveryHours: 24, AtMinute: 180}); err != nil {
		t.Fatal(err)
	}
	f.m.now = func() time.Time { return time.Now().Add(50 * time.Hour) }
	o, _ := f.m.Overview(ctx)
	if len(o.Services) != 1 || o.Services[0].Kind != archive.KindVolume || !hasAlert(o.Alerts, AlertStale) {
		t.Fatalf("overview: %+v %+v", o.Services, o.Alerts)
	}
	prev := dbq.BackupRun{ID: "bkp_1", SizeBytes: 1 << 20, CheckJson: `{"files":5000}`}
	if w := volumeWarning(prev, 1<<20, 1000); w != "files_dropped" {
		t.Errorf("files dropped: %q", w)
	}
	if w := volumeWarning(prev, 100, 5000); w != "shrank" {
		t.Errorf("shrank: %q", w)
	}
	if w := volumeWarning(prev, 1<<20, 4900); w != "" {
		t.Errorf("normal: %q", w)
	}
}

// Disaster recovery brings a volume service back from its newest copy.
func TestRecoverVolumes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.volumeService(t)
	if _, err := f.m.backupVolume(ctx, f.who, s, TriggerManual, ""); err != nil {
		t.Fatal(err)
	}
	want := f.n.volTar
	f.n.volIn = nil
	if err := f.m.RecoverService(ctx, System, "lab", "files", time.Now().Add(time.Hour), []age.Identity{f.id}); err != nil {
		t.Fatal(err)
	}
	f.pm.Wait()
	if !bytes.Equal(f.n.volIn, want) {
		t.Fatal("the volume was not restored")
	}
	if err := f.m.RecoverService(ctx, System, "lab", "files", time.Now().Add(-24*time.Hour), []age.Identity{f.id}); !errors.Is(err, errNoVolumeBackup) {
		t.Fatalf("no copy before that moment: %v", err)
	}
	f.pm.Wait()
}
