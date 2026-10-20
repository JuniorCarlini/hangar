package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/release"
)

// useTestKey swaps the embedded key for one generated in the test.
func useTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	old := release.PublicKeyHex
	release.PublicKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() { release.PublicKeyHex = old })
	return priv
}

type fakeRelease struct {
	version  string
	binary   []byte
	manifest []byte
	sig      string
}

func signedRelease(t *testing.T, priv ed25519.PrivateKey, version string, binary []byte) fakeRelease {
	t.Helper()
	h := sha256.Sum256(binary)
	m, _ := json.Marshal(release.Manifest{Version: version, Files: map[string]string{
		release.AssetName(runtime.GOARCH): hex.EncodeToString(h[:]),
	}})
	return fakeRelease{version: version, binary: binary, manifest: m, sig: release.Sign(m, priv)}
}

// fakeGitHub mimics the releases API.
func fakeGitHub(t *testing.T, rel *fakeRelease) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/JuniorCarlini/hangar/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		asset := func(name string) map[string]any {
			return map[string]any{"name": name, "url": srv.URL + "/assets/" + name}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": rel.version, "body": "novidades", "html_url": "https://github.com/x",
			"assets": []any{asset("release.json"), asset("release.json.sig"), asset(release.AssetName(runtime.GOARCH))},
		})
	})
	mux.HandleFunc("GET /assets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/octet-stream" {
			http.Error(w, "accept", http.StatusBadRequest)
			return
		}
		switch r.PathValue("name") {
		case "release.json":
			_, _ = w.Write(rel.manifest)
		case "release.json.sig":
			_, _ = w.Write([]byte(rel.sig))
		default:
			_, _ = w.Write(rel.binary)
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newChecker(t *testing.T, srv *httptest.Server, current string) (*Checker, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "update")
	return NewChecker(Config{Repo: "JuniorCarlini/hangar", APIBase: srv.URL, Dir: dir, Applier: true}, current), dir
}

func TestCheckFindsNewerVersion(t *testing.T) {
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", []byte("binario-novo"))
	srv := fakeGitHub(t, &rel)

	c, _ := newChecker(t, srv, "v1.0.0")
	av, err := c.Check(context.Background())
	if err != nil || av == nil || av.Version != "v1.1.0" {
		t.Fatalf("Check = %+v, %v", av, err)
	}

	same, _ := newChecker(t, srv, "v1.1.0")
	if av, err := same.Check(context.Background()); err != nil || av != nil {
		t.Fatalf("already up to date: Check = %+v, %v", av, err)
	}
}

func TestStageVerifiesEverything(t *testing.T) {
	priv := useTestKey(t)
	good := signedRelease(t, priv, "v1.1.0", []byte("binario-novo"))

	t.Run("valid", func(t *testing.T) {
		rel := good
		c, dir := newChecker(t, fakeGitHub(t, &rel), "v1.0.0")
		if err := c.Stage(context.Background(), "v1.1.0", "usr_1"); err != nil {
			t.Fatal(err)
		}
		if !Pending(dir) {
			t.Error("request was not written")
		}
	})

	cases := []struct {
		name   string
		mutate func(*fakeRelease)
	}{
		{"signature from another key", func(r *fakeRelease) {
			_, other, _ := ed25519.GenerateKey(nil)
			r.sig = release.Sign(r.manifest, other)
		}},
		{"binary swapped on the server", func(r *fakeRelease) { r.binary = []byte("binario-malicioso") }},
		{"manifest of another version", func(r *fakeRelease) {
			other := signedRelease(t, priv, "v1.0.5", good.binary)
			r.manifest, r.sig = other.manifest, other.sig
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel := good
			tc.mutate(&rel)
			c, dir := newChecker(t, fakeGitHub(t, &rel), "v1.0.0")
			if err := c.Stage(context.Background(), "v1.1.0", "usr_1"); err == nil {
				t.Fatal("tampered release was accepted")
			}
			if Pending(dir) {
				t.Error("request written for a tampered release")
			}
		})
	}

	t.Run("downgrade", func(t *testing.T) {
		rel := good
		c, _ := newChecker(t, fakeGitHub(t, &rel), "v2.0.0")
		if err := c.Stage(context.Background(), "v1.1.0", "usr_1"); !errors.Is(err, release.ErrNotNewer) {
			t.Fatalf("downgrade: %v", err)
		}
	})
}

// fakeService mimics systemd: Start "runs" the installed binary. If it is
// the new, good binary, it migrates the database and writes the ready file.
type fakeService struct {
	a       *Applier
	running bool
	starts  int
	healthy map[string]string // binary content -> version it announces
}

func (f *fakeService) Stop(context.Context) error { f.running = false; return nil }

func (f *fakeService) Start(context.Context) error {
	f.running = true
	f.starts++
	bin, _ := os.ReadFile(f.a.BinaryPath)
	version, ok := f.healthy[string(bin)]
	// Every version that starts touches the database (migration).
	_ = os.WriteFile(filepath.Join(f.a.DataDir, "hangar.db"), []byte("banco migrado por "+string(bin)), 0o600)
	if ok {
		_ = os.MkdirAll(filepath.Join(f.a.DataDir, "run"), 0o750)
		_ = os.WriteFile(filepath.Join(f.a.DataDir, ReadyFile), []byte(version+"\n"), 0o600)
	}
	return nil
}

func stagedApplier(t *testing.T, newBinary []byte) (*Applier, *fakeService) {
	t.Helper()
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", newBinary)
	srv := fakeGitHub(t, &rel)

	data := t.TempDir()
	c := NewChecker(Config{Repo: "JuniorCarlini/hangar", APIBase: srv.URL, Dir: filepath.Join(data, "update"), Applier: true}, "v1.0.0")
	if err := c.Stage(context.Background(), "v1.1.0", "usr_1"); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	a := &Applier{
		DataDir: data, BinaryPath: filepath.Join(binDir, "hangard"), ReadyWait: 2 * time.Second,
		CurrentVersion: func(context.Context, string) (string, error) { return "v1.0.0", nil },
		InstallUnits:   func(context.Context, string) error { return nil },
		Preflight:      func(context.Context, string) error { return nil },
		FreeSpace:      func(string) (uint64, error) { return 1 << 40, nil },
	}
	if err := os.WriteFile(a.BinaryPath, []byte("binario-antigo"), 0o755); err != nil { //nolint:gosec // teste
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "hangar.db"), []byte("banco original"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := &fakeService{a: a, running: true, healthy: map[string]string{"binario-antigo": "v1.0.0"}}
	a.Service = svc
	return a, svc
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplySuccess(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	svc.healthy["binario-novo"] = "v1.1.0"

	st, err := a.Apply(context.Background())
	if err != nil || st.State != "ok" {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if got := read(t, a.BinaryPath); got != "binario-novo" {
		t.Errorf("installed binary: %q", got)
	}
	if got := read(t, filepath.Join(a.DataDir, "releases", "hangard-v1.0.0")); got != "binario-antigo" {
		t.Errorf("old binary was not kept: %q", got)
	}
	if Pending(filepath.Join(a.DataDir, "update")) {
		t.Error("request stayed pending")
	}
	if s, _ := ReadStatus(filepath.Join(a.DataDir, "update")); s == nil || s.State != "ok" || s.From != "v1.0.0" {
		t.Errorf("stored status: %+v", s)
	}

	// Without a new request, running again does nothing.
	if st, err := a.Apply(context.Background()); st != nil || err != nil {
		t.Errorf("second run without a request: %+v, %v", st, err)
	}
}

func TestApplyRollsBackWhenNewVersionDoesNotStart(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-quebrado")) // never writes the ready file

	st, err := a.Apply(context.Background())
	if err == nil || st.State != "rolled_back" {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if got := read(t, a.BinaryPath); got != "binario-antigo" {
		t.Errorf("binary was not restored: %q", got)
	}
	// The broken version migrated the database on start; the rollback restores
	// the earlier copy, and the old binary starts again on top of it.
	if got := read(t, filepath.Join(a.DataDir, "hangar.db")); got != "banco migrado por binario-antigo" {
		t.Errorf("database after rollback: %q", got)
	}
	if !svc.running || svc.starts != 2 {
		t.Errorf("service should be running the old version (running=%v, starts=%d)", svc.running, svc.starts)
	}
}

func TestApplyRefusesTamperedStaging(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	svc.healthy["binario-novo"] = "v1.1.0"

	// Someone with access to the hangar user swaps the already verified binary.
	staged := filepath.Join(a.DataDir, "update", stagingDir, "v1.1.0", release.AssetName(runtime.GOARCH))
	if err := os.WriteFile(staged, []byte("binario-malicioso"), 0o640); err != nil { //nolint:gosec // teste
		t.Fatal(err)
	}

	st, err := a.Apply(context.Background())
	if err == nil || st.State != "failed" {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if got := read(t, a.BinaryPath); got != "binario-antigo" {
		t.Errorf("binary was swapped even though tampered: %q", got)
	}
	if svc.starts != 0 || !svc.running {
		t.Error("the panel should not even have been stopped")
	}
}

func TestApplyRefusesDowngradeRequest(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	a.CurrentVersion = func(context.Context, string) (string, error) { return "v1.2.0", nil }

	st, err := a.Apply(context.Background())
	if err == nil || st.State != "failed" || svc.starts != 0 {
		t.Fatalf("downgrade applied: %+v, %v", st, err)
	}
}

// crashingService mimics systemd restarting a version that crashes.
type crashingService struct {
	fakeService
	restarts int
}

func (c *crashingService) Restarts(context.Context) (int, error) {
	c.restarts++ // every query "sees" one more restart
	return c.restarts, nil
}

func TestApplyDetectsCrashLoopFast(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-quebrado"))
	a.ReadyWait = time.Hour // if it relied on the deadline, the test would hang
	crash := &crashingService{fakeService: *svc}
	crash.a = a
	a.Service = crash

	start := time.Now()
	st, err := a.Apply(context.Background())
	if err == nil || st.State != "rolled_back" {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("took %s to notice the crash loop", time.Since(start))
	}
	if got := read(t, a.BinaryPath); got != "binario-antigo" {
		t.Errorf("binary was not restored: %q", got)
	}
}

// TestPreflightFailureKeepsThePanelUp: a new version that cannot read its
// config or master key (preflight) never stops the running panel.
func TestPreflightFailureKeepsThePanelUp(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	a.Preflight = func(context.Context, string) error { return errors.New("permission denied") }
	st, err := a.Apply(context.Background())
	if err == nil || st == nil || st.State != "failed" || !strings.Contains(st.Message, "preflight") {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if !svc.running {
		t.Fatal("the panel was stopped")
	}
	if got := read(t, a.BinaryPath); got != "binario-antigo" {
		t.Fatalf("binary = %q, the old one must stay", got)
	}
}

// TestRollbackReportsFailedWhenOldVersionDoesNotComeBack: "rolled_back" means
// the previous version is serving again; if it does not come up either, the
// state is "failed".
func TestRollbackReportsFailedWhenOldVersionDoesNotComeBack(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-quebrado"))
	delete(svc.healthy, "binario-antigo") // the old version no longer starts either

	st, err := a.Apply(context.Background())
	if err == nil || st.State != "failed" || !strings.Contains(st.Message, "previous version did not come back") {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if got := read(t, a.BinaryPath); got != "binario-antigo" {
		t.Errorf("binary was not restored: %q", got)
	}
}

// TestNotEnoughDiskKeepsThePanelUp: without room for the copies the update
// makes, nothing stops.
func TestNotEnoughDiskKeepsThePanelUp(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	svc.healthy["binario-novo"] = "v1.1.0"
	var asked []string
	a.FreeSpace = func(path string) (uint64, error) {
		asked = append(asked, path)
		return 10, nil // "banco original" alone is 14 bytes
	}
	st, err := a.Apply(context.Background())
	if err == nil || st == nil || st.State != "failed" || !strings.Contains(st.Message, "preflight: not enough disk") {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if !svc.running || svc.starts != 0 {
		t.Fatal("the panel was stopped")
	}
	if got := read(t, a.BinaryPath); got != "binario-antigo" {
		t.Fatalf("binary = %q, the old one must stay", got)
	}
	if len(asked) == 0 || asked[0] != a.DataDir {
		t.Errorf("free space asked for %v, want the data dir first", asked)
	}
}

func TestCheckDiskNeedsTwiceTheDatabasePlusBinary(t *testing.T) {
	a, _ := stagedApplier(t, []byte("binario-novo"))
	// DataDir needs 2*14 (database) + 14 (largest binary) = 42 bytes;
	// the binary directory needs 14.
	newBin := filepath.Join(t.TempDir(), "novo")
	if err := os.WriteFile(newBin, []byte("binario-novo"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Dir(a.BinaryPath)
	free := map[string]uint64{a.DataDir: 42, binDir: 14}
	a.FreeSpace = func(p string) (uint64, error) { return free[p], nil }
	if err := a.checkDisk(newBin); err != nil {
		t.Fatalf("exactly enough: %v", err)
	}
	free[a.DataDir] = 41
	if err := a.checkDisk(newBin); err == nil {
		t.Fatal("one byte short in the data dir was accepted")
	}
	free[a.DataDir], free[binDir] = 42, 13
	if err := a.checkDisk(newBin); err == nil {
		t.Fatal("one byte short next to the binary was accepted")
	}
}

// TestApplyPrunesOldPreUpdateBackups: each update leaves a database copy;
// only the newest ones stay.
func TestApplyPrunesOldPreUpdateBackups(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	svc.healthy["binario-novo"] = "v1.1.0"
	backups := filepath.Join(a.DataDir, "backups")
	old := time.Now().Add(-48 * time.Hour)
	for i, name := range []string{"pre-update-v0.9.0-a", "pre-update-v0.9.1-b", "pre-update-v0.9.2-c", "pre-update-v0.9.3-d"} {
		dir := filepath.Join(backups, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		mod := old.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(dir, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(backups, "outra-coisa"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if st, err := a.Apply(context.Background()); err != nil || st.State != "ok" {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	entries, _ := os.ReadDir(backups)
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	// The copy this update made plus the two newest older ones; anything
	// that is not a pre-update copy is left alone.
	if len(got) != 4 || got[0] != "outra-coisa" || got[1] != "pre-update-v0.9.2-c" || got[2] != "pre-update-v0.9.3-d" || !strings.HasPrefix(got[3], "pre-update-v1.0.0-") {
		t.Fatalf("backups left: %v", got)
	}
}

// TestRestoreFileReplacesThroughRename: the restored file has the backup's
// content and mode, and no temporary file is left behind.
func TestRestoreFileReplacesThroughRename(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "copia"), filepath.Join(dir, "hangar.db")
	if err := os.WriteFile(src, []byte("copia boa"), 0o640); err != nil { //nolint:gosec // teste
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("banco migrado"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreFile(src, dst); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dst); got != "copia boa" {
		t.Errorf("restored content: %q", got)
	}
	if info, _ := os.Stat(dst); info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("temporary file left behind: %v", entries)
	}

	// A copy that cannot be read leaves the current file whole.
	if err := restoreFile(filepath.Join(dir, "nao-existe"), dst); err == nil {
		t.Fatal("restore from a missing copy succeeded")
	}
	if got := read(t, dst); got != "copia boa" {
		t.Errorf("file touched by a failed restore: %q", got)
	}
}

func TestStageNeedsTheApplier(t *testing.T) {
	c := NewChecker(Config{Repo: "JuniorCarlini/hangar", APIBase: "http://127.0.0.1:9", Dir: t.TempDir()}, "v1.0.0")
	if c.CanApply() {
		t.Fatal("no applier configured, CanApply should be false")
	}
	if err := c.Stage(context.Background(), "v1.0.1", "usr"); err == nil {
		t.Fatal("Stage without an applier should refuse: the request would wait forever")
	}
}

func TestApplierWatches(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "hangar-updater.path")
	if ApplierWatches(unit, "/var/lib/hangar/update") {
		t.Error("missing unit: no applier")
	}
	if err := os.WriteFile(unit, []byte("[Path]\nPathExists=/var/lib/hangar/update/request.json\nUnit=hangar-updater.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ApplierWatches(unit, "/var/lib/hangar/update") {
		t.Error("the unit watches this directory")
	}
	if ApplierWatches(unit, "/home/dev/hangar/.data/update") {
		t.Error("the unit watches another directory: no applier for this one")
	}
}
