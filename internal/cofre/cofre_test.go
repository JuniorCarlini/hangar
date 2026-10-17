package cofre

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
)

func sealed(t *testing.T, id *age.X25519Identity, data []byte, compress bool) []byte {
	t.Helper()
	rs, _ := archive.ParseRecipients([]string{id.Recipient().String()})
	var buf bytes.Buffer
	w, err := archive.Seal(&buf, rs, compress)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// writeDir lays out a synced folder: key -> content (+ metadata sidecar).
func writeDir(t *testing.T, files map[string][]byte, meta map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for k, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(k))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if meta != nil {
			_ = os.WriteFile(p+metaSuffix, []byte(`{"hangar-image":"postgres:18-alpine","hangar-db-user":"app","hangar-db-name":"loja"}`), 0o600)
		}
	}
	return dir
}

func TestParseServiceAndNames(t *testing.T) {
	for in, want := range map[string]string{"loja/db": "loja db", "loja_db": "loja db"} {
		p, s, err := ParseService(in)
		if err != nil || p+" "+s != want {
			t.Errorf("%s: %s %s %v", in, p, s, err)
		}
	}
	if _, _, err := ParseService("loja"); err == nil {
		t.Error("a service without project must fail")
	}
	if DecryptedName("x.tar.zst.age") != "x.tar" || DecryptedName("x.dump.age") != "x.dump" || DecryptedName("x") != "x.decifrado" {
		t.Error("DecryptedName")
	}
}

func TestDirSourceAndDecrypt(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	now := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	key := archive.DumpKey(archive.ClassDaily, "loja", "db", now)
	dir := writeDir(t, map[string][]byte{key: sealed(t, id, []byte("PGDMP dados"), false)}, map[string]string{})
	src := Dir{Root: dir}
	objs, err := src.List(context.Background(), "diario/")
	if err != nil || len(objs) != 1 || objs[0].Key != key {
		t.Fatalf("list: %+v %v", objs, err)
	}
	rc, meta, err := src.Open(context.Background(), key)
	if err != nil || meta["hangar-db-name"] != "loja" {
		t.Fatalf("open: %v %v", meta, err)
	}
	_ = rc.Close()
	if _, _, err := src.Open(context.Background(), "../../etc/passwd"); err == nil {
		t.Fatal("a path outside the folder must be refused")
	}
	v := New(src, []age.Identity{id})
	out := filepath.Join(t.TempDir(), "x.dump")
	if _, err := v.DecryptFile(filepath.Join(dir, filepath.FromSlash(key)), out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "PGDMP dados" {
		t.Fatalf("decrypted %q", b)
	}
	if _, err := v.DecryptFile(filepath.Join(dir, filepath.FromSlash(key)), out); err == nil {
		t.Fatal("decrypt must not overwrite")
	}
	entries, _ := v.List(context.Background())
	if len(entries) != 1 || entries[0].Label != "loja/db" || entries[0].Dumps != 1 {
		t.Fatalf("entries: %+v", entries)
	}
}

// fakeDocker answers the drill's docker calls and records them.
type fakeDocker struct {
	mu    sync.Mutex
	calls []string
	in    []byte
}

func (f *fakeDocker) run(_ context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	if stdin != nil {
		f.in, _ = io.ReadAll(stdin)
	}
	if stdout != nil && args[0] == "exec" {
		last := args[len(args)-1]
		switch {
		case last == "select 1":
			_, _ = io.WriteString(stdout, "1\n")
		case strings.Contains(last, "pg_stat_user_tables"):
			_, _ = io.WriteString(stdout, "4|1234\n")
		}
	}
	return nil
}

func TestDrillRestoresDumpsAndChecksPanel(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	now := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	var panel bytes.Buffer
	tw := tar.NewWriter(&panel)
	for name, body := range map[string]string{"manifest.json": "{}", "hangar.db": "SQLite format 3\x00...", "master.key": strings.Repeat("k", 32)} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	dir := writeDir(t, map[string][]byte{
		archive.DumpKey(archive.ClassDaily, "loja", "db", now.Add(-24*time.Hour)): sealed(t, id, []byte("velho"), false),
		archive.DumpKey(archive.ClassDaily, "loja", "db", now):                    sealed(t, id, []byte("PGDMP novo"), false),
		archive.PanelKey(now): sealed(t, id, panel.Bytes(), true),
	}, map[string]string{})
	fd := &fakeDocker{}
	v := New(Dir{Root: dir}, []age.Identity{id})
	v.Docker = fd.run
	res, err := v.Test(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res[0].OK || res[0].Tables != 4 || res[0].Rows != 1234 || !res[1].OK || res[1].Label != "painel" {
		t.Fatalf("results: %+v", res)
	}
	if string(fd.in) != "PGDMP novo" {
		t.Fatalf("the newest dump must be restored, got %q", fd.in)
	}
	all := strings.Join(fd.calls, "\n")
	if !strings.Contains(all, "rm -f -v hangar-cofre-test-") || !strings.Contains(all, "--network none") {
		t.Fatalf("the throwaway database must be isolated and removed:\n%s", all)
	}
	// A kit that does not open the backups fails the drill.
	other, _ := age.GenerateX25519Identity()
	v.SetIdentities([]age.Identity{other})
	res, _ = v.Test(context.Background(), "")
	for _, r := range res {
		if r.OK {
			t.Fatalf("a wrong kit must fail: %+v", r)
		}
	}
}
