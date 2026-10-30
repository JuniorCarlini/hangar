package update

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// The applier runs as root inside directories the hangar user owns: a
// symlink planted there must never point root's copy or write elsewhere.
func TestRootCopiesDoNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	root := openTestRoot(t, dir)
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("intact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A link where the copy lands is replaced, not written through.
	dst := filepath.Join(dir, "dst")
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}
	if err := copyPreserving(root, "src", "dst"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "intact" {
		t.Errorf("the copy wrote through the link: %q", b)
	}
	if fi, _ := os.Lstat(dst); fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the link is still there")
	}

	// A link as the source is refused, even one that stays inside the root.
	if err := os.Symlink("victim", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := copyPreserving(root, "link", "out"); err == nil {
		t.Error("a symlinked source was copied")
	}

	// The status write too.
	status := filepath.Join(dir, "status.json")
	if err := os.Symlink(victim, status); err != nil {
		t.Fatal(err)
	}
	if err := writeIn(root, "status.json", bytes.NewReader([]byte("{}")), 0o644, -1, -1); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "intact" {
		t.Errorf("the status write went through the link: %q", b)
	}
	if err := writeFileAtomic(status, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "intact" {
		t.Errorf("the checker's status write went through the link: %q", b)
	}
}

// outside builds a directory next to the data dir with files root must
// never touch, and returns it with a check that they are all still there.
func outside(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	names := []string{"hangard-v0.0.1", "hangard-v0.0.2", "hangard-v0.0.3", "hangard-v0.0.4", "hangard-v0.0.5", "passwd", "pre-update-a", "pre-update-b", "pre-update-c", "pre-update-d"}
	old := time.Now().Add(-48 * time.Hour)
	for i, n := range names {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("host file"), 0o600); err != nil {
			t.Fatal(err)
		}
		mod := old.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	return dir, func() {
		t.Helper()
		for _, n := range names {
			if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
				t.Errorf("%s outside the data dir was touched: %v", n, err)
			}
		}
	}
}

// SEC-011: the hangar user swaps releases/ or backups/ for a link to a host
// directory; pruning as root must not delete anything there.
func TestPruneDoesNotFollowSymlinkedDirs(t *testing.T) {
	data := t.TempDir()
	host, intact := outside(t)
	for _, d := range []string{releasesRel, backupsRel} {
		if err := os.Symlink(host, filepath.Join(data, d)); err != nil {
			t.Fatal(err)
		}
	}
	root := openTestRoot(t, data)
	pruneReleases(root, releasesRel, 1)
	pruneOldest(root, backupsRel, "pre-update-", 1)
	intact()

	// The same link pointing inside the data dir is refused too.
	inner := filepath.Join(data, "inner")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"hangard-v1", "hangard-v2"} {
		if err := os.WriteFile(filepath.Join(inner, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Remove(filepath.Join(data, releasesRel))
	if err := os.Symlink("inner", filepath.Join(data, releasesRel)); err != nil {
		t.Fatal(err)
	}
	pruneReleases(root, releasesRel, 0)
	if entries, _ := os.ReadDir(inner); len(entries) != 2 {
		t.Errorf("pruning followed a link inside the data dir: %v", entries)
	}
}

// SEC-011: entries inside releases/ that are links (or not kept binaries)
// are never deleted, and a link entry never makes root delete its target.
func TestPruneReleasesOnlyDeletesKeptBinaries(t *testing.T) {
	data := t.TempDir()
	host, intact := outside(t)
	releases := filepath.Join(data, releasesRel)
	if err := os.MkdirAll(releases, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	for i, n := range []string{"hangard-v0.1.0", "hangard-v0.2.0", "hangard-v0.3.0", "hangard-v0.4.0", "notes.txt"} {
		p := filepath.Join(releases, n)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		mod := old.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	// Links named like kept binaries, pointing outside.
	for _, n := range []string{"hangard-v0.0.1", "hangard-v0.0.2"} {
		if err := os.Symlink(filepath.Join(host, n), filepath.Join(releases, n)); err != nil {
			t.Fatal(err)
		}
	}
	pruneReleases(openTestRoot(t, data), releasesRel, 2)
	intact()
	entries, _ := os.ReadDir(releases)
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	want := "hangard-v0.0.1 hangard-v0.0.2 hangard-v0.3.0 hangard-v0.4.0 notes.txt"
	if strings.Join(got, " ") != want {
		t.Errorf("releases left: %v, want %s", got, want)
	}
}

// SEC-011: mkdirAllNoFollow refuses a component that is a link, so the
// database copy and the kept binary never land outside the data dir.
func TestMkdirAllRefusesSymlinkedComponent(t *testing.T) {
	data := t.TempDir()
	host := t.TempDir()
	if err := os.Symlink(host, filepath.Join(data, backupsRel)); err != nil {
		t.Fatal(err)
	}
	root := openTestRoot(t, data)
	if err := mkdirAllNoFollow(root, backupsRel+"/pre-update-x", 0o700); err == nil {
		t.Fatal("a symlinked backups/ was accepted")
	}
	if entries, _ := os.ReadDir(host); len(entries) != 0 {
		t.Errorf("something was created through the link: %v", entries)
	}
	if err := mkdirAllNoFollow(root, "a/b/c", 0o700); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(data, "a", "b", "c")); err != nil || !fi.IsDir() {
		t.Fatalf("plain directories were not created: %v", err)
	}
}

// SEC-011, end to end: with releases/ and backups/ swapped for links to a
// host directory, an update fails (and rolls back) without touching it.
func TestApplyRefusesSymlinkedDataDirs(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	svc.healthy["binario-novo"] = "v1.1.0"
	host, intact := outside(t)
	for _, d := range []string{releasesRel, backupsRel} {
		_ = os.RemoveAll(filepath.Join(a.DataDir, d))
		if err := os.Symlink(host, filepath.Join(a.DataDir, d)); err != nil {
			t.Fatal(err)
		}
	}
	st, err := a.Apply(context.Background())
	if err == nil || st == nil || st.State == "ok" {
		t.Fatalf("Apply through symlinked dirs = %+v, %v", st, err)
	}
	intact()
	if entries, _ := os.ReadDir(host); len(entries) != 10 {
		t.Errorf("files were added to the host directory: %v", entries)
	}
	if got := read(t, a.BinaryPath); got != "binario-antigo" {
		t.Errorf("binary after the refused update: %q", got)
	}
}

// SEC-011: a staged file swapped for a link to a host file is refused, not
// read as root.
func TestApplyRefusesSymlinkedStagingFile(t *testing.T) {
	a, svc := stagedApplier(t, []byte("binario-novo"))
	svc.healthy["binario-novo"] = "v1.1.0"
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("root only"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(a.DataDir, updateRel, stagingDir, "v1.1.0", "release.json")
	_ = os.Remove(manifest)
	if err := os.Symlink(secret, manifest); err != nil {
		t.Fatal(err)
	}
	st, err := a.Apply(context.Background())
	if err == nil || st == nil || st.State != "failed" {
		t.Fatalf("Apply = %+v, %v", st, err)
	}
	if svc.starts != 0 || !svc.running {
		t.Error("the panel should not even have been stopped")
	}
}
