package update

import (
	"os"
	"path/filepath"
	"testing"
)

// The applier runs as root inside directories the hangar user owns: a
// symlink planted there must never point root's copy or write elsewhere.
func TestRootCopiesDoNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("intact"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A link where the copy lands is replaced, not written through.
	dst := filepath.Join(dir, "dst")
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}
	if err := copyPreserving(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "intact" {
		t.Errorf("the copy wrote through the link: %q", b)
	}
	if fi, _ := os.Lstat(dst); fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the link is still there")
	}

	// A link as the source is refused (root would copy any file out).
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(link, filepath.Join(dir, "out"), 0o600); err == nil {
		t.Error("a symlinked source was copied")
	}

	// The status write too.
	status := filepath.Join(dir, "status.json")
	if err := os.Symlink(victim, status); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(status, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "intact" {
		t.Errorf("the status write went through the link: %q", b)
	}
}
