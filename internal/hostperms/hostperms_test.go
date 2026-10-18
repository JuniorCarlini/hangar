package hostperms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// me resolves every name to the test's own user, so Fix can run unprivileged.
func me(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }

func TestFixRestoresModesAndRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "etc")
	data := filepath.Join(dir, "data")
	for _, d := range []string{cfgDir, data} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(cfgDir, "hangar.toml")
	key := filepath.Join(cfgDir, "master.key")
	if err := os.WriteFile(cfg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}

	changed, err := Fix(Plan(cfg, cfgDir, key, filepath.Join(cfgDir, "github-token"), data), me)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{cfgDir: 0o750, cfg: 0o640, key: 0o400, data: 0o700} {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != want {
			t.Errorf("%s = %o, want %o", path, st.Mode().Perm(), want)
		}
	}
	if len(changed) != 4 {
		t.Errorf("changed = %v", changed)
	}
	if again, _ := Fix(Plan(cfg, cfgDir, key, "", data), me); len(again) != 0 {
		t.Errorf("a second run changed %v", again)
	}

	// A symlink in place of the config is left alone, and said.
	link := filepath.Join(dir, "link.toml")
	if err := os.Symlink("/etc/passwd", link); err != nil {
		t.Fatal(err)
	}
	if _, err := Fix([]Want{{Path: link, Mode: 0o640}}, me); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlink: %v", err)
	}
	if _, err := Fix([]Want{{Path: filepath.Join(dir, "nope"), Mode: 0o640}}, me); err == nil {
		t.Error("a missing required file was not reported")
	}
	if _, err := Fix([]Want{{Path: cfgDir, Mode: 0o640}}, me); err == nil {
		t.Error("a directory where a file belongs was not reported")
	}
}
