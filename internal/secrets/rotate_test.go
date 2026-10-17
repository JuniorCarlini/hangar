package secrets

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRotationCoversEveryAD fails when someone adds a new encrypted column
// (a new "…AD" helper building "table|id|column") without adding it to
// sealedColumns: the rotation would leave it under the old key, unreadable.
func TestRotationCoversEveryAD(t *testing.T) {
	helper := regexp.MustCompile(`func \w*AD\([^)]*\) string \{ return "([a-z_]+)\|`)
	covered := map[string]bool{}
	for _, c := range sealedColumns {
		covered[c.table] = true
	}
	found := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path) //nolint:gosec // walking the repository's own sources
		if err != nil {
			return err
		}
		for _, m := range helper.FindAllStringSubmatch(string(b), -1) {
			found++
			if !covered[m[1]] {
				t.Errorf("%s: table %q is encrypted with the master key but missing from sealedColumns", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 7 {
		t.Fatalf("found only %d AD helpers: did their shape change? update this test", found)
	}
}
