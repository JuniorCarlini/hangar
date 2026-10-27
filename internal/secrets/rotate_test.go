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
//
// It compares the whole shape of the associated data, not only the table:
// two columns of one table (or a column whose AD borrows another table's
// prefix, like the .env text under "services|…|env_file") are different
// secrets, and checking the prefix alone once let one slip through.
func TestRotationCoversEveryAD(t *testing.T) {
	helper := regexp.MustCompile(`func \w*AD\([^)]*\) string \{ return "([a-z_]+)\|[^}]*?(?:"\|([a-z_]+)")? \}`)
	covered := map[string]bool{}
	for _, c := range sealedColumns {
		covered[adShape(c.ad([]string{"\x00", "\x01"}))] = true
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
			shape := m[1] + "|" + m[2]
			if m[2] == "" {
				// The column comes from an argument (gitAD(id, field)): every
				// column must be listed one by one, so ask for at least one.
				shape = m[1] + "|*"
				for c := range covered {
					if strings.HasPrefix(c, m[1]+"|") {
						shape = c
					}
				}
			}
			if !covered[shape] {
				t.Errorf("%s: %q is encrypted with the master key but missing from sealedColumns", path, shape)
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

// adShape reduces an associated data to "table|column", with "*" when the
// last part comes from a key (env_vars|<service>|<KEY>).
func adShape(ad string) string {
	parts := strings.Split(ad, "|")
	last := parts[len(parts)-1]
	if strings.ContainsAny(last, "\x00\x01") {
		last = "*"
	}
	return parts[0] + "|" + last
}
