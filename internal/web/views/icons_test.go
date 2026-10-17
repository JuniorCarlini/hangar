package views

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Every icon a template asks for must be embedded: a missing one would
// render as an empty square without any error.
func TestIconsExist(t *testing.T) {
	use := regexp.MustCompile(`Icon\("([a-z0-9-]+)"`)
	files, _ := filepath.Glob("*.templ")
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		for _, m := range use.FindAllStringSubmatch(string(raw), -1) {
			if iconBody(m[1]) == "" {
				t.Errorf("%s: icon %q is not in views/icons", f, m[1])
			}
		}
	}
	for _, name := range []string{ThemeIcon("system"), ThemeIcon("dark"), ThemeIcon("light")} {
		if iconBody(name) == "" {
			t.Errorf("theme icon %q missing", name)
		}
	}
	// The palette's icons are rendered in a loop, out of the regexp's sight.
	for _, name := range PaletteIcons {
		if iconBody(name) == "" {
			t.Errorf("palette icon %q missing", name)
		}
	}
}
