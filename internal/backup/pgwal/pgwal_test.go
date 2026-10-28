package pgwal

import (
	"strings"
	"testing"
)

// A mount path is free text in the panel: with a ";" or a space it must stay
// one word in the shell, and an ordinary path must not change (that would
// mark every archiving database as needing a redeploy).
func TestQuoteKeepsPathsOneWord(t *testing.T) {
	for in, want := range map[string]string{
		"/var/lib/postgresql/data": "/var/lib/postgresql/data",
		"/dados; rm -rf /":         `'/dados; rm -rf /'`,
		"/it's":                    `'/it'\''s'`,
		"/$(id)":                   `'/$(id)'`,
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
	got := strings.Join(Args("/var/lib/postgresql/data"), " ")
	if strings.Contains(got, "'") {
		t.Errorf("an ordinary path changed the command: %s", got)
	}
}
