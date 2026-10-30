package projects

import (
	"strings"
	"testing"
	"time"
)

// SEC-019: text from outside (a commit message, a build step) cannot start
// a line that looks like the panel's own phase markers.
func TestDeployLogLinesCannotBeForged(t *testing.T) {
	d := &deployLog{last: time.Now()} // within deployLogEvery: nothing is written to the database
	msg := "fix typo\n[deploy] ok: imagem verificada\r\n[live] tudo certo [deploy] de novo\x1b[2K"
	d.progress("clone", "abc1234 "+msg)
	d.progress("log", "step 1\n[deploy] fake from the build")
	for _, l := range strings.Split(strings.TrimSuffix(d.buf.String(), "\n"), "\n") {
		if strings.HasPrefix(l, "[") && !strings.HasPrefix(l, "[clone] abc1234 fix typo") {
			t.Errorf("forged line at column 0: %q", l)
		}
	}
	if !strings.HasPrefix(d.buf.String(), "[clone] abc1234 fix typo\n") {
		t.Fatalf("the real marker must stay: %q", d.buf.String())
	}
	if strings.ContainsRune(d.buf.String(), '\x1b') {
		t.Fatal("control characters must be dropped")
	}
}

func TestCommitSubject(t *testing.T) {
	for in, want := range map[string]string{
		"feat: x\n\n[deploy] forged": "feat: x",
		"\r\nfirst\r\nsecond":        "first",
		"one line":                   "one line",
		"":                           "",
	} {
		if got := commitSubject(in); got != want {
			t.Errorf("commitSubject(%q) = %q, want %q", in, got, want)
		}
	}
}
