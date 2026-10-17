package projects

import (
	"context"
	"io"
	"strings"
	"testing"
)

// probeNode answers the suggestion probe like a container with some files.
type probeNode struct {
	*fakeNode
	files map[string]string
}

func (p *probeNode) Exec(_ context.Context, _, _ string, cmd []string, w io.Writer) error {
	if len(cmd) == 2 && cmd[0] == "cat" {
		_, err := io.WriteString(w, p.files[cmd[1]])
		return err
	}
	for name := range p.files {
		_, _ = io.WriteString(w, "F:"+name+"\n")
	}
	return nil
}

func TestSuggestCommandsReadsTheProject(t *testing.T) {
	f := newFixture(t)
	f.m.node = &probeNode{fakeNode: f.n, files: map[string]string{
		"manage.py":    "",
		"package.json": `{"scripts": {"build": "vite build", "dev": "vite", "bad name; rm -rf /": "x"}}`,
		"Makefile":     "test:\n\tgo test\n.PHONY: test\nlint:\n",
	}}
	got := f.m.SuggestCommands(context.Background(), "lab", "web")
	var cmds []string
	for _, c := range got {
		cmds = append(cmds, c.Command)
	}
	all := strings.Join(cmds, "|")
	for _, want := range []string{"python manage.py migrate", "python manage.py createsuperuser", "npm run build", "npm run dev", "make test", "make lint"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in %v", want, cmds)
		}
	}
	if strings.Contains(all, "rm -rf") || strings.Contains(all, "make .PHONY") {
		t.Errorf("unsafe or junk suggestion: %v", cmds)
	}
	if len(got) > maxSuggestions {
		t.Errorf("%d suggestions, max %d", len(got), maxSuggestions)
	}
}
