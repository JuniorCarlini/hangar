package views

import (
	"context"
	"strings"
	"testing"
)

// The .env modal is a big code editor: the textarea never wraps (so the
// line numbers stay beside their lines), the colored layer and the gutter
// are hidden from screen readers, and the text, secrets included, is the
// textarea's escaped content only.
func TestEnvEditorModal(t *testing.T) {
	d := ServiceData{
		Project: "lab", Slug: "web", CSRF: "tok", CanOperate: true,
		EnvText: "# db\nDB_HOST=${{db.HOST}}\nX=</textarea><b>\n",
	}
	var b strings.Builder
	if err := tabVariables(d).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{
		`class="tuc-modal is-full env-modal" id="env-bulk"`,
		`data-env-editor`, `class="env-editor__gutter" aria-hidden="true"`,
		`class="env-editor__hl" aria-hidden="true"`,
		`id="bulk-env" name="env" wrap="off"`,
		`X=&lt;/textarea&gt;&lt;b&gt;`,
		`data-env-status`, `data-pos="`, `data-invalid-other="`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("modal lacks %q", want)
		}
	}
	if strings.Contains(html, "<b>") {
		t.Error("the editor's text is not escaped")
	}
}
