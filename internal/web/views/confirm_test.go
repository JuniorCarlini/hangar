package views

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

// Every typed-name confirmation offers the name to copy, so it can be pasted
// instead of typed: deleting a service and overwriting it with a restore
// (deleting a project uses the same confirmName).
func TestTypedConfirmationsOfferTheNameToCopy(t *testing.T) {
	d := ServiceData{Project: "lab", Slug: "web", CSRF: "tok", CanAdmin: true, SudoActive: true, SudoCritical: true}
	for name, c := range map[string]templ.Component{
		"delete":  tabSettings(d),
		"restore": svcBackupRestore(d),
	} {
		var b strings.Builder
		if err := c.Render(context.Background(), &b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if html := b.String(); !strings.Contains(html, `data-copy="web"`) || !strings.Contains(html, `name="confirm"`) {
			t.Errorf("%s: the confirmation lacks the name to copy", name)
		}
	}
}
