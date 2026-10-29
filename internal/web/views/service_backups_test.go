package views

import (
	"context"
	"strings"
	"testing"
)

// The routine is one compact row (no sentence about how the copy is made,
// that is its tooltip), and its dialog opens with the page only when the
// "Create routine" link asks for it (?routine=1).
func TestRoutineRowAndDialog(t *testing.T) {
	d := ServiceData{Project: "lab", Slug: "files", CSRF: "tok", CanAdmin: true}
	d.Backups = ServiceBackups{Supported: true, Ready: true, Enabled: true, EveryHours: 24, AtTime: "03:00", NextRun: "29/10 03:00", Method: "volume_pause"}
	render := func() string {
		var b strings.Builder
		if err := svcBackupRoutines(d).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	html := render()
	if strings.Count(html, "Backup completo") != 1 || !strings.Contains(html, `title="Backup completo`) {
		t.Error("how the copy is made belongs in the routine's tooltip only")
	}
	if strings.Contains(html, `data-open="true"`) {
		t.Error("the routine dialog must not open by itself")
	}
	d.Backups.OpenRoutine = true
	if !strings.Contains(render(), `id="routine-modal" aria-labelledby="routine-modal-title" data-open="true"`) {
		t.Error("?routine=1 must open the routine dialog")
	}
}
