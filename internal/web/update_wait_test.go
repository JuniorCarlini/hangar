package web

import (
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/update"
)

// After a click the page waits for the new version even in the moment the
// applier has taken the request but not yet written "applying"; it stops
// on a result written after the click, once running the new version, or
// after a while.
func TestUpdatePageWaitsThroughTheGap(t *testing.T) {
	at := time.Date(2026, 10, 26, 18, 0, 0, 0, time.UTC)
	ask := &updateAsk{version: "v0.5.19", at: at}
	soon := at.Add(5 * time.Second)
	old := &update.Status{State: "ok", Version: "v0.5.18", At: at.Add(-time.Hour)}
	for _, c := range []struct {
		name    string
		current string
		st      *update.Status
		now     time.Time
		want    bool
	}{
		{"no status yet", "v0.5.18", nil, soon, true},
		{"only the previous result", "v0.5.18", old, soon, true},
		{"applying", "v0.5.18", &update.Status{State: "applying", At: soon}, soon, true},
		{"failed after the click", "v0.5.18", &update.Status{State: "failed", At: soon}, soon, false},
		{"new version running", "v0.5.19", nil, soon, false},
		{"asked long ago", "v0.5.18", nil, at.Add(time.Hour), false},
	} {
		if got := ask.waiting(c.current, c.st, c.now); got != c.want {
			t.Errorf("%s: waiting = %v, want %v", c.name, got, c.want)
		}
	}
}
