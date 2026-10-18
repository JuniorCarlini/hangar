package deploy

import (
	"io/fs"
	"strings"
	"testing"
)

// The installer and the updater write these units from inside the binary; a
// missing one breaks every install and every update (it happened once: a
// comment refactor dropped the //go:embed line and v0.3.0 shipped empty).
func TestUnitsAreEmbedded(t *testing.T) {
	for _, name := range []string{"hangard.service", "hangar-updater.service", "hangar-updater.path", "hangar-firewall.service", "hangar-firewall.path", "hangar-firewall.timer", "journald-hangar.conf"} {
		b, err := fs.ReadFile(Systemd, "systemd/"+name)
		if err != nil {
			t.Errorf("%s not embedded: %v", name, err)
			continue
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}
