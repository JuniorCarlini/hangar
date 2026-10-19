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
	for _, name := range []string{"hangard.service", "hangar-updater.service", "hangar-updater.path", "hangar-firewall.service", "hangar-firewall.path", "hangar-firewall.timer", "hangar-volumes.service", "hangar-volumes.path", "journald-hangar.conf"} {
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

// The disk images must be mounted where Docker and the panel see them, and
// before Docker starts the containers that bind to them.
func TestVolumesUnitMountsOnTheHost(t *testing.T) {
	b, err := fs.ReadFile(Systemd, "systemd/hangar-volumes.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(b)
	for _, want := range []string{"\nBefore=docker.service\n", "\nType=oneshot\n", "\nTimeoutStartSec=infinity\n", "system volumes-apply"} {
		if !strings.Contains(unit, want) {
			t.Errorf("hangar-volumes.service lacks %q", want)
		}
	}
	// Any of these gives the unit its own mount namespace: its mounts would
	// vanish with it.
	for _, bad := range []string{"PrivateTmp=", "ProtectHome=", "ProtectSystem=", "PrivateDevices=", "MountFlags=", "ReadWritePaths=", "RootDirectory=", "PrivateMounts="} {
		for line := range strings.SplitSeq(unit, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), bad) {
				t.Errorf("hangar-volumes.service sets %s", bad)
			}
		}
	}
}

// An applier killed by its timeout must not leave the panel stopped.
func TestUpdaterAlwaysStartsThePanelAgain(t *testing.T) {
	b, err := fs.ReadFile(Systemd, "systemd/hangar-updater.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nExecStopPost=/bin/systemctl --no-block start hangard.service\n") {
		t.Error("hangar-updater.service does not start hangard.service after it stops")
	}
}
