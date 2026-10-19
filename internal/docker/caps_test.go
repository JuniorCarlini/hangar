package docker

import (
	"slices"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// TestInitCanForwardTheStopSignal: every container gets KILL, so docker-init
// (root) can pass SIGTERM to an app that dropped to its own user; without it
// postgres, redis and the like were killed instead of shutting down.
func TestInitCanForwardTheStopSignal(t *testing.T) {
	for _, caps := range [][]string{nil, {"CHOWN", "SETUID", "SETGID"}, {"KILL"}, {"CAP_KILL"}} {
		hc := hostConfig(node.ServiceSpec{CapAdd: caps})
		n := 0
		for _, c := range hc.CapAdd {
			if c == "KILL" || c == "CAP_KILL" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("caps %v -> %v: want KILL exactly once", caps, hc.CapAdd)
		}
		if hc.Init == nil || !*hc.Init {
			t.Error("init must stay on")
		}
	}
	in := []string{"CHOWN"}
	_ = hostConfig(node.ServiceSpec{CapAdd: in})
	if !slices.Equal(in, []string{"CHOWN"}) {
		t.Error("the spec's own slice was changed")
	}
}
