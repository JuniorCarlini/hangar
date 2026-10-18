package node

import "testing"

// A service publishing the public panel's listener port (7702), or the
// panel's own configured port, would take it from hangard.
func TestReservedHostPorts(t *testing.T) {
	for _, p := range []int{22, 80, 443, 7700, 7701, 7702} {
		if !ReservedHostPorts[p] {
			t.Errorf("port %d should be reserved", p)
		}
	}
	if ReservedHostPorts[9443] {
		t.Fatal("9443 is not reserved by default")
	}
	ReserveHostPorts(9443, 0, 70000)
	t.Cleanup(func() { delete(ReservedHostPorts, 9443) })
	if !ReservedHostPorts[9443] || ReservedHostPorts[0] || ReservedHostPorts[70000] {
		t.Errorf("ReserveHostPorts adds valid ports only: %v", ReservedHostPorts)
	}
}
