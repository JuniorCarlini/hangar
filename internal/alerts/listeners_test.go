package alerts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A trimmed /proc/net/tcp and tcp6 of a VPS: sshd on 0.0.0.0:22, the panel
// on 127.0.0.1:7700, docker-proxy on 0.0.0.0:5433 (a port opened in the
// panel), the edge hooks listener on 172.30.0.1:7701, a forgotten
// "python -m http.server" on 0.0.0.0:8000, a database on [::]:6379 and an
// established connection (state 01) that must be ignored.
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:1E14 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 2 1 0 100 0 0 10 0
   2: 00000000:1539 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0
   3: 01001EAC:1E15 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 4 1 0 100 0 0 10 0
   4: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 5 1 0 100 0 0 10 0
   5: 0A0A0A0A:0016 1E141E0A:D431 01 00000000:00000000 02:00000000 00000000     0        0 6 1 0 20 4 30 10 -1
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:18EB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 7 1 0 100 0 0 10 0
   1: 00000000000000000000000001000000:1E14 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 8 1 0 100 0 0 10 0
`

func fakeProc(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"tcp": procTCP, "tcp6": procTCP6} {
		if err := os.WriteFile(filepath.Join(dir, "net", name), []byte(body), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	return dir
}

func TestUnknownListenersFromProc(t *testing.T) {
	ls, err := HostListeners(fakeProc(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 7 {
		t.Fatalf("listeners = %+v, want 7 in LISTEN", ls)
	}
	got := UnknownListeners(ls, map[int]bool{22: true, 5433: true, 7700: true})
	ports := map[int]string{}
	for _, l := range got {
		ports[l.Port] = l.Addr.String()
	}
	if len(ports) != 2 || ports[8000] != "0.0.0.0" || ports[6379] != "::" {
		t.Fatalf("unknown = %v, want 8000 and 6379 (loopback and private addresses are not exposed)", ports)
	}
}

// The watcher writes system.port.unknown once per port, and that audit row
// becomes a security alert on the channels.
func TestUnknownPortRaisesSecurityAlert(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "critical")
	e.svc.Observe(e.al)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	proc := fakeProc(t)
	go func() {
		WatchListeners(ctx, 20*time.Millisecond, proc, func(context.Context) map[int]bool {
			return map[int]bool{22: true, 5433: true, 7700: true, 6379: true}
		}, e.al, discard)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.tg.messages()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no alert for the unknown port")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond) // several more scans
	cancel()
	<-done
	msgs := e.tg.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0].Text, "8000") {
		t.Fatalf("messages = %+v, want one about port 8000", msgs)
	}
	var rows int
	if err := e.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'system.port.unknown'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("audit rows = %d, want 1 (a port still open is not reported again)", rows)
	}
}
