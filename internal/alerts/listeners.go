package alerts

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
)

// Listener is a TCP socket listening on the host.
type Listener struct {
	Addr netip.Addr
	Port int
}

// Exposed reports whether the socket can be reached from outside the
// server: listening on every address or on a public one. Loopback and
// private addresses (Docker bridges, the edge network) are not.
func (l Listener) Exposed() bool {
	a := l.Addr.Unmap()
	return a.IsUnspecified() || (!a.IsLoopback() && !a.IsPrivate() && !a.IsLinkLocalUnicast())
}

// ParseProcNetTCP reads /proc/net/tcp or /proc/net/tcp6 and returns the
// sockets in LISTEN state.
func ParseProcNetTCP(r io.Reader) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		host, port, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil {
			continue
		}
		addr, err := procAddr(host)
		if err != nil {
			continue
		}
		out = append(out, Listener{Addr: addr, Port: int(p)})
	}
	return out, sc.Err()
}

// procAddr decodes the kernel's hex address: 32-bit words in host byte
// order (little-endian on amd64 and arm64).
func procAddr(h string) (netip.Addr, error) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, fmt.Errorf("bad address %q", h)
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	return a, nil
}

// HostListeners lists the listening TCP sockets of the host network
// namespace (procDir is /proc; tests pass a fixture).
func HostListeners(procDir string) ([]Listener, error) {
	var all []Listener
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procDir, "net", name)) //nolint:gosec // fixed path under /proc
		if err != nil {
			if name == "tcp6" && os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		ls, err := ParseProcNetTCP(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, ls...)
	}
	return all, nil
}

// UnknownListeners returns the exposed listeners whose port is not in
// allowed, one per port.
func UnknownListeners(ls []Listener, allowed map[int]bool) []Listener {
	seen := map[int]bool{}
	var out []Listener
	for _, l := range ls {
		if !l.Exposed() || allowed[l.Port] || seen[l.Port] {
			continue
		}
		seen[l.Port] = true
		out = append(out, l)
	}
	return out
}

// WatchListeners looks for ports open to the outside that the panel did not
// open (docs/17, hole 33): a forgotten "python -m http.server", a database
// installed on the host, a backdoor. Each new one is written to the audit
// log as system.port.unknown, which raises a security alert (it cannot be
// turned off). allowed returns the expected ports: SSH and the configured
// extras, 80/443 with the edge, the ports published from the panel.
func WatchListeners(ctx context.Context, every time.Duration, procDir string, allowed func(context.Context) map[int]bool, al *audit.Logger, log *slog.Logger) {
	if _, err := HostListeners(procDir); err != nil {
		log.Info("open port watch off: no /proc/net here", "error", err)
		return
	}
	reported := map[int]bool{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		ls, err := HostListeners(procDir)
		if err == nil {
			current := map[int]bool{}
			for _, l := range UnknownListeners(ls, allowed(ctx)) {
				current[l.Port] = true
				if reported[l.Port] {
					continue
				}
				log.Warn("port open outside the panel", "port", l.Port, "address", l.Addr.String())
				_ = al.Record(ctx, audit.Entry{
					Action: "system.port.unknown", Outcome: audit.Error,
					Summary: map[string]any{"port": l.Port, "address": l.Addr.String()},
				})
			}
			// A port that closed and opens again is reported again.
			reported = current
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
