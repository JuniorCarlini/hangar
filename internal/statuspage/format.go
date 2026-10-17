package statuspage

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// WriteJSON writes the snapshot as the documented JSON (docs/15).
func WriteJSON(w io.Writer, p Public) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// WritePrometheus writes the snapshot in the Prometheus text format, with
// the same public labels as the page.
func WritePrometheus(w io.Writer, p Public) error {
	var b strings.Builder
	gauge := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	num := func(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

	gauge("hangar_server_cpu_percent", "Server CPU use, percent of all cores.")
	fmt.Fprintf(&b, "hangar_server_cpu_percent %s\n", num(p.Server.CPUPct))
	gauge("hangar_server_memory_percent", "Server memory in use, percent.")
	fmt.Fprintf(&b, "hangar_server_memory_percent %s\n", num(p.Server.MemPct))
	gauge("hangar_server_disk_percent", "Data disk in use, percent.")
	fmt.Fprintf(&b, "hangar_server_disk_percent %s\n", num(p.Server.DiskPct))
	gauge("hangar_server_network_receive_bytes_per_second", "Bytes received per second.")
	fmt.Fprintf(&b, "hangar_server_network_receive_bytes_per_second %s\n", num(p.Server.NetRxBps))
	gauge("hangar_server_network_transmit_bytes_per_second", "Bytes sent per second.")
	fmt.Fprintf(&b, "hangar_server_network_transmit_bytes_per_second %s\n", num(p.Server.NetTxBps))
	gauge("hangar_server_uptime_seconds", "Seconds since the server booted.")
	fmt.Fprintf(&b, "hangar_server_uptime_seconds %d\n", p.Server.UptimeS)
	gauge("hangar_alerts_active", "Active alerts.")
	fmt.Fprintf(&b, "hangar_alerts_active %d\n", p.AlertsActive)

	if len(p.Services) > 0 {
		gauge("hangar_service_up", "1 when the service is running (degraded counts as up).")
		for _, s := range p.Services {
			up := 0
			if s.State != StateStopped {
				up = 1
			}
			fmt.Fprintf(&b, "hangar_service_up{service=%s} %d\n", label(s.Label), up)
		}
		gauge("hangar_service_state", "Service state: 1 on the current one.")
		for _, s := range p.Services {
			for _, st := range []string{StateRunning, StateDegraded, StateStopped} {
				v := 0
				if s.State == st {
					v = 1
				}
				fmt.Fprintf(&b, "hangar_service_state{service=%s,state=%q} %d\n", label(s.Label), st, v)
			}
		}
		gauge("hangar_service_cpu_percent", "Service CPU use, percent of the server.")
		for _, s := range p.Services {
			fmt.Fprintf(&b, "hangar_service_cpu_percent{service=%s} %s\n", label(s.Label), num(s.CPUPct))
		}
		gauge("hangar_service_memory_percent", "Service memory, percent of its limit.")
		for _, s := range p.Services {
			fmt.Fprintf(&b, "hangar_service_memory_percent{service=%s} %s\n", label(s.Label), num(s.MemPct))
		}
		gauge("hangar_service_network_bytes_per_second", "Service traffic (in + out) per second.")
		for _, s := range p.Services {
			fmt.Fprintf(&b, "hangar_service_network_bytes_per_second{service=%s} %s\n", label(s.Label), num(s.NetBps))
		}
		gauge("hangar_service_uptime_percent_24h", "Share of the last 24 h the service was up.")
		for _, s := range p.Services {
			fmt.Fprintf(&b, "hangar_service_uptime_percent_24h{service=%s} %s\n", label(s.Label), num(s.UptimePct24h))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// label quotes a label value with the escapes the text format requires.
func label(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(v) + `"`
}
