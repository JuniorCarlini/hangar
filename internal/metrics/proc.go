package metrics

import (
	"bufio"
	"strconv"
	"strings"
)

// The host is read straight from /proc (docs/06): no agent, no dependency.
// Every parser takes the file's text so it can be tested with fixtures; off
// Linux the files do not exist and the collector reports zeros.

// cpuTimes are the jiffies of the aggregate "cpu" line of /proc/stat.
type cpuTimes struct {
	busy, total uint64
}

// parseStat reads the first line of /proc/stat:
// cpu user nice system idle iowait irq softirq steal guest guest_nice.
// guest time is already counted in user, so it is left out of the total.
func parseStat(s string) (cpuTimes, bool) {
	line, _, _ := strings.Cut(s, "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return cpuTimes{}, false
	}
	var v [8]uint64
	for i := 1; i < len(f) && i <= 8; i++ {
		n, err := strconv.ParseUint(f[i], 10, 64)
		if err != nil {
			return cpuTimes{}, false
		}
		v[i-1] = n
	}
	var total uint64
	for _, n := range v {
		total += n
	}
	idle := v[3] + v[4] // idle + iowait
	return cpuTimes{busy: total - idle, total: total}, true
}

// cpuPercent is the busy share between two readings, 0–100.
func cpuPercent(prev, cur cpuTimes) float64 {
	if cur.total <= prev.total || cur.busy < prev.busy {
		return 0
	}
	return min(100, float64(cur.busy-prev.busy)*100/float64(cur.total-prev.total))
}

// parseMeminfo returns used and total memory in bytes. Used is total minus
// MemAvailable (what the kernel can hand out without swapping), the figure
// "free" shows as used.
func parseMeminfo(s string) (used, total uint64) {
	var avail uint64
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "MemTotal":
			total = n << 10
		case "MemAvailable":
			avail = n << 10
		}
	}
	if avail > total {
		return 0, total
	}
	return total - avail, total
}

// virtualIface tells interfaces whose traffic stays inside the host:
// loopback, Docker bridges and the host ends of veth pairs. Counting them
// would show every container byte twice.
func virtualIface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range []string{"veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "vxlan", "tunl"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// parseNetDev sums received and sent bytes of the real interfaces in
// /proc/net/dev.
func parseNetDev(s string) (rx, tx uint64) {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		if virtualIface(name) {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, err1 := strconv.ParseUint(f[0], 10, 64)
		t, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		rx += r
		tx += t
	}
	return rx, tx
}

// parseUptime returns the whole seconds in /proc/uptime.
func parseUptime(s string) int64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return int64(v)
}

// rate is bytes per second between two counter readings; a counter that
// went back (interface reset, container restart) gives 0.
func rate(prev, cur uint64, seconds float64) float64 {
	if seconds <= 0 || cur < prev {
		return 0
	}
	return float64(cur-prev) / seconds
}
