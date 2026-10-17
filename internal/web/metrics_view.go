package web

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// decimal formats v with prec decimals in the request's language (comma in
// pt-BR, point in English). Whole numbers lose the decimals.
func decimal(ctx context.Context, v float64, prec int) string {
	s := strconv.FormatFloat(v, 'f', prec, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	if i18n.Locale(ctx) != "en" {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

var byteUnits = []string{"B", "KB", "MB", "GB", "TB"}

// unitFor picks the binary unit that keeps b readable (at most 1023,9 of it).
func unitFor(b float64) int {
	u := 0
	for b >= 1024 && u < len(byteUnits)-1 {
		b /= 1024
		u++
	}
	return u
}

func inUnit(ctx context.Context, b float64, u int) string {
	v := b / math.Pow(1024, float64(u))
	prec := 1
	if v >= 100 || u == 0 {
		prec = 0
	}
	return decimal(ctx, v, prec)
}

// fmtBytes is "410 MB", "1,9 GB".
func fmtBytes(ctx context.Context, b uint64) string {
	u := unitFor(float64(b))
	return inUnit(ctx, float64(b), u) + " " + byteUnits[u]
}

// fmtBytesOf is "1,1 / 2 GB": both in the unit of the larger one.
func fmtBytesOf(ctx context.Context, used, total uint64) string {
	u := unitFor(float64(max(used, total)))
	return inUnit(ctx, float64(used), u) + " / " + inUnit(ctx, float64(total), u) + " " + byteUnits[u]
}

// fmtRate is "1,8 MB/s".
func fmtRate(ctx context.Context, bps float64) string {
	u := unitFor(bps)
	return inUnit(ctx, bps, u) + " " + byteUnits[u] + "/s"
}

// ratePair formats received and sent in one unit, the larger one's.
func ratePair(ctx context.Context, rx, tx float64) (down, up, unit string) {
	u := unitFor(math.Max(rx, tx))
	return inUnit(ctx, rx, u), inUnit(ctx, tx, u), byteUnits[u] + "/s"
}

// hist turns points into bar heights, 0–100 of scale; -1 marks a bar
// without data.
func hist(points []metrics.Point, value func(metrics.Point) float64, scale float64) []int {
	out := make([]int, len(points))
	for i, p := range points {
		if p.At.IsZero() {
			out[i] = -1
			continue
		}
		if scale <= 0 {
			out[i] = 0
			continue
		}
		out[i] = int(math.Round(min(100, value(p)*100/scale)))
	}
	return leftAlign(out)
}

// leftAlign moves the leading gaps (the part of the window before the panel
// had data) to the end, so a young history grows from the left edge to the
// right instead of hugging the right side. Gaps in the middle stay put.
func leftAlign(h []int) []int {
	n := 0
	for n < len(h) && h[n] < 0 {
		n++
	}
	if n == 0 || n == len(h) {
		return h
	}
	return slices.Concat(h[n:], h[:n])
}

// netHist scales received + sent to the busiest bar of the window, and
// returns the peak of each direction.
func netHist(points []metrics.Point) (h []int, peakRx, peakTx float64) {
	top := 0.0
	for _, p := range points {
		top = math.Max(top, p.Rx+p.Tx)
		peakRx, peakTx = math.Max(peakRx, p.Rx), math.Max(peakTx, p.Tx)
	}
	return hist(points, func(p metrics.Point) float64 { return p.Rx + p.Tx }, top), peakRx, peakTx
}

func pct(used, total uint64) int {
	if total == 0 {
		return 0
	}
	return int(math.Round(float64(used) * 100 / float64(total)))
}

// periodName is the validated ?period= (1h when missing or unknown).
func periodOf(r interface{ FormValue(string) string }) metrics.Period {
	return metrics.ParsePeriod(r.FormValue("period"))
}

func periodNames() []string {
	out := make([]string, 0, len(metrics.Periods))
	for _, p := range metrics.Periods {
		out = append(out, p.Name)
	}
	return out
}

// --- server summary ---------------------------------------------------------

var osName = sync.OnceValue(func() string {
	b, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(v, `"`)
			}
		}
	}
	return runtime.GOOS
})

// uptime is "ativo há 14 dias" / "ativo há 3 h".
func uptime(ctx context.Context, d time.Duration) string {
	if d >= 24*time.Hour {
		return i18n.T(ctx, "overview.uptime_days", "n", int(d/(24*time.Hour)))
	}
	return i18n.T(ctx, "overview.uptime_hours", "n", int(d/time.Hour))
}

// --- activity ---------------------------------------------------------------

// activityActions are the audit actions the overview feed shows.
var activityActions = []string{
	"service.deploy", "service.rollback", "service.start", "service.stop", "service.restart",
	"service.create", "service.delete", "service.drift", "project.create", "project.delete",
	"port.open", "port.close", "domain.add", "domain.remove",
	"auth.login.ok", "auth.account.locked",
	"system.update.ok", "system.update.rolled_back", "system.update.failed",
}

// activity turns recent audit records into feed lines in the user's language.
func activity(ctx context.Context, rows []dbq.RecentActivityRow, now time.Time, limit int) []views.OverviewEvent {
	out := []views.OverviewEvent{}
	for _, r := range rows {
		if len(out) == limit {
			break
		}
		// Refused requests are recorded under the same action; they did not happen.
		if r.Outcome == "denied" && r.Action != "auth.account.locked" {
			continue
		}
		var sum map[string]any
		_ = json.Unmarshal([]byte(r.SummaryJson), &sum)
		str := func(k string) string {
			switch v := sum[k].(type) {
			case string:
				return v
			case float64:
				return strconv.FormatFloat(v, 'f', -1, 64)
			}
			return ""
		}
		svc := str("service")
		if r.ServiceSlug != "" {
			svc = r.ServiceSlug
			if r.ProjectSlug != "" {
				svc = r.ProjectSlug + "/" + r.ServiceSlug
			}
		}
		if svc == "" {
			// A service deleted since: the record still names its container.
			svc = str("container")
		}
		failed := r.Outcome == "error"
		e := views.OverviewEvent{Tone: "info"}
		switch r.Action {
		case "service.deploy":
			if failed {
				e.Text, e.Tone = i18n.T(ctx, "activity.deploy_failed", "service", svc), "danger"
			} else {
				e.Text, e.Tone = i18n.T(ctx, "activity.deploy", "service", svc), "success"
			}
		case "service.rollback":
			e.Text, e.Tone = i18n.T(ctx, "activity.rollback", "service", svc), "warning"
		case "service.start":
			e.Text, e.Tone = i18n.T(ctx, "activity.start", "service", svc), "success"
		case "service.stop":
			e.Text, e.Tone = i18n.T(ctx, "activity.stop", "service", svc), "warning"
		case "service.restart":
			e.Text = i18n.T(ctx, "activity.restart", "service", svc)
		case "service.create":
			e.Text = i18n.T(ctx, "activity.service_create", "service", svc)
		case "service.delete":
			e.Text, e.Tone = i18n.T(ctx, "activity.service_delete", "service", svc), "warning"
		case "service.drift":
			// The reconciler only reports (it never fixes): say what it saw.
			name := svc
			if c := str("container"); c != "" {
				name = c
			}
			e.Text, e.Tone = i18n.T(ctx, "activity.drift", "service", name), "warning"
			switch p := str("problem"); p {
			case "orphan", "stopped", "missing":
				e.Text = i18n.T(ctx, "activity.drift_kind."+p, "service", name)
			}
		case "project.create":
			e.Text = i18n.T(ctx, "activity.project_create", "project", str("slug"))
		case "project.delete":
			e.Text, e.Tone = i18n.T(ctx, "activity.project_delete", "project", str("slug")), "warning"
		case "port.open":
			e.Text, e.Tone = i18n.T(ctx, "activity.port_open", "port", str("host_port"), "service", svc), "warning"
		case "port.close":
			e.Text, e.Tone = i18n.T(ctx, "activity.port_close", "port", str("host_port"), "service", svc), "success"
		case "domain.add":
			e.Text, e.Tone = i18n.T(ctx, "activity.domain_add", "domain", str("hostname")), "accent"
		case "domain.remove":
			e.Text = i18n.T(ctx, "activity.domain_remove", "domain", str("hostname"))
		case "auth.login.ok":
			e.Text, e.Tone = i18n.T(ctx, "activity.login"), "accent"
		case "auth.account.locked":
			e.Text, e.Tone = i18n.T(ctx, "activity.locked"), "danger"
		case "system.update.ok":
			e.Text, e.Tone = i18n.T(ctx, "activity.update_ok", "version", str("to")), "success"
		case "system.update.rolled_back":
			e.Text, e.Tone = i18n.T(ctx, "activity.update_rolled_back", "version", str("to")), "warning"
		case "system.update.failed":
			e.Text, e.Tone = i18n.T(ctx, "activity.update_failed", "version", str("to")), "danger"
		default:
			continue
		}
		if failed && r.Action != "service.deploy" {
			e.Tone = "danger"
		}
		e.Meta = ago(ctx, r.Ts, now)
		if who := actorName(r); who != "" {
			e.Meta += " · " + who
		}
		out = append(out, e)
	}
	return out
}

func actorName(r dbq.RecentActivityRow) string {
	if r.UserName != "" {
		return r.UserName
	}
	local, _, _ := strings.Cut(r.UserEmail, "@")
	return local
}

// ago is "agora", "há 5 min", "há 2 h", "há 3 dias".
func ago(ctx context.Context, ts string, now time.Time) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return i18n.T(ctx, "time.just_now")
	case d < time.Hour:
		return i18n.T(ctx, "time.minutes_ago", "n", int(d/time.Minute))
	case d < 24*time.Hour:
		return i18n.T(ctx, "time.hours_ago", "n", int(d/time.Hour))
	}
	return i18n.T(ctx, "time.days_ago", "n", int(d/(24*time.Hour)))
}

// serviceMetrics fills the service's metrics tab: usage against its limits
// (CPU in cores, as docker stats counts it) and the period's history.
// hasDisk says the service has at least one disk, even if not measured yet.
func (h *handlers) serviceMetrics(r *http.Request, s dbq.Service, hasDisk bool) views.ServiceMetrics {
	ctx := r.Context()
	period := periodOf(r)
	m := views.ServiceMetrics{Period: period.Name, Periods: periodNames(), CPU: "–", Mem: "–", Disk: "–", NetDown: "–", NetUp: "–"}
	cores := float64(s.NanoCpus) / 1e9
	if cores <= 0 {
		cores = float64(max(h.metrics.Latest().CPUs, 1))
	}
	limit := uint64(max(s.MemoryBytes, 0)) //nolint:gosec // clamped to >= 0
	coresText := decimal(ctx, cores, 2)
	m.CPUNote = i18n.T(ctx, "service.metrics.cpu_limit", "cpus", coresText)
	m.MemNote = i18n.T(ctx, "service.metrics.mem_limit", "limit", fmtBytes(ctx, limit))

	if c, ok := h.metrics.Container(s.ID); ok && c.State == "running" {
		m.Running = true
		if c.MemLimit > 0 {
			limit = c.MemLimit
		}
		used := c.CPU / 100
		m.CPU = i18n.T(ctx, "service.metrics.cores", "n", decimal(ctx, used, 2))
		m.CPUNote = i18n.T(ctx, "service.metrics.cpu_of", "pct", decimal(ctx, used*100/cores, 0), "cpus", coresText)
		m.Mem = fmtBytes(ctx, c.Mem)
		m.MemNote = i18n.T(ctx, "service.metrics.mem_of", "pct", pct(c.Mem, limit), "limit", fmtBytes(ctx, limit))
		m.NetDown, m.NetUp, m.NetUnit = ratePair(ctx, c.Rx, c.Tx)
	}

	// Disk is the service's volume bytes, from the shared "docker system df"
	// reading (every few minutes), so there is no per-service history to plot.
	if bytes, ok := h.metrics.ServiceDisk(s.ID); ok {
		m.Disk = fmtBytes(ctx, uint64(bytes)) //nolint:gosec // negatives filtered in docker.DiskUsage
		m.DiskNote = i18n.T(ctx, "service.metrics.disk_note")
	} else if hasDisk {
		// A disk added minutes ago waits for the next reading: saying "no
		// volume" next to the disk the operator just created would be wrong.
		m.DiskNote = i18n.T(ctx, "service.metrics.disk_pending")
	} else {
		m.DiskNote = i18n.T(ctx, "service.metrics.disk_none")
	}

	pts, err := h.metrics.History(ctx, s.ID, period)
	if err != nil {
		loggerFrom(ctx).Error("service metrics history", "error", err)
		return m
	}
	m.CPUHist = hist(pts, func(p metrics.Point) float64 { return p.CPU / 100 }, cores)
	m.MemHist = hist(pts, func(p metrics.Point) float64 {
		return float64(p.Mem) * 100 / math.Max(1, float64(max(p.MemLimit, limit)))
	}, 100)
	var rx, tx float64
	m.NetHist, rx, tx = netHist(pts)
	down, up, unit := ratePair(ctx, rx, tx)
	m.NetNote = i18n.T(ctx, "overview.net_peak", "down", down, "up", up, "unit", unit)
	return m
}
