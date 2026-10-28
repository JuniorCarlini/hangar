package web

import (
	"context"
	"math"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// overviewPage shows the server overview: current usage, its history over
// the chosen period, who is using the most and the latest activity.
func (h *handlers) overviewPage(w http.ResponseWriter, r *http.Request) {
	h.renderOverview(w, r, http.StatusOK)
}

// overviewRedirect keeps old /overview links working: the overview is home.
func (h *handlers) overviewRedirect(w http.ResponseWriter, r *http.Request) {
	redirectLocal(w, r, "/")
}

func (h *handlers) renderOverview(w http.ResponseWriter, r *http.Request, status int) {
	ctx := r.Context()
	host, _ := os.Hostname()
	snap := h.metrics.Latest()
	period := periodOf(r)
	cpus := runtime.NumCPU()

	d := views.OverviewData{
		Host: host, Period: period.Name, Periods: periodNames(),
		Summary: osName() + " · " + i18n.T(ctx, "overview.cpus", "n", cpus),
		CPU:     int(math.Round(snap.Host.CPU)), CPUNote: i18n.T(ctx, "overview.cpus", "n", cpus),
		Mem: pct(snap.Host.Mem, snap.Host.MemLimit), MemNote: "–",
		Disk: pct(snap.Host.DiskUsed, snap.Host.DiskTotal), DiskNote: "–",
	}
	// Without /proc (development on macOS) memory reads zero: show a dash,
	// not "0 B".
	if snap.Host.MemLimit > 0 {
		d.Summary += " · " + fmtBytes(ctx, snap.Host.MemLimit)
		d.MemNote = fmtBytesOf(ctx, snap.Host.Mem, snap.Host.MemLimit)
	}
	if snap.Host.DiskTotal > 0 {
		d.DiskNote = i18n.T(ctx, "overview.disk_note", "used", fmtBytes(ctx, snap.Host.DiskUsed), "total", fmtBytes(ctx, snap.Host.DiskTotal))
	}
	if snap.Uptime > 0 {
		d.Summary += " · " + uptime(ctx, snap.Uptime)
	}
	d.NetDown, d.NetUp, d.NetUnit = ratePair(ctx, snap.Host.Rx, snap.Host.Tx)

	if pts, err := h.metrics.History(ctx, metrics.HostKey, period); err != nil {
		loggerFrom(ctx).Error("metrics history", "error", err)
	} else {
		d.CPUHist = hist(pts, func(p metrics.Point) float64 { return p.CPU }, 100)
		d.MemHist = hist(pts, func(p metrics.Point) float64 { return float64(p.Mem) * 100 / math.Max(1, float64(p.MemLimit)) }, 100)
		var rx, tx float64
		d.NetHist, rx, tx = netHist(pts)
		down, up, unit := ratePair(ctx, rx, tx)
		d.NetNote = i18n.T(ctx, "overview.net_peak", "down", down, "up", up, "unit", unit)
		step := period.Step()
		d.CPUTips = sparkTips(pts, step, func(p metrics.Point) string { return decimal(ctx, p.CPU, 1) + "%" },
			func(p metrics.Point) float64 { return p.CPU })
		d.MemTips = sparkTips(pts, step, func(p metrics.Point) string { return memTip(ctx, p.Mem, p.MemLimit) },
			func(p metrics.Point) float64 { return float64(p.Mem) })
		d.NetTips = sparkTips(pts, step, func(p metrics.Point) string { return netTip(ctx, p) },
			func(p metrics.Point) float64 { return p.Rx + p.Tx })
	}

	if snap.Host.DiskTotal > 0 {
		d.DiskSegs, d.DiskFree = diskSegments(ctx, snap)
	}

	known := h.knownServices(ctx)
	who := PrincipalFrom(ctx)
	for _, c := range snap.Containers {
		// A user limited to some projects sees only their containers.
		if who.Limited() && !who.CanSeeProject(c.Project) {
			continue
		}
		share := c.CPU / float64(cpus)
		row := views.OverviewService{
			Name: c.Name, CPU: int(math.Round(share)), CPUText: decimal(ctx, share, 1) + "%",
			State: i18n.T(ctx, "state."+c.State), Tone: stateTone(c.State),
			CPUSort: int64(math.Round(share * 100)),
		}
		if c.Project != "" && c.Service != "" {
			if known == nil || known[c.Project+"/"+c.Service] {
				row.Href = servicePath(c.Project, c.Service)
			} else {
				row.Orphan = true
			}
		}
		if c.State == "running" {
			row.Mem = fmtBytesOf(ctx, c.Mem, c.MemLimit)
			row.Net = fmtRate(ctx, c.Rx+c.Tx)
			row.MemSort, row.NetSort = int64(c.Mem), int64(math.Round(c.Rx+c.Tx)) //nolint:gosec // memory fits in int64
		}
		d.Services = append(d.Services, row)
	}

	if rows, err := h.audit.Recent(ctx, activityActions, 40); err != nil {
		loggerFrom(ctx).Error("recent activity", "error", err)
	} else {
		if who.Limited() {
			mine := rows[:0]
			for _, row := range rows {
				if row.ProjectSlug != "" && who.CanSeeProject(row.ProjectSlug) {
					mine = append(mine, row)
				}
			}
			rows = mine
		}
		d.Events = activity(ctx, rows, time.Now(), 8)
	}

	d.DockerDown = !h.projects.DockerAvailable()
	if !who.Limited() {
		vc := h.depsCounts(ctx)
		d.VulnCritical, d.VulnSecurity = vc["critical"], vc["security"]
	}
	if p := PrincipalFrom(ctx); p != nil && p.Role >= auth.RoleOwner && h.updates != nil {
		if av, _ := h.updates.Latest(); av != nil {
			d.UpdateAvailable = av.Version
		}
	}
	render(w, r, status, views.Overview(d))
}

// stateTone colors a container state like the canvas does.
func stateTone(state string) string {
	switch state {
	case "running":
		return "success"
	case "restarting", "paused":
		return "warning"
	case "exited", "dead":
		return "danger"
	}
	return "info"
}

// diskSegments splits the used part of the disk the way the macOS storage
// bar does: Docker's images, volumes and containers (with the build cache),
// and everything else on the disk. Before Docker's usage is known there is
// a single "in use" segment.
func diskSegments(ctx context.Context, snap metrics.Snapshot) ([]views.DiskSeg, string) {
	total, used := snap.Host.DiskTotal, snap.Host.DiskUsed
	seg := func(label, fill string, b int64) views.DiskSeg {
		b = max(b, 0)
		return views.DiskSeg{
			Label: label, Size: fmtBytes(ctx, uint64(b)), //nolint:gosec // clamped to >= 0
			Fill: fill, Width: float64(b) * 1000 / float64(total),
		}
	}
	var out []views.DiskSeg
	rest := int64(min(used, math.MaxInt64)) //nolint:gosec // clamped
	if !snap.DiskAt.IsZero() {
		du := snap.Disk
		out = append(out,
			seg(i18n.T(ctx, "overview.disk_images"), "fill-accent", du.Images),
			seg(i18n.T(ctx, "overview.disk_volumes"), "fill-info", du.Volumes),
			seg(i18n.T(ctx, "overview.disk_containers"), "fill-success", du.Containers+du.BuildCache))
		rest -= max(du.Images, 0) + max(du.Volumes, 0) + max(du.Containers+du.BuildCache, 0)
		out = append(out, seg(i18n.T(ctx, "overview.disk_other"), "fill-subtle", rest))
	} else {
		out = append(out, seg(i18n.T(ctx, "overview.disk_used"), "fill-subtle", rest))
	}
	// A tiny segment still shows as a sliver, like on the Mac.
	x := 0.0
	for i := range out {
		if out[i].Width > 0 {
			out[i].Width = max(out[i].Width, 6)
		}
		out[i].X = x
		x += out[i].Width
	}
	free := uint64(0)
	if total > used {
		free = total - used
	}
	return out, fmtBytes(ctx, free)
}

// knownServices is the set of "project/service" slugs the panel has, so a
// container left behind by a deleted service is not linked to a page that
// answers 404. Nil when the lookup fails: then every container is linked.
func (h *handlers) knownServices(ctx context.Context) map[string]bool {
	projects, err := h.projects.ListProjects(ctx)
	if err != nil {
		loggerFrom(ctx).Error("list projects", "error", err)
		return nil
	}
	known := map[string]bool{}
	for _, p := range projects {
		svcs, err := h.projects.ListServices(ctx, p.ID)
		if err != nil {
			loggerFrom(ctx).Error("list services", "error", err)
			return nil
		}
		for _, s := range svcs {
			known[p.Slug+"/"+s.Slug] = true
		}
	}
	return known
}
