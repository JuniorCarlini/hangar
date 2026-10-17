package web

import (
	"bytes"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/statuspage"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// publicStatus serves the public status links (docs/15). It deliberately
// holds nothing but the status service: no projects manager, no Docker, no
// secrets. All it can hand out is a statuspage.Public snapshot, which is
// built without real names, images, versions, IPs or domains.
type publicStatus struct {
	svc   *statuspage.Service
	limit *ipRate
}

// Public rate limit: a wall monitor refreshing every 30 s, a phone and a
// Prometheus scraping every 15 s stay far below it.
const (
	publicPerMinute = 60
	publicWindow    = time.Minute
)

func newPublicStatus(svc *statuspage.Service) *publicStatus {
	return &publicStatus{svc: svc, limit: newIPRate(publicPerMinute, publicWindow, time.Now)}
}

// resolve checks the rate limit and the token; on failure it has already
// answered (429 or the generic 404).
func (p *publicStatus) resolve(w http.ResponseWriter, r *http.Request, token string) (statuspage.Resolved, bool) {
	h := w.Header()
	h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	h.Set("Referrer-Policy", "no-referrer")
	ip, _ := netip.ParseAddr(clientIP(r))
	if !p.limit.allow(ip.String()) {
		h.Set("Retry-After", "60")
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return statuspage.Resolved{}, false
	}
	if p.svc == nil {
		http.NotFound(w, r)
		return statuspage.Resolved{}, false
	}
	l, err := p.svc.Resolve(r.Context(), token, ip)
	if err != nil {
		// Same answer for unknown, revoked, expired and filtered tokens.
		http.NotFound(w, r)
		return statuspage.Resolved{}, false
	}
	return l, true
}

// page serves /s/{token} (HTML, ?tv=1 for the kiosk mode) and
// /s/{token}.json.
func (p *publicStatus) page(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	asJSON := strings.HasSuffix(token, ".json")
	token = strings.TrimSuffix(token, ".json")
	l, ok := p.resolve(w, r, token)
	if !ok {
		return
	}
	if asJSON {
		snap := p.svc.Snapshot(r.Context(), l, i18n.Default)
		var buf bytes.Buffer
		if err := statuspage.WriteJSON(&buf, snap); err != nil {
			loggerFrom(r.Context()).Error("status json", "error", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
		return
	}
	ctx := r.Context()
	snap := p.svc.Snapshot(ctx, l, i18n.Locale(ctx))
	tv := r.URL.Query().Get("tv") == "1"
	period := metrics.ParsePeriod(r.URL.Query().Get("period")).Name
	if _, ok := snap.CPUHist[period]; !ok {
		period = statuspage.HistoryPeriods[0]
	}
	d := views.PublicStatusData{
		Token: token, TV: tv, Period: period, Periods: statuspage.HistoryPeriods,
		CPU: decimal(ctx, snap.Server.CPUPct, 1), Mem: decimal(ctx, snap.Server.MemPct, 1), Disk: decimal(ctx, snap.Server.DiskPct, 1),
		CPUHist: snap.CPUHist[period], MemHist: snap.MemHist[period], Alerts: snap.AlertsActive,
		Updated: snap.GeneratedAt.Local().Format("15:04:05"),
	}
	d.NetDown, d.NetUp, d.NetUnit = ratePair(ctx, snap.Server.NetRxBps, snap.Server.NetTxBps)
	d.Uptime = "–"
	if snap.Server.UptimeS > 0 {
		d.Uptime = uptime(ctx, time.Duration(snap.Server.UptimeS)*time.Second)
	}
	for _, s := range snap.Services {
		d.Services = append(d.Services, views.PublicServiceRow{
			Label: s.Label, State: s.State, CPU: decimal(ctx, s.CPUPct, 1) + "%", CPUBar: int(s.CPUPct + 0.5),
			Mem: decimal(ctx, s.MemPct, 1) + "%", Net: fmtRate(ctx, s.NetBps), Uptime: decimal(ctx, s.UptimePct24h, 1) + "%",
		})
		switch s.State {
		case statuspage.StateStopped:
			d.Stopped++
		case statuspage.StateDegraded:
			d.Degraded++
		}
	}
	// Busiest first: the ranking of docs/15.
	views.SortPublicServices(d.Services)
	render(w, r, http.StatusOK, views.PublicStatus(d))
}

// prometheus serves /s/{token}/metrics.
func (p *publicStatus) prometheus(w http.ResponseWriter, r *http.Request) {
	l, ok := p.resolve(w, r, r.PathValue("token"))
	if !ok {
		return
	}
	var buf bytes.Buffer
	if err := statuspage.WritePrometheus(&buf, p.svc.Snapshot(r.Context(), l, i18n.Default)); err != nil {
		loggerFrom(r.Context()).Error("status metrics", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// ipRate allows n requests per window per key (fixed window), in memory.
type ipRate struct {
	mu      sync.Mutex
	n       int
	window  time.Duration
	now     func() time.Time
	entries map[string]*rateWindow
	swept   time.Time
}

type rateWindow struct {
	start time.Time
	count int
}

func newIPRate(n int, window time.Duration, now func() time.Time) *ipRate {
	return &ipRate{n: n, window: window, now: now, entries: map[string]*rateWindow{}}
}

func (l *ipRate) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	// Sweep expired windows now and then, so many addresses cannot grow
	// the map forever.
	if now.Sub(l.swept) > l.window {
		for k, e := range l.entries {
			if now.Sub(e.start) >= l.window {
				delete(l.entries, k)
			}
		}
		l.swept = now
	}
	e, ok := l.entries[key]
	if !ok || now.Sub(e.start) >= l.window {
		e = &rateWindow{start: now}
		l.entries[key] = e
	}
	e.count++
	return e.count <= l.n
}

// exceeded reports, without counting, whether key already used up the
// window (for limits that only count failures).
func (l *ipRate) exceeded(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	return ok && l.now().Sub(e.start) < l.window && e.count >= l.n
}
