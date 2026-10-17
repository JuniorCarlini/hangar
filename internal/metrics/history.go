package metrics

import (
	"context"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Period is a history window shown as a fixed number of bars.
type Period struct {
	Name string
	Span time.Duration
	Bars int
	res  string // stored resolution read for it ("" = memory only)
}

// Step is the time each bar covers.
func (p Period) Step() time.Duration { return p.Span / time.Duration(p.Bars) }

// Periods are the windows the panel offers, shortest first.
var Periods = []Period{
	{Name: "1h", Span: time.Hour, Bars: 60, res: "1m"},
	{Name: "24h", Span: 24 * time.Hour, Bars: 96, res: "1m"},
	{Name: "7d", Span: 7 * 24 * time.Hour, Bars: 84, res: "1h"},
	{Name: "90d", Span: 90 * 24 * time.Hour, Bars: 90, res: "1h"},
}

// ParsePeriod returns the named period, or the first (1 h) when unknown.
func ParsePeriod(name string) Period {
	for _, p := range Periods {
		if p.Name == name {
			return p
		}
	}
	return Periods[0]
}

func resDuration(res string) time.Duration {
	if res == "1h" {
		return time.Hour
	}
	return time.Minute
}

// History returns key's readings over the period as p.Bars averages, oldest
// first; a bar without data has a zero At. It joins what is stored with the
// readings still only in memory.
func (c *Collector) History(ctx context.Context, key string, p Period) ([]Point, error) {
	step := p.Step()
	now := time.Now()
	if c != nil {
		now = c.now()
	}
	end := now.Truncate(step).Add(step)
	from := end.Add(-p.Span)
	if c == nil {
		return make([]Point, p.Bars), nil
	}

	rows, err := c.q.ListMetrics(ctx, dbq.ListMetricsParams{Key: key, Resolution: p.res, Ts: from.Unix()})
	if err != nil {
		return nil, err
	}
	stored := make([]Point, 0, len(rows))
	for _, r := range rows {
		stored = append(stored, Point{
			At: time.Unix(r.Ts, 0), CPU: r.CpuPct, Mem: uint64(r.MemBytes), MemLimit: uint64(r.MemLimit), //nolint:gosec // stored from uint64
			Rx: r.NetRx, Tx: r.NetTx, DiskUsed: uint64(r.DiskUsed), DiskTotal: uint64(r.DiskTotal), //nolint:gosec // stored from uint64
		})
	}
	c.mu.RLock()
	var mem []Point
	if r := c.rings[key]; r != nil {
		mem = r.points(from)
	}
	c.mu.RUnlock()
	return bucket(merge(stored, mem, resDuration(p.res), p.Span <= time.Hour), from, step, p.Bars), nil
}

// merge joins stored rows (each covering res from its At) with the 10 s
// readings in memory. preferMemory (short windows) keeps every reading in
// memory and only the stored rows older than them; otherwise the stored rows
// win and memory fills in after the last one (the minute not yet written).
func merge(stored, mem []Point, res time.Duration, preferMemory bool) []Point {
	if len(mem) == 0 {
		return stored
	}
	if len(stored) == 0 {
		return mem
	}
	out := make([]Point, 0, len(stored)+len(mem))
	if preferMemory {
		first := mem[0].At
		for _, s := range stored {
			if !s.At.Add(res).After(first) {
				out = append(out, s)
			}
		}
		return append(out, mem...)
	}
	out = append(out, stored...)
	after := stored[len(stored)-1].At.Add(res)
	for _, m := range mem {
		if !m.At.Before(after) {
			out = append(out, m)
		}
	}
	return out
}

// bucket averages points into n bars of step starting at from. Limits and
// totals take the maximum, so a bar shows the capacity it was measured
// against.
func bucket(points []Point, from time.Time, step time.Duration, n int) []Point {
	out := make([]Point, n)
	acc := make([]accum, n)
	for _, p := range points {
		if p.At.Before(from) {
			continue
		}
		i := int(p.At.Sub(from) / step)
		if i >= n {
			continue
		}
		acc[i].add(p)
	}
	for i, a := range acc {
		if a.n == 0 {
			continue
		}
		k := float64(a.n)
		out[i] = Point{
			At: from.Add(time.Duration(i) * step), CPU: a.cpu / k, Rx: a.rx / k, Tx: a.tx / k,
			Mem: uint64(a.mem / k), MemLimit: a.memLimit, DiskUsed: uint64(a.dUsed / k), DiskTotal: a.diskTotal,
		}
	}
	return out
}
