package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

const statA = `cpu  1000 0 500 8000 500 0 0 0 0 0
cpu0 500 0 250 4000 250 0 0 0 0 0
intr 12345
`

const statB = `cpu  1300 0 600 8500 600 0 0 0 0 0
cpu0 650 0 300 4250 300 0 0 0 0 0
`

const meminfo = `MemTotal:        8000000 kB
MemFree:          500000 kB
MemAvailable:    6000000 kB
Buffers:          100000 kB
`

const netdev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999     100    0    0    0     0          0         0  9999999     100    0    0    0     0       0          0
  eth0: 1000000    2000    0    0    0     0          0         0   500000    1000    0    0    0     0       0          0
  ens4:    2000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
docker0: 777777       1    0    0    0     0          0         0   777777       1    0    0    0     0       0          0
br-1a2b3c: 55555      1    0    0    0     0          0         0    55555       1    0    0    0     0       0          0
vethab12: 4444       1    0    0    0     0          0         0     4444       1    0    0    0     0       0          0
`

func TestParseStatAndCPUPercent(t *testing.T) {
	a, ok := parseStat(statA)
	if !ok || a.total != 10000 || a.busy != 1500 {
		t.Fatalf("parseStat A = %+v, %v", a, ok)
	}
	b, _ := parseStat(statB)
	// busy +400 of total +1000 (300 user, 100 system, 500 idle, 100 iowait).
	if got := cpuPercent(a, b); math.Abs(got-40) > 0.001 {
		t.Errorf("cpuPercent = %v, want 40", got)
	}
	if got := cpuPercent(b, a); got != 0 {
		t.Errorf("counters going back must give 0, got %v", got)
	}
	if _, ok := parseStat("intr 1 2 3"); ok {
		t.Error("a file without the cpu line must not parse")
	}
	if _, ok := parseStat(""); ok {
		t.Error("empty input (macOS) must not parse")
	}
}

func TestParseMeminfo(t *testing.T) {
	used, total := parseMeminfo(meminfo)
	if total != 8000000<<10 || used != 2000000<<10 {
		t.Errorf("parseMeminfo = %d / %d", used, total)
	}
	if u, tot := parseMeminfo(""); u != 0 || tot != 0 {
		t.Error("empty meminfo must be zero")
	}
}

func TestParseNetDevSkipsVirtual(t *testing.T) {
	rx, tx := parseNetDev(netdev)
	if rx != 1002000 || tx != 501000 {
		t.Errorf("parseNetDev = %d / %d, want only eth0 + ens4", rx, tx)
	}
	if got := rate(1000, 3000, 10); got != 200 {
		t.Errorf("rate = %v", got)
	}
	if got := rate(3000, 1000, 10); got != 0 {
		t.Errorf("a reset counter must give 0, got %v", got)
	}
	if parseUptime("12345.67 99999.00\n") != 12345 {
		t.Error("parseUptime")
	}
}

func TestContainerCPU(t *testing.T) {
	prev := node.ContainerStats{CPUTotal: 1e9, SystemCPU: 100e9, OnlineCPUs: 4}
	cur := node.ContainerStats{CPUTotal: 1.5e9, SystemCPU: 110e9, OnlineCPUs: 4}
	// 0.5 s of 10 s of host time over 4 cores = 20% (docker stats style).
	if got := containerCPU(prev, cur); math.Abs(got-20) > 0.001 {
		t.Errorf("containerCPU = %v, want 20", got)
	}
}

// --- collector ---------------------------------------------------------------

type fakeSource struct {
	managed []node.Managed
	stats   map[string]node.ContainerStats
}

func (f *fakeSource) ListManaged(context.Context) ([]node.Managed, error) { return f.managed, nil }

func (f *fakeSource) ContainerStats(_ context.Context, id string) (node.ContainerStats, error) {
	s, ok := f.stats[id]
	if !ok {
		return s, errors.New("gone")
	}
	return s, nil
}

func (f *fakeSource) DiskUsage(context.Context) (node.DiskUsage, error) {
	return node.DiskUsage{Images: 1 << 30, Volumes: 2 << 30}, nil
}

func (f *fakeSource) ReclaimDisk(context.Context) (node.Reclaimed, error) {
	return node.Reclaimed{}, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestCollector(t *testing.T, src Source) (*Collector, *clock, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c := New(st.DB, src, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	clk := &clock{t: time.Date(2026, 10, 1, 12, 0, 5, 0, time.UTC)}
	c.now = clk.now
	return c, clk, st
}

func TestCollectorSamplesHostAndContainers(t *testing.T) {
	src := &fakeSource{
		managed: []node.Managed{
			{ID: "c1", Name: "lab_web", ServiceID: "svc_web", Project: "lab", Service: "web", State: "running"},
			{ID: "c2", Name: "lab_db", ServiceID: "svc_db", Project: "lab", Service: "db", State: "exited"},
		},
		stats: map[string]node.ContainerStats{"c1": {CPUTotal: 1e9, SystemCPU: 100e9, OnlineCPUs: 2, MemUsed: 64 << 20, MemLimit: 256 << 20, NetRx: 1000}},
	}
	c, clk, _ := newTestCollector(t, src)
	files := map[string]string{"/proc/stat": statA, "/proc/meminfo": meminfo, "/proc/net/dev": netdev}
	c.read = func(p string) (string, error) { return files[p], nil }
	ctx := context.Background()

	c.Sample(ctx)
	if s := c.Latest(); s.Host.CPU != 0 || s.Host.Mem != 2000000<<10 {
		t.Fatalf("first reading: CPU must wait for a second reading, memory is immediate: %+v", s.Host)
	}

	clk.t = clk.t.Add(Step)
	files["/proc/stat"] = statB
	src.stats["c1"] = node.ContainerStats{CPUTotal: 2e9, SystemCPU: 110e9, OnlineCPUs: 2, MemUsed: 80 << 20, MemLimit: 256 << 20, NetRx: 11000}
	c.Sample(ctx)
	s := c.Latest()
	if math.Abs(s.Host.CPU-40) > 0.001 {
		t.Errorf("host CPU = %v", s.Host.CPU)
	}
	if len(s.Containers) != 2 || s.Containers[0].Key != "svc_web" {
		t.Fatalf("containers = %+v", s.Containers)
	}
	web := s.Containers[0]
	if math.Abs(web.CPU-20) > 0.001 || web.Mem != 80<<20 || web.Rx != 1000 {
		t.Errorf("web reading = %+v", web.Point)
	}
	if s.Containers[1].State != "exited" || s.Containers[1].CPU != 0 {
		t.Errorf("stopped container = %+v", s.Containers[1])
	}
	if ct, ok := c.Container("svc_web"); !ok || ct.Name != "lab_web" {
		t.Error("Container(svc_web) not found")
	}
}

// Off Linux there is no /proc: the collector must not fail, only report zeros.
func TestCollectorWithoutProc(t *testing.T) {
	c, _, _ := newTestCollector(t, nil)
	c.read = func(string) (string, error) { return "", errors.New("no /proc") }
	c.Sample(context.Background())
	c.Sample(context.Background())
	if s := c.Latest(); s.Host.CPU != 0 || s.Host.Mem != 0 || len(s.Containers) != 0 {
		t.Errorf("snapshot = %+v", s)
	}
	var nilC *Collector
	nilC.Sample(context.Background())
	if h, err := nilC.History(context.Background(), HostKey, Periods[1]); err != nil || len(h) != 96 {
		t.Errorf("nil collector history = %d, %v", len(h), err)
	}
}

// Readings become minute rows when the minute turns, minute rows become hour
// rows, and old rows go away.
func TestDownsamplingAndRetention(t *testing.T) {
	c, clk, st := newTestCollector(t, nil)
	cpuLine := uint64(0)
	c.read = func(p string) (string, error) {
		if p == "/proc/stat" {
			// Each step: 100 jiffies, half busy → 50%.
			cpuLine += 100
			return fmt.Sprintf("cpu %d 0 0 %d 0 0 0 0\n", cpuLine/2, cpuLine/2), nil
		}
		return "", nil
	}
	ctx := context.Background()
	start := clk.t          // 12:00:05
	for i := range 18 * 6 { // 18 minutes of readings
		clk.t = start.Add(time.Duration(i) * Step)
		c.Sample(ctx)
	}
	q := dbq.New(st.DB)
	mins, err := q.ListMetrics(ctx, dbq.ListMetricsParams{Key: HostKey, Resolution: "1m", Ts: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(mins) < 15 {
		t.Fatalf("minute rows = %d, want one per finished minute", len(mins))
	}
	for _, m := range mins {
		if math.Abs(m.CpuPct-50) > 0.001 || m.Ts%60 != 0 {
			t.Fatalf("minute row %+v", m)
		}
	}
	hours, _ := q.ListMetrics(ctx, dbq.ListMetricsParams{Key: HostKey, Resolution: "1h", Ts: 0})
	if len(hours) != 1 || hours[0].Ts != start.Unix()-start.Unix()%3600 || math.Abs(hours[0].CpuPct-50) > 0.001 {
		t.Fatalf("hour rows = %+v", hours)
	}

	// Old rows past retention.
	old := start.Add(-8 * 24 * time.Hour).Unix()
	ancient := start.Add(-91 * 24 * time.Hour).Unix()
	for _, p := range []dbq.UpsertMetricParams{
		{Key: HostKey, Resolution: "1m", Ts: old - old%60},
		{Key: HostKey, Resolution: "1h", Ts: old - old%3600},
		{Key: HostKey, Resolution: "1h", Ts: ancient - ancient%3600},
	} {
		if err := q.UpsertMetric(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.prune(ctx, start); err != nil {
		t.Fatal(err)
	}
	mins, _ = q.ListMetrics(ctx, dbq.ListMetricsParams{Key: HostKey, Resolution: "1m", Ts: 0})
	for _, m := range mins {
		if m.Ts < start.Add(-minuteKeep).Unix() {
			t.Error("minute rows older than 7 days must be deleted")
		}
	}
	hours, _ = q.ListMetrics(ctx, dbq.ListMetricsParams{Key: HostKey, Resolution: "1h", Ts: 0})
	if len(hours) != 2 {
		t.Errorf("hour rows after retention = %d, want the 8-day-old one and the current", len(hours))
	}

	// History: the 1 h window comes from memory, 24 h from the minute rows.
	h, err := c.History(ctx, HostKey, ParsePeriod("1h"))
	if err != nil || len(h) != 60 {
		t.Fatalf("1h history = %d, %v", len(h), err)
	}
	filled := 0
	for _, p := range h {
		if !p.At.IsZero() {
			filled++
			if math.Abs(p.CPU-50) > 0.001 {
				t.Errorf("bar %+v", p)
			}
		}
	}
	if filled < 17 {
		t.Errorf("1h history has %d bars with data, want 18", filled)
	}
	d, _ := c.History(ctx, HostKey, ParsePeriod("24h"))
	if len(d) != 96 || d[len(d)-1].At.IsZero() && d[len(d)-2].At.IsZero() {
		t.Errorf("24h history should end with data: %+v", d[len(d)-2:])
	}
	if ParsePeriod("bogus").Name != "1h" {
		t.Error("unknown period falls back to 1h")
	}
}

func TestBucketAndMerge(t *testing.T) {
	from := time.Unix(0, 0)
	pts := []Point{
		{At: from.Add(10 * time.Second), CPU: 10, MemLimit: 5},
		{At: from.Add(50 * time.Second), CPU: 30, MemLimit: 7},
		{At: from.Add(130 * time.Second), CPU: 90},
		{At: from.Add(-time.Second), CPU: 99},     // before the window
		{At: from.Add(10 * time.Minute), CPU: 99}, // after it
	}
	b := bucket(pts, from, time.Minute, 3)
	if b[0].CPU != 20 || b[0].MemLimit != 7 || !b[1].At.IsZero() || b[2].CPU != 90 {
		t.Errorf("bucket = %+v", b)
	}
	stored := []Point{{At: from}, {At: from.Add(time.Minute)}}
	mem := []Point{{At: from.Add(70 * time.Second)}, {At: from.Add(130 * time.Second)}}
	if got := merge(stored, mem, time.Minute, true); len(got) != 3 {
		t.Errorf("prefer memory: %d points, want the first stored minute + 2 readings", len(got))
	}
	if got := merge(stored, mem, time.Minute, false); len(got) != 3 {
		t.Errorf("prefer stored: %d points, want 2 stored + the reading after them", len(got))
	}
}

func TestRingKeepsOneHour(t *testing.T) {
	var r ring
	base := time.Unix(0, 0)
	for i := range ringSize + 10 {
		r.push(Point{At: base.Add(time.Duration(i) * Step), CPU: float64(i)})
	}
	all := r.points(time.Time{})
	if len(all) != ringSize || all[0].CPU != 10 || all[len(all)-1].CPU != float64(ringSize+9) {
		t.Errorf("ring = %d points, first %v", len(all), all[0].CPU)
	}
}
