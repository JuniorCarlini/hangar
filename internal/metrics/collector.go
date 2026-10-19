// Package metrics samples the host and the containers Hangar manages and
// keeps their history small (docs/06, docs/20): the last hour at 10 s in
// memory, 1-minute averages for 7 days and 1-hour averages for 90 days in
// SQLite.
package metrics

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Sampling and retention.
const (
	Step         = 10 * time.Second
	ringSize     = int(time.Hour / Step)
	minuteKeep   = 7 * 24 * time.Hour
	hourKeep     = 90 * 24 * time.Hour
	diskEvery    = 10 * time.Minute // "docker system df" is expensive
	reclaimEvery = 24 * time.Hour   // prune old build cache and dangling images
	statsLimit   = 4                // container readings at once
)

// HostKey is the history key of the server itself.
const HostKey = "host"

// Point is one reading, or an average over a bucket. A zero At means no data.
type Point struct {
	At       time.Time
	CPU      float64 // host: percent of all cores; container: 100 = one core (as docker stats)
	Mem      uint64  // bytes in use
	MemLimit uint64  // host: total; container: limit
	Rx, Tx   float64 // bytes per second
	// Host only: the filesystem of the data directory.
	DiskUsed, DiskTotal uint64
}

// Container is a managed container's latest reading.
type Container struct {
	Key     string // history key: the service id, or "ctr:<name>"
	ID      string
	Name    string
	Project string
	Service string
	State   string
	Point
}

// Snapshot is the latest picture of the server.
type Snapshot struct {
	At         time.Time
	Host       Point
	CPUs       int
	Uptime     time.Duration
	Containers []Container // sorted by CPU, highest first
	Disk       node.DiskUsage
	DiskAt     time.Time // when Disk was measured; zero = never
}

// Source lists the managed containers and reads their counters (Docker).
type Source interface {
	ListManaged(ctx context.Context) ([]node.Managed, error)
	node.StatsReader
}

// Collector samples every Step and serves the latest values and history.
// Every method is safe on a nil *Collector (the panel without metrics).
type Collector struct {
	q       *dbq.Queries
	src     Source
	dataDir string
	log     *slog.Logger
	now     func() time.Time
	read    func(string) (string, error)

	mu        sync.RWMutex
	latest    Snapshot
	rings     map[string]*ring
	prevAt    time.Time
	prevCPU   cpuTimes
	prevRx    uint64
	prevTx    uint64
	prevCtr   map[string]ctrReading // by container id
	minute    int64                 // start of the minute being accumulated
	acc       map[string]*accum
	lastPrune time.Time
}

type ctrReading struct {
	at time.Time
	s  node.ContainerStats
}

// New creates a collector. src may be nil (Docker unavailable): then only the
// host is measured.
func New(db *sql.DB, src Source, dataDir string, log *slog.Logger) *Collector {
	return &Collector{
		q: dbq.New(db), src: src, dataDir: dataDir, log: log,
		now:   time.Now,
		read:  readFile,
		rings: map[string]*ring{}, prevCtr: map[string]ctrReading{}, acc: map[string]*accum{},
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // fixed /proc paths
	return string(b), err
}

// Run samples until ctx ends. The first two readings are 2 s apart so CPU and
// network rates show up right after start.
func (c *Collector) Run(ctx context.Context) {
	if c == nil {
		return
	}
	if err := c.q.RollupMetricHours(ctx, c.now().Add(-minuteKeep).Unix()); err != nil {
		c.log.Warn("metrics rollup", "error", err)
	}
	go c.runDisk(ctx)
	go c.runReclaim(ctx)
	c.Sample(ctx)
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}
	c.Sample(ctx)
	t := time.NewTicker(Step)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Sample(ctx)
		}
	}
}

func (c *Collector) runDisk(ctx context.Context) {
	if c.src == nil {
		return
	}
	for {
		dctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		du, err := c.src.DiskUsage(dctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Warn("docker disk usage", "error", err)
		} else {
			c.mu.Lock()
			c.latest.Disk, c.latest.DiskAt = du, c.now()
			c.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(diskEvery):
		}
	}
}

// runReclaim frees old disk once a day: build cache and dangling images that
// are too old for any running build to need. The first run waits a few
// minutes so startup is not slowed.
func (c *Collector) runReclaim(ctx context.Context) {
	if c.src == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Minute):
	}
	for {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		r, err := c.src.ReclaimDisk(rctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Warn("reclaim disk", "error", err)
		}
		if r.BuildCache > 0 || r.Images > 0 {
			c.log.Info("reclaimed disk", "build_cache", r.BuildCache, "images", r.Images)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reclaimEvery):
		}
	}
}

// Sample takes one reading of the host and the containers, records it and,
// at each new minute, writes the previous minute's averages.
func (c *Collector) Sample(ctx context.Context) {
	if c == nil {
		return
	}
	now := c.now()
	stat, _ := c.read("/proc/stat")
	mem, _ := c.read("/proc/meminfo")
	netdev, _ := c.read("/proc/net/dev")
	up, _ := c.read("/proc/uptime")
	cpu, cpuOK := parseStat(stat)
	used, total := parseMeminfo(mem)
	rx, tx := parseNetDev(netdev)
	dUsed, dTotal := diskUsage(c.dataDir)
	managed, readings := c.readContainers(ctx)

	c.mu.Lock()
	first := c.prevAt.IsZero()
	secs := now.Sub(c.prevAt).Seconds()
	host := Point{At: now, Mem: used, MemLimit: total, DiskUsed: dUsed, DiskTotal: dTotal}
	if !first {
		if cpuOK {
			host.CPU = cpuPercent(c.prevCPU, cpu)
		}
		host.Rx, host.Tx = rate(c.prevRx, rx, secs), rate(c.prevTx, tx, secs)
	}
	c.prevAt, c.prevCPU, c.prevRx, c.prevTx = now, cpu, rx, tx

	ctrs := make([]Container, 0, len(managed))
	seen := map[string]bool{}
	var record []Container
	for _, m := range managed {
		ct := Container{Key: keyOf(m), ID: m.ID, Name: m.Name, Project: m.Project, Service: m.Service, State: m.State}
		ct.At = now
		if r, ok := readings[m.ID]; ok {
			seen[m.ID] = true
			ct.Mem, ct.MemLimit = r.MemUsed, r.MemLimit
			if p, ok := c.prevCtr[m.ID]; ok {
				ct.CPU = containerCPU(p.s, r)
				s := now.Sub(p.at).Seconds()
				ct.Rx, ct.Tx = rate(p.s.NetRx, r.NetRx, s), rate(p.s.NetTx, r.NetTx, s)
				record = append(record, ct)
			}
			c.prevCtr[m.ID] = ctrReading{at: now, s: r}
		}
		ctrs = append(ctrs, ct)
	}
	for id := range c.prevCtr {
		if !seen[id] {
			delete(c.prevCtr, id)
		}
	}
	sort.SliceStable(ctrs, func(i, j int) bool { return ctrs[i].CPU > ctrs[j].CPU })
	c.latest.At, c.latest.Host, c.latest.Containers = now, host, ctrs
	c.latest.CPUs = runtime.NumCPU()
	c.latest.Uptime = time.Duration(parseUptime(up)) * time.Second

	var rows []dbq.UpsertMetricParams
	if !first {
		rows = c.recordLocked(now, HostKey, host)
		for _, ct := range record {
			rows = append(rows, c.recordLocked(now, ct.Key, ct.Point)...)
		}
	}
	c.pruneRingsLocked(now)
	c.mu.Unlock()

	if len(rows) > 0 {
		c.write(ctx, now, rows)
	}
}

// keyOf is the history key of a container: its service, so the history
// survives redeploys (new container ids).
func keyOf(m node.Managed) string {
	if m.ServiceID != "" {
		return m.ServiceID
	}
	return "ctr:" + m.Name
}

// containerCPU is docker stats' formula: the container's share of the host
// CPU time between two readings, times the cores (100 = one core).
func containerCPU(prev, cur node.ContainerStats) float64 {
	if cur.CPUTotal < prev.CPUTotal || cur.SystemCPU <= prev.SystemCPU {
		return 0
	}
	cpus := max(cur.OnlineCPUs, 1)
	return float64(cur.CPUTotal-prev.CPUTotal) / float64(cur.SystemCPU-prev.SystemCPU) * float64(cpus) * 100
}

func (c *Collector) readContainers(ctx context.Context) ([]node.Managed, map[string]node.ContainerStats) {
	if c.src == nil {
		return nil, nil
	}
	lctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	managed, err := c.src.ListManaged(lctx)
	if err != nil {
		if ctx.Err() == nil {
			c.log.Warn("list containers for metrics", "error", err)
		}
		return nil, nil
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = map[string]node.ContainerStats{}
		sem = make(chan struct{}, statsLimit)
	)
	for _, m := range managed {
		if m.State != "running" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			s, err := c.src.ContainerStats(lctx, id)
			if err != nil {
				return // stopped between the list and the reading
			}
			mu.Lock()
			out[id] = s
			mu.Unlock()
		}(m.ID)
	}
	wg.Wait()
	return managed, out
}

// recordLocked adds p to key's ring and minute average. When the minute
// changes it returns the finished minute's rows to write.
func (c *Collector) recordLocked(now time.Time, key string, p Point) []dbq.UpsertMetricParams {
	minute := now.Unix() - now.Unix()%60
	var rows []dbq.UpsertMetricParams
	if c.minute != 0 && minute != c.minute {
		for k, a := range c.acc {
			if a.n > 0 {
				rows = append(rows, a.row(k, c.minute))
			}
		}
		c.acc = map[string]*accum{}
	}
	c.minute = minute
	r := c.rings[key]
	if r == nil {
		r = &ring{}
		c.rings[key] = r
	}
	r.push(p)
	a := c.acc[key]
	if a == nil {
		a = &accum{}
		c.acc[key] = a
	}
	a.add(p)
	return rows
}

// pruneRingsLocked forgets containers not seen for an hour.
func (c *Collector) pruneRingsLocked(now time.Time) {
	for k, r := range c.rings {
		if last, ok := r.last(); ok && now.Sub(last.At) > time.Hour {
			delete(c.rings, k)
		}
	}
}

// write stores finished minutes, refreshes the current and previous hour's
// averages and, once an hour, drops what is past retention.
func (c *Collector) write(ctx context.Context, now time.Time, rows []dbq.UpsertMetricParams) {
	for _, r := range rows {
		if err := c.q.UpsertMetric(ctx, r); err != nil {
			c.log.Warn("store metrics", "error", err)
			return
		}
	}
	hour := now.Unix() - now.Unix()%3600
	if err := c.q.RollupMetricHours(ctx, hour-3600); err != nil {
		c.log.Warn("metrics rollup", "error", err)
	}
	if now.Sub(c.lastPrune) >= time.Hour {
		c.lastPrune = now
		if err := c.prune(ctx, now); err != nil {
			c.log.Warn("metrics retention", "error", err)
		}
	}
}

func (c *Collector) prune(ctx context.Context, now time.Time) error {
	if err := c.q.DeleteMetricsBefore(ctx, dbq.DeleteMetricsBeforeParams{Resolution: "1m", Ts: now.Add(-minuteKeep).Unix()}); err != nil {
		return err
	}
	return c.q.DeleteMetricsBefore(ctx, dbq.DeleteMetricsBeforeParams{Resolution: "1h", Ts: now.Add(-hourKeep).Unix()})
}

// Latest is the most recent snapshot (zero before the first reading).
func (c *Collector) Latest() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.latest
	s.Containers = append([]Container(nil), s.Containers...)
	return s
}

// Container is the latest reading of a service's container.
func (c *Collector) Container(serviceID string) (Container, bool) {
	for _, ct := range c.Latest().Containers {
		if ct.Key == serviceID {
			return ct, true
		}
	}
	return Container{}, false
}

// ServiceDisk is a service's volume bytes from the last "docker system df"
// (measured every few minutes, reused from the host disk reading). The bool
// is false when there is no reading yet or the service has no measured volume.
func (c *Collector) ServiceDisk(serviceID string) (int64, bool) {
	if c == nil {
		return 0, false
	}
	n, ok := c.Latest().Disk.ByService[serviceID]
	return n, ok
}

// VolumeDisk is one volume's bytes (by Docker name) from the same reading
// as ServiceDisk. The bool is false when there is no reading of it yet.
func (c *Collector) VolumeDisk(name string) (int64, bool) {
	if c == nil {
		return 0, false
	}
	n, ok := c.Latest().Disk.ByVolume[name]
	return n, ok
}

// accum sums readings of one key within a minute.
type accum struct {
	n                   int
	cpu, rx, tx         float64
	mem, dUsed          float64
	memLimit, diskTotal uint64
}

func (a *accum) add(p Point) {
	a.n++
	a.cpu += p.CPU
	a.rx += p.Rx
	a.tx += p.Tx
	a.mem += float64(p.Mem)
	a.dUsed += float64(p.DiskUsed)
	a.memLimit = max(a.memLimit, p.MemLimit)
	a.diskTotal = max(a.diskTotal, p.DiskTotal)
}

func (a *accum) row(key string, ts int64) dbq.UpsertMetricParams {
	n := float64(a.n)
	return dbq.UpsertMetricParams{
		Key: key, Resolution: "1m", Ts: ts,
		CpuPct: a.cpu / n, MemBytes: int64(a.mem / n), MemLimit: int64(a.memLimit), //nolint:gosec // byte counts fit in int64
		NetRx: a.rx / n, NetTx: a.tx / n,
		DiskUsed: int64(a.dUsed / n), DiskTotal: int64(a.diskTotal), //nolint:gosec // byte counts fit in int64
	}
}

// ring is the last hour of 10 s readings of one key.
type ring struct {
	buf  [ringSize]Point
	next int
	n    int
}

func (r *ring) push(p Point) {
	r.buf[r.next] = p
	r.next = (r.next + 1) % ringSize
	r.n = min(r.n+1, ringSize)
}

// points returns the readings since from, oldest first.
func (r *ring) points(from time.Time) []Point {
	out := make([]Point, 0, r.n)
	for i := range r.n {
		p := r.buf[(r.next-r.n+i+ringSize)%ringSize]
		if !p.At.Before(from) {
			out = append(out, p)
		}
	}
	return out
}

func (r *ring) last() (Point, bool) {
	if r.n == 0 {
		return Point{}, false
	}
	return r.buf[(r.next-1+ringSize)%ringSize], true
}
