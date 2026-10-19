package alerts

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/metrics"
)

// ServiceState is what the monitor needs to know about one service that
// should be running (stopped by the user, never deployed or mid-deploy
// services are left out by whoever lists them).
type ServiceState struct {
	ID           string
	Name         string // project_service, as shown to the operator
	Exists       bool
	Running      bool
	State        string
	RestartCount int
	OOMKilled    bool
}

// StatesFunc lists the services to watch.
type StatesFunc func(ctx context.Context) ([]ServiceState, error)

// SnapshotFunc returns the latest metrics reading.
type SnapshotFunc func() metrics.Snapshot

// VolumeUsage is one volume with a size limit and how full it is.
type VolumeUsage struct {
	Key   string // the Docker volume name
	Name  string // project/service/volume, as shown to the operator
	Used  uint64
	Total uint64
}

// VolumesFunc lists the volumes with a size limit.
type VolumesFunc func(ctx context.Context) ([]VolumeUsage, error)

// restartWindow is how far back restarts are counted (docs/06: > 3 in 5 min).
const restartWindow = 5 * time.Minute

// Monitor evaluates the server rules on a schedule and raises an alert
// when a condition has held for the rule's duration, and a "back to normal"
// notice when it clears.
type Monitor struct {
	mu       sync.Mutex // guards firing for ActiveAlerts
	svc      *Service
	states   StatesFunc
	snapshot SnapshotFunc
	volumes  VolumesFunc
	now      func() time.Time

	since    map[string]time.Time // condition key → first seen
	firing   map[string]Event     // condition key → event that was raised
	restarts map[string][]restartSample
}

type restartSample struct {
	at    time.Time
	count int
}

// NewMonitor creates the server rules monitor. states or snapshot may be nil
// (no Docker, no metrics): their rules are then not evaluated.
func (s *Service) NewMonitor(states StatesFunc, snapshot SnapshotFunc) *Monitor {
	return &Monitor{
		svc: s, states: states, snapshot: snapshot, now: s.opt.Now,
		since: map[string]time.Time{}, firing: map[string]Event{}, restarts: map[string][]restartSample{},
	}
}

// SetVolumes adds the size-limited volumes to the rules (volume_disk,
// volume_full). Call it before Run.
func (m *Monitor) SetVolumes(fn VolumesFunc) { m.volumes = fn }

// Run checks every interval until ctx ends.
func (m *Monitor) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Check(ctx)
		}
	}
}

// condition is a rule currently true for one subject.
type condition struct {
	rule   RuleSetting
	params map[string]string
}

// Check evaluates every rule once.
func (m *Monitor) Check(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	settings, err := m.svc.RuleSettings(ctx)
	if err != nil {
		m.svc.log.Warn("read alert rules", "error", err)
		return
	}
	rules := map[string]RuleSetting{}
	for _, r := range settings {
		if r.Enabled {
			rules[r.Kind] = r
		}
	}
	current := map[string]condition{}
	// Kinds whose source failed this round: their conditions neither fire
	// nor clear (a Docker hiccup must not announce that everything is fine).
	unknown := map[string]bool{}

	if m.states != nil {
		list, err := m.states(ctx)
		if err != nil {
			for _, k := range []string{"container_down", "restart_loop", "oom"} {
				unknown[k] = true
			}
		} else {
			m.serviceConditions(now, list, rules, current)
		}
	}
	if m.snapshot != nil {
		m.metricConditions(m.snapshot(), rules, current, unknown)
	}
	if m.volumes != nil {
		if list, err := m.volumes(ctx); err != nil {
			unknown["volume_disk"], unknown["volume_full"] = true, true
		} else {
			volumeConditions(list, rules, current)
		}
	}

	for key, c := range current {
		if _, ok := m.firing[key]; ok {
			continue
		}
		first, ok := m.since[key]
		if !ok {
			m.since[key], first = now, now
		}
		if now.Sub(first) < c.rule.For {
			continue
		}
		ev := Event{Kind: c.rule.Kind, Severity: c.rule.Severity, Category: Server, Key: key, Params: c.params}
		if _, err := m.svc.Notify(ctx, ev); err != nil {
			m.svc.log.Error("raise alert", "kind", ev.Kind, "error", err)
			continue
		}
		m.firing[key] = ev
		delete(m.since, key)
	}
	for key := range m.since {
		if _, ok := current[key]; !ok && !unknown[kindOf(key)] {
			delete(m.since, key)
		}
	}
	for key, ev := range m.firing {
		if _, ok := current[key]; ok || unknown[ev.Kind] {
			continue
		}
		delete(m.firing, key)
		if _, enabled := rules[ev.Kind]; !enabled {
			continue // turned off: forget it quietly
		}
		ev.Resolved = true
		if _, err := m.svc.Notify(ctx, ev); err != nil {
			m.svc.log.Error("resolve alert", "kind", ev.Kind, "error", err)
		}
	}
}

func kindOf(key string) string {
	k, _, _ := strings.Cut(key, "|")
	return k
}

func (m *Monitor) serviceConditions(now time.Time, list []ServiceState, rules map[string]RuleSetting, out map[string]condition) {
	seen := map[string]bool{}
	for _, s := range list {
		seen[s.ID] = true
		params := map[string]string{"service": s.Name}
		if r, ok := rules["container_down"]; ok && (!s.Exists || (!s.Running && s.State != "restarting")) {
			out["container_down|"+s.ID] = condition{rule: r, params: params}
		}
		if r, ok := rules["oom"]; ok && s.Exists && s.OOMKilled {
			out["oom|"+s.ID] = condition{rule: r, params: params}
		}
		if !s.Exists {
			delete(m.restarts, s.ID)
			continue
		}
		samples := append(m.restarts[s.ID], restartSample{at: now, count: s.RestartCount})
		// A new container (redeploy) starts counting from zero again.
		if n := len(samples); n > 1 && samples[n-1].count < samples[n-2].count {
			samples = samples[n-1:]
		}
		for len(samples) > 1 && now.Sub(samples[0].at) > restartWindow {
			samples = samples[1:]
		}
		m.restarts[s.ID] = samples
		if r, ok := rules["restart_loop"]; ok {
			if n := samples[len(samples)-1].count - samples[0].count; n > r.Value {
				out["restart_loop|"+s.ID] = condition{rule: r, params: map[string]string{
					"service": s.Name, "count": strconv.Itoa(n), "minutes": strconv.Itoa(int(restartWindow.Minutes())),
				}}
			}
		}
	}
	for id := range m.restarts {
		if !seen[id] {
			delete(m.restarts, id)
		}
	}
}

func (m *Monitor) metricConditions(snap metrics.Snapshot, rules map[string]RuleSetting, out map[string]condition, unknown map[string]bool) {
	if snap.At.IsZero() {
		for _, k := range []string{"host_cpu", "host_memory", "host_disk", "service_memory"} {
			unknown[k] = true
		}
		return
	}
	over := func(kind string, used, total float64) (RuleSetting, int, bool) {
		r, ok := rules[kind]
		if !ok || total <= 0 {
			return r, 0, false
		}
		pct := used * 100 / total
		return r, int(pct + 0.5), pct > float64(r.Value)
	}
	h := snap.Host
	if r, ok := rules["host_cpu"]; ok && h.CPU > float64(r.Value) {
		out["host_cpu"] = condition{rule: r, params: map[string]string{"pct": strconv.Itoa(int(h.CPU + 0.5)), "limit": strconv.Itoa(r.Value)}}
	}
	if r, pct, ok := over("host_memory", float64(h.Mem), float64(h.MemLimit)); ok {
		out["host_memory"] = condition{rule: r, params: map[string]string{"pct": strconv.Itoa(pct), "limit": strconv.Itoa(r.Value)}}
	}
	if r, pct, ok := over("host_disk", float64(h.DiskUsed), float64(h.DiskTotal)); ok {
		out["host_disk"] = condition{rule: r, params: map[string]string{"pct": strconv.Itoa(pct), "limit": strconv.Itoa(r.Value)}}
	}
	for _, c := range snap.Containers {
		if c.State != "running" || c.MemLimit == 0 || c.Mem == 0 {
			continue
		}
		if r, pct, ok := over("service_memory", float64(c.Mem), float64(c.MemLimit)); ok {
			name := c.Name
			if c.Project != "" {
				name = c.Project + "_" + c.Service
			}
			out["service_memory|"+c.Key] = condition{rule: r, params: map[string]string{
				"service": name, "pct": strconv.Itoa(pct), "limit": strconv.Itoa(r.Value),
			}}
		}
	}
}

// volumeConditions: each limited volume above a threshold. Above both, both
// hold: the warning was sent on the way up and stays, the critical alert
// comes once; each clears when the volume drops below its own threshold.
func volumeConditions(list []VolumeUsage, rules map[string]RuleSetting, out map[string]condition) {
	for _, v := range list {
		if v.Total == 0 {
			continue
		}
		pct := float64(v.Used) * 100 / float64(v.Total)
		params := func(r RuleSetting) map[string]string {
			return map[string]string{"volume": v.Name, "pct": strconv.Itoa(int(pct + 0.5)), "limit": strconv.Itoa(r.Value)}
		}
		if r, ok := rules["volume_full"]; ok && pct > float64(r.Value) {
			out["volume_full|"+v.Key] = condition{rule: r, params: params(r)}
		}
		if r, ok := rules["volume_disk"]; ok && pct > float64(r.Value) {
			out["volume_disk|"+v.Key] = condition{rule: r, params: params(r)}
		}
	}
}

// ActiveAlerts is how many server conditions are firing now (the public
// status pages show the count, never the details).
func (m *Monitor) ActiveAlerts(context.Context) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.firing)
}
