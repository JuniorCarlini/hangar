package backup

import (
	"context"
	"database/sql"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// job is one queued backup.
type job struct {
	actor   Actor
	trigger string
	kind    string // archive.KindDump, KindBase or KindPanel
	service string // service id ("" for the panel)
	manual  bool   // counted in queued until it ran
}

// Queued reports whether a manual backup of the service ("" = the panel)
// waits in the queue or runs.
func (m *Manager) Queued(serviceID string) bool {
	m.queuedMu.Lock()
	defer m.queuedMu.Unlock()
	return m.queued[serviceID] > 0
}

// pushManual queues the jobs of one "back up now", unless the previous one
// of the same service has not finished.
func (m *Manager) pushManual(key string, jobs ...job) error {
	m.queuedMu.Lock()
	defer m.queuedMu.Unlock()
	if m.queued[key] > 0 {
		return ErrQueued
	}
	if m.queued == nil {
		m.queued = map[string]int{}
	}
	for _, j := range jobs {
		j.manual = true
		if err := m.push(j); err != nil {
			return err
		}
		m.queued[key]++
	}
	return nil
}

func (m *Manager) doneManual(key string) {
	m.queuedMu.Lock()
	defer m.queuedMu.Unlock()
	if m.queued[key]--; m.queued[key] <= 0 {
		delete(m.queued, key)
	}
}

// Enqueue asks for a backup now (button "Fazer backup agora"). It runs in
// the background, after whatever is already queued.
func (m *Manager) Enqueue(ctx context.Context, a Actor, projectSlug, serviceSlug string) error {
	if !m.Ready(ctx) {
		return ErrNotReady
	}
	if projectSlug == "" {
		return m.pushManual("", job{actor: a, trigger: TriggerManual, kind: archive.KindPanel})
	}
	s, err := m.ref(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	// A stopped service's volumes are copied as they are; a dump (pg_dump
	// or a recipe's) needs the server running.
	if s.online() && !m.running(ctx, s) {
		return ErrNotRunning
	}
	jobs := []job{{actor: a, trigger: TriggerManual, kind: s.kind(), service: s.ID}}
	if p, ok := m.ServicePolicy(ctx, s.ID); ok && p.WAL && m.archivingActive(ctx, s) {
		jobs = append(jobs, job{actor: a, trigger: TriggerManual, kind: archive.KindBase, service: s.ID})
	}
	return m.pushManual(s.ID, jobs...)
}

func (m *Manager) push(j job) error {
	select {
	case m.jobs <- j:
		return nil
	default:
		return ErrBusy
	}
}

// Run is the scheduler: queued jobs, due policies, WAL shipping and the
// panel's own backup. It returns when ctx ends.
func (m *Manager) Run(ctx context.Context) {
	_ = m.q.FailRunningBackupRuns(ctx, dbq.FailRunningBackupRunsParams{Error: nullStr("interrupted: the panel stopped"), FinishedAt: nullInt(m.now().Unix())})
	_ = m.q.FailRunningRestores(ctx, dbq.FailRunningRestoresParams{Error: nullStr("interrupted: the panel stopped"), FinishedAt: nullInt(m.now().Unix())})
	_ = m.q.FailRunningProjectRestores(ctx, dbq.FailRunningProjectRestoresParams{Error: nullStr("interrupted: the panel stopped"), FinishedAt: nullInt(m.now().Unix())})
	m.cleanStaging()
	m.unpauseLeftovers(ctx)

	go m.runWAL(ctx)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-m.jobs:
			m.runJob(ctx, j)
		case <-tick.C:
			m.schedule(ctx)
		}
	}
}

// unpauseLeftovers lets go the services a copy of volumes paused when the
// panel stopped in the middle of it. Nothing else in Hangar pauses a
// container, so every paused one it manages is such a leftover.
func (m *Manager) unpauseLeftovers(ctx context.Context) {
	n := m.projects.Node()
	p, ok := n.(node.Pauser)
	if !ok {
		return
	}
	cs, err := n.ListManaged(ctx)
	if err != nil {
		return
	}
	for _, c := range cs {
		if c.State != "paused" || c.Project == "" || c.Service == "" {
			continue
		}
		err := p.Unpause(ctx, c.Project, c.Service)
		m.log.Warn("unpaused a service left paused by an interrupted backup", "service", c.Project+"/"+c.Service, "error", err)
	}
}

// Wait waits for background restores and downloads (shutdown, tests).
func (m *Manager) Wait() { m.wg.Wait() }

func (m *Manager) runJob(ctx context.Context, j job) {
	if j.manual {
		defer m.doneManual(j.service)
	}
	jctx, cancel := context.WithTimeout(ctx, restoreTimeout)
	defer cancel()
	if j.kind == archive.KindPanel {
		_, _ = m.backupPanel(jctx, j.actor, j.trigger)
		return
	}
	s, err := m.refByID(jctx, j.service)
	if err != nil {
		return
	}
	if j.kind == archive.KindBase {
		_, _ = m.backupBase(jctx, j.actor, s, j.trigger)
		return
	}
	_, _ = m.backupService(jctx, j.actor, s, j.trigger)
}

// schedule queues what is due.
func (m *Manager) schedule(ctx context.Context) {
	if !m.Ready(ctx) {
		return
	}
	pols, err := m.q.ListBackupPolicies(ctx)
	if err != nil {
		return
	}
	now := m.now()
	for _, p := range pols {
		if p.Enabled != 1 {
			continue
		}
		due := p.NextRunAt <= now.Unix()
		if due {
			_ = m.q.SetBackupPolicyNextRun(ctx, dbq.SetBackupPolicyNextRunParams{NextRunAt: nextRun(now, int(p.EveryHours), int(p.AtMinute)).Unix(), ID: p.ID})
		}
		if !p.ServiceID.Valid {
			if due {
				_ = m.push(job{actor: System, trigger: TriggerSchedule, kind: archive.KindPanel})
			} else if m.panelChanged(ctx) && m.lastRunOlderThan(ctx, PanelLabel, archive.KindPanel, 2*time.Hour) {
				_ = m.push(job{actor: System, trigger: TriggerChange, kind: archive.KindPanel})
			}
			continue
		}
		s, err := m.refByID(ctx, p.ServiceID.String)
		if err != nil || (s.online() && !m.running(ctx, s)) {
			continue
		}
		if due {
			_ = m.push(job{actor: System, trigger: TriggerSchedule, kind: s.kind(), service: s.ID})
		}
		if p.Wal == 1 && m.needsBase(ctx, s, p, due) {
			trigger := TriggerSchedule
			if !due {
				trigger = TriggerWALStart
			}
			_ = m.push(job{actor: System, trigger: trigger, kind: archive.KindBase, service: s.ID})
		}
	}
	_ = m.q.PruneBackupRuns(ctx, now.Add(-400*24*time.Hour).Unix())
}

// needsBase: a base backup goes with every scheduled run while WAL is on,
// and right away when WAL was just turned on (a point-in-time restore
// needs one to start from).
func (m *Manager) needsBase(ctx context.Context, s svcRef, p dbq.BackupPolicy, due bool) bool {
	if !m.archivingActive(ctx, s) {
		return false
	}
	if due {
		return true
	}
	last, err := m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: s.label(), Kind: archive.KindBase})
	if err != nil {
		return m.lastRunOlderThan(ctx, s.label(), archive.KindBase, 15*time.Minute)
	}
	return p.WalSince.Valid && last.StartedAt < p.WalSince.Int64 && m.lastRunOlderThan(ctx, s.label(), archive.KindBase, 15*time.Minute)
}

func (m *Manager) lastRunOlderThan(ctx context.Context, label, kind string, d time.Duration) bool {
	r, err := m.q.LastBackupRun(ctx, dbq.LastBackupRunParams{Label: label, Kind: kind})
	return err != nil || m.now().Sub(time.Unix(r.StartedAt, 0)) > d
}

// runWAL ships WAL every 15 seconds for every service that archives it.
func (m *Manager) runWAL(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m.ShipAllWAL(ctx)
		}
	}
}

// ShipAllWAL runs one WAL pass over every service with WAL on.
func (m *Manager) ShipAllWAL(ctx context.Context) {
	pols, err := m.q.ListBackupPolicies(ctx)
	if err != nil {
		return
	}
	for _, p := range pols {
		if p.Enabled != 1 || p.Wal != 1 || !p.ServiceID.Valid {
			continue
		}
		s, err := m.refByID(ctx, p.ServiceID.String)
		if err != nil || !m.running(ctx, s) {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		if err := m.shipWAL(sctx, s); err != nil {
			m.log.Warn("ship WAL", "service", s.label(), "error", err)
		}
		cancel()
	}
}

func nullInt(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }
