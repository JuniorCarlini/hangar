package backup

import (
	"context"
	"database/sql"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// job is one queued backup.
type job struct {
	actor   Actor
	trigger string
	kind    string // archive.KindDump, KindBase or KindPanel
	service string // service id ("" for the panel)
}

// Enqueue asks for a backup now (button "Fazer backup agora"). It runs in
// the background, after whatever is already queued.
func (m *Manager) Enqueue(ctx context.Context, a Actor, projectSlug, serviceSlug string) error {
	if !m.Ready(ctx) {
		return ErrNotReady
	}
	if projectSlug == "" {
		return m.push(job{actor: a, trigger: TriggerManual, kind: archive.KindPanel})
	}
	s, err := m.ref(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if !m.running(ctx, s) {
		return ErrNotRunning
	}
	if err := m.push(job{actor: a, trigger: TriggerManual, kind: archive.KindDump, service: s.ID}); err != nil {
		return err
	}
	if p, ok := m.ServicePolicy(ctx, s.ID); ok && p.WAL && m.archivingActive(ctx, s) {
		return m.push(job{actor: a, trigger: TriggerManual, kind: archive.KindBase, service: s.ID})
	}
	return nil
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
	m.cleanStaging()

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

// Wait waits for background restores and downloads (shutdown, tests).
func (m *Manager) Wait() { m.wg.Wait() }

func (m *Manager) runJob(ctx context.Context, j job) {
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
	_, _ = m.backupDump(jctx, j.actor, s, j.trigger)
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
		if err != nil || !m.running(ctx, s) {
			continue
		}
		if due {
			_ = m.push(job{actor: System, trigger: TriggerSchedule, kind: archive.KindDump, service: s.ID})
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
