// Package retention is the panel's janitor: one goroutine that, every hour
// (with jitter), applies the retention policy of docs/20 to everything
// that accumulates, then maintains the SQLite file.
//
// Every rule deletes in small batches (Batch rows per statement, a short
// pause between them, at most MaxBatches per rule and run), so the single
// SQLite writer is never held for long and a large backlog is worked off
// over several runs instead of in one long lock.
package retention

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Policy is how long each kind of record lives. The values and where they
// come from are in docs/20; Default is what the panel uses.
type Policy struct {
	// Metrics (Prometheus/Grafana-style rollups): the charts read 1-minute
	// averages only for the 1 h and 24 h ranges and hourly ones for 7 and
	// 90 days (metrics.Periods), so minutes are kept two days (a margin
	// over the longest range that reads them) and hours 90 days.
	MetricMinutes time.Duration
	MetricHours   time.Duration

	// Certificate decisions of the on-demand TLS ask (docs/03): denials are
	// noise once they stop (a week to notice an attack and block it);
	// approvals exempt a domain from the hourly cap when it renews, so they
	// outlive a certificate (90 days) twice.
	AskDenied  time.Duration
	AskAllowed time.Duration

	// Alerts: 90 days, like PagerDuty/Grafana OnCall incident history. A
	// server alert still firing stays until StaleAlert.
	Alerts           time.Duration
	StaleAlert       time.Duration
	AlertDeliveries  time.Duration
	DeploysPerSvc    int // rows kept per service (Heroku keeps every release; Vercel/Render a history of this order)
	DeployLogsPerSvc int // of those, how many keep their build log

	// Backups: a run's record lives while its object can still be in the
	// bucket (the lifecycle days of its folder, archive.DefaultRetentionDays)
	// plus BackupGrace of history; failed runs have no object.
	BackupGrace  time.Duration
	BackupFailed time.Duration
	Restores     time.Duration // backup and project restores (manual, rare)

	ResolvedFindings time.Duration // vulnerabilities fixed long ago
	ImageProbes      time.Duration // package lists of image digests no longer scanned
	LoginIPs         time.Duration // a known IP unused this long is "new" again
	Invites          time.Duration // after use or expiry
	LogMarks         time.Duration // container logs rotate long before (50 MB x 3)
	TempFiles        time.Duration // leftovers of image scans in data_dir/tmp
}

// Default is the panel's retention policy (docs/20).
var Default = Policy{
	MetricMinutes: 48 * time.Hour, MetricHours: 90 * 24 * time.Hour,
	AskDenied: 7 * 24 * time.Hour, AskAllowed: 180 * 24 * time.Hour,
	Alerts: 90 * 24 * time.Hour, StaleAlert: 365 * 24 * time.Hour, AlertDeliveries: 30 * 24 * time.Hour,
	DeploysPerSvc: 100, DeployLogsPerSvc: 20,
	BackupGrace: 30 * 24 * time.Hour, BackupFailed: 90 * 24 * time.Hour, Restores: 400 * 24 * time.Hour,
	ResolvedFindings: 180 * 24 * time.Hour, ImageProbes: 60 * 24 * time.Hour,
	LoginIPs: 180 * 24 * time.Hour, Invites: 30 * 24 * time.Hour, LogMarks: 30 * 24 * time.Hour,
	TempFiles: 24 * time.Hour,
}

// Batching (see the package comment).
const (
	Batch      = 500
	MaxBatches = 200
	pause      = 20 * time.Millisecond
)

// Every is how often the janitor runs; each wait gets up to ±10 % jitter,
// so many panels started together do not all prune at the same minute.
const Every = time.Hour

// Janitor applies a Policy. Create it with New.
type Janitor struct {
	st      *store.Store
	q       *dbq.Queries
	dataDir string
	log     *slog.Logger
	policy  Policy
	now     func() time.Time
	batch   int64
	pause   time.Duration
}

// New creates the janitor of the panel database; dataDir holds the files
// it also cleans (empty: none).
func New(st *store.Store, dataDir string, log *slog.Logger) *Janitor {
	return &Janitor{
		st: st, q: st.Q, dataDir: dataDir, log: log, policy: Default,
		now: time.Now, batch: Batch, pause: pause,
	}
}

// Report is what one run removed, by rule.
type Report struct {
	Removed map[string]int64
	Stats   store.Stats
}

// rule is one retention step: it returns how many records it removed.
type rule struct {
	name string
	run  func(ctx context.Context, now time.Time) (int64, error)
}

func (j *Janitor) rules() []rule {
	p := j.policy
	return []rule{
		{"metrics", j.pruneMetrics},
		{"tls_ask_log", func(ctx context.Context, now time.Time) (int64, error) {
			hour := now.Unix() / 3600
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneTLSAsks(ctx, dbq.PruneTLSAsksParams{
					DenyBefore: hour - int64(p.AskDenied/time.Hour), AllowBefore: hour - int64(p.AskAllowed/time.Hour), Lim: lim,
				})
			})
		}},
		{"alerts", func(ctx context.Context, now time.Time) (int64, error) {
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneAlertRows(ctx, dbq.PruneAlertRowsParams{
					Before: now.Add(-p.Alerts).Unix(), StaleBefore: now.Add(-p.StaleAlert).Unix(), Lim: lim,
				})
			})
		}},
		{"alert_deliveries", func(ctx context.Context, now time.Time) (int64, error) {
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneAlertDeliveryRows(ctx, dbq.PruneAlertDeliveryRowsParams{Before: now.Add(-p.AlertDeliveries).Unix(), Lim: lim})
			})
		}},
		{"deployments", func(ctx context.Context, _ time.Time) (int64, error) {
			if _, err := j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.TrimDeploymentLogs(ctx, dbq.TrimDeploymentLogsParams{Skip: int64(p.DeployLogsPerSvc - 1), Lim: lim})
			}); err != nil {
				return 0, err
			}
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneDeploymentRows(ctx, dbq.PruneDeploymentRowsParams{Skip: int64(p.DeploysPerSvc - 1), Lim: lim})
			})
		}},
		{"backup_runs", func(ctx context.Context, now time.Time) (int64, error) {
			kept := func(folder string) int64 {
				return now.Add(-time.Duration(archive.DefaultRetentionDays[folder])*24*time.Hour - p.BackupGrace).Unix()
			}
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneBackupRunRows(ctx, dbq.PruneBackupRunRowsParams{
					FailedBefore: now.Add(-p.BackupFailed).Unix(),
					DailyBefore:  kept(archive.FolderOf(archive.ClassDaily)),
					WeeklyBefore: kept(archive.FolderOf(archive.ClassWeekly)),
					PanelBefore:  kept(archive.FolderPanel),
					BaseBefore:   kept(archive.FolderWAL),
					OtherBefore:  kept(archive.FolderOf(archive.ClassMonthly)),
					Lim:          lim,
				})
			})
		}},
		{"restores", func(ctx context.Context, now time.Time) (int64, error) {
			before := now.Add(-p.Restores).Unix()
			n, err := j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneBackupRestoreRows(ctx, dbq.PruneBackupRestoreRowsParams{Before: before, Lim: lim})
			})
			if err != nil {
				return n, err
			}
			m, err := j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneProjectRestoreRows(ctx, dbq.PruneProjectRestoreRowsParams{Before: before, Lim: lim})
			})
			return n + m, err
		}},
		{"dependency_findings", func(ctx context.Context, now time.Time) (int64, error) {
			n, err := j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneResolvedFindings(ctx, dbq.PruneResolvedFindingsParams{Before: nullInt(now.Add(-p.ResolvedFindings).Unix()), Lim: lim})
			})
			if err != nil {
				return n, err
			}
			m, err := j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneFindingIgnoreRows(ctx, dbq.PruneFindingIgnoreRowsParams{Now: nullInt(now.Unix()), Lim: lim})
			})
			if err != nil {
				return n + m, err
			}
			k, err := j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneImageProbeRows(ctx, dbq.PruneImageProbeRowsParams{Before: now.Add(-p.ImageProbes).Unix(), Lim: lim})
			})
			return n + m + k, err
		}},
		{"login_ips", func(ctx context.Context, now time.Time) (int64, error) {
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneLoginIPs(ctx, dbq.PruneLoginIPsParams{Before: now.Add(-p.LoginIPs).Unix(), Lim: lim})
			})
		}},
		{"invites", func(ctx context.Context, now time.Time) (int64, error) {
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneInvites(ctx, dbq.PruneInvitesParams{Before: nullInt(now.Add(-p.Invites).Unix()), Lim: lim})
			})
		}},
		{"log_marks", func(ctx context.Context, now time.Time) (int64, error) {
			return j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneLogMarks(ctx, dbq.PruneLogMarksParams{BeforeNs: now.Add(-p.LogMarks).UnixNano(), Lim: lim})
			})
		}},
		{"audit_log", func(ctx context.Context, now time.Time) (int64, error) {
			n, err := audit.Archive(ctx, j.st.DB, now)
			if err != nil {
				return int64(n), err
			}
			_, err = audit.ExpireArchive(ctx, j.st.DB, now)
			return int64(n), err
		}},
		{"temp_files", j.pruneTemp},
	}
}

// RunOnce applies every rule, then maintains the file. A failing rule is
// logged and the others still run.
func (j *Janitor) RunOnce(ctx context.Context) (Report, error) {
	now := j.now()
	rep := Report{Removed: map[string]int64{}}
	var errs []error
	for _, r := range j.rules() {
		n, err := r.run(ctx, now)
		if n > 0 {
			rep.Removed[r.name] = n
		}
		if err != nil {
			if ctx.Err() != nil {
				return rep, ctx.Err()
			}
			j.log.Warn("retention rule failed", "rule", r.name, "error", err)
			errs = append(errs, err)
		}
	}
	st, err := j.st.Maintain(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	rep.Stats = st
	return rep, errors.Join(errs...)
}

// Run converts an old file to incremental vacuum once, then runs the
// janitor every Every (±10 %) until ctx ends. The first run comes a few
// minutes after start, out of the way of the boot.
func (j *Janitor) Run(ctx context.Context) {
	if changed, err := j.st.EnsureAutoVacuum(ctx); err != nil {
		j.log.Warn("database auto vacuum", "error", err)
	} else if changed {
		j.log.Info("database switched to incremental vacuum")
	}
	wait := 5*time.Minute + jitter(5*time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		start := time.Now()
		rep, err := j.RunOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		level := slog.LevelInfo
		if err != nil || rep.Stats.SizeBytes > store.SizeWarning {
			level = slog.LevelWarn
		}
		attrs := []any{"took", time.Since(start).Round(time.Millisecond), "size_bytes", rep.Stats.SizeBytes, "free_bytes", rep.Stats.FreeBytes}
		for k, n := range rep.Removed {
			attrs = append(attrs, k, n)
		}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		j.log.Log(ctx, level, "retention", attrs...)
		wait = Every - Every/10 + jitter(Every/5)
	}
}

func jitter(span time.Duration) time.Duration {
	return time.Duration(rand.Int64N(int64(span))) //nolint:gosec // scheduling jitter, not a secret
}

// drain repeats one batched delete until a batch comes back short (or
// MaxBatches ran: the rest waits for the next run), pausing between
// batches so other writers get the lock.
func (j *Janitor) drain(ctx context.Context, del func(lim int64) (int64, error)) (int64, error) {
	var total int64
	for range MaxBatches {
		n, err := del(j.batch)
		total += n
		if err != nil || n < j.batch {
			return total, err
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(j.pause):
		}
	}
	return total, nil
}

// pruneMetrics drops minute and hour averages past retention, one history
// key at a time so each delete walks the primary key.
func (j *Janitor) pruneMetrics(ctx context.Context, now time.Time) (int64, error) {
	keys, err := j.q.MetricKeys(ctx)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, key := range keys {
		for _, r := range []struct {
			res  string
			keep time.Duration
		}{{"1m", j.policy.MetricMinutes}, {"1h", j.policy.MetricHours}} {
			n, err := j.drain(ctx, func(lim int64) (int64, error) {
				return j.q.PruneMetricKey(ctx, dbq.PruneMetricKeyParams{Key: key, Resolution: r.res, Before: now.Add(-r.keep).Unix(), Lim: lim})
			})
			total += n
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// pruneTemp removes what image scans left in data_dir/tmp (a crash
// mid-scan); nothing there is meant to outlive a scan.
func (j *Janitor) pruneTemp(_ context.Context, now time.Time) (int64, error) {
	if j.dataDir == "" {
		return 0, nil
	}
	dir := filepath.Join(j.dataDir, "tmp")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < j.policy.TempFiles {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err == nil {
			n++
		}
	}
	return n, nil
}

func nullInt(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }
