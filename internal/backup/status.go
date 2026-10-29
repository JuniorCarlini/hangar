package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Alert thresholds (docs/09: they cannot be turned off).
const (
	StaleAfter = 26 * time.Hour
	WALLagMax  = 5 * time.Minute
)

// Alert kinds.
const (
	AlertNoKit       = "no_kit"
	AlertNoTarget    = "no_target"
	AlertTargetError = "target_error"
	AlertStale       = "stale"
	AlertFailed      = "failed"
	AlertSize        = "size"
	AlertWALLag      = "wal_lag"
	AlertWALRestart  = "wal_restart"
	AlertWALFailing  = "wal_failing"
	AlertRestore     = "restore_failed"
)

// RestoreAlertFor is how long a failed restore stays on the backups page
// (unless a later restore of the same service works).
const RestoreAlertFor = 72 * time.Hour

// Alert is a problem the backups page shows until it is solved.
type Alert struct {
	Kind  string
	Label string // service, destination or "painel"
	Info  string // a size warning code, an error
}

// Run is a backup as the UI shows it.
type Run struct {
	ID        string
	ServiceID string
	Label     string
	Kind      string
	Trigger   string
	Class     string
	Status    string
	Key       string
	Size      int64
	Verified  bool
	Tables    int64
	Rows      int64
	// Files and PauseMS describe a copy of volumes: the entries it holds
	// and how long the services were held for it; Held says how
	// (ConsistencyPause or ConsistencyStop).
	Files   int64
	PauseMS int64
	Held    string
	// Counts are what a recipe's test restore found (tables, rows,
	// users...).
	Counts   []Count
	Warning  string
	Error    string
	Uploads  []upload
	Started  time.Time
	Finished time.Time
}

func toRun(r dbq.BackupRun) Run {
	out := Run{
		ID: r.ID, ServiceID: r.ServiceID.String, Label: r.Label, Kind: r.Kind, Trigger: r.Trigger, Class: r.Class,
		Status: r.Status, Key: r.ObjectKey, Size: r.SizeBytes, Verified: r.Verified == 1, Warning: r.Warning,
		Error: r.Error.String, Started: time.Unix(r.StartedAt, 0),
	}
	if r.FinishedAt.Valid {
		out.Finished = time.Unix(r.FinishedAt.Int64, 0)
	}
	switch r.Kind {
	case archive.KindVolume:
		var c VolumeCheck
		if json.Unmarshal([]byte(r.CheckJson), &c) == nil {
			out.Files, out.PauseMS, out.Held = c.Files, c.PauseMS, c.Mode
		}
	case archive.KindRecipe:
		if c := recipeCheckOf(r); c != nil {
			out.Counts = c.Counts()
		}
	default:
		var c Check
		if json.Unmarshal([]byte(r.CheckJson), &c) == nil {
			out.Tables, out.Rows = c.Tables, c.Rows
		}
	}
	_ = json.Unmarshal([]byte(r.UploadsJson), &out.Uploads)
	return out
}

// UploadSummary is how each destination took a run.
type UploadSummary struct {
	Target string
	OK     bool
}

// UploadList returns the per-destination result.
func (r Run) UploadList() []UploadSummary {
	out := make([]UploadSummary, 0, len(r.Uploads))
	for _, u := range r.Uploads {
		out = append(out, UploadSummary{Target: u.Target, OK: u.OK})
	}
	return out
}

// WALState is the continuous archiving of a service.
type WALState struct {
	LastName      string
	LastAt        time.Time
	Pending       int64
	OldestPending time.Time
	Error         string
	CheckedAt     time.Time
}

// Lagging reports archiving more than WALLagMax behind.
func (w WALState) Lagging(now time.Time) bool {
	return w.Pending > 0 && !w.OldestPending.IsZero() && now.Sub(w.OldestPending) > WALLagMax
}

// Covered reports whether the row's service is backed up by itself: a
// routine is on.
func (r Row) Covered() bool { return r.HasPolicy && r.Policy.Enabled }

// Row is one line of the backups table.
type Row struct {
	Project   string
	Service   string
	ServiceID string
	Label     string
	Running   bool
	Policy    Policy
	HasPolicy bool
	// Kind is the kind of its full backups: a dump, a recipe's backup or a
	// copy of volumes.
	Kind     string
	Last     *Run // newest full backup (or panel) run
	LastOK   *Run
	LastBase *Run
	WAL      *WALState
}

// Overview is the backups page.
type Overview struct {
	Recipients []Recipient
	Targets    []Target
	Ready      bool
	Mode       string // ModeSimple or ModeKit
	Services   []Row
	Panel      Row
	Runs       []Run
	Restores   []Restore // the newest restores of every service
	Alerts     []Alert
}

func (m *Manager) lastRun(ctx context.Context, label, kind string, okOnly bool) *Run {
	var r dbq.BackupRun
	var err error
	if okOnly {
		r, err = m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: label, Kind: kind})
	} else {
		r, err = m.q.LastBackupRun(ctx, dbq.LastBackupRunParams{Label: label, Kind: kind})
	}
	if err != nil {
		return nil
	}
	run := toRun(r)
	return &run
}

func (m *Manager) walState(ctx context.Context, serviceID string) *WALState {
	w, err := m.q.GetWALStatus(ctx, serviceID)
	if errors.Is(err, sql.ErrNoRows) || err != nil {
		return nil
	}
	st := &WALState{LastName: w.LastArchivedWal, Pending: w.Pending, Error: w.LastError, CheckedAt: time.Unix(w.CheckedAt, 0)}
	if w.LastArchivedAt.Valid {
		st.LastAt = time.Unix(w.LastArchivedAt.Int64, 0)
	}
	if w.OldestPendingAt.Valid {
		st.OldestPending = time.Unix(w.OldestPendingAt.Int64, 0)
	}
	return st
}

// Overview gathers everything the backups page shows.
func (m *Manager) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	var err error
	if o.Recipients, err = m.Recipients(ctx); err != nil {
		return o, err
	}
	if o.Targets, err = m.Targets(ctx); err != nil {
		return o, err
	}
	o.Ready = m.Ready(ctx)
	o.Mode = m.Mode(ctx)
	all, err := m.q.ListAllServices(ctx)
	if err != nil {
		return o, err
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].ProjectSlug != all[j].ProjectSlug {
			return all[i].ProjectSlug < all[j].ProjectSlug
		}
		return all[i].Slug < all[j].Slug
	})
	// Every service that keeps data is listed, with a routine or not: the
	// ones without one show as not backed up.
	for _, s := range all {
		kind := archive.KindDump
		switch m.projects.BackupMethod(ctx, dbq.Service{ID: s.ID, Template: s.Template}) {
		case projects.BackupPGDump:
		case projects.BackupRecipe:
			kind = archive.KindRecipe
		case projects.BackupVolume:
			kind = archive.KindVolume
		default:
			continue
		}
		row := Row{Project: s.ProjectSlug, Service: s.Slug, ServiceID: s.ID, Label: s.ProjectSlug + "/" + s.Slug, Kind: kind}
		row.Policy, row.HasPolicy = m.ServicePolicy(ctx, s.ID)
		row.Last = m.lastRun(ctx, row.Label, kind, false)
		row.LastOK = m.lastRun(ctx, row.Label, kind, true)
		row.LastBase = m.lastRun(ctx, row.Label, archive.KindBase, true)
		if row.Policy.WAL {
			row.WAL = m.walState(ctx, s.ID)
		}
		if st, err := m.projects.Status(ctx, s.ProjectSlug, s.Slug); err == nil {
			row.Running = st.Running
		}
		o.Services = append(o.Services, row)
	}
	o.Panel = Row{Label: PanelLabel}
	if p, err := m.q.GetBackupPolicy(ctx, PanelPolicyID); err == nil {
		o.Panel.Policy, o.Panel.HasPolicy = toPolicy(p), true
	}
	o.Panel.Last = m.lastRun(ctx, PanelLabel, archive.KindPanel, false)
	o.Panel.LastOK = m.lastRun(ctx, PanelLabel, archive.KindPanel, true)
	runs, err := m.q.ListBackupRuns(ctx, 30)
	if err != nil {
		return o, err
	}
	for _, r := range runs {
		o.Runs = append(o.Runs, toRun(r))
	}
	restores, err := m.q.ListRestores(ctx, 50)
	if err != nil {
		return o, err
	}
	for _, r := range restores {
		o.Restores = append(o.Restores, toRestore(r))
	}
	o.Alerts = m.alerts(o)
	return o, nil
}

// alerts derives what is wrong from an overview.
func (m *Manager) alerts(o Overview) []Alert {
	var out []Alert
	confirmed := false
	for _, r := range o.Recipients {
		confirmed = confirmed || r.Confirmed
	}
	if !confirmed && o.Mode != ModeSimple {
		out = append(out, Alert{Kind: AlertNoKit})
	}
	if len(o.Targets) == 0 {
		out = append(out, Alert{Kind: AlertNoTarget})
	}
	for _, t := range o.Targets {
		if t.CheckError != "" {
			out = append(out, Alert{Kind: AlertTargetError, Label: t.Name, Info: t.CheckError})
		}
	}
	now := m.now()
	check := func(r Row, policyAge time.Time) {
		if !r.HasPolicy || !r.Policy.Enabled || !o.Ready {
			return
		}
		if r.Last != nil && r.Last.Status == "failed" {
			out = append(out, Alert{Kind: AlertFailed, Label: r.Label, Info: r.Last.Error})
		}
		if (r.LastOK == nil && now.Sub(policyAge) > StaleAfter) || (r.LastOK != nil && now.Sub(r.LastOK.Started) > StaleAfter) {
			out = append(out, Alert{Kind: AlertStale, Label: r.Label})
		}
		if r.LastOK != nil && r.LastOK.Warning != "" && (r.Last == nil || r.Last.ID == r.LastOK.ID) {
			out = append(out, Alert{Kind: AlertSize, Label: r.Label, Info: r.LastOK.Warning})
		}
		if w := r.WAL; w != nil {
			switch {
			case w.Error == WALRestartNeeded:
				out = append(out, Alert{Kind: AlertWALRestart, Label: r.Label})
			case w.Error == WALArchiveFails:
				out = append(out, Alert{Kind: AlertWALFailing, Label: r.Label})
			case w.Lagging(now) || (w.Error != "" && now.Sub(w.CheckedAt) < time.Hour && w.Pending > 0):
				out = append(out, Alert{Kind: AlertWALLag, Label: r.Label, Info: w.Error})
			}
		}
	}
	for _, r := range o.Services {
		check(r, r.Policy.NextRun.Add(-time.Duration(r.Policy.EveryHours)*time.Hour))
	}
	check(o.Panel, o.Panel.Policy.NextRun.Add(-24*time.Hour))
	// A failed restore is said where the backups are, not only in the
	// service's tab: the owner must not think it worked.
	seen := map[string]bool{}
	for _, r := range o.Restores { // newest first
		if seen[r.Source] {
			continue
		}
		seen[r.Source] = true
		if r.Status == "failed" && now.Sub(r.FinishedAt) < RestoreAlertFor {
			out = append(out, Alert{Kind: AlertRestore, Label: r.Source, Info: r.Error})
		}
	}
	return out
}

// AlertCount is the number of backup problems (the menu badge). Every
// page asks, so it is cached for half a minute.
func (m *Manager) AlertCount(ctx context.Context) int {
	m.alertMu.Lock()
	defer m.alertMu.Unlock()
	if m.now().Before(m.alertAt.Add(30 * time.Second)) {
		return m.alertN
	}
	o, err := m.Overview(ctx)
	if err != nil {
		return m.alertN
	}
	n := 0
	for _, a := range o.Alerts {
		if a.Kind != AlertNoKit && a.Kind != AlertNoTarget {
			n++
		}
	}
	m.alertN, m.alertAt = n, m.now()
	return n
}

// ServiceRuns lists a service's recent backups.
func (m *Manager) ServiceRuns(ctx context.Context, serviceID string, limit int64) ([]Run, error) {
	rows, err := m.q.ListServiceBackupRuns(ctx, dbq.ListServiceBackupRunsParams{ServiceID: nullStr(serviceID), Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Run, 0, len(rows))
	for _, r := range rows {
		out = append(out, toRun(r))
	}
	return out, nil
}

// ServiceWAL is the WAL state of a service (nil when off).
func (m *Manager) ServiceWAL(ctx context.Context, serviceID string) *WALState {
	return m.walState(ctx, serviceID)
}
