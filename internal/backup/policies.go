package backup

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/pgwal"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// PanelPolicyID is the fixed id of the panel's own backup policy.
const PanelPolicyID = "bp_panel"

// How a copy of volumes stays consistent (backup_policies.consistency).
const (
	// ConsistencyPause freezes the services that write to the volumes
	// for the copy (docker pause): they keep their connections and
	// memory, and no file is caught half written. The default.
	ConsistencyPause = "pause"
	// ConsistencyStop stops them for the copy and starts them again:
	// the app shuts down cleanly first (flushes what it keeps in memory).
	ConsistencyStop = "stop"
	// ConsistencyLive copies while they run: no interruption, but a file
	// being written during the copy may come out half done.
	ConsistencyLive = "live"
)

// Consistencies are the choices, the default first.
var Consistencies = []string{ConsistencyPause, ConsistencyStop, ConsistencyLive}

// Policy is a backup schedule.
type Policy struct {
	ID         string
	ServiceID  string // "" = the panel
	Enabled    bool
	EveryHours int
	AtMinute   int
	WAL        bool
	WALSince   time.Time
	NextRun    time.Time
	// Consistency is how a copy of volumes is taken (volume backups).
	Consistency string
}

func toPolicy(p dbq.BackupPolicy) Policy {
	out := Policy{
		ID: p.ID, ServiceID: p.ServiceID.String, Enabled: p.Enabled == 1, EveryHours: int(p.EveryHours),
		AtMinute: int(p.AtMinute), WAL: p.Wal == 1, NextRun: time.Unix(p.NextRunAt, 0), Consistency: p.Consistency,
	}
	if !slices.Contains(Consistencies, out.Consistency) {
		out.Consistency = ConsistencyPause
	}
	if p.WalSince.Valid {
		out.WALSince = time.Unix(p.WalSince.Int64, 0)
	}
	return out
}

// nextRun is the first slot after now: at atMinute past local midnight,
// then every everyHours.
func nextRun(now time.Time, everyHours, atMinute int) time.Time {
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	t := day.Add(time.Duration(atMinute)*time.Minute - 24*time.Hour)
	step := time.Duration(everyHours) * time.Hour
	for !t.After(now) {
		t = t.Add(step)
	}
	return t
}

// ServicePolicy returns the service's policy, or a disabled default.
func (m *Manager) ServicePolicy(ctx context.Context, serviceID string) (Policy, bool) {
	p, err := m.q.GetBackupPolicyByService(ctx, nullStr(serviceID))
	if err != nil {
		return Policy{ServiceID: serviceID, EveryHours: 24, AtMinute: 180, Consistency: ConsistencyPause}, false
	}
	return toPolicy(p), true
}

// PolicyInput is the schedule form.
type PolicyInput struct {
	Enabled     bool
	EveryHours  int
	AtMinute    int
	WAL         bool
	Consistency string // "" keeps ConsistencyPause
}

func (in *PolicyInput) validate() error {
	switch in.EveryHours {
	case 1, 6, 12, 24:
	default:
		return i18n.E("backup.error.schedule")
	}
	if in.AtMinute < 0 || in.AtMinute > 1439 {
		return i18n.E("backup.error.schedule")
	}
	if in.Consistency == "" {
		in.Consistency = ConsistencyPause
	}
	if !slices.Contains(Consistencies, in.Consistency) {
		return i18n.E("backup.error.consistency")
	}
	return nil
}

// SetServicePolicy saves the schedule of a service. Turning WAL on (a
// PostgreSQL only) needs a ready kit and destination (otherwise WAL piles
// up on the server with nowhere to go) and takes effect at the next
// deploy.
func (m *Manager) SetServicePolicy(ctx context.Context, a Actor, projectSlug, serviceSlug string, in PolicyInput) error {
	if err := in.validate(); err != nil {
		return err
	}
	s, err := m.ref(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if in.Enabled && !m.Ready(ctx) {
		return ErrNotReady
	}
	if in.WAL && (s.DataPath == "" || s.Method != projects.BackupPGDump) {
		return ErrUnsupported
	}
	old, existed := m.ServicePolicy(ctx, s.ID)
	id := old.ID
	if !existed {
		id = "bp_" + s.ID
	}
	now := m.now()
	walSince := sql.NullInt64{}
	switch {
	case in.WAL && old.WAL && existed:
		walSince = sql.NullInt64{Int64: old.WALSince.Unix(), Valid: !old.WALSince.IsZero()}
	case in.WAL:
		walSince = sql.NullInt64{Int64: now.Unix(), Valid: true}
	}
	enabled, wal := int64(0), int64(0)
	if in.Enabled {
		enabled = 1
	}
	if in.WAL && in.Enabled {
		wal = 1
	}
	created := now.Unix()
	if err := m.q.UpsertBackupPolicy(ctx, dbq.UpsertBackupPolicyParams{
		ID: id, ServiceID: nullStr(s.ID), Enabled: enabled, EveryHours: int64(in.EveryHours), AtMinute: int64(in.AtMinute),
		Wal: wal, WalSince: walSince, NextRunAt: nextRun(now, in.EveryHours, in.AtMinute).Unix(), Consistency: in.Consistency,
		CreatedAt: created, UpdatedAt: created,
	}); err != nil {
		return err
	}
	summary := map[string]any{
		"service": s.label(), "enabled": in.Enabled, "every_hours": in.EveryHours, "at_minute": in.AtMinute, "wal": in.WAL && in.Enabled,
	}
	if s.Method == projects.BackupVolume {
		summary["consistency"] = in.Consistency
	}
	m.record(ctx, a, "backup.policy.set", "service", s.ID, audit.OK, summary)
	return nil
}

// ensurePanelPolicy creates the panel's daily backup once backups can run.
func (m *Manager) ensurePanelPolicy(ctx context.Context) {
	if _, err := m.q.GetBackupPolicy(ctx, PanelPolicyID); err == nil {
		return
	}
	now := m.now()
	_ = m.q.UpsertBackupPolicy(ctx, dbq.UpsertBackupPolicyParams{
		ID: PanelPolicyID, Enabled: 1, EveryHours: 24, AtMinute: 185,
		NextRunAt: nextRun(now, 24, 185).Unix(), Consistency: ConsistencyPause, CreatedAt: now.Unix(), UpdatedAt: now.Unix(),
	})
}

// ref loads a service that has backups by slugs.
func (m *Manager) ref(ctx context.Context, projectSlug, serviceSlug string) (svcRef, error) {
	p, s, err := m.projects.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return svcRef{}, err
	}
	return m.toRef(ctx, p, s)
}

func (m *Manager) toRef(ctx context.Context, p dbq.Project, s dbq.Service) (svcRef, error) {
	method := m.projects.BackupMethod(ctx, s)
	if method == "" {
		return svcRef{}, ErrUnsupported
	}
	r := svcRef{ID: s.ID, Project: p.Slug, Service: s.Slug, Image: s.Image, Memory: s.MemoryBytes, Method: method}
	if method == projects.BackupVolume {
		var err error
		r.Vols, err = m.projects.OwnedVolumes(ctx, p.Slug, s)
		return r, err
	}
	// Database and user names travel with the backups (object metadata) so
	// hangar-cofre can bring them up without the panel.
	if env, err := m.projects.ListEnv(ctx, s.ID); err == nil {
		for _, e := range env {
			switch e.Key {
			case "POSTGRES_USER":
				r.DBUser = e.Value
			case "POSTGRES_DB":
				r.DBName = e.Value
			}
		}
	}
	vols, err := m.q.ListVolumes(ctx, s.ID)
	if err != nil {
		return r, err
	}
	for _, v := range vols {
		if v.Name == pgwal.DataVolume {
			owner := s.Slug
			if v.OwnerSlug != "" { // the volume of another service it shares
				owner = v.OwnerSlug
			}
			r.DataPath, r.Volume = v.Path, node.VolumeName(p.Slug, owner, v.Name)
		}
	}
	return r, nil
}

// refByID loads a service by id (the scheduler).
func (m *Manager) refByID(ctx context.Context, serviceID string) (svcRef, error) {
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return svcRef{}, err
	}
	all, err := m.q.ListAllServices(ctx)
	if err != nil {
		return svcRef{}, err
	}
	for _, x := range all {
		if x.ID == serviceID {
			p, err := m.projects.GetProject(ctx, x.ProjectSlug)
			if err != nil {
				return svcRef{}, err
			}
			return m.toRef(ctx, p, s)
		}
	}
	return svcRef{}, errors.New("service not found")
}

// running reports whether the service's container is up.
func (m *Manager) running(ctx context.Context, s svcRef) bool {
	st, err := m.projects.Status(ctx, s.Project, s.Service)
	return err == nil && st.Running
}
