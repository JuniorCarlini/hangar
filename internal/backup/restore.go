package backup

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Restore modes and destinations.
const (
	ModePITR          = "pitr"
	ModeDump          = "dump"
	DestNew           = "new"
	DestOverwrite     = "overwrite"
	restoreTimeout    = 3 * time.Hour
	promotionTimeout  = time.Hour
	deployWaitTimeout = 20 * time.Minute
)

// RestoreRequest is the restore form (docs/09 "Restaurar pelo painel").
type RestoreRequest struct {
	Project, Service string
	Mode             string
	At               time.Time // ModePITR: the minute to go back to
	Key              string    // ModeDump: the dump object
	Destination      string
	NewService       string // DestNew
	Confirm          string // DestOverwrite: the service name, typed
	// Identities are the private keys from the kit. They live only in
	// memory, only for this restore (docs/09).
	Identities []age.Identity
}

// Restore is a restore as the UI shows it.
type Restore struct {
	ID          string
	Mode        string
	Point       string
	Destination string
	NewService  string
	Status      string
	Step        string
	Error       string
	StartedAt   time.Time
	FinishedAt  time.Time
}

func toRestore(r dbq.BackupRestore) Restore {
	out := Restore{
		ID: r.ID, Mode: r.Mode, Point: r.Point, Destination: r.Destination, NewService: r.NewService,
		Status: r.Status, Step: r.Step, Error: r.Error.String, StartedAt: time.Unix(r.StartedAt, 0),
	}
	if r.FinishedAt.Valid {
		out.FinishedAt = time.Unix(r.FinishedAt.Int64, 0)
	}
	return out
}

// Restores lists a service's restores, newest first.
func (m *Manager) Restores(ctx context.Context, serviceID string, limit int64) ([]Restore, error) {
	rows, err := m.q.ListServiceRestores(ctx, dbq.ListServiceRestoresParams{ServiceID: nullStr(serviceID), Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Restore, 0, len(rows))
	for _, r := range rows {
		out = append(out, toRestore(r))
	}
	return out, nil
}

// StartRestore validates the request, checks the key opens the chosen
// backup, and runs the restore in the background. It returns the restore
// id; progress is in Restores.
func (m *Manager) StartRestore(ctx context.Context, a Actor, req RestoreRequest) (string, error) {
	if _, _, err := m.tasker(); err != nil {
		return "", err
	}
	s, err := m.ref(ctx, req.Project, req.Service)
	if err != nil {
		return "", err
	}
	req.Identities = m.withServerIdentity(ctx, req.Identities)
	if len(req.Identities) == 0 {
		return "", i18n.E("backup.error.kit")
	}
	var probe string
	switch req.Mode {
	case ModePITR:
		if req.At.IsZero() || req.At.After(m.now().Add(time.Minute)) {
			return "", i18n.E("backup.error.when")
		}
		objs, err := m.list(ctx, archive.WALPrefix(s.Project, s.Service))
		if err != nil {
			return "", err
		}
		plan, err := archive.PlanRecovery(objs, req.At)
		if errors.Is(err, archive.ErrNoBase) {
			return "", i18n.E("backup.error.no_base")
		}
		if err != nil {
			return "", err
		}
		probe = plan.Base.Key
	case ModeDump:
		o, ok := archive.ParseKey(req.Key)
		if !ok || o.Kind != archive.KindDump || o.Project != s.Project || o.Service != s.Service {
			return "", i18n.E("backup.error.point")
		}
		probe = req.Key
	default:
		return "", i18n.E("backup.error.point")
	}
	switch req.Destination {
	case DestNew:
		if !node.SlugRE.MatchString(req.NewService) {
			return "", i18n.E("service.error.slug")
		}
		if _, _, err := m.projects.GetService(ctx, s.Project, req.NewService); err == nil {
			return "", projects.ErrExists
		}
	case DestOverwrite:
		if req.Confirm != s.Service {
			return "", i18n.E("service.danger.name_mismatch")
		}
	default:
		return "", i18n.E("backup.error.point")
	}
	if err := m.keyOpens(ctx, probe, req.Identities); err != nil {
		return "", err
	}
	// Held from here to the end of the restore, so a second request (a
	// second click) cannot slip in before the first one starts.
	unlock, ok := m.tryLock("restore:" + s.label())
	if !ok {
		return "", ErrBusy
	}
	started := false
	defer func() {
		if !started {
			unlock()
		}
	}()

	id := ids.New("bkr_")
	point := req.Key
	if req.Mode == ModePITR {
		point = req.At.UTC().Format(time.RFC3339)
	}
	if err := m.q.CreateBackupRestore(ctx, dbq.CreateBackupRestoreParams{
		ID: id, ServiceID: nullStr(s.ID), Label: s.label(), Mode: req.Mode, Point: point,
		Destination: req.Destination, NewService: req.NewService, Step: "queued",
		CreatedBy: nullStr(a.UserID), StartedAt: m.now().Unix(),
	}); err != nil {
		return "", err
	}
	m.record(ctx, a, "backup.restore.start", "service", s.ID, outcomeOf(nil), map[string]any{
		"service": s.label(), "mode": req.Mode, "point": point, "destination": req.Destination,
		"new_service": req.NewService, "private_key_used": true, "restore": id,
	})
	started = true
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer unlock()
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreTimeout)
		defer cancel()
		err := m.runRestore(rctx, a, id, s, req)
		req.Identities = nil // the key is dropped as soon as the restore ends
		status, errText := "ok", sql.NullString{}
		if err != nil {
			status = "failed"
			errText = sql.NullString{String: truncate(err.Error(), 2000), Valid: true}
			m.log.Warn("restore failed", "service", s.label(), "restore", id, "error", err)
		}
		_ = m.q.FinishBackupRestore(context.WithoutCancel(ctx), dbq.FinishBackupRestoreParams{
			Status: status, Error: errText, FinishedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: id,
		})
		m.record(rctx, a, "backup.restore", "service", s.ID, outcomeOf(err), map[string]any{
			"service": s.label(), "mode": req.Mode, "destination": req.Destination, "restore": id, "error": errText.String,
		})
	}()
	return id, nil
}

// keyOpens reads only the age header of key: a wrong kit fails here, in
// the form, instead of minutes into the restore.
func (m *Manager) keyOpens(ctx context.Context, key string, ids []age.Identity) error {
	rc, _, err := m.fetch(ctx, key)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	if _, err := age.Decrypt(rc, ids...); err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return i18n.E("backup.error.wrong_key")
		}
		return err
	}
	return nil
}

func (m *Manager) step(ctx context.Context, id, step string) {
	if id != "" {
		_ = m.q.SetBackupRestoreStep(context.WithoutCancel(ctx), dbq.SetBackupRestoreStepParams{Step: step, ID: id})
	}
}

// runRestore runs with the service's restore lock held (StartRestore).
func (m *Manager) runRestore(ctx context.Context, a Actor, id string, s svcRef, req RestoreRequest) error {
	if req.Destination == DestOverwrite {
		// docs/09: overwriting first backs up the current state.
		m.step(ctx, id, "pre_backup")
		if _, err := m.backupDump(ctx, a, s, TriggerPreRestore); err != nil {
			return fmt.Errorf("backup of the current state failed, nothing was changed: %w", err)
		}
	}
	t := s
	if req.Destination == DestNew {
		m.step(ctx, id, "create")
		c, err := m.projects.CloneService(ctx, a, s.Project, s.Service, req.NewService)
		if err != nil {
			return err
		}
		if t, err = m.ref(ctx, s.Project, c.Slug); err != nil {
			return err
		}
		m.step(ctx, id, "deploy")
		if err := m.deployAndWait(ctx, a, t, "create"); err != nil {
			return err
		}
	}
	switch req.Mode {
	case ModeDump:
		return m.restoreDump(ctx, id, t, req.Key, req.Identities)
	default:
		return m.restorePITR(ctx, a, id, t, s, req.At, req.Identities)
	}
}

// deployAndWait deploys and waits for the result.
func (m *Manager) deployAndWait(ctx context.Context, a Actor, s svcRef, trigger string) error {
	depID, err := m.projects.Deploy(ctx, a, s.Project, s.Service, trigger)
	if err != nil {
		return err
	}
	deadline := m.now().Add(deployWaitTimeout)
	for m.now().Before(deadline) {
		deps, err := m.projects.Deployments(ctx, s.ID, 5)
		if err != nil {
			return err
		}
		for _, d := range deps {
			if d.ID != depID {
				continue
			}
			switch d.Status {
			case "live":
				return nil
			case "failed":
				return fmt.Errorf("deploy failed: %s", d.Error.String)
			}
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	return errors.New("deploy did not finish in time")
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

var pgReady = []string{"sh", "-c", `pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"`}

func (m *Manager) waitReady(ctx context.Context, s svcRef, timeout time.Duration) error {
	n, _, err := m.tasker()
	if err != nil {
		return err
	}
	deadline := m.now().Add(timeout)
	for {
		if err := n.Exec(ctx, s.Project, s.Service, pgReady, io.Discard); err == nil {
			return nil
		}
		if m.now().After(deadline) {
			return errors.New("the database did not accept connections in time")
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

// pgRestoreCmd restores a custom-format dump read from stdin into the
// service's database, all or nothing.
var pgRestoreCmd = []string{"sh", "-c", `exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --single-transaction --exit-on-error`}

func (m *Manager) restoreDump(ctx context.Context, id string, t svcRef, key string, ids []age.Identity) error {
	_, tk, err := m.tasker()
	if err != nil {
		return err
	}
	m.step(ctx, id, "restore")
	if err := m.waitReady(ctx, t, 5*time.Minute); err != nil {
		return err
	}
	rc, _, err := m.fetch(ctx, key)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	plain, err := archive.Open(rc, ids, archive.DefaultLimits)
	if err != nil {
		return err
	}
	defer func() { _ = plain.Close() }()
	if err := tk.ExecIO(ctx, t.Project, t.Service, pgRestoreCmd, plain, io.Discard); err != nil {
		return fmt.Errorf("pg_restore: %w", err)
	}
	m.step(ctx, id, "done")
	return nil
}

const rollbackScript = `set -eu
[ -d "$PGDATA.before-restore" ] || exit 0
rm -rf "$PGDATA"
mv "$PGDATA.before-restore" "$PGDATA"
`

var (
	inRecoveryCmd = []string{"sh", "-c", `exec psql -AtX -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select pg_is_in_recovery()"`}
	cleanupCmd    = []string{"sh", "-c", `rm -rf "$PGDATA/` + archive.RestoreWALDir + `" "$PGDATA.before-restore"`}
)

// restorePITR replaces t's data with a base backup plus WAL replayed up to
// at. src is where the backups come from (t itself, or the original when
// restoring into a new service).
func (m *Manager) restorePITR(ctx context.Context, a Actor, id string, t, src svcRef, at time.Time, ids []age.Identity) error {
	n, tk, err := m.tasker()
	if err != nil {
		return err
	}
	if t.Volume == "" {
		return ErrUnsupported
	}
	m.step(ctx, id, "plan")
	objs, err := m.list(ctx, archive.WALPrefix(src.Project, src.Service))
	if err != nil {
		return err
	}
	plan, err := archive.PlanRecovery(objs, at)
	if err != nil {
		return err
	}
	m.step(ctx, id, "stop")
	if err := n.Stop(ctx, t.Project, t.Service); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	m.step(ctx, id, "stage")
	pr, pw := io.Pipe()
	go func() { _ = pw.CloseWithError(archive.WriteRecoveryTar(pw, plan, m.opener(ctx), ids)) }()
	spec := node.TaskSpec{
		Image: t.Image, Cmd: []string{"sh", "-c", archive.StageScript},
		Mounts:      []node.TaskMount{{Volume: t.Volume, Path: t.DataPath}},
		MemoryBytes: 256 << 20, NanoCPUs: 1e9, PidsLimit: 128,
	}
	serr := tk.RunTask(ctx, spec, pr, io.Discard)
	_ = pr.CloseWithError(serr)
	if serr == nil {
		m.step(ctx, id, "recover")
		serr = m.deployAndWait(ctx, a, t, "restore")
		if serr == nil {
			serr = m.waitPromoted(ctx, t)
		}
	}
	if serr != nil {
		// Put the previous data back, so a failed restore leaves the
		// service as it was.
		_ = n.Stop(context.WithoutCancel(ctx), t.Project, t.Service)
		spec.Cmd = []string{"sh", "-c", rollbackScript}
		if rerr := tk.RunTask(context.WithoutCancel(ctx), spec, nil, io.Discard); rerr == nil {
			_ = m.deployAndWait(context.WithoutCancel(ctx), a, t, "rollback")
		}
		return serr
	}
	_ = n.Exec(ctx, t.Project, t.Service, cleanupCmd, io.Discard)
	m.step(ctx, id, "done")
	return nil
}

// waitPromoted waits until recovery reached the target and the server
// accepts writes again.
func (m *Manager) waitPromoted(ctx context.Context, t svcRef) error {
	n, _, err := m.tasker()
	if err != nil {
		return err
	}
	deadline := m.now().Add(promotionTimeout)
	for m.now().Before(deadline) {
		var out bytes.Buffer
		if err := n.Exec(ctx, t.Project, t.Service, inRecoveryCmd, &out); err == nil && strings.TrimSpace(out.String()) == "f" {
			return nil
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	return errors.New("recovery did not finish in time")
}

// opener reads objects from the destinations for archive.WriteRecoveryTar.
func (m *Manager) opener(ctx context.Context) archive.Opener {
	return func(key string) (io.ReadCloser, error) {
		rc, _, err := m.fetch(ctx, key)
		return rc, err
	}
}

// Dumps lists the logical backups of a service in the bucket, newest
// first (the restore form's choices).
func (m *Manager) Dumps(ctx context.Context, projectSlug, serviceSlug string) ([]archive.Listed, error) {
	var out []archive.Listed
	for _, folder := range []string{"diario", "semanal", "mensal"} {
		objs, err := m.list(ctx, folder+"/"+projectSlug+"/"+serviceSlug+"/")
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			if p, ok := archive.ParseKey(o.Key); ok && p.Kind == archive.KindDump {
				out = append(out, o)
			}
		}
	}
	sortListed(out)
	return out, nil
}

func sortListed(l []archive.Listed) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j].LastModified.After(l[j-1].LastModified); j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// PITRWindow is the span a point-in-time restore can reach.
type PITRWindow struct {
	From, To time.Time
	OK       bool
}

// Window reads the oldest base backup and the newest WAL in the bucket.
func (m *Manager) Window(ctx context.Context, projectSlug, serviceSlug string) PITRWindow {
	objs, err := m.list(ctx, archive.WALPrefix(projectSlug, serviceSlug))
	if err != nil {
		return PITRWindow{}
	}
	var w PITRWindow
	for _, o := range objs {
		p, ok := archive.ParseKey(o.Key)
		if !ok {
			continue
		}
		if p.Kind == archive.KindBase && (w.From.IsZero() || o.LastModified.Before(w.From)) {
			w.From = o.LastModified
		}
		if o.LastModified.After(w.To) {
			w.To = o.LastModified
		}
	}
	w.OK = !w.From.IsZero()
	return w
}
