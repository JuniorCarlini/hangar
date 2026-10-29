package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgroles"
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
	// Source is the service restored from ("project/service").
	Source string
	// CreatedRoles are the roles the restore created without a password:
	// the app cannot log in with them until they get one.
	CreatedRoles []string
	// SavedRoles are the roles the restore recreated from the roles saved
	// with the dump, as they were (same password).
	SavedRoles []string
	// Cleanup says what happened to the new service of a failed restore
	// into a new service: CleanupRemoved or CleanupKept.
	Cleanup string
}

// Cleanup outcomes of a failed restore into a new service.
const (
	CleanupRemoved = "removed"
	CleanupKept    = "kept"
)

func toRestore(r dbq.BackupRestore) Restore {
	out := Restore{
		ID: r.ID, Mode: r.Mode, Point: r.Point, Destination: r.Destination, NewService: r.NewService,
		Status: r.Status, Step: r.Step, Error: r.Error.String, StartedAt: time.Unix(r.StartedAt, 0),
		Source: r.Label, Cleanup: r.Cleanup,
	}
	if r.FinishedAt.Valid {
		out.FinishedAt = time.Unix(r.FinishedAt.Int64, 0)
	}
	_ = json.Unmarshal([]byte(r.CreatedRoles), &out.CreatedRoles)
	_ = json.Unmarshal([]byte(r.SavedRoles), &out.SavedRoles)
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

// ServiceRestores lists, newest first, the restores of a service and the
// ones that created it as a new service: the copy shows where it came
// from and what is left to do (passwords of the roles a restore created).
func (m *Manager) ServiceRestores(ctx context.Context, projectSlug string, s dbq.Service, limit int64) ([]Restore, error) {
	rows, err := m.q.ListServiceRestoresBoth(ctx, dbq.ListServiceRestoresBothParams{
		ServiceID: nullStr(s.ID), Slug: s.Slug, LabelPrefix: projectSlug + "/%", CreatedAt: s.CreatedAt, Lim: limit,
	})
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
		if s.Method != projects.BackupPGDump {
			return "", i18n.E("backup.error.point")
		}
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
		// The mode is "a backup file": a dump, a recipe's backup or a
		// copy of the volumes, as the service is backed up (the key says
		// which).
		if !ok || o.Kind != s.kind() || o.Project != s.Project || o.Service != s.Service {
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
func (m *Manager) runRestore(ctx context.Context, a Actor, id string, s svcRef, req RestoreRequest) (err error) {
	switch s.Method {
	case projects.BackupVolume:
		return m.runVolumeRestore(ctx, a, id, s, req)
	case projects.BackupRecipe:
		return m.runRecipeRestore(ctx, a, id, s, req)
	}
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
		c, cerr := m.projects.CloneService(ctx, a, s.Project, s.Service, req.NewService)
		if cerr != nil {
			return cerr
		}
		// From here on the new service exists: if the restore fails, it
		// goes away with its container and disks, instead of staying up
		// with an empty (or half restored) database that looks restored.
		defer func() {
			if err != nil {
				m.dropNewService(ctx, a, id, s, c.Slug)
			}
		}()
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
		roles, rerr := m.restoreDump(ctx, id, t, req.Key, req.Identities)
		m.recordRoles(ctx, id, roles)
		return rerr
	default:
		return m.restorePITR(ctx, a, id, t, s, req.At, req.Identities)
	}
}

// dropNewService removes the service a failed restore created. It is only
// ever the new one: never the service restored from.
func (m *Manager) dropNewService(ctx context.Context, a Actor, id string, src svcRef, slug string) {
	if slug == "" || slug == src.Service {
		return
	}
	ctx = context.WithoutCancel(ctx)
	outcome := CleanupRemoved
	if err := m.projects.DeleteService(ctx, a, src.Project, slug); err != nil {
		outcome = CleanupKept
		m.log.Warn("remove the service of a failed restore", "service", src.Project+"/"+slug, "restore", id, "error", err)
	}
	if id != "" {
		_ = m.q.SetBackupRestoreCleanup(ctx, dbq.SetBackupRestoreCleanupParams{Cleanup: outcome, ID: id})
	}
}

// recordRoles keeps the roles a restore recreated (as in the original) and
// the ones it created without a password, by name. They stay even when
// the restore then fails: they are in the server now.
func (m *Manager) recordRoles(ctx context.Context, id string, roles RolesDone) {
	if id == "" {
		return
	}
	ctx = context.WithoutCancel(ctx)
	if len(roles.NoLogin) > 0 {
		j, _ := json.Marshal(roles.NoLogin)
		_ = m.q.SetBackupRestoreRoles(ctx, dbq.SetBackupRestoreRolesParams{CreatedRoles: string(j), ID: id})
	}
	if len(roles.Saved) > 0 {
		j, _ := json.Marshal(roles.Saved)
		_ = m.q.SetBackupRestoreSavedRoles(ctx, dbq.SetBackupRestoreSavedRolesParams{SavedRoles: string(j), ID: id})
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
// service's database, all or nothing, with the owners and permissions of
// the original: the roles they name were recreated first (applyRoles,
// prepareRoles).
var pgRestoreCmd = []string{"sh", "-c", `exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --single-transaction --exit-on-error`}

// pgRestoreNoOwnerCmd is pgRestoreCmd for a dump saved without the roles
// of its server (made before they were saved): objects belong to whoever
// restores, as such a restore always did.
var pgRestoreNoOwnerCmd = []string{"sh", "-c", `exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --single-transaction --exit-on-error`}

// pgSchemaCmd prints, as SQL, the schema part of a custom-format dump read
// from stdin (no data), then reads the rest of the input so the sender
// never writes into a closed pipe.
var pgSchemaCmd = []string{"sh", "-c", `pg_restore --schema-only -f - ; s=$?; cat >/dev/null; exit $s`}

// pgSchemaCreateCmd is pgSchemaCmd with the database-level entries too
// (--create): the database's owner, settings, comment and GRANTs.
var pgSchemaCreateCmd = []string{"sh", "-c", `pg_restore --create --schema-only -f - ; s=$?; cat >/dev/null; exit $s`}

// pgScriptCmd runs a psql script read from stdin as the service's own
// superuser. Errors are terse: PostgreSQL does not quote the statement
// (a roles script holds password hashes).
var pgScriptCmd = []string{"sh", "-c", `exec psql -qAtX -v ON_ERROR_STOP=1 -v VERBOSITY=terse -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f -`}

// pgDatabaseCmd runs pgroles.DatabaseScript in the service's database,
// named by its own environment.
var pgDatabaseCmd = []string{"sh", "-c", `exec psql -qAtX -v ON_ERROR_STOP=1 -v VERBOSITY=terse -v ` + pgroles.DatabaseVar + `="$POSTGRES_DB" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f -`}

// RolesDone is what a restore did about the roles of the original server.
type RolesDone struct {
	// Saved were recreated from the roles saved with the dump, as they
	// were: attributes, password hash, memberships, settings.
	Saved []string
	// NoLogin were created without a password (NOLOGIN): the dump
	// names them and no saved role (or the server) has them.
	NoLogin []string
}

// restoreDump restores the dump key into t as a copy of the original: the
// server's roles saved with it first (only the ones t lacks, as they were;
// roles that exist are never touched), then the data with its owners and
// permissions, then the database's own settings and GRANTs. A dump saved
// before roles were kept restores as it always did: the roles it names are
// created without a password and objects belong to whoever restores. It
// returns what it did about roles, also when it fails after.
func (m *Manager) restoreDump(ctx context.Context, id string, t svcRef, key string, ids []age.Identity) (RolesDone, error) {
	var done RolesDone
	_, tk, err := m.tasker()
	if err != nil {
		return done, err
	}
	m.step(ctx, id, "restore")
	if err := m.waitReady(ctx, t, 5*time.Minute); err != nil {
		return done, err
	}
	g, saved, err := m.loadRoles(ctx, key, ids)
	if err != nil {
		return done, err
	}
	if saved {
		if done.Saved, err = m.applyRoles(ctx, t, g); err != nil {
			return done, err
		}
	}
	schema, err := m.prepareRoles(ctx, t, key, ids, saved)
	done.NoLogin = schema.Roles
	if err != nil {
		return done, err
	}
	rc, _, err := m.fetch(ctx, key)
	if err != nil {
		return done, err
	}
	defer func() { _ = rc.Close() }()
	plain, err := archive.Open(rc, ids, archive.DefaultLimits)
	if err != nil {
		return done, err
	}
	defer func() { _ = plain.Close() }()
	cmd := pgRestoreNoOwnerCmd
	if saved {
		cmd = pgRestoreCmd
	}
	if err := tk.ExecIO(ctx, t.Project, t.Service, cmd, plain, io.Discard); err != nil {
		return done, fmt.Errorf("pg_restore: %w", err)
	}
	if script := pgroles.DatabaseScript(schema.Database); saved && script != "" {
		if err := tk.ExecIO(ctx, t.Project, t.Service, pgDatabaseCmd, strings.NewReader(script), io.Discard); err != nil {
			return done, fmt.Errorf("apply the database settings: %w", err)
		}
	}
	m.step(ctx, id, "done")
	return done, nil
}

// applyRoles recreates in t's server the roles saved with the dump that it
// lacks, exactly as they were (pgroles ApplyScript), and returns them.
// Password hashes stay out of errors and logs.
func (m *Manager) applyRoles(ctx context.Context, t svcRef, g pgroles.Globals) ([]string, error) {
	_, tk, err := m.tasker()
	if err != nil {
		return nil, err
	}
	script, err := g.ApplyScript()
	if err != nil || script == "" {
		return nil, err
	}
	var out bytes.Buffer
	if err := tk.ExecIO(ctx, t.Project, t.Service, pgScriptCmd, strings.NewReader(script), &out); err != nil {
		return nil, errors.New("recreate the roles of the backup: " + g.Redact(err.Error()))
	}
	saved := pgroles.ParseSaved(out.String())
	if len(saved) > 0 {
		m.log.Info("restore recreated roles as in the original", "service", t.label(), "roles", saved)
	}
	return saved, nil
}

// prepareRoles creates in t's server the roles the dump names that it
// still lacks, so the restore can apply the dump's permissions (and, with
// owners, its ownership) as they were in the original. Roles are not in a
// pg_dump (they belong to the server, not the database): with the roles
// saved next to the dump (applyRoles) only the original's own superuser
// can be missing here; for a dump saved without them, every app role is.
// They are created without a password and cannot log in (NOLOGIN) until
// the owner sets one; existing roles are never touched. It reads the dump
// once more for this (only its schema reaches the database container) and
// returns the roles it created in Schema.Roles, and the database-level
// statements when owners is set.
func (m *Manager) prepareRoles(ctx context.Context, t svcRef, key string, ids []age.Identity, owners bool) (pgroles.Schema, error) {
	var none pgroles.Schema
	_, tk, err := m.tasker()
	if err != nil {
		return none, err
	}
	rc, _, err := m.fetch(ctx, key)
	if err != nil {
		return none, err
	}
	defer func() { _ = rc.Close() }()
	plain, err := archive.Open(rc, ids, archive.DefaultLimits)
	if err != nil {
		return none, err
	}
	defer func() { _ = plain.Close() }()
	type found struct {
		schema pgroles.Schema
		err    error
	}
	pr, pw := io.Pipe()
	done := make(chan found, 1)
	go func() {
		s, err := pgroles.ReadSchema(pr, owners)
		_, _ = io.Copy(io.Discard, pr)
		done <- found{s, err}
	}()
	cmd := pgSchemaCmd
	if owners {
		cmd = pgSchemaCreateCmd
	}
	err = tk.ExecIO(ctx, t.Project, t.Service, cmd, plain, pw)
	_ = pw.CloseWithError(err)
	f := <-done
	if err != nil {
		return none, fmt.Errorf("read the roles of the dump: %w", err)
	}
	if f.err != nil {
		return none, fmt.Errorf("read the roles of the dump: %w", f.err)
	}
	out := pgroles.Schema{Database: f.schema.Database}
	script, err := pgroles.CreateScript(f.schema.Roles)
	if err != nil || script == "" {
		return out, err
	}
	var res bytes.Buffer
	if err := tk.ExecIO(ctx, t.Project, t.Service, pgScriptCmd, strings.NewReader(script), &res); err != nil {
		return out, fmt.Errorf("create the roles of the dump: %w", err)
	}
	out.Roles = pgroles.ParseCreated(res.String())
	if len(out.Roles) > 0 {
		m.log.Info("restore created roles without a password", "service", t.label(), "roles", out.Roles)
	}
	return out, nil
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

// Dumps lists the backups a whole service restores from (its dumps, or
// its copies of volumes) in the bucket, newest first (the restore form's
// choices).
func (m *Manager) Dumps(ctx context.Context, projectSlug, serviceSlug string) ([]archive.Listed, error) {
	var out []archive.Listed
	for _, folder := range []string{"diario", "semanal", "mensal"} {
		objs, err := m.list(ctx, folder+"/"+projectSlug+"/"+serviceSlug+"/")
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			if p, ok := archive.ParseKey(o.Key); ok && archive.IsPoint(p.Kind) {
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
