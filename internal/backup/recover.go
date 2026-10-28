package backup

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Disaster recovery (docs/09 "Recuperação de desastre"): after `hangard
// restore` put the panel database and master key back on a new server,
// RecoverAll recreates the networks, brings every PostgreSQL back from its
// newest backup (to a minute with WAL, else the newest pg_dump), the
// volumes of every other service with backups from their newest copy, and
// deploys the remaining services.

// RecoverStep reports progress (a message key and its arguments).
type RecoverStep func(key string, args ...any)

// RecoverAll rebuilds every project on this server from the backups.
func (m *Manager) RecoverAll(ctx context.Context, ids []age.Identity, at time.Time, tr RecoverStep) error {
	n, _, err := m.tasker()
	if err != nil {
		return err
	}
	if at.IsZero() {
		at = m.now()
	}
	all, err := m.q.ListAllServices(ctx)
	if err != nil {
		return err
	}
	projs := map[string]string{}
	for _, s := range all {
		projs[s.ProjectSlug] = s.ProjectID
	}
	for slug, id := range projs {
		if err := n.EnsureProjectNetwork(ctx, id, slug); err != nil {
			return fmt.Errorf("network of %s: %w", slug, err)
		}
	}
	// Databases first, so apps start against their data.
	sort.SliceStable(all, func(i, j int) bool { return all[i].Stateful > all[j].Stateful })
	var errs []error
	for _, s := range all {
		label := s.ProjectSlug + "/" + s.Slug
		if s.DesiredState != "running" {
			continue
		}
		switch m.projects.BackupMethod(ctx, dbq.Service{ID: s.ID, Template: s.Template}) {
		case projects.BackupPGDump:
			tr("recover.database", "service", label)
		case projects.BackupVolume:
			tr("recover.volumes", "service", label)
		default:
			tr("recover.deploy", "service", label)
			r := svcRef{ID: s.ID, Project: s.ProjectSlug, Service: s.Slug}
			if err := m.deployAndWait(ctx, System, r, "restore"); err != nil {
				tr("recover.failed", "service", label, "error", err)
				errs = append(errs, fmt.Errorf("%s: %w", label, err))
			}
			continue
		}
		err := m.RecoverService(ctx, System, s.ProjectSlug, s.Slug, at, ids)
		switch {
		case errors.Is(err, errNoVolumeBackup):
			// Never backed up: it runs, with empty volumes.
			tr("recover.no_copy", "service", label)
		case err != nil:
			tr("recover.failed", "service", label, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
		}
	}
	return errors.Join(errs...)
}

// RecoverService brings one service back on a server where it has no
// data yet: a fresh deploy, then, for a PostgreSQL, point-in-time from
// base + WAL when the bucket has them, else the newest pg_dump before at;
// for a service backed up as volumes, the newest copy before at.
func (m *Manager) RecoverService(ctx context.Context, a Actor, projectSlug, serviceSlug string, at time.Time, ids []age.Identity) error {
	s, err := m.ref(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	unlock := m.lock("restore:" + s.label())
	defer unlock()
	if err := m.deployAndWait(ctx, a, s, "restore"); err != nil {
		return err
	}
	if s.Method == projects.BackupVolume {
		// Read again: the deploy created the volumes.
		if s, err = m.ref(ctx, projectSlug, serviceSlug); err != nil {
			return err
		}
		return m.recoverVolumes(ctx, a, s, at, ids)
	}
	objs, err := m.list(ctx, archive.WALPrefix(s.Project, s.Service))
	if err != nil {
		return err
	}
	if _, perr := archive.PlanRecovery(objs, at); perr == nil {
		return m.restorePITR(ctx, a, "", s, s, at, ids)
	}
	dumps, err := m.Dumps(ctx, s.Project, s.Service)
	if err != nil {
		return err
	}
	for _, d := range dumps { // newest first
		if o, ok := archive.ParseKey(d.Key); ok && o.Kind == archive.KindDump && !d.LastModified.After(at) {
			// The roles it had to create (no password) are logged by
			// prepareRoles.
			_, err := m.restoreDump(ctx, "", s, d.Key, ids)
			return err
		}
	}
	return errors.New("no backup of this database in the destinations")
}
