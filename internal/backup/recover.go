package backup

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
)

// Disaster recovery (docs/09 "Recuperação de desastre"): after `hangard
// restore` put the panel database and master key back on a new server,
// RecoverAll recreates the networks, brings every PostgreSQL back from its
// newest backup (to a minute with WAL, else the newest pg_dump) and
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
	projects := map[string]string{}
	for _, s := range all {
		projects[s.ProjectSlug] = s.ProjectID
	}
	for slug, id := range projects {
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
		if m.projects.CanDownloadBackup(s.Template) {
			tr("recover.database", "service", label)
			if err := m.RecoverService(ctx, System, s.ProjectSlug, s.Slug, at, ids); err != nil {
				tr("recover.failed", "service", label, "error", err)
				errs = append(errs, fmt.Errorf("%s: %w", label, err))
			}
			continue
		}
		tr("recover.deploy", "service", label)
		r := svcRef{ID: s.ID, Project: s.ProjectSlug, Service: s.Slug}
		if err := m.deployAndWait(ctx, System, r, "restore"); err != nil {
			tr("recover.failed", "service", label, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
		}
	}
	return errors.Join(errs...)
}

// RecoverService brings one PostgreSQL back on a server where it has no
// data yet: a fresh deploy, then point-in-time from base + WAL when the
// bucket has them, else the newest pg_dump before at.
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
		if !d.LastModified.After(at) {
			return m.restoreDump(ctx, "", s, d.Key, ids)
		}
	}
	return errors.New("no backup of this database in the destinations")
}
