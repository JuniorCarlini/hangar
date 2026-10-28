package projects

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/pgwal"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// CanDownloadBackup reports whether the service's template supports "Download
// backup".
func (m *Manager) CanDownloadBackup(template string) bool {
	t, ok := m.catalog().Get(template)
	return ok && t.Backup == "pg_dump"
}

// walEnabled reports whether the service's backup policy archives WAL.
func (m *Manager) walEnabled(ctx context.Context, serviceID string) bool {
	n, err := m.q.WALEnabled(ctx, sql.NullString{String: serviceID, Valid: true})
	return err == nil && n > 0
}

// withWALArchiving appends the archiving options to a PostgreSQL command
// when its backup policy asks for continuous WAL (docs/09). The stored
// command stays as the user left it.
func (m *Manager) withWALArchiving(ctx context.Context, s dbq.Service, cmd []string, vols []node.Volume) []string {
	if !m.walEnabled(ctx, s.ID) || !pgwal.Supports(cmd) {
		return cmd
	}
	for _, v := range vols {
		if v.Name == pgwal.DataVolume {
			return append(append([]string(nil), cmd...), pgwal.Args(v.Path)...)
		}
	}
	return cmd
}

// CloneService copies a service under a new name without deploying it:
// image, command, limits, healthcheck, volume definitions (new, empty
// volumes), variables and exports. Exports that name the original
// container point to the copy. Restores use it to bring a backup up next
// to the original (docs/09: restore into a new service by default).
func (m *Manager) CloneService(ctx context.Context, a Actor, projectSlug, sourceSlug, newSlug string) (dbq.Service, error) {
	p, src, err := m.GetService(ctx, projectSlug, sourceSlug)
	if err != nil {
		return dbq.Service{}, err
	}
	if !node.SlugRE.MatchString(newSlug) {
		return dbq.Service{}, i18n.E("service.error.slug")
	}
	if _, err := m.q.GetService(ctx, dbq.GetServiceParams{ProjectID: p.ID, Slug: newSlug}); err == nil {
		return dbq.Service{}, ErrExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return dbq.Service{}, err
	}
	vols, err := m.q.ListVolumes(ctx, src.ID)
	if err != nil {
		return dbq.Service{}, err
	}
	env, err := m.q.ListEnv(ctx, src.ID)
	if err != nil {
		return dbq.Service{}, err
	}
	exps, err := m.q.ListExports(ctx, src.ID)
	if err != nil {
		return dbq.Service{}, err
	}
	oldName, newName := node.ContainerName(p.Slug, src.Slug), node.ContainerName(p.Slug, newSlug)

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return dbq.Service{}, err
	}
	defer func() { _ = tx.Rollback() }()
	q := m.q.WithTx(tx)
	now := m.now().Unix()
	id := ids.New("svc_")
	if err := q.CreateService(ctx, dbq.CreateServiceParams{
		ID: id, ProjectID: p.ID, Slug: newSlug, Image: src.Image, InternalPort: src.InternalPort,
		MemoryBytes: src.MemoryBytes, NanoCpus: src.NanoCpus, PidsLimit: src.PidsLimit, ReadOnly: src.ReadOnly,
		CommandJson: src.CommandJson, Template: src.Template, Stateful: src.Stateful,
		HealthJson: src.HealthJson, CapAddJson: src.CapAddJson, StopGraceS: src.StopGraceS, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return dbq.Service{}, err
	}
	for _, v := range vols {
		// The copy gets volumes of its own, even where the original
		// mounts another service's: a restore must never write there.
		if err := q.AddVolume(ctx, dbq.AddVolumeParams{ServiceID: id, Name: v.Name, Path: v.Path, ReadOnly: v.ReadOnly}); err != nil {
			return dbq.Service{}, err
		}
	}
	for _, e := range env {
		plain, err := m.box.Open(e.ValueEnc, envAD(src.ID, e.Key))
		if err != nil {
			return dbq.Service{}, err
		}
		sealed, err := m.box.Seal(plain, envAD(id, e.Key))
		if err != nil {
			return dbq.Service{}, err
		}
		if err := q.UpsertEnv(ctx, dbq.UpsertEnvParams{ServiceID: id, Key: e.Key, ValueEnc: sealed, Secret: e.Secret, UpdatedAt: now}); err != nil {
			return dbq.Service{}, err
		}
	}
	for _, e := range exps {
		plain, err := m.box.Open(e.ValueEnc, exportAD(src.ID, e.Key))
		if err != nil {
			return dbq.Service{}, err
		}
		value := strings.ReplaceAll(string(plain), oldName, newName)
		sealed, err := m.box.Seal([]byte(value), exportAD(id, e.Key))
		if err != nil {
			return dbq.Service{}, err
		}
		if err := q.UpsertExport(ctx, dbq.UpsertExportParams{ServiceID: id, Key: e.Key, ValueEnc: sealed, Secret: e.Secret}); err != nil {
			return dbq.Service{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return dbq.Service{}, err
	}
	m.record(ctx, a, "service.create", "service", id, audit.OK,
		map[string]any{"project": p.Slug, "service": newSlug, "image": src.Image, "copy_of": src.Slug})
	return m.q.GetServiceByID(ctx, id)
}

// Node exposes the container node to the backup package (nil without
// Docker).
func (m *Manager) Node() node.Node { return m.node }
