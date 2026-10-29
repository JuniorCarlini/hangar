package projects

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/pgwal"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// How a service is backed up (docs/09). It is never a user's choice:
// Hangar picks it from the template and the service, and every service
// that keeps data gets one, as a whole (every byte, users and passwords).
const (
	// BackupPGDump: pg_dump and the server's roles, tested in a
	// throwaway PostgreSQL; WAL for any minute.
	BackupPGDump = templates.BackupPGDump
	// BackupRecipe: the template's own dump and restore commands
	// (templates.Recipe), tested in a throwaway instance.
	BackupRecipe = templates.BackupRecipe
	// BackupVolume: a copy of the files of the volumes the service owns,
	// with the service stopped (a database) or paused (anything else).
	BackupVolume = templates.BackupVolume
)

// BackupMethod says how a service is backed up: BackupPGDump or
// BackupRecipe when its template declares one, else BackupVolume when it
// owns volumes (a template's or not), else "" (nothing to back up). A
// volume it mounts from another service is the other's to back up.
func (m *Manager) BackupMethod(ctx context.Context, s dbq.Service) string {
	if t, ok := m.serviceTemplate(s); ok {
		switch t.Backup {
		case BackupPGDump, BackupRecipe:
			return t.Backup
		}
	}
	if m.ownsVolumes(ctx, s.ID) {
		return BackupVolume
	}
	return ""
}

// SnapshotMethod is BackupMethod for a service of a backup before it
// exists on this server: what its template here declares, else a copy of
// the volumes it owns.
func (m *Manager) SnapshotMethod(s ServiceSnapshot) string {
	if t, ok := m.serviceTemplate(dbq.Service{Template: s.Template}); ok {
		switch t.Backup {
		case BackupPGDump, BackupRecipe:
			return t.Backup
		}
	}
	for _, v := range s.Vols {
		if v.From == "" {
			return BackupVolume
		}
	}
	return ""
}

func (m *Manager) serviceTemplate(s dbq.Service) (*templates.Template, bool) {
	if s.Template == "" {
		return nil, false
	}
	return m.catalog().Get(s.Template)
}

// BackupRecipe returns the native recipe of a BackupRecipe service.
func (m *Manager) BackupRecipe(s dbq.Service) (*templates.Recipe, bool) {
	t, ok := m.serviceTemplate(s)
	if !ok || t.Backup != BackupRecipe || t.Recipe == nil {
		return nil, false
	}
	return t.Recipe, true
}

// databaseImages are images of databases and brokers, by repository name
// (the last path element, no tag): copied file by file, they are only
// safe with the server stopped, since a running one keeps pages in memory
// and writes files in an order of its own.
var databaseImages = []string{
	"mysql", "mariadb", "percona", "percona-server", "mongo", "mongodb", "mongodb-community-server",
	"redis", "redis-stack", "redis-stack-server", "valkey", "keydb", "dragonfly", "postgres", "postgis",
	"timescaledb", "timescaledb-ha", "pgvector", "cockroach", "yugabyte", "clickhouse-server",
	"elasticsearch", "opensearch", "influxdb", "questdb", "neo4j", "cassandra", "scylla", "couchdb",
	"couchbase", "arangodb", "rethinkdb", "surrealdb", "etcd", "rabbitmq", "nats", "kafka", "memgraph",
	"typesense", "qdrant", "weaviate", "milvus", "firebird", "mssql-server", "oracle-free", "db2",
}

// IsDatabase reports whether a service is a database (its template's
// category, or a known database image): a copy of its volumes is taken
// with it stopped, never paused.
func (m *Manager) IsDatabase(s dbq.Service) bool {
	if t, ok := m.serviceTemplate(s); ok && t.Category == "database" {
		return true
	}
	return DatabaseImage(s.Image)
}

// DatabaseImage reports whether image is a known database's.
func DatabaseImage(image string) bool {
	name := image
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.Index(name, ":"); i >= 0 {
		name = name[:i]
	}
	return slices.Contains(databaseImages, strings.ToLower(name))
}

// SetTemplateCreated sets what runs right after services are created from
// a template (the catalog, or a compose file's database), before their
// first deploy: the backups give each stateful one its daily routine.
func (m *Manager) SetTemplateCreated(fn func(context.Context, Actor, []dbq.Service)) { m.created = fn }

func (m *Manager) templateCreated(ctx context.Context, a Actor, svcs []dbq.Service) {
	if m.created != nil && len(svcs) > 0 {
		m.created(ctx, a, svcs)
	}
}

func (m *Manager) ownsVolumes(ctx context.Context, serviceID string) bool {
	vols, err := m.q.ListVolumes(ctx, serviceID)
	if err != nil {
		return false
	}
	for _, v := range vols {
		if v.OwnerSlug == "" {
			return true
		}
	}
	return false
}

// OwnedVolume is a volume a service owns, as a backup of it sees it.
type OwnedVolume struct {
	Name   string
	Path   string
	Docker string
	// Users are the services that mount it: the owner first, then the
	// ones that share it. They write to it, so all of them pause.
	Users []string
	// Limit is its disk's size (0: no limit).
	Limit int64
	// Used is what it held at the last measure (-1: not measured).
	Used int64
}

// OwnedVolumes lists the volumes s owns, in name order.
func (m *Manager) OwnedVolumes(ctx context.Context, projectSlug string, s dbq.Service) ([]OwnedVolume, error) {
	all, err := m.ListServiceVolumes(ctx, projectSlug, s)
	if err != nil {
		return nil, err
	}
	var out []OwnedVolume
	for _, v := range all {
		if v.Owner != "" {
			continue
		}
		bv := OwnedVolume{Name: v.Name, Path: v.Path, Docker: v.Docker, Used: v.Used, Users: append([]string{s.Slug}, v.SharedWith...)}
		if v.Limit != nil && (v.Limit.Active() || v.Limit.State == limitNew) {
			bv.Limit = v.Limit.Size
		}
		out = append(out, bv)
	}
	slices.SortFunc(out, func(a, b OwnedVolume) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
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
