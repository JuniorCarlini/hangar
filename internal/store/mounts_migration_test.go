package store

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

// The stop grace, read-only and shared volume columns keep every existing
// row as it was (default grace, writable, its own volume) and go away on a
// downgrade.
func TestMountMigrationsKeepExistingRows(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "h.db")+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	migrations, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 91); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO projects (id, slug, name, created_at, updated_at) VALUES ('prj_1', 'lab', 'lab', 1, 1)`,
		`INSERT INTO services (id, project_id, slug, image, internal_port, memory_bytes, nano_cpus, pids_limit, command_json, created_at, updated_at)
		 VALUES ('svc_1', 'prj_1', 'db', 'postgres:18', 5432, 1, 1, 1, '[]', 1, 1)`,
		`INSERT INTO service_volumes (service_id, name, path) VALUES ('svc_1', 'data', '/var/lib/postgresql')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.UpTo(ctx, 94); err != nil {
		t.Fatal(err)
	}
	var grace, ro int64
	var owner sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT s.stop_grace_s, v.read_only, v.owner_service_id FROM services s JOIN service_volumes v ON v.service_id = s.id`).Scan(&grace, &ro, &owner); err != nil {
		t.Fatal(err)
	}
	if grace != 0 || ro != 0 || owner.Valid {
		t.Errorf("existing rows changed: grace=%d read_only=%d owner=%v", grace, ro, owner)
	}
	if _, err := p.DownTo(ctx, 91); err != nil {
		t.Fatal(err)
	}
}
