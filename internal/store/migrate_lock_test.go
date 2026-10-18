package store

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestTimedLockMigrationOpensOldLocks: an account left locked for good by
// the old rule (only SSH could open it) gets a short lock counted from when
// it was locked, so in practice it opens again after the update.
func TestTimedLockMigrationOpensOldLocks(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "h.db"))
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
	if _, err := p.UpTo(ctx, 88); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, failed_logins, locked_at, created_at, updated_at)
		VALUES ('usr_1', 'a@hangar.dev', 'x', 'owner', 20, 1000, 1, 1), ('usr_2', 'b@hangar.dev', 'x', 'admin', 3, NULL, 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 89); err != nil {
		t.Fatal(err)
	}

	var until sql.NullInt64
	var count, failed int64
	if err := db.QueryRow("SELECT locked_until, lock_count, failed_logins FROM users WHERE id = 'usr_1'").Scan(&until, &count, &failed); err != nil {
		t.Fatal(err)
	}
	if !until.Valid || until.Int64 != 1900 || count != 1 || failed != 0 {
		t.Errorf("old lock became until=%v count=%d failed=%d, want 1900/1/0", until, count, failed)
	}
	if err := db.QueryRow("SELECT locked_until, lock_count, failed_logins FROM users WHERE id = 'usr_2'").Scan(&until, &count, &failed); err != nil {
		t.Fatal(err)
	}
	if until.Valid || count != 0 || failed != 3 {
		t.Errorf("unlocked account changed: until=%v count=%d failed=%d", until, count, failed)
	}

	// And back down, for a downgrade.
	if _, err := p.DownTo(ctx, 88); err != nil {
		t.Fatal(err)
	}
}
