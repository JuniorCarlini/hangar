package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestEnsureAutoVacuumConvertsAnOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hangar.db")
	// A file created before auto_vacuum was set: the plain mode.
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=auto_vacuum(NONE)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("CREATE TABLE x (a INTEGER)"); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	s, err := Open(context.Background(), path, filepath.Join(dir, "backups"), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	var mode int
	_ = s.DB.QueryRow("PRAGMA auto_vacuum").Scan(&mode)
	if mode == 2 {
		t.Fatal("the test file should start without incremental vacuum")
	}
	changed, err := s.EnsureAutoVacuum(ctx)
	if err != nil || !changed {
		t.Fatalf("EnsureAutoVacuum = %v, %v; want a conversion", changed, err)
	}
	_ = s.DB.QueryRow("PRAGMA auto_vacuum").Scan(&mode)
	if mode != 2 {
		t.Fatalf("auto_vacuum = %d, want 2 (incremental)", mode)
	}
	if changed, err := s.EnsureAutoVacuum(ctx); err != nil || changed {
		t.Fatalf("second call = %v, %v; want nothing to do", changed, err)
	}
}
