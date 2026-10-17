package store

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestOpenCreatesPrivateFileAndMigrates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "hangar.db")

	s, err := Open(context.Background(), path, filepath.Join(dir, "backups"), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("database mode = %o, want 600", mode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Errorf("directory mode = %o, want 700", mode)
	}

	var fk int
	if err := s.DB.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d (%v), want 1", fk, err)
	}
	var mode string
	if err := s.DB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q (%v), want wal", mode, err)
	}
	if _, err := s.DB.Exec("SELECT 1 FROM audit_log LIMIT 1"); err != nil {
		t.Errorf("audit_log table missing: %v", err)
	}
	var av int
	if err := s.DB.QueryRow("PRAGMA auto_vacuum").Scan(&av); err != nil || av != 2 {
		t.Errorf("auto_vacuum = %d (%v), want 2 (incremental)", av, err)
	}
}

func TestMaintainReclaimsSpace(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), filepath.Join(dir, "hangar.db"), filepath.Join(dir, "backups"), discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	big := make([]byte, 4096)
	for i := range 500 {
		if _, err := s.DB.Exec("INSERT INTO settings (key, value_json) VALUES (?, ?)", i, string(big)); err != nil {
			t.Fatal(err)
		}
	}
	before, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("DELETE FROM settings"); err != nil {
		t.Fatal(err)
	}

	after, err := s.Maintain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.SizeBytes >= before.SizeBytes/2 {
		t.Errorf("maintenance did not reclaim space: before %d, after %d", before.SizeBytes, after.SizeBytes)
	}
	if after.FreeBytes != 0 {
		t.Errorf("%d free bytes still not reclaimed", after.FreeBytes)
	}
}

func TestReopenIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hangar.db")
	for range 2 {
		s, err := Open(context.Background(), path, filepath.Join(dir, "backups"), discard)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
	}
	// With no pending migration on the second open, no copy is made.
	if entries, _ := os.ReadDir(filepath.Join(dir, "backups")); len(entries) != 0 {
		t.Errorf("expected no pre-migration copies, found %d", len(entries))
	}
}
