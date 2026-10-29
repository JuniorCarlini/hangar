package store

import (
	"context"
	"fmt"
)

// Stats is the database size after maintenance.
type Stats struct {
	SizeBytes int64 // used + free pages
	FreeBytes int64 // free pages not yet returned to disk
}

// vacuumPages bounds how many free pages one Maintain returns to the disk
// (16 MB at the default 4 KB page): incremental_vacuum holds the write
// lock while it works, and what is left goes on the next run.
const vacuumPages = 4096

// Maintain empties the WAL into the database, returns up to vacuumPages
// free pages to the disk and refreshes the query planner statistics. It is
// cheap; the retention janitor runs it after every pass (docs/20).
//
// Why incremental vacuum and not a periodic VACUUM: the database is
// created with auto_vacuum=INCREMENTAL (see Open, and EnsureAutoVacuum for
// older files), so freed pages go back to the disk a bounded batch at a
// time without rewriting the file. A full VACUUM rewrites everything,
// needs twice the space and blocks every writer for the whole copy; with
// retention keeping the file small, fragmentation never pays for that.
// PRAGMA optimize is what the SQLite docs recommend running periodically
// on long-lived connections (https://sqlite.org/lang_analyze.html).
func (s *Store) Maintain(ctx context.Context) (Stats, error) {
	for _, stmt := range []string{
		"PRAGMA wal_checkpoint(TRUNCATE)",
		fmt.Sprintf("PRAGMA incremental_vacuum(%d)", vacuumPages),
		"PRAGMA optimize",
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return Stats{}, fmt.Errorf("maintenance (%s): %w", stmt, err)
		}
	}
	return s.Stats(ctx)
}

// convertLimit is the largest file EnsureAutoVacuum rewrites: a VACUUM
// blocks the panel for the whole copy, so a bigger one is left to the
// operator (docs/20).
const convertLimit = 256 << 20

// EnsureAutoVacuum switches a database created without
// auto_vacuum=INCREMENTAL to it. The mode only changes with a VACUUM
// (https://sqlite.org/pragma.html#pragma_auto_vacuum), which works in WAL
// mode; it is done once, and only while the file is small. It reports
// whether it converted.
func (s *Store) EnsureAutoVacuum(ctx context.Context) (bool, error) {
	var mode int
	if err := s.DB.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&mode); err != nil {
		return false, fmt.Errorf("read auto_vacuum: %w", err)
	}
	if mode == 2 { // INCREMENTAL
		return false, nil
	}
	st, err := s.Stats(ctx)
	if err != nil {
		return false, err
	}
	if st.SizeBytes > convertLimit {
		return false, fmt.Errorf("database of %d bytes has auto_vacuum=%d: run PRAGMA auto_vacuum=INCREMENTAL and VACUUM off-peak", st.SizeBytes, mode)
	}
	for _, stmt := range []string{"PRAGMA auto_vacuum = INCREMENTAL", "VACUUM"} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return false, fmt.Errorf("enable incremental vacuum (%s): %w", stmt, err)
		}
	}
	return true, nil
}

// Stats measures the database.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var pageSize, pages, free int64
	for _, q := range []struct {
		sql string
		dst *int64
	}{
		{"PRAGMA page_size", &pageSize},
		{"PRAGMA page_count", &pages},
		{"PRAGMA freelist_count", &free},
	} {
		if err := s.DB.QueryRowContext(ctx, q.sql).Scan(q.dst); err != nil {
			return Stats{}, fmt.Errorf("measure database: %w", err)
		}
	}
	return Stats{SizeBytes: pageSize * pages, FreeBytes: pageSize * free}, nil
}

// SizeWarning is the size from which the panel database deserves attention:
// with the retention policy in docs/20 it should never get there.
const SizeWarning = 512 << 20
