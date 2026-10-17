package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Stats is the database size after maintenance.
type Stats struct {
	SizeBytes int64 // used + free pages
	FreeBytes int64 // free pages not yet returned to disk
}

// Maintain returns the space of deleted rows to disk, empties the WAL and
// refreshes the query planner statistics. It is cheap; it runs every few
// hours.
func (s *Store) Maintain(ctx context.Context) (Stats, error) {
	// Certificate decisions (docs/20): denials are kept 30 days; approvals
	// 180, because they exempt a domain from the hourly cap when it renews.
	hour := time.Now().Unix() / 3600
	if _, err := s.DB.ExecContext(ctx,
		"DELETE FROM tls_ask_log WHERE (decision = 'deny' AND hour < ?) OR hour < ?",
		hour-30*24, hour-180*24); err != nil {
		return Stats{}, fmt.Errorf("maintenance (tls_ask_log): %w", err)
	}
	for _, stmt := range []string{
		"PRAGMA wal_checkpoint(TRUNCATE)",
		"PRAGMA incremental_vacuum",
		"PRAGMA optimize",
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return Stats{}, fmt.Errorf("maintenance (%s): %w", stmt, err)
		}
	}
	return s.Stats(ctx)
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

// RunMaintenance calls Maintain every interval until ctx ends.
func (s *Store) RunMaintenance(ctx context.Context, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st, err := s.Maintain(ctx)
			if err != nil {
				log.Error("database maintenance failed", "error", err)
				continue
			}
			level := slog.LevelInfo
			if st.SizeBytes > SizeWarning {
				level = slog.LevelWarn
			}
			log.Log(ctx, level, "database maintenance", "size_bytes", st.SizeBytes, "free_bytes", st.FreeBytes)
		}
	}
}
