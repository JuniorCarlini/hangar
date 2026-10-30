package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
)

// recordAt writes one record per timestamp.
func recordAt(t *testing.T, l *audit.Logger, at ...time.Time) {
	t.Helper()
	for _, ts := range at {
		l.WithClock(func() time.Time { return ts })
		record(t, l, "service.deploy")
	}
}

func TestArchiveMovesWholeOldMonthsAndChainStillVerifies(t *testing.T) {
	s := openStore(t)
	l := audit.New(s.DB)
	now := time.Date(2027, 6, 15, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-audit.HotKeep) // 2026-05-11: archive up to 2026-05-01
	recordAt(t, l,
		time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 3, 30, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 4, 30, 23, 59, 59, 900_000_000, time.UTC), // last one of April
		time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),               // first of May: stays
		cutoff.Add(-time.Hour),                                    // older than 400 days but in May: stays
		now.Add(-time.Hour),
	)

	moved, err := l.Archive(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if moved != 3 {
		t.Fatalf("moved %d records, want 3 (March and April)", moved)
	}
	var hot, chunks int
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&hot)
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_archive`).Scan(&chunks)
	if hot != 3 || chunks != 2 {
		t.Fatalf("hot=%d chunks=%d, want 3 and 2 (one per month)", hot, chunks)
	}
	// A second run finds nothing new.
	if moved, err := l.Archive(context.Background(), now); err != nil || moved != 0 {
		t.Fatalf("second run moved %d (%v), want 0", moved, err)
	}

	// New records keep chaining from the newest hot one.
	l.WithClock(func() time.Time { return now })
	record(t, l, "login.ok")
	n, err := audit.Verify(context.Background(), s.Q, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("verified %d records, want 7", n)
	}
}

func TestArchiveKeepsTheNewestRecord(t *testing.T) {
	s := openStore(t)
	l := audit.New(s.DB)
	now := time.Date(2028, 1, 10, 0, 0, 0, 0, time.UTC)
	recordAt(t, l, time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC))

	if _, err := l.Archive(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	var hot int
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&hot)
	if hot != 1 {
		t.Fatalf("hot=%d, want the newest record kept", hot)
	}
	// Its id is past the archived range: a new record never reuses one.
	l.WithClock(func() time.Time { return now })
	record(t, l, "login.ok")
	if _, err := audit.Verify(context.Background(), s.Q, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteOnlyArchivedRecords(t *testing.T) {
	s := openStore(t)
	l := audit.New(s.DB)
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	recordAt(t, l, time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), now, now)
	if _, err := l.Archive(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_log WHERE id = 2`); err == nil {
		t.Error("deleting a record no chunk holds should fail")
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_archive`); err == nil {
		t.Error("deleting a chunk should fail")
	}
	if _, err := s.DB.Exec(`UPDATE audit_archive SET last_hash = x'00'`); err == nil {
		t.Error("changing a chunk's hashes should fail")
	}
}

func TestExpireArchiveKeepsHashes(t *testing.T) {
	s := openStore(t)
	l := audit.New(s.DB)
	// Really past ArchiveKeep: the database judges the age by its own clock.
	old := time.Now().UTC().AddDate(-8, 0, 0).Truncate(time.Hour)
	now := old.Add(audit.ArchiveKeep + 60*24*time.Hour)
	recordAt(t, l, old, old.Add(time.Hour), now)
	if _, err := l.Archive(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	n, err := audit.ExpireArchive(context.Background(), s.DB, now)
	if err != nil || n != 1 {
		t.Fatalf("expired %d (%v), want 1", n, err)
	}
	var nulls int
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_archive WHERE data IS NULL AND expired_at IS NOT NULL`).Scan(&nulls)
	if nulls != 1 {
		t.Fatal("the chunk's data should be gone")
	}
	// Only the hot record is checked one by one; the chain still holds.
	if n, err := audit.Verify(context.Background(), s.Q, nil); err != nil || n != 1 {
		t.Fatalf("verify = %d, %v; want 1, nil", n, err)
	}
	// A chunk not yet past ArchiveKeep keeps its data.
	if n, _ := audit.ExpireArchive(context.Background(), s.DB, now); n != 0 {
		t.Fatalf("expired again: %d", n)
	}
}

func TestVerifyDetectsArchiveTampering(t *testing.T) {
	cases := []struct {
		name   string
		tamper string
	}{
		{"chunk data changed", `UPDATE audit_archive SET data = x'1f8b'`},
		{"chunk removed", `DELETE FROM audit_archive`},
		{"hot record that chunk ends at removed", `DELETE FROM audit_log WHERE id = (SELECT min(id) FROM audit_log)`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := openStore(t)
			l := audit.New(s.DB)
			now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
			recordAt(t, l, time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC), now, now)
			if _, err := l.Archive(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(`DROP TRIGGER audit_archive_no_update; DROP TRIGGER audit_archive_no_delete; DROP TRIGGER audit_log_no_delete;`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(c.tamper); err != nil {
				t.Fatal(err)
			}
			var te *audit.TamperError
			if _, err := audit.Verify(context.Background(), s.Q, nil); !errors.As(err, &te) {
				t.Fatalf("expected TamperError, got %v", err)
			}
		})
	}
}

func TestArchiveRefusesABrokenChain(t *testing.T) {
	s := openStore(t)
	l := audit.New(s.DB)
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	recordAt(t, l, time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC), now)
	if _, err := s.DB.Exec(`DROP TRIGGER audit_log_no_update; UPDATE audit_log SET action = 'x' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	var te *audit.TamperError
	if _, err := l.Archive(context.Background(), now); !errors.As(err, &te) {
		t.Fatalf("expected TamperError, got %v", err)
	}
	var chunks int
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_archive`).Scan(&chunks)
	if chunks != 0 {
		t.Fatal("a tampered month must not be archived")
	}
}
