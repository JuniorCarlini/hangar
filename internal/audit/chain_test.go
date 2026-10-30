package audit_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
)

func newBox(t *testing.T, b byte) *secrets.Box {
	t.Helper()
	box, err := secrets.NewBox(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func keyedLogger(t *testing.T, s *store.Store, box *secrets.Box) *audit.Logger {
	t.Helper()
	l := audit.New(s.DB)
	if err := l.UseKey(context.Background(), box); err != nil {
		t.Fatal(err)
	}
	return l
}

func dropGuards(t *testing.T, s *store.Store) {
	t.Helper()
	for _, tr := range []string{"audit_log_no_update", "audit_log_no_delete", "audit_archive_no_update", "audit_archive_no_delete", "audit_archive_insert", "audit_chain_no_delete", "audit_chain_no_update"} {
		if _, err := s.DB.Exec(`DROP TRIGGER ` + tr); err != nil {
			t.Fatal(err)
		}
	}
}

func expectTamper(t *testing.T, s *store.Store, box *secrets.Box, reason string) {
	t.Helper()
	var te *audit.TamperError
	_, err := audit.Verify(context.Background(), s.Q, box)
	if !errors.As(err, &te) {
		t.Fatalf("expected TamperError, got %v", err)
	}
	if reason != "" && te.Reason != reason {
		t.Fatalf("reason %q, want %q", te.Reason, reason)
	}
}

func TestKeyedChainVerifiesOnlyWithTheKey(t *testing.T) {
	s := openStore(t)
	box := newBox(t, 7)
	l := keyedLogger(t, s, box)
	for _, a := range []string{"login.ok", "sudo.ok"} {
		record(t, l, a)
	}
	n, err := audit.Verify(context.Background(), s.Q, box)
	if err != nil || n != 3 { // the anchor and the two records
		t.Fatalf("verify = %d, %v; want 3, nil", n, err)
	}
	if _, err := audit.Verify(context.Background(), s.Q, nil); !errors.Is(err, audit.ErrKeyRequired) {
		t.Fatalf("without the key: %v", err)
	}
	if _, err := audit.Verify(context.Background(), s.Q, newBox(t, 8)); !errors.Is(err, audit.ErrKeyMismatch) {
		t.Fatalf("another master key: %v", err)
	}
	// Keying again (a restart) reuses the key: no second anchor.
	l2 := keyedLogger(t, s, box)
	record(t, l2, "login.ok")
	if n, err := audit.Verify(context.Background(), s.Q, box); err != nil || n != 4 {
		t.Fatalf("after a restart: %d, %v", n, err)
	}
	// A logger without the key cannot add a plain record to a keyed chain.
	err = audit.New(s.DB).Record(context.Background(), audit.Entry{Action: "x", Outcome: audit.OK})
	if !errors.Is(err, audit.ErrKeyRequired) {
		t.Fatalf("plain record on a keyed chain: %v", err)
	}
}

// SEC-010: whoever writes the database but not the master key cannot
// rewrite a record and recompute the chain.
func TestRewrittenKeyedRecordIsDetected(t *testing.T) {
	s := openStore(t)
	box := newBox(t, 7)
	l := keyedLogger(t, s, box)
	record(t, l, "secret.reveal")
	record(t, l, "login.ok")
	dropGuards(t, s)
	// Replace the keyed records with a consistent plain SHA-256 chain,
	// what an attacker could compute, and remove the key row too: the
	// keyed anchor left behind no longer verifies.
	forger := audit.New(s.DB)
	if _, err := s.DB.Exec(`DELETE FROM audit_log WHERE action != ?`, audit.AnchorAction); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_chain`); err != nil {
		t.Fatal(err)
	}
	record(t, forger, "login.ok")
	expectTamper(t, s, box, "content_changed")
}

func TestRemovingTheKeyedTailIsDetected(t *testing.T) {
	s := openStore(t)
	l := audit.New(s.DB)
	record(t, l, "login.ok") // before the key
	box := newBox(t, 7)
	l = keyedLogger(t, s, box)
	record(t, l, "secret.reveal")
	dropGuards(t, s)
	if _, err := s.DB.Exec(`DELETE FROM audit_log WHERE id > 1`); err != nil {
		t.Fatal(err)
	}
	expectTamper(t, s, box, "removed_or_reordered")
}

// SEC-010: a made-up chunk no longer unlocks deleting records.
func TestFakeChunkCannotUnlockDeletion(t *testing.T) {
	s := openStore(t)
	box := newBox(t, 7)
	l := keyedLogger(t, s, box)
	for range 3 {
		record(t, l, "login.ok")
	}
	// The pre-fix trick: a chunk claiming every record.
	_, err := s.DB.Exec(`INSERT INTO audit_archive (first_id, last_id, records, first_ts, last_ts, prev_hash, last_hash, data, data_sha256, archived_at, mac)
		VALUES (1, 1000000, 1, 'x', 'x', zeroblob(32), x'00', x'00', x'00', 0, x'00')`)
	if err == nil {
		t.Fatal("a chunk that does not match the records must be refused")
	}
	// A chunk that matches the oldest records' hashes is accepted by the
	// database, but its forged data and MAC fail verification.
	_, err = s.DB.Exec(`INSERT INTO audit_archive (first_id, last_id, records, first_ts, last_ts, prev_hash, last_hash, data, data_sha256, archived_at, mac)
		SELECT 1, 2, 2, 'x', 'x', (SELECT prev_hash FROM audit_log WHERE id = 1), (SELECT hash FROM audit_log WHERE id = 2), x'00', x'00', 0, x'00'`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_log WHERE id <= 2`); err != nil {
		t.Fatal(err)
	}
	expectTamper(t, s, box, "unauthenticated")
	// Without a MAC at all the database refuses it on a keyed chain.
	if _, err := s.DB.Exec(`INSERT INTO audit_archive (first_id, last_id, records, first_ts, last_ts, prev_hash, last_hash, data, data_sha256, archived_at)
		SELECT 3, 3, 1, 'x', 'x', (SELECT prev_hash FROM audit_log WHERE id = 3), (SELECT hash FROM audit_log WHERE id = 3), x'00', x'00', 0`); err == nil {
		t.Fatal("a chunk without a MAC on a keyed chain must be refused")
	}
}

// SEC-010: dropping a chunk's data before its retention is refused by the
// database and caught by Verify.
func TestEarlyExpiryIsRefusedAndDetected(t *testing.T) {
	s := openStore(t)
	box := newBox(t, 7)
	l := audit.New(s.DB).WithClock(func() time.Time { return time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC) })
	if err := l.UseKey(context.Background(), box); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	recordAt(t, l, time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC), now, now)
	if moved, err := l.Archive(context.Background(), now); err != nil || moved != 2 {
		t.Fatalf("archived %d (%v), want 2 (the anchor and January)", moved, err)
	}
	if _, err := audit.Verify(context.Background(), s.Q, box); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE audit_archive SET data = NULL, expired_at = 1`); err == nil {
		t.Fatal("dropping a young chunk's data must be refused")
	}
	dropGuards(t, s)
	if _, err := s.DB.Exec(`UPDATE audit_archive SET data = NULL, expired_at = 1`); err != nil {
		t.Fatal(err)
	}
	expectTamper(t, s, box, "expired_early")
}

// Old chains stay verifiable: a database archived and written before the
// key is keyed in place, its chunks authenticated, and editing the old
// records is caught through the anchor.
func TestLegacyChainIsKeyedInPlace(t *testing.T) {
	s := openStore(t)
	plain := audit.New(s.DB)
	now := time.Date(2027, 6, 15, 0, 0, 0, 0, time.UTC)
	recordAt(t, plain, time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC), now)
	if _, err := plain.Archive(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	box := newBox(t, 7)
	l := keyedLogger(t, s, box)
	l.WithClock(func() time.Time { return now })
	record(t, l, "login.ok")
	if n, err := audit.Verify(context.Background(), s.Q, box); err != nil || n != 5 {
		t.Fatalf("verify = %d, %v; want 5", n, err)
	}
	var unsealed int
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_archive WHERE mac IS NULL`).Scan(&unsealed)
	if unsealed != 0 {
		t.Fatal("the chunks archived before the key must be authenticated")
	}
	// The newest plain record is pinned by the anchor that chains from it.
	dropGuards(t, s)
	if _, err := s.DB.Exec(`UPDATE audit_log SET action = 'nada' WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	expectTamper(t, s, box, "content_changed")
}

func TestRotationKeepsTheChainVerifiable(t *testing.T) {
	s := openStore(t)
	box := newBox(t, 7)
	l := keyedLogger(t, s, box)
	record(t, l, "login.ok")
	next := newBox(t, 9)
	if _, err := secrets.Rotate(context.Background(), s.DB, box, next); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(context.Background(), s.Q, next); err != nil {
		t.Fatalf("after rotating the master key: %v", err)
	}
	record(t, keyedLogger(t, s, next), "login.ok")
	if _, err := audit.Verify(context.Background(), s.Q, next); err != nil {
		t.Fatal(err)
	}
}
