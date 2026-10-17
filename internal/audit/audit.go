// Package audit writes and verifies the hash-chained audit log.
//
// Each record stores hash = SHA-256(previous_hash || record). Changing,
// removing or reordering any row breaks the chain from that point on, and
// Verify points to where. No secret goes into the summary: callers of Record
// are responsible for that.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Outcome is the result of an audited action.
type Outcome string

const (
	OK     Outcome = "ok"
	Denied Outcome = "denied"
	Error  Outcome = "error"
)

// Entry is an action to record. Empty fields become NULL.
type Entry struct {
	ActorID    string
	IP         string
	UserAgent  string
	Action     string
	TargetType string
	TargetID   string
	Outcome    Outcome
	Summary    map[string]any
}

// Logger writes chained records.
type Logger struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex
	// observers see every committed record (security alerts, docs/17 ⑰).
	observers []func(Entry)
}

// Observe registers fn to run after each record is committed. fn runs on the
// caller's goroutine and must not block: hand the entry off and return.
func (l *Logger) Observe(fn func(Entry)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.observers = append(l.observers, fn)
}

// New creates a Logger on the panel database.
func New(db *sql.DB) *Logger {
	return &Logger{db: db, now: time.Now}
}

var genesis = make([]byte, sha256.Size)

// MaxSummaryBytes caps each record's summary (see docs/20): the audit log
// stores what happened, not payloads.
const MaxSummaryBytes = 4 << 10

// Record writes an entry. Reading the last hash and inserting happen in the
// same transaction, so the chain never forks.
func (l *Logger) Record(ctx context.Context, e Entry) error {
	if e.Action == "" {
		return errors.New("audit: empty action")
	}
	switch e.Outcome {
	case OK, Denied, Error:
	default:
		return fmt.Errorf("audit: invalid outcome %q", e.Outcome)
	}

	summary := "{}"
	if len(e.Summary) > 0 {
		b, err := json.Marshal(e.Summary)
		if err != nil {
			return fmt.Errorf("audit: summary: %w", err)
		}
		if len(b) > MaxSummaryBytes {
			return fmt.Errorf("audit: summary of %d bytes exceeds the %d limit", len(b), MaxSummaryBytes)
		}
		summary = string(b)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := dbq.New(tx)

	prev, err := q.LastAuditHash(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		prev = genesis
	case err != nil:
		return fmt.Errorf("audit: last hash: %w", err)
	}

	row := dbq.AuditLog{
		Ts:          l.now().UTC().Format(time.RFC3339Nano),
		ActorID:     nullable(e.ActorID),
		Ip:          nullable(e.IP),
		UserAgent:   nullable(e.UserAgent),
		Action:      e.Action,
		TargetType:  nullable(e.TargetType),
		TargetID:    nullable(e.TargetID),
		Outcome:     string(e.Outcome),
		SummaryJson: summary,
		PrevHash:    prev,
	}
	row.Hash = chainHash(prev, row)

	if _, err := q.InsertAudit(ctx, dbq.InsertAuditParams{
		Ts: row.Ts, ActorID: row.ActorID, Ip: row.Ip, UserAgent: row.UserAgent,
		Action: row.Action, TargetType: row.TargetType, TargetID: row.TargetID,
		Outcome: row.Outcome, SummaryJson: row.SummaryJson, PrevHash: row.PrevHash, Hash: row.Hash,
	}); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, fn := range l.observers {
		fn(e)
	}
	return nil
}

// Recent returns the latest records of the given actions, newest first, with
// the actor's name and the service they touched (for the activity feed).
func (l *Logger) Recent(ctx context.Context, actions []string, limit int) ([]dbq.RecentActivityRow, error) {
	if l == nil {
		return nil, nil
	}
	return dbq.New(l.db).RecentActivity(ctx, dbq.RecentActivityParams{Actions: actions, Limit: int64(limit)})
}

// TamperError tells where the chain broke.
type TamperError struct {
	ID     int64
	Reason string // removed_or_reordered or content_changed
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("audit log tampered at record %d: %s", e.ID, e.Reason)
}

// Verify walks the whole chain and returns how many records it checked.
func Verify(ctx context.Context, q *dbq.Queries) (int, error) {
	const page = 500
	prev := genesis
	var lastID int64
	count := 0

	for {
		rows, err := q.ListAuditAfter(ctx, dbq.ListAuditAfterParams{ID: lastID, Limit: page})
		if err != nil {
			return count, fmt.Errorf("audit: read: %w", err)
		}
		for _, r := range rows {
			if !bytes.Equal(r.PrevHash, prev) {
				return count, &TamperError{ID: r.ID, Reason: "removed_or_reordered"}
			}
			if !bytes.Equal(r.Hash, chainHash(prev, r)) {
				return count, &TamperError{ID: r.ID, Reason: "content_changed"}
			}
			prev = r.Hash
			lastID = r.ID
			count++
		}
		if len(rows) < page {
			return count, nil
		}
	}
}

// chainHash serializes each field with a length prefix (and a NULL marker),
// so two different records never produce the same byte sequence.
func chainHash(prev []byte, r dbq.AuditLog) []byte {
	h := sha256.New()
	h.Write(prev)
	writeField(h, r.Ts, true)
	writeField(h, r.ActorID.String, r.ActorID.Valid)
	writeField(h, r.Ip.String, r.Ip.Valid)
	writeField(h, r.UserAgent.String, r.UserAgent.Valid)
	writeField(h, r.Action, true)
	writeField(h, r.TargetType.String, r.TargetType.Valid)
	writeField(h, r.TargetID.String, r.TargetID.Valid)
	writeField(h, r.Outcome, true)
	writeField(h, r.SummaryJson, true)
	return h.Sum(nil)
}

func writeField(h interface{ Write([]byte) (int, error) }, s string, valid bool) {
	if !valid {
		_, _ = h.Write([]byte{0})
		return
	}
	var n [9]byte
	n[0] = 1
	binary.BigEndian.PutUint64(n[1:], uint64(len(s))) //nolint:gosec // len is never negative
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(s))
}

func nullable(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
