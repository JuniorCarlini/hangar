// Package audit writes and verifies the hash-chained audit log.
//
// Each record stores hash = HMAC-SHA256(key, previous_hash || record), with
// a key derived from the master key (chain.go); records written before the
// chain had a key use a plain SHA-256. Changing, removing or reordering any
// row breaks the chain from that point on, and Verify points to where. No
// secret goes into the summary: callers of Record are responsible for that.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// timeNow is the clock Verify judges a chunk's age by.
var timeNow = time.Now

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
	// chain is the key records are written with (UseKey); plain until set.
	chain chain
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
	return &Logger{db: db, now: time.Now, chain: plainChain}
}

// WithClock makes the logger stamp records with now instead of the wall
// clock (tests that write records in the past).
func (l *Logger) WithClock(now func() time.Time) *Logger {
	l.now = now
	return l
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

	c, err := l.chainIn(ctx, q)
	if err != nil {
		return err
	}
	if _, err := l.insertSummary(ctx, q, c.key, e, summary); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, fn := range l.observers {
		fn(e)
	}
	return nil
}

// chainIn is the chain this logger writes with, checked against the
// database: a keyed chain needs the key (UseKey), or a plain record would
// break it.
func (l *Logger) chainIn(ctx context.Context, q *dbq.Queries) (chain, error) {
	if l.chain.key != nil {
		return l.chain, nil
	}
	if _, err := q.GetAuditChain(ctx); err == nil {
		return chain{}, ErrKeyRequired
	} else if !errors.Is(err, sql.ErrNoRows) {
		return chain{}, fmt.Errorf("audit: chain key: %w", err)
	}
	return plainChain, nil
}

// insert writes e chained to the newest record, keyed with key (nil:
// plain). It returns the record's id.
func (l *Logger) insert(ctx context.Context, q *dbq.Queries, key []byte, e Entry) (int64, error) {
	b, err := json.Marshal(e.Summary)
	if err != nil {
		return 0, fmt.Errorf("audit: summary: %w", err)
	}
	return l.insertSummary(ctx, q, key, e, string(b))
}

func (l *Logger) insertSummary(ctx context.Context, q *dbq.Queries, key []byte, e Entry, summary string) (int64, error) {
	prev, err := q.LastAuditHash(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		prev = genesis
	case err != nil:
		return 0, fmt.Errorf("audit: last hash: %w", err)
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
	row.Hash = chainHash(key, prev, row)

	id, err := q.InsertAudit(ctx, dbq.InsertAuditParams{
		Ts: row.Ts, ActorID: row.ActorID, Ip: row.Ip, UserAgent: row.UserAgent,
		Action: row.Action, TargetType: row.TargetType, TargetID: row.TargetID,
		Outcome: row.Outcome, SummaryJson: row.SummaryJson, PrevHash: row.PrevHash, Hash: row.Hash,
	})
	if err != nil {
		return 0, fmt.Errorf("audit: insert: %w", err)
	}
	return id, nil
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

// Verify walks the whole chain, the archived chunks first (docs/20), and
// returns how many records it checked one by one (expired chunks are
// checked by their hashes and their HMAC only). box holds the master key;
// it may be nil only for a chain that was never keyed.
func Verify(ctx context.Context, q *dbq.Queries, box *secrets.Box) (int, error) {
	const page = 500
	prev := genesis
	var lastID int64
	count := 0

	c, err := loadChain(ctx, q, box)
	if err != nil {
		return 0, err
	}
	// The anchor (the first keyed record) must still be there: without
	// it, removing everything written since the key would go unseen.
	sawAnchor := !c.keyed()

	chunks, err := q.ListAuditArchive(ctx)
	if err != nil {
		return 0, fmt.Errorf("audit: read archive: %w", err)
	}
	now := timeNow()
	for _, ch := range chunks {
		// Once keyed, every chunk carries the HMAC of what it claims; a
		// chunk with one and no key in the database means the key was
		// removed.
		if c.keyed() != (ch.Mac != nil) || (c.keyed() && !hmac.Equal(ch.Mac, chunkMAC(c.key, ch))) {
			return count, &TamperError{ID: ch.FirstID, Reason: "unauthenticated"}
		}
		n, err := verifyChunk(prev, ch, c, now)
		count += n
		if err != nil {
			return count, err
		}
		if ch.FirstID <= c.fromID && c.fromID <= ch.LastID {
			sawAnchor = true
		}
		prev, lastID = ch.LastHash, ch.LastID
	}

	for {
		rows, err := q.ListAuditAfter(ctx, dbq.ListAuditAfterParams{ID: lastID, Limit: page})
		if err != nil {
			return count, fmt.Errorf("audit: read: %w", err)
		}
		for _, r := range rows {
			if err := checkLink(prev, r, c.keyFor(r.ID)); err != nil {
				return count, err
			}
			if r.ID == c.fromID {
				sawAnchor = true
			}
			prev = r.Hash
			lastID = r.ID
			count++
		}
		if len(rows) < page {
			if !sawAnchor {
				return count, &TamperError{ID: c.fromID, Reason: "removed_or_reordered"}
			}
			return count, nil
		}
	}
}

// chainHash serializes each field with a length prefix (and a NULL marker),
// so two different records never produce the same byte sequence. With a
// key it is an HMAC; without, a plain SHA-256 (records before the key).
func chainHash(key, prev []byte, r dbq.AuditLog) []byte {
	var h hash.Hash
	if key != nil {
		h = hmac.New(sha256.New, key)
	} else {
		h = sha256.New()
	}
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
