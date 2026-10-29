package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Retention of the audit log (docs/20). PCI DSS v4.0 req. 10.5.1 asks for
// 12 months of audit history with the last 3 immediately available, and
// ISO 27001 / NIST SP 800-92 leave the length to policy with a year as
// the usual floor. The panel keeps 400 days in the table (13 months, so
// "the same month last year" is still on screen) and the older records
// compressed in audit_archive, verifiable with the rest of the chain, up
// to seven years (SOX-style). After that only the chunk's hashes remain,
// so the chain still verifies from genesis.
const (
	HotKeep     = 400 * 24 * time.Hour
	ArchiveKeep = 7 * 365 * 24 * time.Hour
	// archiveMonths bounds the months one Archive call moves, so catching
	// up a large backlog is spread over several runs.
	archiveMonths = 3
)

// archived is one record in a chunk (one JSON object per line).
type archived struct {
	ID         int64   `json:"id"`
	Ts         string  `json:"ts"`
	ActorID    *string `json:"actor_id,omitempty"`
	IP         *string `json:"ip,omitempty"`
	UserAgent  *string `json:"user_agent,omitempty"`
	Action     string  `json:"action"`
	TargetType *string `json:"target_type,omitempty"`
	TargetID   *string `json:"target_id,omitempty"`
	Outcome    string  `json:"outcome"`
	Summary    string  `json:"summary_json"`
	PrevHash   []byte  `json:"prev_hash"`
	Hash       []byte  `json:"hash"`
}

func toArchived(r dbq.AuditLog) archived {
	p := func(s sql.NullString) *string {
		if !s.Valid {
			return nil
		}
		return &s.String
	}
	return archived{
		ID: r.ID, Ts: r.Ts, ActorID: p(r.ActorID), IP: p(r.Ip), UserAgent: p(r.UserAgent), Action: r.Action,
		TargetType: p(r.TargetType), TargetID: p(r.TargetID), Outcome: r.Outcome, Summary: r.SummaryJson,
		PrevHash: r.PrevHash, Hash: r.Hash,
	}
}

func (a archived) row() dbq.AuditLog {
	n := func(s *string) sql.NullString {
		if s == nil {
			return sql.NullString{}
		}
		return sql.NullString{String: *s, Valid: true}
	}
	return dbq.AuditLog{
		ID: a.ID, Ts: a.Ts, ActorID: n(a.ActorID), Ip: n(a.IP), UserAgent: n(a.UserAgent), Action: a.Action,
		TargetType: n(a.TargetType), TargetID: n(a.TargetID), Outcome: a.Outcome, SummaryJson: a.Summary,
		PrevHash: a.PrevHash, Hash: a.Hash,
	}
}

// monthStart is the first instant of t's month in the records' timestamp
// format, without the zone: records are RFC 3339 UTC, and comparing
// against the prefix keeps "…00:00:00.5Z" (later) from sorting before
// "…00:00:00Z" as whole strings would.
func monthStart(t time.Time) string {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05")
}

// Archive moves the records older than HotKeep, whole calendar months at
// a time, into audit_archive. Each month is one transaction: the chunk is
// written and its records deleted together, so a crash leaves either the
// rows or the chunk, never neither. It refuses to archive a chain that
// does not verify. It returns how many records it moved.
func Archive(ctx context.Context, db *sql.DB, now time.Time) (int, error) {
	cutoff := monthStart(now.Add(-HotKeep))
	moved := 0
	for range archiveMonths {
		n, err := archiveMonth(ctx, db, cutoff, now)
		if err != nil || n == 0 {
			return moved, err
		}
		moved += n
	}
	return moved, nil
}

func archiveMonth(ctx context.Context, db *sql.DB, cutoff string, now time.Time) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	q := dbq.New(tx)

	oldest, err := q.OldestAudit(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if oldest.Ts >= cutoff {
		return 0, nil
	}
	first, err := time.Parse(time.RFC3339Nano, oldest.Ts)
	if err != nil {
		return 0, fmt.Errorf("audit archive: record %d: %w", oldest.ID, err)
	}
	end := monthStart(first.AddDate(0, 1, 0))
	end = min(end, cutoff)
	lastID, err := q.LastAuditBefore(ctx, end)
	if err != nil || lastID < oldest.ID {
		return 0, err
	}

	prev := genesis
	if c, err := q.LastAuditArchive(ctx); err == nil {
		prev = c.LastHash
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	chunk := dbq.InsertAuditArchiveParams{FirstID: oldest.ID, PrevHash: prev, ArchivedAt: now.Unix()}
	after := oldest.ID - 1
	for after < lastID {
		rows, err := q.ListAuditAfter(ctx, dbq.ListAuditAfterParams{ID: after, Limit: 500})
		if err != nil {
			return 0, err
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if r.ID > lastID {
				after = lastID
				break
			}
			if err := checkLink(prev, r); err != nil {
				return 0, err
			}
			if err := enc.Encode(toArchived(r)); err != nil {
				return 0, err
			}
			if chunk.Records == 0 {
				chunk.FirstTs = r.Ts
			}
			chunk.Records++
			chunk.LastID, chunk.LastTs, chunk.LastHash = r.ID, r.Ts, r.Hash
			prev, after = r.Hash, r.ID
		}
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	if chunk.Records == 0 {
		return 0, nil
	}
	chunk.Data = buf.Bytes()
	sum := sha256.Sum256(chunk.Data)
	chunk.DataSha256 = sum[:]
	if err := q.InsertAuditArchive(ctx, chunk); err != nil {
		return 0, fmt.Errorf("audit archive: %w", err)
	}
	if _, err := q.DeleteAuditThrough(ctx, chunk.LastID); err != nil {
		return 0, fmt.Errorf("audit archive: %w", err)
	}
	return int(chunk.Records), tx.Commit()
}

// ExpireArchive drops the data of chunks whose newest record is older
// than ArchiveKeep; their hashes stay, so the chain still verifies.
func ExpireArchive(ctx context.Context, db *sql.DB, now time.Time) (int, error) {
	q := dbq.New(db)
	ids, err := q.ExpirableAuditArchives(ctx, now.Add(-ArchiveKeep).UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := q.ExpireAuditArchive(ctx, dbq.ExpireAuditArchiveParams{ExpiredAt: sql.NullInt64{Int64: now.Unix(), Valid: true}, FirstID: id}); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

// checkLink verifies that r chains from prev and its hash matches.
func checkLink(prev []byte, r dbq.AuditLog) error {
	if !bytes.Equal(r.PrevHash, prev) {
		return &TamperError{ID: r.ID, Reason: "removed_or_reordered"}
	}
	if !bytes.Equal(r.Hash, chainHash(prev, r)) {
		return &TamperError{ID: r.ID, Reason: "content_changed"}
	}
	return nil
}

// verifyChunk checks one archived chunk: it continues the chain from prev,
// its data matches the stored SHA-256 and its records chain to last_hash.
// An expired chunk (no data) is checked by its hashes only. It returns how
// many records it verified one by one.
func verifyChunk(prev []byte, c dbq.AuditArchive) (int, error) {
	if !bytes.Equal(c.PrevHash, prev) {
		return 0, &TamperError{ID: c.FirstID, Reason: "removed_or_reordered"}
	}
	if c.Data == nil {
		return 0, nil
	}
	if sum := sha256.Sum256(c.Data); !bytes.Equal(sum[:], c.DataSha256) {
		return 0, &TamperError{ID: c.FirstID, Reason: "content_changed"}
	}
	zr, err := gzip.NewReader(bytes.NewReader(c.Data))
	if err != nil {
		return 0, &TamperError{ID: c.FirstID, Reason: "content_changed"}
	}
	dec := json.NewDecoder(bufio.NewReader(zr))
	n := 0
	var last archived
	for {
		var a archived
		if err := dec.Decode(&a); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return n, &TamperError{ID: c.FirstID, Reason: "content_changed"}
		}
		if err := checkLink(prev, a.row()); err != nil {
			return n, err
		}
		prev, last = a.Hash, a
		n++
	}
	if int64(n) != c.Records || last.ID != c.LastID || !bytes.Equal(last.Hash, c.LastHash) {
		return n, &TamperError{ID: c.LastID, Reason: "removed_or_reordered"}
	}
	return n, nil
}
