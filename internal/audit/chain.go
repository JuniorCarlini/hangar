package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// The keyed chain (SEC-010). A plain SHA-256 chain only proves the rows
// agree with each other: whoever can write the database can rewrite them
// and recompute every hash. From audit_chain.from_id on, each record's
// hash is an HMAC-SHA256 under a key derived from the master key (which
// lives outside the database), and each archived chunk carries an HMAC of
// its metadata. The first keyed record is an anchor written when the
// chain is keyed: it chains from the last plain record, so the history
// before the key is pinned by it too.
const (
	chainVersion = 2
	chainKeyInfo = "hangar audit chain v2"
	// AnchorAction is the record that opens the keyed chain.
	AnchorAction = "audit.chain.keyed"
)

// ChainKeyAD is the associated data of the sealed chain key.
func ChainKeyAD(version string) string { return "audit_chain|" + version + "|key" }

var (
	// ErrKeyRequired: the chain is keyed and no master key was given.
	ErrKeyRequired = i18n.E("audit.error.key_required")
	// ErrKeyMismatch: the stored chain key does not open with this master
	// key, or is not the key it claims to be.
	ErrKeyMismatch = i18n.E("audit.error.key_mismatch")
)

// chain is how the hashes are computed: plain up to fromID, keyed from it.
type chain struct {
	key    []byte
	fromID int64 // math.MaxInt64 while the chain has no key
}

var plainChain = chain{fromID: math.MaxInt64}

func (c chain) keyed() bool { return c.fromID != math.MaxInt64 }

// keyFor is the HMAC key of record id (nil: plain SHA-256).
func (c chain) keyFor(id int64) []byte {
	if c.keyed() && id >= c.fromID {
		return c.key
	}
	return nil
}

// loadChain reads the chain's key. box may be nil while the chain is plain.
func loadChain(ctx context.Context, q *dbq.Queries, box *secrets.Box) (chain, error) {
	row, err := q.GetAuditChain(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return plainChain, nil
	}
	if err != nil {
		return chain{}, fmt.Errorf("audit: chain key: %w", err)
	}
	if box == nil {
		return chain{}, ErrKeyRequired
	}
	key, err := box.Open(row.KeyEnc, ChainKeyAD(strconv.Itoa(chainVersion)))
	if err != nil {
		return chain{}, ErrKeyMismatch
	}
	if sum := sha256.Sum256(key); !hmac.Equal(sum[:], row.KeyID) {
		return chain{}, ErrKeyMismatch
	}
	return chain{key: key, fromID: row.FromID}, nil
}

// UseKey makes the logger chain with the key derived from the master key
// in box. The first time, it keys the chain: it stores the sealed key,
// authenticates the chunks archived before (those that verify) and writes
// the anchor record. Every record written afterwards is keyed; a logger
// without the key then refuses to write (ErrKeyRequired).
func (l *Logger) UseKey(ctx context.Context, box *secrets.Box) error {
	if box == nil {
		return ErrKeyRequired
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	// Two processes keying the same fresh database (the panel and a CLI
	// command at the first start) race on one write: the loser retries
	// and finds the key the winner stored.
	for range 3 {
		var c chain
		if c, err = l.keyChain(ctx, box); err == nil {
			l.chain = c
			return nil
		}
		if errors.Is(err, ErrKeyMismatch) || errors.Is(err, ErrKeyRequired) {
			return err
		}
	}
	return err
}

func (l *Logger) keyChain(ctx context.Context, box *secrets.Box) (chain, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return chain{}, err
	}
	defer func() { _ = tx.Rollback() }()
	q := dbq.New(tx)
	c, err := loadChain(ctx, q, box)
	if err != nil || c.keyed() {
		return c, err
	}
	key, err := box.DeriveKey(chainKeyInfo)
	if err != nil {
		return chain{}, err
	}
	sealed, err := box.Seal(key, ChainKeyAD(strconv.Itoa(chainVersion)))
	if err != nil {
		return chain{}, err
	}
	from, err := q.NextAuditID(ctx)
	if err != nil {
		return chain{}, err
	}
	sum := sha256.Sum256(key)
	if err := q.InsertAuditChain(ctx, dbq.InsertAuditChainParams{FromID: from, KeyEnc: sealed, KeyID: sum[:], CreatedAt: l.now().Unix()}); err != nil {
		return chain{}, fmt.Errorf("audit: key the chain: %w", err)
	}
	c = chain{key: key, fromID: from}
	if err := sealLegacyChunks(ctx, q, c); err != nil {
		return chain{}, err
	}
	id, err := l.insert(ctx, q, c.key, Entry{Action: AnchorAction, Outcome: OK, Summary: map[string]any{"from_id": from}})
	if err != nil {
		return chain{}, err
	}
	if id != from {
		return chain{}, fmt.Errorf("audit: the anchor got id %d, want %d", id, from)
	}
	return c, tx.Commit()
}

// sealLegacyChunks authenticates the chunks archived before the chain had
// a key, in order, as long as they verify; the first that does not stays
// unauthenticated, and Verify reports it.
func sealLegacyChunks(ctx context.Context, q *dbq.Queries, c chain) error {
	chunks, err := q.ListAuditArchive(ctx)
	if err != nil {
		return err
	}
	prev := genesis
	for _, ch := range chunks {
		if ch.Mac != nil {
			return nil
		}
		if _, err := verifyChunk(prev, ch, plainChain, timeNow()); err != nil {
			return nil //nolint:nilerr // left for Verify to report
		}
		if err := q.SetAuditArchiveMac(ctx, dbq.SetAuditArchiveMacParams{Mac: chunkMAC(c.key, ch), FirstID: ch.FirstID}); err != nil {
			return err
		}
		prev = ch.LastHash
	}
	return nil
}

// chunkMAC authenticates a chunk's metadata: what it claims to hold and
// the hash of its data, so it still proves something once the data
// expires.
func chunkMAC(key []byte, c dbq.AuditArchive) []byte {
	m := hmac.New(sha256.New, key)
	writeField(m, "audit_archive", true)
	for _, n := range []int64{c.FirstID, c.LastID, c.Records, c.ArchivedAt} {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n)) //nolint:gosec // ids and counts are never negative
		_, _ = m.Write(b[:])
	}
	writeField(m, c.FirstTs, true)
	writeField(m, c.LastTs, true)
	writeField(m, string(c.PrevHash), true)
	writeField(m, string(c.LastHash), true)
	writeField(m, string(c.DataSha256), true)
	return m.Sum(nil)
}
