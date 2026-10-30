package backup

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// Authenticity of the objects in the destinations (SEC-005).
//
// age gives secrecy, not authenticity: the public key is no secret, so
// whoever can write the bucket (a leaked credential, the provider, the
// server's own credential after a break-in) can seal a dump of their own,
// or copy an older, genuine object to a newer key so a restore silently
// goes back in time. Object Lock stops overwrites and deletes, not new
// keys nor new versions.
//
// So a restore believes an object only when this panel vouches for it:
//
//   - its run record (backup_runs, kept as long as the bucket keeps the
//     object) names its size and SHA-256; or
//   - its metadata carries hangar-mac, an HMAC-SHA256 over its key, size
//     and every hangar-* metadata value (the SHA-256 among them), with a
//     key derived from the server's own backup key. The server's key lives
//     sealed in the panel database, so a panel restored on a new server
//     (hangard restore) checks the objects the old one wrote; nobody
//     without the panel's database can make one. Binding the key defeats
//     a copy of an old object under a new name.
//
// The bytes are then downloaded to the staging dir and hashed before any
// of them is used, so a version swapped under a vouched-for key is caught
// before it reaches a database or a volume.
//
// An object the panel cannot vouch for (made by another server, or before
// this check existed and with no record left) is refused unless the owner
// confirmed the restore of unverified backups (withUnverified). One that
// contradicts its record is refused always.

// metaMAC is the metadata entry with the object's HMAC.
const metaMAC = "hangar-mac"

// macInfo separates this key and MAC from any other use of the server's
// key; changing it invalidates every MAC already in the bucket.
const macInfo = "hangar backup object mac v1"

var (
	// errUnverified: no record and no valid MAC.
	errUnverified = errors.New("the backup cannot be verified as made by this panel")
	// errTampered: the object contradicts what this panel recorded.
	errTampered = errors.New("the backup does not match what this panel recorded")
)

// unverifiedErr is errUnverified with the message the user reads.
func unverifiedErr(key string) error {
	return fmt.Errorf("%w: %w", errUnverified, i18n.E("backup.error.unverified", "key", key))
}

func tamperedErr(key string) error {
	return fmt.Errorf("%w: %w", errTampered, i18n.E("backup.error.tampered", "key", key))
}

type unverifiedKey struct{}

// withUnverified lets the restores under ctx use objects this panel cannot
// vouch for (the owner confirmed it, or the operator asked for it on the
// command line). Tampered objects stay refused.
func withUnverified(ctx context.Context) context.Context {
	return context.WithValue(ctx, unverifiedKey{}, true)
}

func unverifiedOK(ctx context.Context) bool {
	ok, _ := ctx.Value(unverifiedKey{}).(bool)
	return ok
}

// macKey derives the objects' HMAC key from the server's own backup key
// (made now if there is none: in the kit mode it encrypts nothing).
func (m *Manager) macKey(ctx context.Context) ([]byte, error) {
	id, err := m.serverIdentity(ctx, true)
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, []byte(id.String()), nil, macInfo, sha256.Size)
}

// objectMAC is the HMAC of an object: its key in the destination (without
// the destination's prefix), its size and its hangar-* metadata but the
// MAC itself, in a canonical order.
func objectMAC(k []byte, key string, size int64, meta map[string]string) string {
	h := hmac.New(sha256.New, k)
	_, _ = io.WriteString(h, macInfo+"\nkey="+strconv.Quote(key)+"\nsize="+strconv.FormatInt(size, 10)+"\n")
	names := make([]string, 0, len(meta))
	for n := range meta {
		if strings.HasPrefix(n, "hangar-") && n != metaMAC {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	for _, n := range names {
		_, _ = io.WriteString(h, strconv.Quote(n)+"="+strconv.Quote(meta[n])+"\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// signMeta adds hangar-mac to the metadata of an object about to be sent.
func (m *Manager) signMeta(ctx context.Context, key string, size int64, md map[string]string) error {
	k, err := m.macKey(ctx)
	if err != nil {
		return err
	}
	md[metaMAC] = objectMAC(k, key, size, md)
	return nil
}

// expected is what an object must hash to. Zero: nothing to check (an
// unverified object the caller accepted).
type expected struct {
	sha  string
	size int64
}

// authenticate decides, from the run records and the object's metadata
// (info from a Head or a Get), what the object at key must be.
func (m *Manager) authenticate(ctx context.Context, key string, info s3.ObjectInfo) (expected, error) {
	run, err := m.q.GetBackupRunByObject(ctx, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return expected{}, err
	}
	hasRun := err == nil
	mac, macOK := info.Metadata[metaMAC], false
	if mac != "" {
		k, err := m.macKey(ctx)
		if err != nil {
			return expected{}, err
		}
		macOK = hmac.Equal([]byte(mac), []byte(objectMAC(k, key, info.Size, info.Metadata)))
	}
	switch {
	case hasRun && (mac != "" && !macOK || info.Size != run.SizeBytes):
		// The record says what this object is: its metadata or its size
		// was changed since.
		m.log.Warn("backup object contradicts its record", "key", key, "size", info.Size, "want_size", run.SizeBytes, "mac_ok", macOK)
		return expected{}, tamperedErr(key)
	case hasRun:
		return expected{sha: run.Sha256, size: run.SizeBytes}, nil
	case macOK:
		return expected{sha: info.Metadata["hangar-sha256"], size: info.Size}, nil
	case unverifiedOK(ctx):
		m.log.Warn("restoring a backup this panel cannot verify, as confirmed", "key", key)
		return expected{}, nil
	}
	return expected{}, unverifiedErr(key)
}

// checkObject authenticates the object at key from its metadata alone
// (no download): a form refuses an object it could never restore, and a
// restore checks its dump before changing anything.
func (m *Manager) checkObject(ctx context.Context, key string) error {
	if localFrom(ctx) != nil {
		return nil
	}
	ts, err := m.targets(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range ts {
		info, err := t.store.Head(ctx, t.Prefix+key)
		if err == nil {
			_, err = m.authenticate(ctx, key, info)
			return err
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// verified authenticates the object rc (at key, with info) and returns
// its bytes once they are proven: downloaded to the staging dir, counted
// and hashed. The staged copy goes away when the returned reader closes.
// rc is closed in every case.
func (m *Manager) verified(ctx context.Context, key string, rc io.ReadCloser, info s3.ObjectInfo) (io.ReadCloser, error) {
	want, err := m.authenticate(ctx, key, info)
	if err != nil || want.sha == "" {
		if err != nil {
			_ = rc.Close()
			return nil, err
		}
		return rc, nil
	}
	defer func() { _ = rc.Close() }()
	f, err := m.stagingFile("fetch-*.age")
	if err != nil {
		return nil, err
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(&roomWriter{w: f, dir: m.opt.StagingDir}, sum), io.LimitReader(rc, want.size+1))
	if err == nil && (n != want.size || hex.EncodeToString(sum.Sum(nil)) != want.sha) {
		m.log.Warn("backup object does not hash to its record", "key", key, "size", n, "want_size", want.size)
		err = tamperedErr(key)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		removeFile(f)
		return nil, err
	}
	return stagedObject{f}, nil
}

// stagedObject is a verified copy in the staging dir, removed on Close.
type stagedObject struct{ *os.File }

func (s stagedObject) Close() error {
	err := s.File.Close()
	if rerr := os.Remove(s.Name()); err == nil {
		err = rerr
	}
	return err
}
