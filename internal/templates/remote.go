package templates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/netguard"
	"github.com/JuniorCarlini/hangar/internal/release"
)

// The community catalog (github.com/JuniorCarlini/hangar-templates) is
// published as catalog.tar.gz, signed with Ed25519 (catalog.tar.gz.sig,
// base64 of the signature over the tarball's bytes) by that repository's
// CI. The panel fetches it once a day, checks the signature with the key
// embedded below, and then validates every template with exactly the rules
// the embedded ones pass: a signed but unsafe template is still refused.
//
// Next to it, catalog.tar.gz.meta (CatalogMeta, JSON) and its signature
// catalog.tar.gz.meta.sig bind the tarball's SHA-256 to a sequence number
// and an expiry. The panel keeps the highest sequence it accepted and
// refuses an older catalog (a replay of a once-valid signed catalog that
// would freeze vulnerable images) and an expired one, so the catalog's CI
// re-signs it on a schedule.

// CatalogPublicKeyHex is the community catalog's public key. Empty turns
// the sync off. Test builds may set it with -ldflags "-X
// github.com/JuniorCarlini/hangar/internal/templates.CatalogPublicKeyHex=...".
var CatalogPublicKeyHex = "188a4925cba3cb0e1bcd51a389128bc8b2d29f0568d85ba781e6e566f028e941"

// DefaultCatalogURL is where the signed community catalog is published.
const DefaultCatalogURL = "https://github.com/JuniorCarlini/hangar-templates/releases/latest/download/catalog.tar.gz"

// Limits of the community catalog.
const (
	MaxCatalogBytes   = 5 << 20  // the compressed tarball
	maxUnpackedBytes  = 20 << 20 // everything inside it
	maxCatalogEntries = 2000
	maxSigBytes       = 1 << 10
	maxMetaBytes      = 4 << 10
	// MaxCatalogValidity caps expires - issued: a catalog cannot be signed
	// to stay valid for longer, whatever its metadata says.
	MaxCatalogValidity = 45 * 24 * time.Hour
	// DefaultCatalogValidity is what pack signs for; the catalog's CI
	// re-signs weekly, so a few failed runs do not expire it.
	DefaultCatalogValidity = 30 * 24 * time.Hour
)

// metaFormat is the only CatalogMeta format this build understands.
const metaFormat = 1

// metaContext prefixes the signed metadata bytes, so a signature over the
// metadata can never be taken for one over a tarball (or the other way).
const metaContext = "hangar-template-catalog-meta/v1\n"

// Files kept in data_dir/templates/.
const (
	storedCatalog = "catalog.tar.gz"
	storedSig     = "catalog.tar.gz.sig"
	storedMeta    = "catalog.tar.gz.meta"
	storedMetaSig = "catalog.tar.gz.meta.sig"
)

// Suffixes, after the catalog URL, of its signature and metadata.
const (
	sigSuffix     = ".sig"
	metaSuffix    = ".meta"
	metaSigSuffix = ".meta.sig"
)

// ErrBadSignature means the catalog was not signed by the catalog key.
var ErrBadSignature = errors.New("template catalog: bad signature")

// Errors of the signed catalog metadata.
var (
	ErrBadMeta         = errors.New("template catalog: invalid metadata")
	ErrCatalogExpired  = errors.New("template catalog: expired")
	ErrCatalogRollback = errors.New("template catalog: older than the one already accepted")
)

// CatalogMeta is the signed metadata of a catalog tarball.
type CatalogMeta struct {
	Format int `json:"format"`
	// Sequence grows with every publication (pack uses the Unix time).
	Sequence int64     `json:"sequence"`
	Issued   time.Time `json:"issued"`
	Expires  time.Time `json:"expires"`
	// SHA256 is the hex digest of the tarball it describes.
	SHA256 string `json:"sha256"`
}

// SignCatalogMeta builds the metadata for tarball and signs it. It returns
// the metadata file and its signature (base64).
func SignCatalogMeta(tarball []byte, sequence int64, issued time.Time, validity time.Duration, priv ed25519.PrivateKey) ([]byte, string, error) {
	if sequence <= 0 || validity <= 0 || validity > MaxCatalogValidity {
		return nil, "", fmt.Errorf("%w: sequence must be positive and validity at most %s", ErrBadMeta, MaxCatalogValidity)
	}
	sum := sha256.Sum256(tarball)
	issued = issued.UTC().Truncate(time.Second)
	meta, err := json.Marshal(CatalogMeta{
		Format: metaFormat, Sequence: sequence, Issued: issued, Expires: issued.Add(validity), SHA256: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		return nil, "", err
	}
	return meta, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(metaContext), meta...))), nil
}

// VerifyCatalogMeta checks the metadata's signature with pub and that it
// describes tarball. Expiry and sequence are checked by the caller (an
// expired catalog still tells which sequence was accepted).
func VerifyCatalogMeta(pub ed25519.PublicKey, tarball, meta []byte, sigB64 string) (*CatalogMeta, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return nil, ErrBadSignature
	}
	if !ed25519.Verify(pub, append([]byte(metaContext), meta...), sig) {
		return nil, ErrBadSignature
	}
	var m CatalogMeta
	dec := json.NewDecoder(bytes.NewReader(meta))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadMeta, err) //nolint:errorlint // the cause is only for the log
	}
	sum := sha256.Sum256(tarball)
	switch {
	case m.Format != metaFormat:
		return nil, fmt.Errorf("%w: format %d", ErrBadMeta, m.Format)
	case m.Sequence <= 0:
		return nil, fmt.Errorf("%w: sequence %d", ErrBadMeta, m.Sequence)
	case !m.Expires.After(m.Issued) || m.Expires.Sub(m.Issued) > MaxCatalogValidity:
		return nil, fmt.Errorf("%w: validity from %s to %s", ErrBadMeta, m.Issued, m.Expires)
	case subtle.ConstantTimeCompare([]byte(m.SHA256), []byte(hex.EncodeToString(sum[:]))) != 1:
		return nil, fmt.Errorf("%w: it describes another tarball", ErrBadMeta)
	}
	return &m, nil
}

// CatalogPublicKey decodes CatalogPublicKeyHex; nil when it is empty.
func CatalogPublicKey() (ed25519.PublicKey, error) {
	if CatalogPublicKeyHex == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(CatalogPublicKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid template catalog public key in the binary")
	}
	return ed25519.PublicKey(b), nil
}

// SignCatalog signs a tarball (the pack command, in the catalog's CI).
func SignCatalog(tarball []byte, priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, tarball))
}

// VerifyCatalog checks the signature of tarball with pub.
func VerifyCatalog(pub ed25519.PublicKey, tarball []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub, tarball, sig) {
		return ErrBadSignature
	}
	return nil
}

// Pack builds the catalog tarball from the template folders under root:
// every one must be valid. The output is deterministic (sorted, no
// timestamps or owners), so the same folders always give the same bytes.
func Pack(root string) ([]byte, error) {
	fsys := os.DirFS(root)
	if _, err := LoadFS(fsys, "."); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if !isTemplateDir(e) {
			continue
		}
		files, err := readFolder(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			hdr := &tar.Header{Name: e.Name() + "/" + n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, err
			}
			if _, err := tw.Write(files[n]); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unpack reads a catalog tarball into folders (id -> file -> content). A
// malformed archive (links, paths outside a single folder level, too big)
// fails as a whole; the templates themselves are validated afterwards.
func Unpack(tarball []byte) (map[string]map[string][]byte, error) {
	if len(tarball) > MaxCatalogBytes {
		return nil, fmt.Errorf("catalog: %d bytes, at most %d", len(tarball), MaxCatalogBytes)
	}
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(io.LimitReader(gz, maxUnpackedBytes+1))
	out := map[string]map[string][]byte{}
	total, n := 0, 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("catalog: %w", err)
		}
		if n++; n > maxCatalogEntries {
			return nil, errors.New("catalog: too many entries")
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		dir, file := path.Split(name)
		dir = strings.TrimSuffix(dir, "/")
		switch {
		case hdr.Typeflag != tar.TypeReg:
			return nil, fmt.Errorf("catalog: %s: only regular files are allowed", hdr.Name)
		case path.Clean(name) != name || strings.Contains(dir, "/") || !idRE.MatchString(dir) || file == "":
			return nil, fmt.Errorf("catalog: %s: entries must be <id>/<file>", hdr.Name)
		case hdr.Size < 0 || hdr.Size > maxFileBytes:
			return nil, fmt.Errorf("catalog: %s: %d bytes, at most %d", hdr.Name, hdr.Size, maxFileBytes)
		}
		total += int(hdr.Size)
		if total > maxUnpackedBytes {
			return nil, errors.New("catalog: too large once unpacked")
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("catalog: %s: %w", hdr.Name, err)
		}
		if out[dir] == nil {
			out[dir] = map[string][]byte{}
		}
		if _, dup := out[dir][file]; dup {
			return nil, fmt.Errorf("catalog: %s: repeated", hdr.Name)
		}
		out[dir][file] = b
	}
	return out, nil
}

// Accept validates every folder of an unpacked catalog and keeps the
// templates this Hangar can run: an invalid template, or one that needs a
// newer Hangar (min_hangar), is skipped on its own, with the reason.
func Accept(folders map[string]map[string][]byte, running string) ([]*Template, []error) {
	ids := make([]string, 0, len(folders))
	for id := range folders {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var ok []*Template
	var skipped []error
	for _, id := range ids {
		t, err := Parse(id, folders[id])
		if err != nil {
			skipped = append(skipped, prefixLines(id+"/", err))
			continue
		}
		if !runsOn(t.MinHangar, running) {
			skipped = append(skipped, fmt.Errorf("%s: needs Hangar %s or newer (running %s)", id, t.MinHangar, running))
			continue
		}
		t.Remote = true
		ok = append(ok, t)
	}
	return ok, skipped
}

// runsOn reports whether a template needing minimum runs on running. A
// development build ("dev", or a git describe like v1.2.3-4-gabc) counts
// as its base version; one with no version at all accepts everything.
func runsOn(minimum, running string) bool {
	if minimum == "" {
		return true
	}
	need, err := release.ParseVersion(minimum)
	if err != nil {
		return false
	}
	base, _, _ := strings.Cut(running, "-")
	have, err := release.ParseVersion(base)
	if err != nil {
		return true
	}
	return !need.Newer(have)
}

// Syncer keeps the community catalog: it loads the copy saved in Dir at
// start and refreshes it once a day.
type Syncer struct {
	// URL of catalog.tar.gz; the signature is URL + ".sig".
	URL string
	// Dir keeps the last accepted catalog (data_dir/templates).
	Dir string
	// Version is the running Hangar (for min_hangar).
	Version string
	// Key verifies the signature; nil turns the sync off.
	Key      ed25519.PublicKey
	Registry *Registry
	Base     *Catalog
	HTTP     *http.Client
	Log      *slog.Logger
	// Now is the clock for expiry (default time.Now).
	Now func() time.Time

	mu sync.Mutex
	// accepted is the metadata of the catalog in use (or, when that one
	// expired, of the last one accepted): its sequence is the floor for
	// the next one.
	accepted *CatalogMeta
}

// NewSyncer prepares the sync with the embedded key and the safe HTTP
// client: public addresses only, https only, redirects (GitHub sends the
// download to its CDN) checked the same way.
func NewSyncer(url, dir, version string, reg *Registry, log *slog.Logger) (*Syncer, error) {
	key, err := CatalogPublicKey()
	if err != nil {
		return nil, err
	}
	c := netguard.Client(false, 2*time.Minute)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirect to a non-https URL")
		}
		return nil
	}
	return &Syncer{URL: url, Dir: dir, Version: version, Key: key, Registry: reg, Base: Builtin(), HTTP: c, Log: log}, nil
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// signed is a catalog as published: the tarball, its signature, its
// metadata and the metadata's signature.
type signed struct {
	tarball, sig, meta, metaSig []byte
}

// LoadStored applies the catalog saved by an earlier sync, checking it
// again (the disk is not trusted more than the network). An expired one is
// not applied, but its sequence still is the floor for the next sync. A
// catalog stored by a build without metadata fails here and is replaced by
// the next sync.
func (s *Syncer) LoadStored() error {
	if s.Key == nil {
		return nil
	}
	var c signed
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{{storedCatalog, &c.tarball}, {storedSig, &c.sig}, {storedMeta, &c.meta}, {storedMetaSig, &c.metaSig}} {
		b, err := os.ReadFile(filepath.Join(s.Dir, f.name))
		if errors.Is(err, os.ErrNotExist) && f.name == storedCatalog {
			return nil
		}
		if err != nil {
			return err
		}
		*f.dst = b
	}
	if err := VerifyCatalog(s.Key, c.tarball, string(c.sig)); err != nil {
		return err
	}
	meta, err := VerifyCatalogMeta(s.Key, c.tarball, c.meta, string(c.metaSig))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.accepted = meta
	s.mu.Unlock()
	if !s.now().Before(meta.Expires) {
		return fmt.Errorf("%w on %s", ErrCatalogExpired, meta.Expires.Format(time.RFC3339))
	}
	_, err = s.apply(c.tarball)
	return err
}

// check verifies a fetched catalog against the key, the clock and the
// sequence already accepted.
func (s *Syncer) check(c signed) (*CatalogMeta, error) {
	if err := VerifyCatalog(s.Key, c.tarball, string(c.sig)); err != nil {
		return nil, err
	}
	meta, err := VerifyCatalogMeta(s.Key, c.tarball, c.meta, string(c.metaSig))
	if err != nil {
		return nil, err
	}
	if !s.now().Before(meta.Expires) {
		return nil, fmt.Errorf("%w on %s", ErrCatalogExpired, meta.Expires.Format(time.RFC3339))
	}
	s.mu.Lock()
	floor := s.accepted
	s.mu.Unlock()
	if floor != nil {
		switch {
		case meta.Sequence < floor.Sequence:
			return nil, fmt.Errorf("%w: sequence %d, already accepted %d", ErrCatalogRollback, meta.Sequence, floor.Sequence)
		case meta.Sequence == floor.Sequence && meta.SHA256 != floor.SHA256:
			// Two different catalogs signed with one sequence: keep the
			// first.
			return nil, fmt.Errorf("%w: sequence %d reused for another catalog", ErrCatalogRollback, meta.Sequence)
		}
	}
	return meta, nil
}

// dropIfExpired goes back to the embedded catalog once the accepted one
// expired and no newer one could be fetched.
func (s *Syncer) dropIfExpired() {
	s.mu.Lock()
	meta := s.accepted
	s.mu.Unlock()
	if meta != nil && !s.now().Before(meta.Expires) && s.Registry.Catalog() != s.Base {
		s.Log.Warn("community template catalog expired; using only the embedded templates", "expired", meta.Expires)
		s.Registry.Set(s.Base)
	}
}

// Sync downloads, verifies and applies the community catalog, then saves
// it for the next start. It returns how many templates were accepted.
func (s *Syncer) Sync(ctx context.Context) (int, error) {
	if s.Key == nil {
		return 0, errors.New("template catalog: no public key in this build")
	}
	var c signed
	var err error
	if c.tarball, err = s.fetch(ctx, s.URL, MaxCatalogBytes); err != nil {
		return 0, err
	}
	if c.sig, err = s.fetch(ctx, s.URL+sigSuffix, maxSigBytes); err != nil {
		return 0, err
	}
	if c.meta, err = s.fetch(ctx, s.URL+metaSuffix, maxMetaBytes); err != nil {
		return 0, err
	}
	if c.metaSig, err = s.fetch(ctx, s.URL+metaSigSuffix, maxSigBytes); err != nil {
		return 0, err
	}
	meta, err := s.check(c)
	if err != nil {
		return 0, err
	}
	n, err := s.apply(c.tarball)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.accepted = meta
	s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return n, err
	}
	// Each file is replaced on its own; a crash halfway leaves a set whose
	// signatures do not match, which the next start refuses and the next
	// sync replaces.
	for _, f := range []struct {
		name string
		data []byte
	}{{storedSig, c.sig}, {storedCatalog, c.tarball}, {storedMetaSig, c.metaSig}, {storedMeta, c.meta}} {
		if err := writeAtomic(filepath.Join(s.Dir, f.name), f.data); err != nil {
			return n, err
		}
	}
	return n, nil
}

// apply unpacks an already verified tarball and puts it in use.
func (s *Syncer) apply(tarball []byte) (int, error) {
	folders, err := Unpack(tarball)
	if err != nil {
		return 0, err
	}
	ok, skipped := Accept(folders, s.Version)
	merged, refused := MergeChecked(s.Base, ok)
	for _, e := range append(skipped, refused...) {
		s.Log.Warn("community template skipped", "reason", e.Error())
	}
	s.Registry.Set(merged)
	return len(ok) - len(refused), nil
}

func (s *Syncer) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	// The client refuses internal addresses at connect time (netguard).
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("template catalog: %s: only https URLs are allowed", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("template catalog: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("template catalog: %s: HTTP %d", url, res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("template catalog: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("template catalog: %s is larger than %d bytes", url, limit)
	}
	return b, nil
}

// Run syncs shortly after start (a random delay, so servers do not all
// call at once) and then about once a day, until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	if s.Key == nil {
		s.Log.Info("community template catalog sync disabled: no catalog public key in this build")
		return
	}
	wait := 30*time.Second + jitter(5*time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if n, err := s.Sync(ctx); err != nil {
			s.Log.Warn("sync community template catalog", "error", err)
			s.dropIfExpired()
		} else {
			s.Log.Info("community template catalog synced", "templates", n)
		}
		wait = 24*time.Hour + jitter(time.Hour)
	}
}

func jitter(max time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return time.Duration(n.Int64())
}

func writeAtomic(name string, data []byte) error {
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}
