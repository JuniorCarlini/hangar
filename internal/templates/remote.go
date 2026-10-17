package templates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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

// CatalogPublicKeyHex is the community catalog's public key. Empty turns
// the sync off. Test builds may set it with -ldflags "-X
// github.com/JuniorCarlini/hangar/internal/templates.CatalogPublicKeyHex=...".
var CatalogPublicKeyHex = ""

// DefaultCatalogURL is where the signed community catalog is published.
const DefaultCatalogURL = "https://github.com/JuniorCarlini/hangar-templates/releases/latest/download/catalog.tar.gz"

// Limits of the community catalog.
const (
	MaxCatalogBytes   = 5 << 20  // the compressed tarball
	maxUnpackedBytes  = 20 << 20 // everything inside it
	maxCatalogEntries = 2000
	maxSigBytes       = 1 << 10
)

// Files kept in data_dir/templates/.
const (
	storedCatalog = "catalog.tar.gz"
	storedSig     = "catalog.tar.gz.sig"
)

// ErrBadSignature means the catalog was not signed by the catalog key.
var ErrBadSignature = errors.New("template catalog: bad signature")

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

// LoadStored applies the catalog saved by an earlier sync, checking it
// again (the disk is not trusted more than the network).
func (s *Syncer) LoadStored() error {
	if s.Key == nil {
		return nil
	}
	tarball, err := os.ReadFile(filepath.Join(s.Dir, storedCatalog))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(s.Dir, storedSig))
	if err != nil {
		return err
	}
	_, err = s.apply(tarball, string(sig))
	return err
}

// Sync downloads, verifies and applies the community catalog, then saves
// it for the next start. It returns how many templates were accepted.
func (s *Syncer) Sync(ctx context.Context) (int, error) {
	if s.Key == nil {
		return 0, errors.New("template catalog: no public key in this build")
	}
	tarball, err := s.fetch(ctx, s.URL, MaxCatalogBytes)
	if err != nil {
		return 0, err
	}
	sig, err := s.fetch(ctx, s.URL+".sig", maxSigBytes)
	if err != nil {
		return 0, err
	}
	n, err := s.apply(tarball, string(sig))
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return n, err
	}
	if err := writeAtomic(filepath.Join(s.Dir, storedSig), sig); err != nil {
		return n, err
	}
	return n, writeAtomic(filepath.Join(s.Dir, storedCatalog), tarball)
}

func (s *Syncer) apply(tarball []byte, sig string) (int, error) {
	if err := VerifyCatalog(s.Key, tarball, sig); err != nil {
		return 0, err
	}
	folders, err := Unpack(tarball)
	if err != nil {
		return 0, err
	}
	ok, skipped := Accept(folders, s.Version)
	for _, e := range skipped {
		s.Log.Warn("community template skipped", "reason", e.Error())
	}
	s.Registry.Set(Merge(s.Base, ok))
	return len(ok), nil
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
