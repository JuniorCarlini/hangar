package templates

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// publication is one signed catalog as the catalog's CI publishes it.
type publication struct {
	tarball, meta []byte
	sig, metaSig  string
}

func publish(t *testing.T, priv ed25519.PrivateKey, folders map[string]map[string][]byte, seq int64, issued time.Time, validity time.Duration) publication {
	t.Helper()
	tarball, err := Pack(writeFolders(t, folders))
	if err != nil {
		t.Fatal(err)
	}
	meta, metaSig, err := SignCatalogMeta(tarball, seq, issued, validity, priv)
	if err != nil {
		t.Fatal(err)
	}
	return publication{tarball: tarball, sig: SignCatalog(tarball, priv), meta: meta, metaSig: metaSig}
}

// catalogServer serves whatever publication is current; nil meta files
// answer 404 (a catalog published by an older pack).
type catalogServer struct {
	*httptest.Server
	mu  sync.Mutex
	cur publication
}

func newCatalogServer(t *testing.T, p publication) *catalogServer {
	t.Helper()
	cs := &catalogServer{cur: p}
	cs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		p := cs.cur
		cs.mu.Unlock()
		var body []byte
		switch r.URL.Path {
		case "/catalog.tar.gz":
			body = p.tarball
		case "/catalog.tar.gz.sig":
			body = []byte(p.sig)
		case "/catalog.tar.gz.meta":
			body = p.meta
		case "/catalog.tar.gz.meta.sig":
			body = []byte(p.metaSig)
		}
		if body == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *catalogServer) set(p publication) {
	cs.mu.Lock()
	cs.cur = p
	cs.mu.Unlock()
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// builtinBump is the embedded postgres template with another image tag and
// a higher version: what the catalog's daily updater publishes.
func builtinBump(t *testing.T, image string, version string) map[string][]byte {
	t.Helper()
	f, err := readFolder(catalogFS, "catalog/postgres")
	if err != nil {
		t.Fatal(err)
	}
	f[FileCompose] = []byte(strings.Replace(string(f[FileCompose]), "image: postgres:18", "image: "+image, 1))
	f[FileMeta] = []byte(strings.Replace(string(f[FileMeta]), "version = 2", "version = "+version, 1))
	return f
}

func TestSyncerFetchesVerifiesStoresAndReloads(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	clk := &clock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	p := publish(t, priv, map[string]map[string][]byte{
		"extra":    community("extra", "1", ""),
		"postgres": builtinBump(t, "postgres:18.1", "99"),
	}, 100, clk.t, DefaultCatalogValidity)
	srv := newCatalogServer(t, p)

	dir := t.TempDir()
	newSyncer := func(key ed25519.PublicKey) (*Syncer, *Registry) {
		reg := NewRegistry(Builtin())
		return &Syncer{
			URL: srv.URL + "/catalog.tar.gz", Dir: dir, Version: "v1.0.0", Key: key, Registry: reg, Base: Builtin(),
			HTTP: srv.Client(), Log: slog.New(slog.DiscardHandler), Now: clk.now,
		}, reg
	}

	s, reg := newSyncer(pub)
	n, err := s.Sync(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("sync: %d, %v", n, err)
	}
	if _, ok := reg.Catalog().Get("extra"); !ok {
		t.Error("the community template must be offered")
	}
	if pg, _ := reg.Catalog().Get("postgres"); !pg.Remote || pg.Version != 99 || pg.Services[0].Image != "postgres:18.1" {
		t.Errorf("a higher version that only moves the image tag updates the embedded one: %+v", pg)
	}

	// A restart loads what was stored, checking the signatures again.
	s2, reg2 := newSyncer(pub)
	if err := s2.LoadStored(); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg2.Catalog().Get("extra"); !ok {
		t.Error("stored catalog not loaded at start")
	}
	if err := os.WriteFile(filepath.Join(dir, storedCatalog), append(p.tarball, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	s3, reg3 := newSyncer(pub)
	if err := s3.LoadStored(); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a tampered stored catalog must be refused: %v", err)
	}
	if _, ok := reg3.Catalog().Get("extra"); ok {
		t.Error("a tampered catalog must not be applied")
	}

	// Signed with another key: refused, and the catalog stays as it was.
	other, _, _ := ed25519.GenerateKey(nil)
	s4, reg4 := newSyncer(other)
	if _, err := s4.Sync(context.Background()); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key: %v", err)
	}
	if reg4.Catalog() != Builtin() {
		t.Error("a refused catalog must leave the embedded one in place")
	}

	// No key in the build: the sync is off.
	s5, _ := newSyncer(nil)
	if _, err := s5.Sync(context.Background()); err == nil {
		t.Error("sync without a key must fail")
	}
	s5.Run(context.Background()) // returns at once
}

// SEC-020: a once-valid signed catalog with a lower sequence (a replay by
// whoever sits between the panel and GitHub, or a mirror) is refused, even
// after a restart; so is an expired one, or one without metadata.
func TestSyncerRefusesReplayAndExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	clk := &clock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	old := publish(t, priv, map[string]map[string][]byte{"postgres": builtinBump(t, "postgres:18.0", "3")}, 100, clk.t.Add(-48*time.Hour), DefaultCatalogValidity)
	cur := publish(t, priv, map[string]map[string][]byte{"postgres": builtinBump(t, "postgres:18.1", "4")}, 200, clk.t, DefaultCatalogValidity)
	srv := newCatalogServer(t, cur)
	dir := t.TempDir()
	newSyncer := func() (*Syncer, *Registry) {
		reg := NewRegistry(Builtin())
		return &Syncer{
			URL: srv.URL + "/catalog.tar.gz", Dir: dir, Version: "v1.0.0", Key: pub, Registry: reg, Base: Builtin(),
			HTTP: srv.Client(), Log: slog.New(slog.DiscardHandler), Now: clk.now,
		}, reg
	}
	image := func(reg *Registry) string {
		pg, _ := reg.Catalog().Get("postgres")
		return pg.Services[0].Image
	}

	s, reg := newSyncer()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatalf("the current catalog must be accepted: %v", err)
	}
	if image(reg) != "postgres:18.1" {
		t.Fatalf("image = %s", image(reg))
	}

	// Replay of the older catalog, live and after a restart.
	srv.set(old)
	if _, err := s.Sync(context.Background()); !errors.Is(err, ErrCatalogRollback) {
		t.Errorf("older sequence: %v", err)
	}
	if image(reg) != "postgres:18.1" {
		t.Error("a replayed catalog replaced the current one")
	}
	s2, reg2 := newSyncer()
	if err := s2.LoadStored(); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Sync(context.Background()); !errors.Is(err, ErrCatalogRollback) {
		t.Errorf("older sequence after a restart: %v", err)
	}
	if image(reg2) != "postgres:18.1" {
		t.Error("a replayed catalog replaced the stored one after a restart")
	}

	// The same sequence for different content is refused; the same
	// catalog again is fine.
	equivocal := publish(t, priv, map[string]map[string][]byte{"postgres": builtinBump(t, "postgres:18.2", "5")}, 200, clk.t, DefaultCatalogValidity)
	srv.set(equivocal)
	if _, err := s.Sync(context.Background()); !errors.Is(err, ErrCatalogRollback) {
		t.Errorf("reused sequence: %v", err)
	}
	srv.set(cur)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Errorf("the same catalog again: %v", err)
	}

	// Without metadata (an older publication format) nothing is applied.
	srv.set(publication{tarball: cur.tarball, sig: cur.sig})
	fresh := &Syncer{
		URL: srv.URL + "/catalog.tar.gz", Dir: t.TempDir(), Version: "v1.0.0", Key: pub, Registry: NewRegistry(Builtin()), Base: Builtin(),
		HTTP: srv.Client(), Log: slog.New(slog.DiscardHandler), Now: clk.now,
	}
	freshReg := fresh.Registry
	if _, err := fresh.Sync(context.Background()); err == nil {
		t.Error("a catalog without metadata was accepted")
	}
	if freshReg.Catalog() != Builtin() {
		t.Error("a catalog without metadata was applied")
	}

	// Time passes beyond the expiry with no newer catalog: the next
	// failed sync drops back to the embedded templates, a restart does
	// not load the expired one, and its sequence still blocks the replay.
	clk.t = clk.t.Add(DefaultCatalogValidity + time.Hour)
	srv.set(cur)
	if _, err := s.Sync(context.Background()); !errors.Is(err, ErrCatalogExpired) {
		t.Errorf("expired: %v", err)
	}
	s.dropIfExpired()
	if reg.Catalog() != Builtin() {
		t.Error("an expired catalog stayed in use")
	}
	s3, reg3 := newSyncer()
	if err := s3.LoadStored(); !errors.Is(err, ErrCatalogExpired) {
		t.Errorf("expired stored catalog: %v", err)
	}
	if reg3.Catalog() != Builtin() {
		t.Error("an expired stored catalog was applied")
	}
	srv.set(publish(t, priv, map[string]map[string][]byte{"postgres": builtinBump(t, "postgres:18.0", "3")}, 150, clk.t, DefaultCatalogValidity))
	if _, err := s3.Sync(context.Background()); !errors.Is(err, ErrCatalogRollback) {
		t.Errorf("a fresh signature on an older sequence after expiry: %v", err)
	}
	newer := publish(t, priv, map[string]map[string][]byte{"postgres": builtinBump(t, "postgres:18.3", "6")}, 300, clk.t, DefaultCatalogValidity)
	srv.set(newer)
	if _, err := s3.Sync(context.Background()); err != nil || image(reg3) != "postgres:18.3" {
		t.Errorf("a newer re-signed catalog must be accepted: %v, %s", err, image(reg3))
	}
}

func TestCatalogMetaRules(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tarball := []byte("tarball")
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	meta, sig, err := SignCatalogMeta(tarball, 1, now, DefaultCatalogValidity, priv)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := VerifyCatalogMeta(pub, tarball, meta, sig); err != nil || m.Sequence != 1 || !m.Expires.Equal(now.Add(DefaultCatalogValidity)) {
		t.Fatalf("good metadata: %+v, %v", m, err)
	}
	if _, err := VerifyCatalogMeta(pub, []byte("other"), meta, sig); !errors.Is(err, ErrBadMeta) {
		t.Errorf("metadata of another tarball: %v", err)
	}
	// The tarball's own signature cannot stand in for the metadata's
	// (domain separation), nor the other way round.
	if _, err := VerifyCatalogMeta(pub, tarball, meta, SignCatalog(meta, priv)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a plain signature over the metadata was accepted: %v", err)
	}
	if _, _, err := SignCatalogMeta(tarball, 1, now, MaxCatalogValidity+time.Hour, priv); err == nil {
		t.Error("pack signed a validity above the cap")
	}
	if _, _, err := SignCatalogMeta(tarball, 0, now, time.Hour, priv); err == nil {
		t.Error("pack signed sequence 0")
	}
	// A validity above the cap is refused even when signed by hand.
	long := []byte(`{"format":1,"sequence":5,"issued":"2026-01-01T00:00:00Z","expires":"2027-01-01T00:00:00Z","sha256":"` + sha(tarball) + `"}`)
	if _, err := VerifyCatalogMeta(pub, tarball, long, signMeta(long, priv)); !errors.Is(err, ErrBadMeta) {
		t.Errorf("a year of validity: %v", err)
	}
	unknown := []byte(`{"format":2,"sequence":5,"issued":"2026-01-01T00:00:00Z","expires":"2026-01-02T00:00:00Z","sha256":"` + sha(tarball) + `"}`)
	if _, err := VerifyCatalogMeta(pub, tarball, unknown, signMeta(unknown, priv)); !errors.Is(err, ErrBadMeta) {
		t.Errorf("unknown format: %v", err)
	}
}

// SEC-020: the community catalog cannot replace a template the binary
// ships; it may only move its images' tags.
func TestMergeCommunityCannotShadowBuiltin(t *testing.T) {
	parse := func(f map[string][]byte) *Template {
		t.Helper()
		tp, err := Parse("postgres", f)
		if err != nil {
			t.Fatal(err)
		}
		tp.Remote = true
		return tp
	}
	emb, _ := Builtin().Get("postgres")

	cases := map[string]map[string][]byte{
		"other image repository": builtinBump(t, "evil/postgres:18.1", "50"),
		"other registry":         builtinBump(t, "ghcr.io/x/postgres:18", "50"),
	}
	cmd := builtinBump(t, "postgres:18.1", "50")
	if !strings.Contains(string(cmd[FileCompose]), "    environment:\n") {
		t.Fatal("test case does not apply: environment")
	}
	cmd[FileCompose] = []byte(strings.Replace(string(cmd[FileCompose]), "    environment:\n", "    environment:\n      EXTRA: \"1\"\n", 1))
	cases["extra env"] = cmd
	for name, f := range cases {
		merged, refused := MergeChecked(Builtin(), []*Template{parse(f)})
		got, _ := merged.Get("postgres")
		if len(refused) != 1 || got != emb {
			t.Errorf("%s: shadowed the embedded template (refused %v)", name, refused)
		}
	}

	// Only a tag move (and text) is taken; the text stays the embedded one.
	bump := builtinBump(t, "postgres:18.1@sha256:"+strings.Repeat("a", 64), "50")
	bump[FileMeta] = []byte(strings.Replace(string(bump[FileMeta]), "PostgreSQL", "Totally Legit DB", 1))
	merged, refused := MergeChecked(Builtin(), []*Template{parse(bump)})
	got, _ := merged.Get("postgres")
	if len(refused) != 0 || got.Version != 50 || !got.Remote || !strings.HasPrefix(got.Services[0].Image, "postgres:18.1@") {
		t.Fatalf("image bump: %+v, refused %v", got, refused)
	}
	if got.Name.In("en") != emb.Name.In("en") || string(got.Logo) != string(emb.Logo) {
		t.Error("the presentation of a bumped template must stay the embedded one")
	}
	if emb.Services[0].Image != "postgres:18" {
		t.Error("the merge modified the embedded template in place")
	}

	// Same or lower version: the embedded one stays, nothing is refused.
	if merged, refused := MergeChecked(Builtin(), []*Template{parse(builtinBump(t, "postgres:18.1", "2"))}); len(refused) != 0 {
		t.Errorf("tie refused: %v", refused)
	} else if pg, _ := merged.Get("postgres"); pg != emb {
		t.Error("a tie replaced the embedded template")
	}
}

func TestImageRepo(t *testing.T) {
	for in, want := range map[string]string{
		"postgres:18":                      "postgres",
		"postgres":                         "postgres",
		"registry:5000/x/y:1.2":            "registry:5000/x/y",
		"registry:5000/x/y":                "registry:5000/x/y",
		"ghcr.io/a/b:1@sha256:" + "ab":     "ghcr.io/a/b",
		"ghcr.io/a/b@sha256:" + "ab":       "ghcr.io/a/b",
		"docker.io/library/redis:8-alpine": "docker.io/library/redis",
	} {
		if got := imageRepo(in); got != want {
			t.Errorf("imageRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// signMeta signs hand-written metadata the way pack does.
func signMeta(meta []byte, priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(metaContext), meta...)))
}
