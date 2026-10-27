// Package cofre is hangar-cofre, the operator's own tool (docs/09): it
// runs on the operator's computer, with a read-only bucket credential and
// the recovery kit, and works without the panel. It copies backups to a
// local disk, decrypts them, brings a database up in the local Docker at
// a chosen minute and runs the monthly restore drill.
package cofre

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/pelletier/go-toml/v2"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
)

// Config is cofre.toml.
type Config struct {
	Endpoint  string `toml:"endpoint"`
	Region    string `toml:"region"`
	Bucket    string `toml:"bucket"`
	Prefix    string `toml:"prefix"`
	PathStyle bool   `toml:"path_style"`
	// AccessKey and SecretKey are a READ-ONLY credential. They may also
	// come from HANGAR_COFRE_ACCESS_KEY and HANGAR_COFRE_SECRET_KEY.
	AccessKey string `toml:"access_key"`
	SecretKey string `toml:"secret_key"`
	// Identity is the path of hangar-kit.txt.
	Identity string `toml:"identity"`
}

// DefaultConfigPath is ~/.config/hangar-cofre/cofre.toml.
func DefaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "hangar-cofre", "cofre.toml")
}

// LoadConfig reads the file (missing is fine: flags and environment may
// carry everything) and applies the environment.
func LoadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's own config file
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return c, err
	default:
		dec := toml.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
	}
	if v := os.Getenv("HANGAR_COFRE_ACCESS_KEY"); v != "" {
		c.AccessKey = v
	}
	if v := os.Getenv("HANGAR_COFRE_SECRET_KEY"); v != "" {
		c.SecretKey = v
	}
	c.Identity = expandHome(c.Identity)
	c.Prefix = strings.Trim(c.Prefix, "/")
	if c.Prefix != "" {
		c.Prefix += "/"
	}
	return c, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

// ExampleConfig is what `hangar-cofre init` writes.
const ExampleConfig = `# hangar-cofre (docs/09). Credencial SÓ LEITURA do bucket: crie uma chave
# de aplicação que só lê e lista. Prefira as variáveis de ambiente
# HANGAR_COFRE_ACCESS_KEY e HANGAR_COFRE_SECRET_KEY a gravar aqui.
endpoint = "https://s3.us-west-004.backblazeb2.com"
region = "us-west-004"
bucket = "hangar-backups"
prefix = ""
path_style = true
access_key = ""
secret_key = ""
# O kit de recuperação baixado na tela de Backups.
identity = "~/hangar-kit.txt"
`

// Progress receives a message key and its arguments (the CLI translates).
type Progress func(key string, args ...any)

// Docker runs the docker CLI (tests swap it).
type Docker func(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error

// DockerCLI runs `docker` with the arguments as given: no shell.
func DockerCLI(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // fixed binary, arguments built by this package
	cmd.Stdin = stdin
	if stdout == nil {
		stdout = io.Discard
	}
	cmd.Stdout = stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		return fmt.Errorf("docker %s: %w: %s", args[0], err, msg)
	}
	return nil
}

// Source is where backups are read from: the bucket or a synced folder.
type Source interface {
	List(ctx context.Context, prefix string) ([]archive.Listed, error)
	Open(ctx context.Context, key string) (io.ReadCloser, map[string]string, error)
}

// Vault is hangar-cofre with its source, key and Docker.
type Vault struct {
	Src      Source
	Docker   Docker
	Progress Progress
	// Image, when set by the operator (-image), is the image restores run;
	// otherwise only an official postgres image named by the backup is used.
	Image string
	ids   []age.Identity
	now   func() time.Time
}

// New builds a Vault reading from src.
func New(src Source, ids []age.Identity) *Vault {
	return &Vault{Src: src, Docker: DockerCLI, Progress: func(string, ...any) {}, ids: ids, now: time.Now}
}

// tr reports progress by message key; the CLI translates it.
func (v *Vault) tr(key string, args ...any) { v.Progress(key, args...) }

// SetIdentities sets the kit's keys.
func (v *Vault) SetIdentities(ids []age.Identity) { v.ids = ids }

// --- sources ------------------------------------------------------------------

// Bucket reads from the bucket.
type Bucket struct {
	C      *s3.Client
	Prefix string
}

// NewBucket connects to the bucket in cfg.
func NewBucket(cfg Config) (*Bucket, error) {
	c, err := s3.New(s3.Config{
		Endpoint: cfg.Endpoint, Region: cfg.Region, Bucket: cfg.Bucket,
		AccessKey: cfg.AccessKey, SecretKey: cfg.SecretKey, PathStyle: cfg.PathStyle,
	}, &http.Client{Timeout: 6 * time.Hour})
	if err != nil {
		return nil, err
	}
	return &Bucket{C: c, Prefix: cfg.Prefix}, nil
}

// List lists keys under prefix.
func (b *Bucket) List(ctx context.Context, prefix string) ([]archive.Listed, error) {
	var out []archive.Listed
	err := b.C.List(ctx, b.Prefix+prefix, func(o s3.ObjectInfo) error {
		out = append(out, archive.Listed{Key: strings.TrimPrefix(o.Key, b.Prefix), Size: o.Size, LastModified: o.LastModified})
		return nil
	})
	return out, err
}

// Open downloads an object.
func (b *Bucket) Open(ctx context.Context, key string) (io.ReadCloser, map[string]string, error) {
	rc, info, err := b.C.Get(ctx, b.Prefix+key)
	return rc, info.Metadata, err
}

// Dir reads a folder filled by Sync.
type Dir struct{ Root string }

// List lists files under prefix (their keys), skipping metadata sidecars.
func (d Dir) List(_ context.Context, prefix string) ([]archive.Listed, error) {
	var out []archive.Listed
	base := filepath.Join(d.Root, filepath.FromSlash(prefix))
	err := filepath.WalkDir(base, func(p string, e fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.SkipAll
		}
		if err != nil || e.IsDir() || strings.HasSuffix(p, metaSuffix) {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(d.Root, p)
		out = append(out, archive.Listed{Key: filepath.ToSlash(rel), Size: info.Size(), LastModified: info.ModTime()})
		return nil
	})
	return out, err
}

// Open opens a synced file and its metadata sidecar.
func (d Dir) Open(_ context.Context, key string) (io.ReadCloser, map[string]string, error) {
	clean, err := archive.CleanName(key)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(d.Root)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.FromSlash(clean))
	if err != nil {
		return nil, nil, err
	}
	meta := map[string]string{}
	if raw, err := root.ReadFile(filepath.FromSlash(clean) + metaSuffix); err == nil {
		_ = json.Unmarshal(raw, &meta)
	}
	return f, meta, nil
}

const metaSuffix = ".meta.json"

// --- sync -----------------------------------------------------------------------

// SyncStats counts what Sync did.
type SyncStats struct {
	New, Skipped int
	Bytes        int64
}

// Sync copies every backup in the bucket into dir (never deleting
// anything there) and checks each new file against the SHA-256 recorded
// when it was uploaded.
func (v *Vault) Sync(ctx context.Context, b *Bucket, dir string) (SyncStats, error) {
	var st SyncStats
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return st, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return st, err
	}
	defer func() { _ = root.Close() }()
	objs, err := b.List(ctx, "")
	if err != nil {
		return st, err
	}
	for _, o := range objs {
		if _, ok := archive.ParseKey(o.Key); !ok {
			continue // probes and anything else that is not a backup
		}
		local := filepath.FromSlash(o.Key)
		if info, err := root.Stat(local); err == nil && info.Size() == o.Size {
			st.Skipped++
			continue
		}
		if err := v.syncOne(ctx, b, root, o, local); err != nil {
			return st, fmt.Errorf("%s: %w", o.Key, err)
		}
		st.New++
		st.Bytes += o.Size
		v.tr("cofre.sync_file", "key", o.Key)
	}
	return st, nil
}

func (v *Vault) syncOne(ctx context.Context, b *Bucket, root *os.Root, o archive.Listed, local string) error {
	rc, meta, err := b.Open(ctx, o.Key)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	if err := root.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		return err
	}
	tmp := local + ".part"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(f, h), rc)
	if err := f.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		_ = root.Remove(tmp)
		return cerr
	}
	if want := meta["hangar-sha256"]; want != "" && want != hex.EncodeToString(h.Sum(nil)) {
		_ = root.Remove(tmp)
		return errors.New("checksum differs from the one recorded at upload")
	}
	if err := root.Rename(tmp, local); err != nil {
		return err
	}
	if raw, err := json.Marshal(meta); err == nil {
		_ = root.WriteFile(local+metaSuffix, raw, 0o600)
	}
	_ = root.Chtimes(local, o.LastModified, o.LastModified)
	return nil
}

// --- list -------------------------------------------------------------------------

// Entry summarizes the backups of one service (or the panel).
type Entry struct {
	Label    string
	Dumps    int
	Latest   time.Time
	WALFrom  time.Time
	WALTo    time.Time
	Segments int
}

// List summarizes what the source has.
func (v *Vault) List(ctx context.Context) ([]Entry, error) {
	objs, err := v.Src.List(ctx, "")
	if err != nil {
		return nil, err
	}
	byLabel := map[string]*Entry{}
	get := func(label string) *Entry {
		if e, ok := byLabel[label]; ok {
			return e
		}
		e := &Entry{Label: label}
		byLabel[label] = e
		return e
	}
	for _, l := range objs {
		o, ok := archive.ParseKey(l.Key)
		if !ok {
			continue
		}
		switch o.Kind {
		case archive.KindDump:
			e := get(o.Project + "/" + o.Service)
			e.Dumps++
			if l.LastModified.After(e.Latest) {
				e.Latest = l.LastModified
			}
		case archive.KindBase:
			e := get(o.Project + "/" + o.Service)
			if e.WALFrom.IsZero() || l.LastModified.Before(e.WALFrom) {
				e.WALFrom = l.LastModified
			}
		case archive.KindWAL:
			e := get(o.Project + "/" + o.Service)
			e.Segments++
			if l.LastModified.After(e.WALTo) {
				e.WALTo = l.LastModified
			}
		case archive.KindPanel:
			e := get("painel")
			e.Dumps++
			if l.LastModified.After(e.Latest) {
				e.Latest = l.LastModified
			}
		}
	}
	out := make([]Entry, 0, len(byLabel))
	for _, e := range byLabel {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

// --- decrypt -----------------------------------------------------------------------

// DecryptFile opens an encrypted backup into out (never overwriting).
func (v *Vault) DecryptFile(in, out string) (int64, error) {
	f, err := os.Open(in) //nolint:gosec // a file the operator named
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	plain, err := archive.Open(f, v.ids, archive.DefaultLimits)
	if err != nil {
		return 0, err
	}
	defer func() { _ = plain.Close() }()
	o, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path the operator named
	if err != nil {
		return 0, err
	}
	n, cerr := io.Copy(o, plain)
	if err := o.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		_ = os.Remove(out)
	}
	return n, cerr
}

// DecryptedName drops .age (and .zst, which Open decompresses).
func DecryptedName(in string) string {
	out := strings.TrimSuffix(in, ".age")
	out = strings.TrimSuffix(out, ".zst")
	if out == in {
		out += ".decifrado"
	}
	return out
}

// --- bucket setup ------------------------------------------------------------------

// SetupBucket checks Object Lock and applies the lifecycle rules (docs/09)
// with the operator's administrator credential: only this tool, never the
// server, may change them.
func SetupBucket(ctx context.Context, admin *s3.Client, prefix string) ([]s3.LifecycleRule, error) {
	lock, err := admin.ObjectLock(ctx)
	if err != nil {
		return nil, err
	}
	if !lock.Enabled {
		return nil, errors.New("object lock is not enabled on this bucket")
	}
	var rules []s3.LifecycleRule
	for _, f := range archive.Folders {
		rules = append(rules, s3.LifecycleRule{ID: "hangar-" + f, Prefix: prefix + f + "/", Days: archive.DefaultRetentionDays[f]})
	}
	rules = append(rules, s3.LifecycleRule{ID: "hangar-check", Prefix: prefix + "hangar-check/", Days: 2})
	return rules, admin.PutLifecycle(ctx, rules)
}
