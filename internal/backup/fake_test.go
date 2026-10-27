package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// fakeNode is "Docker" for the backup tests: pg_dump answers dumpData,
// the test restore answers checkOut, and the WAL outbox is a map.
type fakeNode struct {
	mu       sync.Mutex
	dumpData []byte
	checkOut string
	taskIn   []byte
	outbox   map[string][]byte
	removed  []string
	archive  string // what pg_stat_archiver answers
	execs    []string
}

func (f *fakeNode) EnsureEdge(context.Context, node.EdgeSpec) error            { return nil }
func (f *fakeNode) ConnectEdge(context.Context, string) error                  { return nil }
func (f *fakeNode) EnsureProjectNetwork(context.Context, string, string) error { return nil }
func (f *fakeNode) RemoveProjectNetwork(context.Context, string) error         { return nil }
func (f *fakeNode) Start(context.Context, string, string) error                { return nil }
func (f *fakeNode) Stop(context.Context, string, string) error                 { return nil }
func (f *fakeNode) Restart(context.Context, string, string) error              { return nil }
func (f *fakeNode) Remove(context.Context, string, string) error               { return nil }
func (f *fakeNode) SetLinked(context.Context, string, string, []string) error  { return nil }
func (f *fakeNode) ListManaged(context.Context) ([]node.Managed, error)        { return nil, nil }
func (f *fakeNode) ServiceAddress(context.Context, string, string, int) (string, error) {
	return "", nil
}

func (f *fakeNode) Logs(context.Context, string, string, node.LogOptions, func(node.LogLine) error) error {
	return nil
}

func (f *fakeNode) Deploy(_ context.Context, s node.ServiceSpec, _ node.DeployOptions) (node.DeployResult, error) {
	return node.DeployResult{ContainerID: "c_" + s.Service, ImageRef: s.Image}, s.Validate()
}

func (f *fakeNode) Status(context.Context, string, string) (node.Status, error) {
	return node.Status{Exists: true, Running: true, State: "running"}, nil
}

func (f *fakeNode) Exec(ctx context.Context, p, s string, cmd []string, w io.Writer) error {
	return f.ExecIO(ctx, p, s, cmd, nil, w)
}

func (f *fakeNode) ExecIO(_ context.Context, _, _ string, cmd []string, _ io.Reader, w io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	full := strings.Join(cmd, " ")
	f.execs = append(f.execs, full)
	switch {
	case strings.Contains(full, "pg_dump"):
		_, err := w.Write(f.dumpData)
		return err
	case strings.Contains(full, "pg_stat_archiver"):
		_, err := io.WriteString(w, f.archive+"\n")
		return err
	case strings.Contains(full, "ls -1"):
		var names []string
		for n := range f.outbox {
			names = append(names, n)
		}
		sort.Strings(names)
		_, err := io.WriteString(w, strings.Join(names, "\n"))
		return err
	case cmd[0] == "cat":
		_, err := w.Write(f.outbox[filepath.Base(cmd[1])])
		return err
	case cmd[0] == "rm":
		name := filepath.Base(cmd[2])
		delete(f.outbox, name)
		f.removed = append(f.removed, name)
	}
	return nil
}

func (f *fakeNode) RunTask(_ context.Context, spec node.TaskSpec, stdin io.Reader, stdout io.Writer) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	f.mu.Lock()
	f.taskIn = in
	out := f.checkOut
	f.mu.Unlock()
	if out == "" {
		return io.ErrUnexpectedEOF
	}
	_, err := io.WriteString(stdout, out)
	return err
}

// memStore is an in-memory bucket with Object Lock and a credential that
// cannot delete.
type memStore struct {
	mu        sync.Mutex
	objects   map[string][]byte
	opts      map[string]s3.PutOptions
	times     map[string]time.Time
	canDelete bool
	noLock    bool
}

func newMemStore() *memStore {
	return &memStore{objects: map[string][]byte{}, opts: map[string]s3.PutOptions{}, times: map[string]time.Time{}}
}

func (s *memStore) Put(_ context.Context, key string, f s3.File, size int64, o s3.PutOptions) error {
	if s.noLock && o.LockMode != "" {
		return &s3.Error{Status: 400, Code: "InvalidRequest", Message: "Bucket is missing Object Lock Configuration"}
	}
	b := make([]byte, size)
	if _, err := f.ReadAt(b, 0); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key], s.opts[key], s.times[key] = b, o, time.Now()
	return nil
}

func (s *memStore) Head(_ context.Context, key string) (s3.ObjectInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	if !ok {
		return s3.ObjectInfo{}, &s3.Error{Status: 404, Code: "NoSuchKey"}
	}
	return s3.ObjectInfo{Key: key, Size: int64(len(b)), Metadata: s.opts[key].Metadata, LockMode: s.opts[key].LockMode, LastModified: s.times[key]}, nil
}

func (s *memStore) Get(ctx context.Context, key string) (io.ReadCloser, s3.ObjectInfo, error) {
	info, err := s.Head(ctx, key)
	if err != nil {
		return nil, info, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return io.NopCloser(bytes.NewReader(s.objects[key])), info, nil
}

func (s *memStore) List(_ context.Context, prefix string, fn func(s3.ObjectInfo) error) error {
	s.mu.Lock()
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	s.mu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		s.mu.Lock()
		info := s3.ObjectInfo{Key: k, Size: int64(len(s.objects[k])), LastModified: s.times[k]}
		s.mu.Unlock()
		if err := fn(info); err != nil {
			return err
		}
	}
	return nil
}

func (s *memStore) Delete(context.Context, string, string) error {
	if s.canDelete {
		return nil
	}
	return &s3.Error{Status: 403, Code: "AccessDenied"}
}

func (s *memStore) PresignGet(key string, _ time.Duration) string {
	return "https://bucket.example/" + key + "?sig"
}

func (s *memStore) keys(prefix string) []string {
	var out []string
	_ = s.List(context.Background(), prefix, func(o s3.ObjectInfo) error { out = append(out, o.Key); return nil })
	return out
}

type fixture struct {
	m     *Manager
	pm    *projects.Manager
	n     *fakeNode
	store *memStore
	id    *age.X25519Identity
	who   Actor
	dir   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{7}, 32))
	n := &fakeNode{outbox: map[string][]byte{}, archive: "on|0|0|0", dumpData: []byte("PGDMP" + strings.Repeat(" pedido", 500)), checkOut: "HANGAR-CHECK tables=3 restored=3 rows=42\n"}
	al := audit.New(st.DB)
	pm := projects.New(st.DB, box, n, al, log)
	m, err := New(st.DB, box, pm, al, log, Options{
		StagingDir: filepath.Join(dir, "staging"), DBPath: filepath.Join(dir, "h.db"),
		MasterKeyFile: writeFile(t, dir, "master.key", "0123456789abcdef0123456789abcdef"),
		ConfigFile:    writeFile(t, dir, "hangar.toml", "data_dir = \"data\"\n"), Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	mem := newMemStore()
	m.openStore = func(TargetConfig) (ObjectStore, error) { return mem, nil }
	id, _ := age.GenerateX25519Identity()
	// The tests below cover the recovery kit; the simple mode has its own.
	if err := m.q.SetSetting(context.Background(), dbq.SetSettingParams{Key: settingMode, ValueJson: `"kit"`}); err != nil {
		t.Fatal(err)
	}
	return &fixture{m: m, pm: pm, n: n, store: mem, id: id, who: Actor{UserID: "usr_1", IP: "189.1.2.3"}, dir: dir}
}

// ready registers and confirms a kit key and a destination.
func (f *fixture) ready(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	code := archive.ConfirmCode(f.id)
	rid, err := f.m.AddRecipient(ctx, f.who, "Junior", f.id.Recipient().String(), archive.CodeHash(code))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.ConfirmRecipient(ctx, f.who, rid, code); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.AddTarget(ctx, f.who, validTarget()); err != nil {
		t.Fatal(err)
	}
}

func validTarget() TargetInput {
	return TargetInput{
		Name: "B2 principal", Provider: "b2", LockMode: s3.Compliance, LockDays: 30,
		Config: TargetConfig{Endpoint: "https://s3.us-west-004.backblazeb2.com", Region: "us-west-004", Bucket: "hangar-bk", Prefix: "lab", AccessKey: "k", SecretKey: "s"},
	}
}

// postgres creates a project with a PostgreSQL service.
func (f *fixture) postgres(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.pm.CreateProject(ctx, f.who, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pm.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.pm.Wait()
}

func (f *fixture) open(t *testing.T, key string) []byte {
	t.Helper()
	rc, _, err := f.store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := archive.Open(rc, []age.Identity{f.id}, archive.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
