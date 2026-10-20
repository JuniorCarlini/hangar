package projects

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
)

// fakeNode records what the Manager asked "Docker" for.
type fakeNode struct {
	mu       sync.Mutex
	networks map[string]bool
	deployed map[string]node.ServiceSpec
	failNext error
	// failRes and failPhases shape the next failure like the real node:
	// the phases it went through (e.g. health, then restore) and what
	// became of the previous version.
	failRes    node.DeployResult
	failPhases []string
	opts       []node.DeployOptions
	images     []string
	shells     [][]string
}

func newFakeNode() *fakeNode {
	return &fakeNode{networks: map[string]bool{}, deployed: map[string]node.ServiceSpec{}}
}

func (f *fakeNode) EnsureProjectNetwork(_ context.Context, _, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.networks[p] = true
	return nil
}

func (f *fakeNode) RemoveProjectNetwork(_ context.Context, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.networks, p)
	return nil
}

func (f *fakeNode) Deploy(_ context.Context, s node.ServiceSpec, opt node.DeployOptions) (node.DeployResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := s.Validate(); err != nil {
		return node.DeployResult{}, err
	}
	f.opts = append(f.opts, opt)
	if opt.Progress != nil {
		opt.Progress(node.PhasePull, s.Image)
		opt.Progress(node.PhaseHealth, "")
	}
	if f.failNext != nil {
		err, res := f.failNext, f.failRes
		for _, ph := range f.failPhases {
			if opt.Progress != nil {
				opt.Progress(ph, "")
			}
		}
		f.failNext, f.failRes, f.failPhases = nil, node.DeployResult{}, nil
		return res, err
	}
	f.deployed[node.ContainerName(s.Project, s.Service)] = s
	f.images = append(f.images, s.Image)
	return node.DeployResult{ContainerID: "c1", ImageRef: "sha256:" + fmt.Sprint(len(f.images))}, nil
}

func (f *fakeNode) Start(context.Context, string, string) error   { return nil }
func (f *fakeNode) Stop(context.Context, string, string) error    { return nil }
func (f *fakeNode) Restart(context.Context, string, string) error { return nil }

func (f *fakeNode) Remove(_ context.Context, p, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.deployed, node.ContainerName(p, s))
	return nil
}

func (f *fakeNode) Status(context.Context, string, string) (node.Status, error) {
	return node.Status{Exists: true, Running: true, State: "running"}, nil
}

func (f *fakeNode) Logs(context.Context, string, string, node.LogOptions, func(node.LogLine) error) error {
	return nil
}
func (f *fakeNode) ListManaged(context.Context) ([]node.Managed, error) { return nil, nil }
func (f *fakeNode) EnsureEdge(context.Context, node.EdgeSpec) error     { return nil }
func (f *fakeNode) ConnectEdge(context.Context, string, string) error   { return nil }
func (f *fakeNode) Exec(_ context.Context, _, _ string, cmd []string, w io.Writer) error {
	_, err := io.WriteString(w, "exec:"+strings.Join(cmd, " "))
	return err
}
func (f *fakeNode) SetLinked(context.Context, string, string, []string) error { return nil }

// OpenShell records what the terminal asked the container to run.
func (f *fakeNode) OpenShell(_ context.Context, _, _ string, cmd []string, _, _ uint) (node.Shell, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shells = append(f.shells, cmd)
	return nopShell{}, nil
}

type nopShell struct{}

func (nopShell) Read([]byte) (int, error)                 { return 0, io.EOF }
func (nopShell) Write(p []byte) (int, error)              { return len(p), nil }
func (nopShell) Close() error                             { return nil }
func (nopShell) Resize(context.Context, uint, uint) error { return nil }
func (f *fakeNode) ServiceAddress(context.Context, string, string, int) (string, error) {
	return "", nil
}

func (f *fakeNode) spec(name string) (node.ServiceSpec, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.deployed[name]
	return s, ok
}

type fixture struct {
	m    *Manager
	n    *fakeNode
	st   *store.Store
	who  Actor
	logs *bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{5}, 32))
	n := newFakeNode()
	logs := &bytes.Buffer{}
	m := New(st.DB, box, n, audit.New(st.DB), slog.New(slog.NewTextHandler(logs, nil)))
	return &fixture{m: m, n: n, st: st, who: Actor{UserID: "usr_1", IP: "189.10.20.30"}, logs: logs}
}

func (f *fixture) service(t *testing.T) (string, string) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", "Laboratório"); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	return "lab", s.ID
}

func TestCreateProjectAndServiceDeploysWithLimits(t *testing.T) {
	f := newFixture(t)
	f.service(t)

	if !f.n.networks["lab"] {
		t.Error("project network was not created")
	}
	spec, ok := f.n.spec("lab_web")
	if !ok {
		t.Fatal("service was not sent to Docker")
	}
	if spec.MemoryBytes != DefaultMemoryMB<<20 || spec.NanoCPUs != 1e9 || spec.PidsLimit != DefaultPids {
		t.Errorf("default limits not applied: %+v", spec)
	}
	deps, _ := f.m.Deployments(context.Background(), spec.ServiceID, 5)
	if len(deps) != 1 || deps[0].Status != "live" {
		t.Errorf("deploy history: %+v", deps)
	}
}

func TestValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, slug := range []string{"A", "lab_x", "-lab", "lab;rm", strings.Repeat("a", 40)} {
		if _, err := f.m.CreateProject(ctx, f.who, slug, ""); err == nil {
			t.Errorf("invalid project slug accepted: %q", slug)
		}
	}
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate project: %v", err)
	}
	for _, in := range []ServiceInput{
		{Slug: "web", Image: "nginx; rm -rf /"},
		{Slug: "web", Image: "NGINX"},
		{Slug: "web", Image: "nginx", MemoryMB: 1},
		{Slug: "Web", Image: "nginx"},
		{Slug: "web", Image: "nginx", Port: 70000},
	} {
		if _, err := f.m.CreateService(ctx, f.who, "lab", in); err == nil {
			t.Errorf("invalid service accepted: %+v", in)
		}
	}
}

func TestServiceLookupIsScopedToProject(t *testing.T) {
	f := newFixture(t)
	f.service(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "outro", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.m.GetService(ctx, "outro", "web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a project's service reachable through another project's URL: %v", err)
	}
}

func TestEnvSecretsAreEncryptedMaskedAndAudited(t *testing.T) {
	f := newFixture(t)
	_, svcID := f.service(t)
	ctx := context.Background()

	if err := f.m.SetEnv(ctx, f.who, svcID, "SECRET_KEY", "super-segredo-123", true); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetEnv(ctx, f.who, svcID, "DEBUG", "false", false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"1ABC", "A-B", "A B", ""} {
		if err := f.m.SetEnv(ctx, f.who, svcID, bad, "x", false); err == nil {
			t.Errorf("invalid variable name accepted: %q", bad)
		}
	}

	vars, err := f.m.ListEnv(ctx, svcID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vars {
		if v.Key == "SECRET_KEY" && v.Value != "" {
			t.Error("secret value leaked into the listing")
		}
		if v.Key == "DEBUG" && v.Value != "false" {
			t.Errorf("plain value: %q", v.Value)
		}
	}

	var raw []byte
	if err := f.st.DB.QueryRow("SELECT value_enc FROM env_vars WHERE key = 'SECRET_KEY'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("super-segredo")) {
		t.Fatal("secret stored in clear text")
	}

	v, err := f.m.RevealEnv(ctx, f.who, svcID, "SECRET_KEY")
	if err != nil || v != "super-segredo-123" {
		t.Fatalf("reveal: %q %v", v, err)
	}

	// The value never reaches the audit log, neither on set nor on reveal.
	var leaked int
	if err := f.st.DB.QueryRow("SELECT count(*) FROM audit_log WHERE summary_json LIKE '%super-segredo%'").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("secret value leaked into the audit log")
	}
	var reveals int
	_ = f.st.DB.QueryRow("SELECT count(*) FROM audit_log WHERE action = 'secret.reveal' AND actor_id = 'usr_1'").Scan(&reveals)
	if reveals != 1 {
		t.Errorf("reveal not audited (%d)", reveals)
	}
}

func TestPendingChangesAndDeployCarriesEnv(t *testing.T) {
	f := newFixture(t)
	_, svcID := f.service(t)
	ctx := context.Background()

	if p, _ := f.m.PendingChanges(ctx, svcID); p {
		t.Error("without changes there should be nothing pending")
	}
	_ = f.m.SetEnv(ctx, f.who, svcID, "DATABASE_URL", "postgres://x", true)
	if p, _ := f.m.PendingChanges(ctx, svcID); !p {
		t.Error("a new variable should leave a pending change")
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if p, _ := f.m.PendingChanges(ctx, svcID); p {
		t.Error("after the deploy nothing should be pending")
	}
	spec, _ := f.n.spec("lab_web")
	if spec.Env["DATABASE_URL"] != "postgres://x" {
		t.Errorf("variable did not reach the container: %+v", spec.Env)
	}
}

func TestFailedDeployIsRecorded(t *testing.T) {
	f := newFixture(t)
	_, svcID := f.service(t)
	f.n.failNext = errors.New("imagem não encontrada")
	if _, err := f.m.Deploy(context.Background(), f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	deps, _ := f.m.Deployments(context.Background(), svcID, 5)
	if deps[0].Status != "failed" || !strings.Contains(deps[0].Error.String, "imagem não encontrada") {
		t.Errorf("failed deploy: %+v", deps[0])
	}
	if deps[1].Status != "live" {
		t.Errorf("the previous deploy should remain live: %+v", deps[1])
	}
}

func TestDeleteProjectRequiresEmpty(t *testing.T) {
	f := newFixture(t)
	f.service(t)
	ctx := context.Background()
	if err := f.m.DeleteProject(ctx, f.who, "lab"); !errors.Is(err, ErrHasServices) {
		t.Fatalf("delete project with a service: %v", err)
	}
	if err := f.m.DeleteService(ctx, f.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.DeleteProject(ctx, f.who, "lab"); err != nil {
		t.Fatal(err)
	}
	if f.n.networks["lab"] {
		t.Error("project network was not removed")
	}
}

func TestWithoutDocker(t *testing.T) {
	f := newFixture(t)
	f.m.node = nil
	if _, err := f.m.CreateProject(context.Background(), f.who, "lab", ""); !errors.Is(err, ErrDockerDisabled) {
		t.Fatalf("without Docker: %v", err)
	}
}

func TestReconcileDetectsMissingContainer(t *testing.T) {
	f := newFixture(t)
	f.service(t)
	if d, err := f.m.Reconcile(context.Background()); err != nil || len(d) != 1 || d[0].Problem != "missing" {
		// fakeNode lists no containers: the live service shows up as missing
		t.Fatalf("Reconcile = %+v, %v", d, err)
	}
}

func TestCreateProjectNamedDerivesTheIdentifier(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, c := range []struct{ name, slug string }{
		{"Notícias Portal", "noticias-portal"},
		{"Notícias  portal!", "noticias-portal-2"},
		{"Hangar", "hangar-2"}, // reserved: Hangar's own containers
	} {
		p, err := f.m.CreateProjectNamed(ctx, f.who, c.name)
		if err != nil {
			t.Fatalf("%q: %v", c.name, err)
		}
		if p.Slug != c.slug || p.Name != strings.TrimSpace(c.name) {
			t.Errorf("%q: got %s / %q, want %s", c.name, p.Slug, p.Name, c.slug)
		}
	}
	if _, err := f.m.CreateProjectNamed(ctx, f.who, " ! "); err == nil {
		t.Error("a name with nothing usable should be refused")
	}
}
