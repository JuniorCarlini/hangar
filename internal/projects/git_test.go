package projects

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
)

func init() { gitsrc.AllowLocalForTesting() }

// buildNode is fakeNode plus a builder that "builds" by checking the
// context and echoing log lines (some of them carrying secrets).
type buildNode struct {
	*fakeNode
	bmu     sync.Mutex
	builds  []node.BuildSpec
	echo    []string
	pruned  [][]string
	failErr error
}

func (b *buildNode) Build(_ context.Context, spec node.BuildSpec, log func(string)) (string, error) {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	if _, err := os.Stat(filepath.Join(spec.ContextDir, spec.Dockerfile)); err != nil {
		return "", err
	}
	b.builds = append(b.builds, spec)
	log("#1 [1/2] FROM alpine")
	for _, e := range b.echo {
		log("#2 " + e)
	}
	if b.failErr != nil {
		return "", b.failErr
	}
	return "sha256:built", nil
}

func (b *buildNode) PruneBuilds(_ context.Context, _ string, keep []string) error {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	b.pruned = append(b.pruned, keep)
	return nil
}

func (b *buildNode) buildCount() int {
	b.bmu.Lock()
	defer b.bmu.Unlock()
	return len(b.builds)
}

type gitFixture struct {
	*fixture
	b        *buildNode
	buildDir string
	repo     string
	repoDir  string
}

func newGitFixture(t *testing.T) *gitFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{7}, 32))
	b := &buildNode{fakeNode: newFakeNode()}
	logs := &bytes.Buffer{}
	m := New(st.DB, box, b, audit.New(st.DB), slog.New(slog.NewTextHandler(logs, nil)))
	g := &gitFixture{
		fixture:  &fixture{m: m, n: b.fakeNode, st: st, who: Actor{UserID: "usr_1", IP: "189.10.20.30"}, logs: logs},
		b:        b,
		buildDir: filepath.Join(dir, "builds"),
	}
	m.SetBuildDir(g.buildDir)
	g.repoDir = filepath.Join(dir, "repo")
	g.repo = "file://" + g.repoDir
	commitFiles(t, g.repoDir, "main", map[string]string{
		"Dockerfile":     "FROM alpine:3.22\nCMD [\"sleep\", \"3600\"]\n",
		"app/Dockerfile": "FROM alpine:3.22\n",
		"README.md":      "lab\n",
	}, "primeira versão\n\ncorpo")
	if _, err := m.CreateProject(context.Background(), g.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	return g
}

// commitFiles creates (or updates) a repository at dir with files on branch.
func commitFiles(t *testing.T, dir, branch string, files map[string]string, msg string) string {
	t.Helper()
	repo, err := git.PlainOpen(dir)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		repo, err = git.PlainInitWithOptions(dir, &git.PlainInitOptions{
			InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName(branch)},
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if _, err := wt.Add(name); err != nil {
			t.Fatal(err)
		}
	}
	h, err := wt.Commit(msg, &git.CommitOptions{Author: &object.Signature{Name: "Lab", Email: "lab@hangar.dev", When: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	return h.String()
}

func (g *gitFixture) create(t *testing.T, in GitServiceInput) string {
	t.Helper()
	if in.Slug == "" {
		in.Slug = "web"
	}
	if in.URL == "" {
		in.URL = g.repo
	}
	s, err := g.m.CreateGitService(context.Background(), g.who, "lab", in)
	if err != nil {
		t.Fatal(err)
	}
	g.m.Wait()
	return s.ID
}

func TestGitServiceIsClonedBuiltAndDeployed(t *testing.T) {
	g := newGitFixture(t)
	id := g.create(t, GitServiceInput{ServiceInput: ServiceInput{Port: 8000}})

	deps, _ := g.m.Deployments(context.Background(), id, 5)
	if len(deps) != 1 || deps[0].Status != "live" {
		t.Fatalf("deploy: %+v", deps)
	}
	if len(deps[0].CommitSha) != 40 || deps[0].CommitMessage != "primeira versão" {
		t.Errorf("commit not recorded: %q %q", deps[0].CommitSha, deps[0].CommitMessage)
	}
	if !strings.HasSuffix(deps[0].Image, "@main") {
		t.Errorf("history should show repository@branch, got %q", deps[0].Image)
	}
	spec, ok := g.n.spec("lab_web")
	if !ok || !strings.HasPrefix(spec.Image, "hangar/lab/web:") {
		t.Fatalf("deployed image: %+v", spec.Image)
	}
	if !g.n.opts[0].LocalImage {
		t.Error("a built image must not be pulled")
	}
	if g.b.builds[0].Dockerfile != "Dockerfile" || g.b.builds[0].Tag != spec.Image {
		t.Errorf("build spec: %+v", g.b.builds[0])
	}
	if entries, _ := os.ReadDir(g.buildDir); len(entries) != 0 {
		t.Errorf("workspace left behind: %v", entries)
	}
	if !strings.Contains(deps[0].Log, "[clone]") || !strings.Contains(deps[0].Log, "[build]") {
		t.Errorf("log lacks the build phases:\n%s", deps[0].Log)
	}
	if len(g.b.pruned) == 0 {
		t.Error("old builds were not pruned")
	}
}

func TestDeletingGitServiceRemovesItsBuilds(t *testing.T) {
	g := newGitFixture(t)
	g.create(t, GitServiceInput{})
	if err := g.m.DeleteService(context.Background(), g.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	last := g.b.pruned[len(g.b.pruned)-1]
	if len(last) != 0 {
		t.Errorf("deleting the service should remove every build, kept %v", last)
	}
	var n int
	_ = g.st.DB.QueryRow("SELECT count(*) FROM service_git").Scan(&n)
	if n != 0 {
		t.Error("the Git source outlived the service")
	}
}

func TestGitSubdirectoryAndValidation(t *testing.T) {
	g := newGitFixture(t)
	g.create(t, GitServiceInput{ServiceInput: ServiceInput{Slug: "api"}, GitSourceInput: GitSourceInput{Subdir: "app"}})
	if got := g.b.builds[0].ContextDir; !strings.HasSuffix(got, string(filepath.Separator)+"app") {
		t.Errorf("context dir: %s", got)
	}
	ctx := context.Background()
	for _, in := range []GitServiceInput{
		{ServiceInput: ServiceInput{Slug: "x1"}, GitSourceInput: GitSourceInput{URL: "http://github.com/a/b"}},
		{ServiceInput: ServiceInput{Slug: "x2"}, GitSourceInput: GitSourceInput{URL: "https://user:pw@github.com/a/b"}},
		{ServiceInput: ServiceInput{Slug: "x3"}, GitSourceInput: GitSourceInput{URL: g.repo, Branch: "../etc"}},
		{ServiceInput: ServiceInput{Slug: "x4"}, GitSourceInput: GitSourceInput{URL: g.repo, Subdir: "../.."}},
		{ServiceInput: ServiceInput{Slug: "x5"}, GitSourceInput: GitSourceInput{URL: g.repo, Dockerfile: "../Dockerfile"}},
		{ServiceInput: ServiceInput{Slug: "x6"}, GitSourceInput: GitSourceInput{URL: g.repo, Branch: "nao-existe"}},
		{ServiceInput: ServiceInput{Slug: "x7"}, GitSourceInput: GitSourceInput{URL: g.repo}, Token: "tem espaço"},
	} {
		if _, err := g.m.CreateGitService(ctx, g.who, "lab", in); err == nil {
			t.Errorf("accepted: %+v", in)
		}
	}
}

func TestBuildLogNeverShowsSecrets(t *testing.T) {
	g := newGitFixture(t)
	const secret, token = "s3nha-do-banco-muito-secreta", "ghp_tokenDeLeitura1234567890"
	g.b.echo = []string{
		"RUN echo " + secret,
		"token=" + token,
		"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token)),
		"url-encoded: " + "s3nha-do-banco-muito-secreta",
	}
	id := g.create(t, GitServiceInput{Token: token})
	ctx := context.Background()
	if err := g.m.SetEnv(ctx, g.who, id, "DB_PASSWORD", secret, true); err != nil {
		t.Fatal(err)
	}
	g.b.failErr = errors.New("build failed: process \"echo " + secret + "\" did not complete")
	if _, err := g.m.Deploy(ctx, g.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	g.m.Wait()
	deps, _ := g.m.Deployments(ctx, id, 5)
	d := deps[0]
	if d.Status != "failed" {
		t.Fatalf("status %s", d.Status)
	}
	all := d.Log + "\n" + d.Error.String + "\n" + g.logs.String()
	for _, s := range []string{secret, token, base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))} {
		if strings.Contains(all, s) {
			t.Fatalf("secret %q leaked into the deploy log:\n%s", s, all)
		}
	}
	if !strings.Contains(d.Log, "RUN echo ••••") {
		t.Errorf("masked line missing:\n%s", d.Log)
	}
	// The token is stored encrypted, never in clear.
	var enc []byte
	if err := g.st.DB.QueryRow("SELECT token_enc FROM service_git WHERE service_id = ?", id).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte(token)) {
		t.Error("token stored in clear")
	}
	if got, err := g.m.RevealGitToken(ctx, g.who, id); err != nil || got != token {
		t.Errorf("reveal: %q %v", got, err)
	}
}

func TestRollbackOfGitServiceDoesNotRebuild(t *testing.T) {
	g := newGitFixture(t)
	id := g.create(t, GitServiceInput{})
	ctx := context.Background()
	commitFiles(t, g.repoDir, "main", map[string]string{"README.md": "v2\n"}, "segunda versão")
	if _, err := g.m.Deploy(ctx, g.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	g.m.Wait()
	deps, _ := g.m.Deployments(ctx, id, 5)
	if deps[0].CommitMessage != "segunda versão" || deps[1].Status != "superseded" {
		t.Fatalf("history: %+v", deps)
	}
	builds := g.b.buildCount()
	if _, err := g.m.Rollback(ctx, g.who, "lab", "web", deps[1].ID); err != nil {
		t.Fatal(err)
	}
	g.m.Wait()
	if g.b.buildCount() != builds {
		t.Error("rollback rebuilt the image")
	}
	deps, _ = g.m.Deployments(ctx, id, 5)
	if deps[0].Trigger != "rollback" || deps[0].CommitMessage != "primeira versão" || deps[0].Status != "live" {
		t.Errorf("rollback deploy: %+v", deps[0])
	}
}

func TestChangingRepositoryDropsTheToken(t *testing.T) {
	g := newGitFixture(t)
	id := g.create(t, GitServiceInput{Token: "ghp_original12345"})
	ctx := context.Background()
	other := filepath.Join(t.TempDir(), "other")
	commitFiles(t, other, "main", map[string]string{"Dockerfile": "FROM alpine\n"}, "x")
	if err := g.m.SetGitSource(ctx, g.who, id, GitSourceInput{URL: "file://" + other, Branch: "main"}, ""); err != nil {
		t.Fatal(err)
	}
	src, _, _ := g.m.GetGitSource(ctx, id)
	if src.HasToken {
		t.Error("token kept after pointing the service at another repository")
	}
	// Same repository, new branch: the token stays.
	if err := g.m.SetGitToken(ctx, g.who, id, "ghp_novo123456"); err != nil {
		t.Fatal(err)
	}
	commitFiles(t, other, "main", map[string]string{"x.txt": "x"}, "y")
	if err := g.m.SetGitSource(ctx, g.who, id, GitSourceInput{URL: "file://" + other, Branch: "main", Dockerfile: "Dockerfile"}, ""); err != nil {
		t.Fatal(err)
	}
	if src, _, _ = g.m.GetGitSource(ctx, id); !src.HasToken {
		t.Error("token dropped without a repository change")
	}
}

// pushBody is a GitHub push event.
func pushBody(ref string, pushedAt time.Time, repo string) []byte {
	b, _ := json.Marshal(map[string]any{
		"ref": ref, "after": strings.Repeat("a", 40), "deleted": false,
		"repository": map[string]any{"pushed_at": pushedAt.Unix(), "clone_url": repo, "html_url": repo},
	})
	return b
}

func TestGitHubWebhook(t *testing.T) {
	g := newGitFixture(t)
	id := g.create(t, GitServiceInput{})
	ctx := context.Background()
	w, err := g.m.RotateWebhook(ctx, g.who, id)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	body := pushBody("refs/heads/main", now, g.repo)
	hook := func(event, delivery string, body []byte, sig string) (HookOutcome, error) {
		return g.m.GitHubHook(ctx, HookDelivery{Token: w.Token, Event: event, ID: delivery, Signature: sig, Body: body, IP: "140.82.115.1"})
	}
	sign := func(b []byte) string { return gitsrc.Sign([]byte(w.Secret), b) }
	before := len(g.n.images)

	if _, err := hook("push", "d-0001-aaaa", body, gitsrc.Sign([]byte("outro-segredo"), body)); !errors.Is(err, ErrHookSignature) {
		t.Fatalf("wrong signature: %v", err)
	}
	if _, err := hook("push", "d-0002-aaaa", body, ""); !errors.Is(err, ErrHookSignature) {
		t.Fatalf("no signature: %v", err)
	}
	if _, err := g.m.GitHubHook(ctx, HookDelivery{Token: strings.Repeat("x", 43), Event: "push", ID: "d-0003-aaaa", Body: body, Signature: sign(body)}); !errors.Is(err, ErrHookUnknown) {
		t.Fatalf("unknown token: %v", err)
	}
	if out, err := hook("ping", "d-0004-aaaa", []byte(`{"zen":"x"}`), sign([]byte(`{"zen":"x"}`))); err != nil || out != HookPong {
		t.Fatalf("ping: %v %v", out, err)
	}
	other := pushBody("refs/heads/feature", now, g.repo)
	if out, err := hook("push", "d-0005-aaaa", other, sign(other)); err != nil || out != HookIgnoredBranch {
		t.Fatalf("other branch: %v %v", out, err)
	}
	stale := pushBody("refs/heads/main", now.Add(-time.Hour), g.repo)
	if _, err := hook("push", "d-0006-aaaa", stale, sign(stale)); !errors.Is(err, ErrHookStale) {
		t.Fatalf("old push: %v", err)
	}
	g.m.Wait()
	if len(g.n.images) != before {
		t.Fatal("a refused delivery deployed")
	}

	if out, err := hook("push", "d-0007-aaaa", body, sign(body)); err != nil || out != HookDeployed {
		t.Fatalf("valid push: %v %v", out, err)
	}
	g.m.Wait()
	if len(g.n.images) != before+1 {
		t.Fatal("valid push did not deploy")
	}
	if _, err := hook("push", "d-0007-aaaa", body, sign(body)); !errors.Is(err, ErrHookReplay) {
		t.Fatalf("replayed delivery: %v", err)
	}
	g.m.Wait()
	if len(g.n.images) != before+1 {
		t.Fatal("a replayed delivery deployed again")
	}
	deps, _ := g.m.Deployments(ctx, id, 1)
	if deps[0].Trigger != "webhook" {
		t.Errorf("trigger %q", deps[0].Trigger)
	}

	// Rotating invalidates the old URL.
	if _, err := g.m.RotateWebhook(ctx, g.who, id); err != nil {
		t.Fatal(err)
	}
	if _, err := hook("push", "d-0008-aaaa", body, sign(body)); !errors.Is(err, ErrHookUnknown) {
		t.Fatalf("old webhook still works: %v", err)
	}
	var denied int
	_ = g.st.DB.QueryRow("SELECT count(*) FROM audit_log WHERE action = 'service.webhook' AND outcome = 'denied'").Scan(&denied)
	if denied < 3 {
		t.Errorf("refused deliveries not audited: %d", denied)
	}
}

func TestWebhookWhileDeployingIsQueued(t *testing.T) {
	g := newGitFixture(t)
	id := g.create(t, GitServiceInput{})
	ctx := context.Background()
	w, _ := g.m.RotateWebhook(ctx, g.who, id)
	// Pretend a deploy is running.
	if _, err := g.st.DB.Exec("UPDATE deployments SET status = 'running' WHERE service_id = ?", id); err != nil {
		t.Fatal(err)
	}
	body := pushBody("refs/heads/main", time.Now(), g.repo)
	out, err := g.m.GitHubHook(ctx, HookDelivery{Token: w.Token, Event: "push", ID: "q-0001-aaaa", Signature: gitsrc.Sign([]byte(w.Secret), body), Body: body})
	if err != nil || out != HookQueued {
		t.Fatalf("%v %v", out, err)
	}
	if _, err := g.st.DB.Exec("UPDATE deployments SET status = 'live' WHERE service_id = ?", id); err != nil {
		t.Fatal(err)
	}
	builds := g.b.buildCount()
	g.m.runQueued(ctx, id)
	g.m.Wait()
	if g.b.buildCount() != builds+1 {
		t.Error("queued push never deployed")
	}
}

func TestMasker(t *testing.T) {
	m := newMasker("abc", "segredo-1", "postgres://app:s3nh4F0rte@db:5432/app", "")
	got := m.apply("a abc segredo-1 segredo%2D1 s3nh4F0rte postgres://app:s3nh4F0rte@db:5432/app")
	for _, bad := range []string{"segredo-1", "s3nh4F0rte"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q not masked: %s", bad, got)
		}
	}
	if !strings.Contains(got, "abc") {
		t.Error("values shorter than the minimum must be left alone")
	}
	var nilMask *masker
	if nilMask.apply("x") != "x" {
		t.Error("nil masker changed text")
	}
}
