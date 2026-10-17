//go:build integration

package projects

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/docker"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// TestGitBuildOnRealDocker builds a small app from a repository on disk with
// the real Docker (BuildKit), deploys it, deploys a new commit through a
// signed webhook, and checks that a secret printed during the build never
// reaches the deploy log. Run: go test -tags integration ./internal/projects/
// Everything it creates is named e2e-gb-* and removed at the end.
func TestGitBuildOnRealDocker(t *testing.T) {
	ctx := context.Background()
	d, err := docker.New(ctx, "")
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{9}, 32))
	logs := &bytes.Buffer{}
	m := New(st.DB, box, d, audit.New(st.DB), slog.New(slog.NewTextHandler(logs, nil)))
	m.SetBuildDir(filepath.Join(dir, "builds"))
	who := Actor{UserID: "usr_e2e"}

	b := make([]byte, 3)
	_, _ = rand.Read(b)
	project := "e2e-gb-" + hex.EncodeToString(b)
	const secret = "s3cr3t-do-build-e2e-XYZ"

	repoDir := filepath.Join(dir, "repo")
	dockerfile := "FROM alpine:3.22\n" +
		"COPY version.txt /www/index.html\n" +
		"RUN cat /www/index.html && echo \"leak: " + secret + "\"\n" +
		"CMD [\"sleep\", \"3600\"]\n"
	commitFiles(t, repoDir, "main", map[string]string{"Dockerfile": dockerfile, "version.txt": "v1\n", ".dockerignore": "*.md\n"}, "v1")

	var svcID string
	t.Cleanup(func() {
		cctx := context.Background()
		m.Wait()
		_ = m.DeleteService(cctx, who, project, "web")
		if svcID != "" {
			_ = d.PruneBuilds(cctx, svcID, nil)
		}
		_ = m.DeleteProject(cctx, who, project)
	})

	if _, err := m.CreateProject(ctx, who, project, ""); err != nil {
		t.Fatal(err)
	}
	s, err := m.CreateGitService(ctx, who, project, GitServiceInput{
		ServiceInput:   ServiceInput{Slug: "web", MemoryMB: 128},
		GitSourceInput: GitSourceInput{URL: "file://" + repoDir, Branch: "main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	svcID = s.ID
	m.Wait()
	deps, _ := m.Deployments(ctx, s.ID, 5)
	if len(deps) == 0 || deps[0].Status != "live" {
		t.Fatalf("first deploy: %+v\n%s", deps, logOf(deps))
	}
	if !strings.Contains(deps[0].Log, "[build]") || !strings.Contains(deps[0].Log, "RUN cat /www/index.html") {
		t.Errorf("build output missing from the deploy log:\n%s", deps[0].Log)
	}
	st1, err := d.Status(ctx, project, "web")
	if err != nil || !st1.Running || st1.Deployment != deps[0].ID || st1.Image != deps[0].ImageRef {
		t.Fatalf("container: %+v %v", st1, err)
	}

	// The secret becomes a variable; the next build (new commit, so the RUN
	// step runs again) prints it, and the log must show •••• instead.
	if err := m.SetEnv(ctx, who, s.ID, "BUILD_SECRET", secret, true); err != nil {
		t.Fatal(err)
	}
	sha2 := commitFiles(t, repoDir, "main", map[string]string{"version.txt": "v2\n"}, "v2 pelo webhook")
	hook, err := m.RotateWebhook(ctx, who, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := pushBody("refs/heads/main", time.Now(), "file://"+repoDir)
	out, err := m.GitHubHook(ctx, HookDelivery{
		Token: hook.Token, Event: "push", ID: "e2e-" + hex.EncodeToString(b), Body: body,
		Signature: gitsrc.Sign([]byte(hook.Secret), body), ContentType: "application/json",
	})
	if err != nil || out != HookDeployed {
		t.Fatalf("webhook: %v %v", out, err)
	}
	m.Wait()
	deps, _ = m.Deployments(ctx, s.ID, 5)
	if deps[0].Status != "live" || deps[0].Trigger != "webhook" || deps[0].CommitSha != sha2 {
		t.Fatalf("webhook deploy: %+v\n%s", deps[0], deps[0].Log)
	}
	if strings.Contains(deps[0].Log, secret) || strings.Contains(logs.String(), secret) {
		t.Fatalf("secret leaked into the build log:\n%s", deps[0].Log)
	}
	if !strings.Contains(deps[0].Log, "leak: ••••") {
		t.Errorf("masked build line not found:\n%s", deps[0].Log)
	}
	// Rollback to v1 uses the old image, no build.
	if _, err := m.Rollback(ctx, who, project, "web", deps[1].ID); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	deps, _ = m.Deployments(ctx, s.ID, 5)
	if deps[0].Status != "live" || strings.Contains(deps[0].Log, "[build]") {
		t.Fatalf("rollback: %+v\n%s", deps[0], deps[0].Log)
	}
	// A rebuild of the same commit runs every step again (no cache).
	if _, err := m.Rebuild(ctx, who, project, "web"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	deps, _ = m.Deployments(ctx, s.ID, 5)
	if deps[0].Status != "live" || deps[0].Trigger != "rebuild" {
		t.Fatalf("rebuild: %+v\n%s", deps[0], deps[0].Log)
	}
	// (The FROM line still says CACHED: the base image is already here.)
	if strings.Count(deps[0].Log, "CACHED") > 1 || !strings.Contains(deps[0].Log, "leak: ••••") {
		t.Errorf("a rebuild must run the steps again, not reuse the cache:\n%s", deps[0].Log)
	}
}

func logOf(deps []dbq.Deployment) string {
	if len(deps) == 0 {
		return ""
	}
	return deps[0].Log + "\n" + deps[0].Error.String
}
