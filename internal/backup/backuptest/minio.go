//go:build integration

// Package backuptest starts throwaway services for the backup integration
// tests: a MinIO with an Object Lock bucket and the two credentials Hangar
// uses (the server's, which cannot delete, and the operator's read-only
// one). Containers are named e2e-bk-* and removed when the test ends.
package backuptest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/s3"
)

// MinIOImage is the last community MinIO release (RELEASE.2025-09-07T16-13-09Z),
// pinned by digest. MinIO stopped publishing community images after it;
// override with HANGAR_MINIO_IMAGE.
const (
	MinIOImage = "quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"
	MCImage    = "quay.io/minio/mc@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727"
)

// MinIO is a running test bucket.
type MinIO struct {
	Endpoint string
	Bucket   string
	Root     s3.Config // can do anything (the bucket owner)
	Writer   s3.Config // the server's credential: write and read, never delete
	Reader   s3.Config // the operator's computer: read only
	name     string
}

// Docker runs the docker CLI and returns its trimmed output.
func Docker(ctx context.Context, t testing.TB, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() //nolint:gosec // test helper with fixed arguments
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// RandName returns prefix plus a random suffix.
func RandName(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func image(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}

// StartMinIO starts MinIO with a versioned, Object Lock bucket and the
// writer/reader users, or skips the test when Docker is not available.
func StartMinIO(ctx context.Context, t testing.TB) *MinIO {
	t.Helper()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("Docker unavailable:", err)
	}
	name := RandName("e2e-bk-minio-")
	rootPass := RandName("root-")
	Docker(ctx, t, "run", "-d", "--name", name, "-p", "127.0.0.1::9000",
		"-e", "MINIO_ROOT_USER=hangar-root", "-e", "MINIO_ROOT_PASSWORD="+rootPass,
		image("HANGAR_MINIO_IMAGE", MinIOImage), "server", "/data")
	t.Cleanup(func() { _ = exec.CommandContext(context.WithoutCancel(ctx), "docker", "rm", "-f", "-v", name).Run() }) //nolint:gosec // name is generated here
	port := Docker(ctx, t, "port", name, "9000/tcp")
	port = port[strings.LastIndex(port, ":")+1:]
	m := &MinIO{Endpoint: "http://127.0.0.1:" + port, Bucket: "hangar-backups", name: name}
	waitHTTP(ctx, t, m.Endpoint+"/minio/health/live")

	mc := func(args ...string) string {
		full := append([]string{
			"run", "--rm", "--network", "container:" + name,
			"-e", "MC_HOST_local=http://hangar-root:" + rootPass + "@127.0.0.1:9000",
			"--entrypoint", "sh", image("HANGAR_MC_IMAGE", MCImage), "-c",
		}, strings.Join(args, " "))
		return Docker(ctx, t, full...)
	}
	writerPass, readerPass := RandName("w-"), RandName("r-")
	// Least privilege, as docs/09 asks of the real bucket: the server
	// writes (with retention) and reads, and has no delete of any kind.
	writerPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectRetention","s3:GetObject","s3:GetObjectRetention","s3:ListBucket","s3:GetBucketLocation","s3:GetBucketObjectLockConfiguration","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::hangar-backups","arn:aws:s3:::hangar-backups/*"]}]}`
	readerPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket","s3:GetBucketLocation"],"Resource":["arn:aws:s3:::hangar-backups","arn:aws:s3:::hangar-backups/*"]}]}`
	mc("mc mb --with-lock local/hangar-backups &&",
		"echo '"+writerPolicy+"' > /tmp/w.json && echo '"+readerPolicy+"' > /tmp/r.json &&",
		"mc admin policy create local hangar-writer /tmp/w.json &&",
		"mc admin policy create local hangar-reader /tmp/r.json &&",
		"mc admin user add local hangar-writer "+writerPass+" &&",
		"mc admin user add local hangar-reader "+readerPass+" &&",
		"mc admin policy attach local hangar-writer --user hangar-writer &&",
		"mc admin policy attach local hangar-reader --user hangar-reader")
	cfg := func(user, pass string) s3.Config {
		return s3.Config{Endpoint: m.Endpoint, Region: "us-east-1", Bucket: m.Bucket, AccessKey: user, SecretKey: pass, PathStyle: true}
	}
	m.Root, m.Writer, m.Reader = cfg("hangar-root", rootPass), cfg("hangar-writer", writerPass), cfg("hangar-reader", readerPass)
	return m
}

func waitHTTP(ctx context.Context, t testing.TB, url string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		req, _ := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s did not come up", url)
}

// Client returns an S3 client for cfg.
func Client(t testing.TB, cfg s3.Config) *s3.Client {
	t.Helper()
	c, err := s3.New(cfg, &http.Client{Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// String describes the bucket for logs.
func (m *MinIO) String() string { return fmt.Sprintf("minio %s (%s)", m.name, m.Endpoint) }
