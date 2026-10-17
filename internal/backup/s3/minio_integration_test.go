//go:build integration

package s3_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/backuptest"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
)

// Runs against a throwaway MinIO: go test -tags integration ./internal/backup/...
func TestObjectLockAndLeastPrivilege(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	m := backuptest.StartMinIO(ctx, t)
	writer, reader, root := backuptest.Client(t, m.Writer), backuptest.Client(t, m.Reader), backuptest.Client(t, m.Root)

	lock, err := writer.ObjectLock(ctx)
	if err != nil || !lock.Enabled {
		t.Fatalf("bucket lock: %+v %v", lock, err)
	}

	until := time.Now().Add(24 * time.Hour)
	data := []byte("age-encryption.org/v1 ... (cifrado)")
	key := "diario/lab/db/20261015T143200Z.dump.age"
	if err := writer.Put(ctx, key, bytes.NewReader(data), int64(len(data)), s3.PutOptions{
		LockMode: s3.Compliance, RetainUntil: until, Metadata: map[string]string{"hangar-sha256": "x"},
	}); err != nil {
		t.Fatalf("upload with the server credential: %v", err)
	}
	info, err := writer.Head(ctx, key)
	if err != nil || info.LockMode != s3.Compliance || info.RetainUntil.Before(until.Add(-time.Minute)) || info.Metadata["hangar-sha256"] != "x" {
		t.Fatalf("head: %+v %v", info, err)
	}

	// The server's credential cannot delete, not even by leaving a delete
	// marker (which would hide the backup from a listing).
	if err := writer.Delete(ctx, key, ""); !s3.IsAccessDenied(err) {
		t.Fatalf("delete with the server credential must be denied, got %v", err)
	}
	if err := writer.Delete(ctx, key, info.VersionID); !s3.IsAccessDenied(err) {
		t.Fatalf("delete of the version with the server credential must be denied, got %v", err)
	}
	// Even the bucket owner cannot remove the locked version (compliance).
	if err := root.Delete(ctx, key, info.VersionID); err == nil {
		t.Fatal("compliance lock must stop even the owner from deleting the version")
	}
	// The operator's read-only credential reads but cannot write.
	rc, _, err := reader.Get(ctx, key)
	if err != nil {
		t.Fatalf("read-only get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("read-only get returned other bytes")
	}
	if err := reader.Put(ctx, "x", bytes.NewReader(data), int64(len(data)), s3.PutOptions{}); !s3.IsAccessDenied(err) {
		t.Fatalf("read-only credential must not write: %v", err)
	}

	// Multipart upload keeps the lock.
	old := s3.PartSize
	s3.PartSize = 5 << 20
	defer func() { s3.PartSize = old }()
	big := make([]byte, 11<<20)
	_, _ = rand.Read(big)
	if err := writer.Put(ctx, "wal/lab/db/base/big.tar.zst.age", bytes.NewReader(big), int64(len(big)), s3.PutOptions{LockMode: s3.Compliance, RetainUntil: until}); err != nil {
		t.Fatalf("multipart: %v", err)
	}
	if bi, err := writer.Head(ctx, "wal/lab/db/base/big.tar.zst.age"); err != nil || bi.Size != int64(len(big)) || bi.LockMode != s3.Compliance {
		t.Fatalf("multipart head: %+v %v", bi, err)
	}

	n := 0
	if err := reader.List(ctx, "", func(s3.ObjectInfo) error { n++; return nil }); err != nil || n != 2 {
		t.Fatalf("list: %d %v", n, err)
	}

	// A presigned link downloads without credentials.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, writer.PresignGet(key, 5*time.Minute), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("presigned get: %v %v", resp, err)
	}
	_ = resp.Body.Close()
}
