package s3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The two examples from the AWS Signature V4 documentation for S3
// ("Examples: Signature calculations"), which pin the signer byte for byte.
var awsExample = Config{
	Endpoint: "https://s3.amazonaws.com", Region: "us-east-1", Bucket: "examplebucket",
	AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

type captureRT struct{ req *http.Request }

func (c *captureRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	return &http.Response{StatusCode: 206, Body: io.NopCloser(strings.NewReader("0123456789")), Header: http.Header{}, Request: r}, nil
}

func exampleClient(t *testing.T, rt http.RoundTripper) *Client {
	t.Helper()
	c, err := New(awsExample, &http.Client{Transport: rt})
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }
	return c
}

func TestSignatureMatchesAWSExample(t *testing.T) {
	rt := &captureRT{}
	c := exampleClient(t, rt)
	if _, err := c.GetRange(context.Background(), "test.txt", 10); err != nil {
		t.Fatal(err)
	}
	auth := rt.req.Header.Get("Authorization")
	want := "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if !strings.HasSuffix(auth, want) || rt.req.URL.Host != "examplebucket.s3.amazonaws.com" {
		t.Fatalf("Authorization = %s (host %s)", auth, rt.req.URL.Host)
	}
}

func TestPresignMatchesAWSExample(t *testing.T) {
	c := exampleClient(t, nil)
	u := c.PresignGet("test.txt", 24*time.Hour)
	if !strings.Contains(u, "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404") {
		t.Fatalf("presigned URL = %s", u)
	}
}

// fakeS3 keeps objects in memory and checks what Hangar's uploads must
// carry: Content-MD5 and the Object Lock headers.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	headers map[string]http.Header
	parts   map[string][]byte
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/bkt/")
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodPut && q.Get("partNumber") != "":
		b, _ := io.ReadAll(r.Body)
		f.parts[q.Get("partNumber")] = b
		w.Header().Set("ETag", `"p`+q.Get("partNumber")+`"`)
	case r.Method == http.MethodPut:
		if r.Header.Get("Content-MD5") == "" {
			http.Error(w, "<Error><Code>InvalidRequest</Code></Error>", 400)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.objects[key], f.headers[key] = b, r.Header.Clone()
	case r.Method == http.MethodPost && q.Has("uploads"):
		f.headers[key] = r.Header.Clone()
		_, _ = io.WriteString(w, "<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>")
	case r.Method == http.MethodPost && q.Get("uploadId") == "u1":
		var all []byte
		for i := 1; i <= len(f.parts); i++ {
			all = append(all, f.parts[strconv.Itoa(i)]...)
		}
		f.objects[key] = all
		_, _ = io.WriteString(w, "<CompleteMultipartUploadResult/>")
	case r.Method == http.MethodGet && q.Get("list-type") == "2":
		_, _ = io.WriteString(w, "<ListBucketResult><IsTruncated>false</IsTruncated>")
		for k, v := range f.objects {
			if strings.HasPrefix(k, q.Get("prefix")) {
				_, _ = io.WriteString(w, "<Contents><Key>"+k+"</Key><Size>"+strconv.Itoa(len(v))+"</Size><LastModified>2026-10-15T14:32:00.000Z</LastModified></Contents>")
			}
		}
		_, _ = io.WriteString(w, "</ListBucketResult>")
	case r.Method == http.MethodGet:
		b, ok := f.objects[key]
		if !ok {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>")
			return
		}
		_, _ = w.Write(b)
	case r.Method == http.MethodDelete:
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>no</Message></Error>")
	}
}

func TestPutGetListAgainstFake(t *testing.T) {
	f := &fakeS3{objects: map[string][]byte{}, headers: map[string]http.Header{}, parts: map[string][]byte{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, Bucket: "bkt", AccessKey: "a", SecretKey: "b", PathStyle: true}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	until := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	data := []byte("cifrado")
	if err := c.Put(ctx, "diario/a b/x.age", bytes.NewReader(data), int64(len(data)), PutOptions{LockMode: Compliance, RetainUntil: until, Metadata: map[string]string{"hangar-sha256": "abc"}}); err != nil {
		t.Fatal(err)
	}
	h := f.headers["diario/a b/x.age"]
	if h.Get("X-Amz-Object-Lock-Mode") != Compliance || h.Get("X-Amz-Object-Lock-Retain-Until-Date") != "2026-11-15T00:00:00Z" || h.Get("X-Amz-Meta-Hangar-Sha256") != "abc" {
		t.Fatalf("lock headers: %v", h)
	}
	rc, _, err := c.Get(ctx, "diario/a b/x.age")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != "cifrado" {
		t.Fatalf("get = %q", got)
	}
	if _, _, err := c.Get(ctx, "nada"); !IsNotFound(err) {
		t.Fatalf("missing object: %v", err)
	}
	if err := c.Delete(ctx, "diario/a b/x.age", ""); !IsAccessDenied(err) {
		t.Fatalf("delete: %v", err)
	}

	// Multipart: three parts, reassembled in order, lock on the start call.
	old := PartSize
	PartSize = 4
	defer func() { PartSize = old }()
	big := []byte("0123456789")
	if err := c.Put(ctx, "big", bytes.NewReader(big), int64(len(big)), PutOptions{LockMode: Governance, RetainUntil: until}); err != nil {
		t.Fatal(err)
	}
	if string(f.objects["big"]) != string(big) || f.headers["big"].Get("X-Amz-Object-Lock-Mode") != Governance {
		t.Fatalf("multipart: %q %v", f.objects["big"], f.headers["big"])
	}
	var keys []string
	if err := c.List(ctx, "diario/", func(o ObjectInfo) error { keys = append(keys, o.Key); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "diario/a b/x.age" {
		t.Fatalf("list: %v", keys)
	}
}
