// Package s3 is a small S3 client with only what Hangar's backups use:
// upload with Object Lock (single and multipart), head, get, list,
// presigned GET and the bucket checks. It signs with AWS Signature V4 and
// works with AWS, Backblaze B2, Wasabi, Cloudflare R2 and MinIO.
//
// A full SDK would bring dozens of packages for these few calls
// (docs/12: fewer dependencies, less attack surface).
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // Content-MD5 is required by S3 for Object Lock uploads; not used for security
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config is how to reach a bucket.
type Config struct {
	Endpoint  string // https://s3.us-west-004.backblazeb2.com
	Region    string // us-west-004 ("auto" for R2)
	Bucket    string
	AccessKey string
	SecretKey string
	// PathStyle puts the bucket in the path (https://endpoint/bucket/key)
	// instead of the host. MinIO and most S3-compatible services need it.
	PathStyle bool
}

// Client talks to one bucket.
type Client struct {
	cfg  Config
	base *url.URL
	http *http.Client
	now  func() time.Time
}

// New returns a client. hc decides what may be dialed (netguard.Client on
// the server).
func New(cfg Config, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("s3: invalid endpoint %q", cfg.Endpoint)
	}
	if cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("s3: bucket and credentials are required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{cfg: cfg, base: u, http: hc, now: time.Now}, nil
}

// Error is an error answered by the service.
type Error struct {
	Status  int
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("s3: HTTP %d", e.Status)
	}
	return fmt.Sprintf("s3: %s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

// IsAccessDenied reports whether err is a permission refusal (including
// Object Lock refusing a delete).
func IsAccessDenied(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == http.StatusForbidden || e.Code == "AccessDenied")
}

// IsNotFound reports whether the object or bucket does not exist.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Code == "NoSuchKey")
}

// --- signing ------------------------------------------------------------------

const (
	algorithm   = "AWS4-HMAC-SHA256"
	amzDate     = "20060102T150405Z"
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// escape is S3's URI encoding: everything but unreserved characters, and
// "/" kept in paths.
func escape(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, escape(k, false)+"="+escape(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (c *Client) signingKey(day string) []byte {
	k := hmacSHA256([]byte("AWS4"+c.cfg.SecretKey), day)
	k = hmacSHA256(k, c.cfg.Region)
	k = hmacSHA256(k, "s3")
	return hmacSHA256(k, "aws4_request")
}

// target returns the URL (without query) and the canonical path for a key.
func (c *Client) target(key string) (*url.URL, string) {
	u := *c.base
	path := strings.TrimRight(u.Path, "/")
	if c.cfg.PathStyle {
		path += "/" + c.cfg.Bucket
	} else {
		u.Host = c.cfg.Bucket + "." + u.Host
	}
	path += "/" + key
	u.Path = path
	u.RawPath = escape(path, true)
	return &u, escape(path, true)
}

// sign adds the V4 Authorization header. payloadHash is the hex SHA-256 of
// the body.
func (c *Client) sign(req *http.Request, canonicalPath, payloadHash string) {
	t := c.now().UTC()
	req.Header.Set("X-Amz-Date", t.Format(amzDate))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	names := []string{"host"}
	values := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-md5" || lk == "content-type" || lk == "range" {
			names = append(names, lk)
			values[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + values[n] + "\n")
	}
	signed := strings.Join(names, ";")
	creq := strings.Join([]string{req.Method, canonicalPath, canonicalQuery(req.URL.Query()), ch.String(), signed, payloadHash}, "\n")
	day := t.Format("20060102")
	scope := day + "/" + c.cfg.Region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(creq))
	sts := algorithm + "\n" + t.Format(amzDate) + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	sig := hex.EncodeToString(hmacSHA256(c.signingKey(day), sts))
	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", algorithm, c.cfg.AccessKey, scope, signed, sig))
}

// PresignGet returns a URL anyone can use to download key until it
// expires (max 7 days).
func (c *Client) PresignGet(key string, expires time.Duration) string {
	u, path := c.target(key)
	t := c.now().UTC()
	day := t.Format("20060102")
	scope := day + "/" + c.cfg.Region + "/s3/aws4_request"
	q := url.Values{}
	q.Set("X-Amz-Algorithm", algorithm)
	q.Set("X-Amz-Credential", c.cfg.AccessKey+"/"+scope)
	q.Set("X-Amz-Date", t.Format(amzDate))
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires.Seconds())))
	q.Set("X-Amz-SignedHeaders", "host")
	creq := strings.Join([]string{http.MethodGet, path, canonicalQuery(q), "host:" + u.Host + "\n", "host", "UNSIGNED-PAYLOAD"}, "\n")
	sum := sha256.Sum256([]byte(creq))
	sts := algorithm + "\n" + t.Format(amzDate) + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	q.Set("X-Amz-Signature", hex.EncodeToString(hmacSHA256(c.signingKey(day), sts)))
	u.RawQuery = canonicalQuery(q)
	return u.String()
}

// --- requests -----------------------------------------------------------------

type request struct {
	method string
	key    string
	query  url.Values
	header http.Header
	body   []byte        // small bodies (XML)
	stream io.ReadSeeker // object bodies
	size   int64
	sha    string // hex SHA-256 of stream
}

func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * time.Second):
			}
		}
		resp, err := c.once(ctx, r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		var se *Error
		if errors.As(err, &se) && se.Status < 500 {
			return nil, err // a client error does not get better by retrying
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) once(ctx context.Context, r request) (*http.Response, error) {
	u, path := c.target(r.key)
	if r.query != nil {
		u.RawQuery = canonicalQuery(r.query)
	}
	var body io.Reader
	payload := emptySHA256
	var length int64
	switch {
	case r.stream != nil:
		if _, err := r.stream.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		body, payload, length = io.LimitReader(r.stream, r.size), r.sha, r.size
	case r.body != nil:
		sum := sha256.Sum256(r.body)
		body, payload, length = bytes.NewReader(r.body), hex.EncodeToString(sum[:]), int64(len(r.body))
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.URL.RawPath = path
	req.ContentLength = length
	if body == nil {
		req.Body = http.NoBody
	}
	for k, v := range r.header {
		req.Header[k] = v
	}
	c.sign(req, path, payload)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3: %w", err)
	}
	if resp.StatusCode >= 300 {
		defer func() { _ = resp.Body.Close() }()
		e := &Error{Status: resp.StatusCode}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = xml.Unmarshal(raw, e)
		return nil, e
	}
	return resp, nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

// --- objects ------------------------------------------------------------------

// Lock modes (Object Lock).
const (
	Compliance = "COMPLIANCE"
	Governance = "GOVERNANCE"
)

// PutOptions are the extras of an upload.
type PutOptions struct {
	// LockMode and RetainUntil set Object Lock on the new version: nobody
	// (in compliance mode, not even the account root) can delete or
	// overwrite it before RetainUntil.
	LockMode    string
	RetainUntil time.Time
	// Metadata become x-amz-meta-* headers (lowercase keys).
	Metadata map[string]string
}

// PartSize is the multipart chunk; files up to PartSize go in one PUT.
var PartSize int64 = 64 << 20

func (o PutOptions) headers() http.Header {
	h := http.Header{}
	if o.LockMode != "" {
		h.Set("X-Amz-Object-Lock-Mode", o.LockMode)
		h.Set("X-Amz-Object-Lock-Retain-Until-Date", o.RetainUntil.UTC().Format(time.RFC3339))
	}
	for k, v := range o.Metadata {
		h.Set("X-Amz-Meta-"+k, v)
	}
	return h
}

// hashRange returns the hex SHA-256 and the base64 MD5 of size bytes of f
// from off.
func hashRange(f io.ReadSeeker, off, size int64) (string, string, error) {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", "", err
	}
	s, m := sha256.New(), md5.New() //nolint:gosec // see import
	n, err := io.Copy(io.MultiWriter(s, m), io.LimitReader(f, size))
	if err != nil {
		return "", "", err
	}
	if n != size {
		return "", "", io.ErrUnexpectedEOF
	}
	return hex.EncodeToString(s.Sum(nil)), base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}

// section is a seekable window of a file.
type section struct {
	r        io.ReaderAt
	off, pos int64
	size     int64
}

func (s *section) Read(p []byte) (int, error) {
	if s.pos >= s.size {
		return 0, io.EOF
	}
	if int64(len(p)) > s.size-s.pos {
		p = p[:s.size-s.pos]
	}
	n, err := s.r.ReadAt(p, s.off+s.pos)
	s.pos += int64(n)
	if err == io.EOF && s.pos < s.size {
		err = io.ErrUnexpectedEOF
	} else if err == io.EOF {
		err = nil
	}
	return n, err
}

func (s *section) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.pos = off
	case io.SeekCurrent:
		s.pos += off
	case io.SeekEnd:
		s.pos = s.size + off
	}
	return s.pos, nil
}

// File is what Put uploads: seekable and readable at offsets (an *os.File
// or a bytes.Reader).
type File interface {
	io.ReadSeeker
	io.ReaderAt
}

// Put uploads size bytes of f as key. Large files go multipart.
func (c *Client) Put(ctx context.Context, key string, f File, size int64, o PutOptions) error {
	if size > PartSize {
		return c.putMultipart(ctx, key, f, size, o)
	}
	sha, md, err := hashRange(f, 0, size)
	if err != nil {
		return err
	}
	h := o.headers()
	h.Set("Content-MD5", md)
	h.Set("Content-Type", "application/octet-stream")
	resp, err := c.do(ctx, request{method: http.MethodPut, key: key, header: h, stream: &section{r: f, size: size}, size: size, sha: sha})
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

type completePart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

func (c *Client) putMultipart(ctx context.Context, key string, f File, size int64, o PutOptions) (err error) {
	h := o.headers()
	h.Set("Content-Type", "application/octet-stream")
	resp, err := c.do(ctx, request{method: http.MethodPost, key: key, query: url.Values{"uploads": {""}}, header: h})
	if err != nil {
		return err
	}
	var init struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&init)
	drain(resp)
	if err != nil || init.UploadID == "" {
		return fmt.Errorf("s3: start multipart upload: %w", errors.Join(err, errors.New("no upload id")))
	}
	defer func() {
		if err != nil {
			// Without this, the parts stay billed in the bucket.
			if r, aerr := c.do(context.WithoutCancel(ctx), request{method: http.MethodDelete, key: key, query: url.Values{"uploadId": {init.UploadID}}}); aerr == nil {
				drain(r)
			}
		}
	}()
	var parts []completePart
	for n, off := 1, int64(0); off < size; n, off = n+1, off+PartSize {
		part := min(PartSize, size-off)
		sha, md, herr := hashRange(f, off, part)
		if herr != nil {
			return herr
		}
		ph := http.Header{}
		ph.Set("Content-MD5", md)
		q := url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {init.UploadID}}
		r, perr := c.do(ctx, request{method: http.MethodPut, key: key, query: q, header: ph, stream: &section{r: f, off: off, size: part}, size: part, sha: sha})
		if perr != nil {
			return perr
		}
		parts = append(parts, completePart{PartNumber: n, ETag: r.Header.Get("ETag")})
		drain(r)
	}
	body, _ := xml.Marshal(struct {
		XMLName xml.Name       `xml:"CompleteMultipartUpload"`
		Parts   []completePart `xml:"Part"`
	}{Parts: parts})
	ch := http.Header{}
	ch.Set("Content-Type", "application/xml")
	resp, err = c.do(ctx, request{method: http.MethodPost, key: key, query: url.Values{"uploadId": {init.UploadID}}, header: ch, body: body})
	if err != nil {
		return err
	}
	// The service may answer 200 with an error inside the body.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if bytes.Contains(raw, []byte("<Error>")) {
		e := &Error{Status: resp.StatusCode}
		_ = xml.Unmarshal(raw, e)
		return e
	}
	return nil
}

// ObjectInfo describes a stored object.
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
	Metadata     map[string]string
	LockMode     string
	RetainUntil  time.Time
	VersionID    string
}

func infoFrom(key string, h http.Header) ObjectInfo {
	oi := ObjectInfo{Key: key, ETag: strings.Trim(h.Get("ETag"), `"`), LockMode: h.Get("X-Amz-Object-Lock-Mode"), VersionID: h.Get("X-Amz-Version-Id"), Metadata: map[string]string{}}
	oi.Size, _ = strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	oi.LastModified, _ = http.ParseTime(h.Get("Last-Modified"))
	oi.RetainUntil, _ = time.Parse(time.RFC3339, h.Get("X-Amz-Object-Lock-Retain-Until-Date"))
	for k, v := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz-meta-") && len(v) > 0 {
			oi.Metadata[strings.TrimPrefix(lk, "x-amz-meta-")] = v[0]
		}
	}
	return oi
}

// Head reads an object's metadata.
func (c *Client) Head(ctx context.Context, key string) (ObjectInfo, error) {
	resp, err := c.do(ctx, request{method: http.MethodHead, key: key})
	if err != nil {
		return ObjectInfo{}, err
	}
	drain(resp)
	return infoFrom(key, resp.Header), nil
}

// Get opens an object for reading; the caller closes it.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, ObjectInfo, error) {
	resp, err := c.do(ctx, request{method: http.MethodGet, key: key})
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	return resp.Body, infoFrom(key, resp.Header), nil
}

// GetRange reads n bytes from the start of an object.
func (c *Client) GetRange(ctx context.Context, key string, n int64) ([]byte, error) {
	h := http.Header{}
	h.Set("Range", fmt.Sprintf("bytes=0-%d", n-1))
	resp, err := c.do(ctx, request{method: http.MethodGet, key: key, header: h})
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	return io.ReadAll(io.LimitReader(resp.Body, n))
}

// Delete deletes an object (or one version of it). The server's credential
// is never allowed to: this exists to prove that, and for the operator's
// own tools.
func (c *Client) Delete(ctx context.Context, key, versionID string) error {
	var q url.Values
	if versionID != "" {
		q = url.Values{"versionId": {versionID}}
	}
	resp, err := c.do(ctx, request{method: http.MethodDelete, key: key, query: q})
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// List calls fn for every object under prefix, in key order.
func (c *Client) List(ctx context.Context, prefix string, fn func(ObjectInfo) error) error {
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.do(ctx, request{method: http.MethodGet, key: "", query: q})
		if err != nil {
			return err
		}
		var page struct {
			Contents []struct {
				Key          string `xml:"Key"`
				Size         int64  `xml:"Size"`
				ETag         string `xml:"ETag"`
				LastModified string `xml:"LastModified"`
			} `xml:"Contents"`
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&page)
		drain(resp)
		if err != nil {
			return fmt.Errorf("s3: list: %w", err)
		}
		for _, o := range page.Contents {
			t, _ := time.Parse(time.RFC3339Nano, o.LastModified)
			if err := fn(ObjectInfo{Key: o.Key, Size: o.Size, ETag: strings.Trim(o.ETag, `"`), LastModified: t}); err != nil {
				return err
			}
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			return nil
		}
		token = page.NextContinuationToken
	}
}

// --- bucket -------------------------------------------------------------------

// LockConfig is the bucket's Object Lock setting.
type LockConfig struct {
	Enabled bool
	Mode    string // default retention mode, if any
	Days    int
}

// ObjectLock reads the bucket's Object Lock configuration.
func (c *Client) ObjectLock(ctx context.Context) (LockConfig, error) {
	resp, err := c.do(ctx, request{method: http.MethodGet, key: "", query: url.Values{"object-lock": {""}}})
	if err != nil {
		var e *Error
		if errors.As(err, &e) && strings.Contains(e.Code, "ObjectLockConfigurationNotFound") {
			return LockConfig{}, nil
		}
		return LockConfig{}, err
	}
	var v struct {
		Enabled string `xml:"ObjectLockEnabled"`
		Mode    string `xml:"Rule>DefaultRetention>Mode"`
		Days    int    `xml:"Rule>DefaultRetention>Days"`
	}
	err = xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&v)
	drain(resp)
	if err != nil {
		return LockConfig{}, err
	}
	return LockConfig{Enabled: v.Enabled == "Enabled", Mode: v.Mode, Days: v.Days}, nil
}

// LifecycleRule expires objects under Prefix after Days (and their old
// versions after the same time).
type LifecycleRule struct {
	ID     string
	Prefix string
	Days   int
}

// PutLifecycle replaces the bucket's lifecycle rules. Only the operator's
// own credential (hangar-cofre) may do this, never the server's.
func (c *Client) PutLifecycle(ctx context.Context, rules []LifecycleRule) error {
	type expiration struct {
		Days int `xml:"Days"`
	}
	type ncExpiration struct {
		NoncurrentDays int `xml:"NoncurrentDays"`
	}
	type rule struct {
		ID                          string                  `xml:"ID"`
		Filter                      struct{ Prefix string } `xml:"Filter"`
		Status                      string                  `xml:"Status"`
		Expiration                  expiration              `xml:"Expiration"`
		NoncurrentVersionExpiration ncExpiration            `xml:"NoncurrentVersionExpiration"`
	}
	var doc struct {
		XMLName xml.Name `xml:"LifecycleConfiguration"`
		Rules   []rule   `xml:"Rule"`
	}
	for _, r := range rules {
		x := rule{ID: r.ID, Status: "Enabled", Expiration: expiration{Days: r.Days}, NoncurrentVersionExpiration: ncExpiration{NoncurrentDays: 1}}
		x.Filter.Prefix = r.Prefix
		doc.Rules = append(doc.Rules, x)
	}
	body, _ := xml.Marshal(doc)
	m := md5.Sum(body) //nolint:gosec // required header, not security
	h := http.Header{}
	h.Set("Content-MD5", base64.StdEncoding.EncodeToString(m[:]))
	h.Set("Content-Type", "application/xml")
	resp, err := c.do(ctx, request{method: http.MethodPut, key: "", query: url.Values{"lifecycle": {""}}, header: h, body: body})
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}
