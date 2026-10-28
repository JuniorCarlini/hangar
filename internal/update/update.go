// Package update implements the one-click panel update (docs/21).
//
// Flow: hangard (unprivileged) finds the new version, downloads and verifies
// everything into data_dir/update/, and writes a request. systemd notices the
// request and runs `hangard self-update apply` as root, which verifies
// everything again, swaps the binary, restarts, and rolls back on its own if
// the new version does not come up.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/release"
)

// Download limits: a compromised release server cannot fill the disk.
const (
	maxManifestBytes = 64 << 10
	maxBinaryBytes   = 200 << 20
)

// Files in data_dir/update/.
const (
	requestFile = "request.json"
	statusFile  = "status.json"
	stagingDir  = "staging"
)

// Config says where releases come from.
type Config struct {
	Repo    string // "JuniorCarlini/hangar"
	APIBase string // "https://api.github.com"
	// WebBase serves the release downloads ("https://github.com"); empty =
	// derived from APIBase (the same server outside GitHub, as in tests).
	WebBase string
	Token   string // needed while the repository is private
	Dir     string // data_dir/update
	// Applier: the root applier (hangar-updater.path) watches Dir. Without
	// it (a panel run by hand, a development machine) a request would wait
	// forever, so the button is not offered.
	Applier bool
}

// Available is a newer version that was found.
type Available struct {
	Version   string    `json:"version"`
	Notes     string    `json:"notes"`
	URL       string    `json:"url"`
	CheckedAt time.Time `json:"checked_at"`
}

// Request is what hangard leaves for the root applier.
type Request struct {
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	RequestedBy string    `json:"requested_by"`
	At          time.Time `json:"at"`
}

// Status is the result of the last apply, written by the applier.
type Status struct {
	State   string    `json:"state"` // applying, ok, rolled_back, failed
	Version string    `json:"version"`
	From    string    `json:"from"`
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

// ErrPending: an update is already being downloaded or waits for the
// applier.
var ErrPending = &i18n.Error{Key: "update.error.pending"}

// Checker looks up and stages updates. Safe for concurrent use.
type Checker struct {
	cfg     Config
	current string
	http    *http.Client
	// probe does not follow redirects: the background lookup only reads
	// where GitHub's "latest download" link points (see latestTag).
	probe *http.Client

	mu     sync.Mutex
	latest *Available
	err    error
	// What the background schedule needs (schedule.go): when the last
	// lookup ran, how many failed in a row, and until when GitHub asked us
	// to wait (rate limit).
	lastAttempt time.Time
	failures    int
	retryAt     time.Time
	// The last good answer of releases/latest and its validators: the next
	// lookup is a conditional request, and a 304 reuses this.
	cached       *ghRelease
	etag         string
	lastModified string
	// verified is the newer version whose signed manifest was checked, so
	// the background lookup verifies each release once.
	verified *Available

	// fetch is held while a lookup runs: a click and the schedule never
	// query at the same time, and a page visit does not start a second one.
	fetch    sync.Mutex
	checking atomic.Bool

	// staging is held while a version downloads, so a second click on the
	// button cannot download into the same directory meanwhile.
	staging sync.Mutex
}

// NewChecker creates the checker for the running version.
func NewChecker(cfg Config, current string) *Checker {
	if cfg.WebBase == "" {
		cfg.WebBase = cfg.APIBase
		if strings.TrimRight(cfg.APIBase, "/") == "https://api.github.com" {
			cfg.WebBase = "https://github.com"
		}
	}
	return &Checker{
		cfg: cfg, current: current,
		http: &http.Client{Timeout: 2 * time.Minute},
		probe: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Current is the running version.
func (c *Checker) Current() string { return c.current }

// CanApply reports whether a staged update would be applied here.
func (c *Checker) CanApply() bool { return c.cfg.Applier }

// ApplierWatches reports whether the systemd path unit at unitPath starts
// the applier for requests left in dir.
func ApplierWatches(unitPath, dir string) bool {
	b, err := os.ReadFile(unitPath) //nolint:gosec // fixed system path
	if err != nil {
		return false
	}
	want := "PathExists=" + filepath.Join(dir, requestFile)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// Latest returns the last newer version found (nil when up to date) and the
// error from the last lookup.
func (c *Checker) Latest() (*Available, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latest, c.err
}

// ghRelease is the part of GitHub's releases API we use.
type ghRelease struct {
	TagName    string    `json:"tag_name"`
	Body       string    `json:"body"`
	HTMLURL    string    `json:"html_url"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"url"` // API URL; with Accept octet-stream it downloads the file
	Size int64  `json:"size"`
}

// Check looks up the latest stable release now (the "check now" button and
// the schedule in Run).
func (c *Checker) Check(ctx context.Context) (*Available, error) {
	c.fetch.Lock()
	defer c.fetch.Unlock()
	return c.check(ctx)
}

// check runs one lookup; the caller holds c.fetch.
func (c *Checker) check(ctx context.Context) (*Available, error) {
	c.checking.Store(true)
	defer c.checking.Store(false)
	av, err := c.lookup(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	// On failure the newer version found before stays known: a flaky
	// network must not make the sidebar badge blink.
	if err == nil {
		c.latest = av
	}
	c.err = err
	c.attempted(err)
	return av, err
}

// lookup finds the newer stable version, if any.
//
// Without a token (a public repository) it costs one small request outside
// the API and its rate limit: where the "latest download" link redirects to
// names the tag. Only a tag newer than the running version is looked at
// further, once: its signed manifest is downloaded and verified (the badge
// never announces an unsigned release) and the API gives the notes.
//
// With a token (a private repository, whose download links need the API)
// it asks the API, conditionally: an unchanged answer is a 304 that an
// authenticated request does not count.
func (c *Checker) lookup(ctx context.Context) (*Available, error) {
	if c.cfg.Token != "" {
		rel, err := c.latestRelease(ctx)
		if err != nil {
			return nil, err
		}
		if newer, err := release.IsUpgrade(c.current, rel.TagName); err != nil || !newer {
			return nil, err
		}
		return &Available{Version: rel.TagName, Notes: truncate(rel.Body, 4000), URL: rel.HTMLURL, CheckedAt: time.Now()}, nil
	}
	tag, err := c.latestTag(ctx)
	if err != nil {
		return nil, err
	}
	if newer, err := release.IsUpgrade(c.current, tag); err != nil || !newer {
		return nil, err
	}
	c.mu.Lock()
	known := c.verified
	c.mu.Unlock()
	if known != nil && known.Version == tag {
		av := *known
		av.CheckedAt = time.Now()
		return &av, nil
	}
	if err := c.verifyTag(ctx, tag); err != nil {
		return nil, err
	}
	av := &Available{Version: tag, URL: c.webURL("releases/tag/" + url.PathEscape(tag)), CheckedAt: time.Now()}
	// The notes are a nicety: without them (API rate limit) the version is
	// still shown.
	if rel, err := c.latestRelease(ctx); err == nil && rel.TagName == tag {
		av.Notes = truncate(rel.Body, 4000)
		if rel.HTMLURL != "" {
			av.URL = rel.HTMLURL
		}
	}
	c.mu.Lock()
	c.verified = av
	c.mu.Unlock()
	return av, nil
}

// webURL is a page or download of the repository on GitHub's web side.
func (c *Checker) webURL(path string) string {
	return strings.TrimRight(c.cfg.WebBase, "/") + "/" + c.cfg.Repo + "/" + path
}

// latestTag reads the tag of the latest stable release from where
// "releases/latest/download/release.json" redirects to
// (".../releases/download/<tag>/release.json"), without following it: a
// bodyless 302 from github.com. GitHub sends no validator for it (no ETag,
// Cache-Control: no-cache), so it cannot be made conditional; it is already
// the smallest answer there is.
func (c *Checker) latestTag(ctx context.Context) (string, error) {
	req, err := c.newRequest(ctx, c.webURL("releases/latest/download/release.json"), "*/*")
	if err != nil {
		return "", err
	}
	req.Header.Del("X-GitHub-Api-Version")
	resp, err := c.probe.Do(req)
	if err != nil {
		return "", fmt.Errorf("query releases: %w", err)
	}
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusFound, http.StatusMovedPermanently, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		if until := rateLimitedUntil(resp.StatusCode, resp.Header, time.Now()); !until.IsZero() {
			c.mu.Lock()
			c.retryAt = until
			c.mu.Unlock()
		}
		return "", i18n.E("update.error.http", "host", req.URL.Host, "status", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("latest release redirect: %w", err)
	}
	tag, ok := tagFromDownload(loc.EscapedPath())
	if !ok {
		return "", fmt.Errorf("latest release redirect: unexpected location %q", loc.Path)
	}
	return tag, nil
}

// tagFromDownload takes the tag out of a ".../releases/download/<tag>/<file>"
// path.
func tagFromDownload(p string) (string, bool) {
	_, rest, ok := strings.Cut(p, "/releases/download/")
	if !ok {
		return "", false
	}
	tag, _, ok := strings.Cut(rest, "/")
	if !ok || tag == "" {
		return "", false
	}
	tag, err := url.PathUnescape(tag)
	if err != nil {
		return "", false
	}
	if _, err := release.ParseVersion(tag); err != nil {
		return "", false
	}
	return tag, true
}

// verifyTag downloads the signed manifest of tag and checks it: the
// signature and that it names that version. Stage verifies everything again
// before anything is applied.
func (c *Checker) verifyTag(ctx context.Context, tag string) error {
	base := "releases/download/" + url.PathEscape(tag) + "/"
	manifest, err := c.get(ctx, c.webURL(base+"release.json"), "application/octet-stream", maxManifestBytes)
	if err != nil {
		return err
	}
	sig, err := c.get(ctx, c.webURL(base+"release.json.sig"), "application/octet-stream", maxManifestBytes)
	if err != nil {
		return err
	}
	m, err := release.VerifyManifest(manifest, string(sig))
	if err != nil {
		return err
	}
	if m.Version != tag {
		return i18n.E("update.error.manifest_version", "manifest", m.Version, "requested", tag)
	}
	return nil
}

// latestRelease asks GitHub for the latest release. It is a conditional
// request (ETag / Last-Modified of the previous answer): while nothing was
// released GitHub answers 304 with no body, which an authenticated request
// does not even count against the rate limit.
func (c *Checker) latestRelease(ctx context.Context) (ghRelease, error) {
	u := strings.TrimRight(c.cfg.APIBase, "/") + "/repos/" + c.cfg.Repo + "/releases/latest"
	var rel ghRelease
	req, err := c.newRequest(ctx, u, "application/vnd.github+json")
	if err != nil {
		return rel, err
	}
	c.mu.Lock()
	cached := c.cached
	if cached != nil {
		if c.etag != "" {
			req.Header.Set("If-None-Match", c.etag)
		}
		if c.lastModified != "" {
			req.Header.Set("If-Modified-Since", c.lastModified)
		}
	}
	c.mu.Unlock()
	resp, err := c.http.Do(req)
	if err != nil {
		return rel, fmt.Errorf("query releases: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotModified && cached != nil:
		rel = *cached
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
		if err != nil {
			return rel, err
		}
		if int64(len(body)) > maxManifestBytes {
			return rel, fmt.Errorf("response from %s exceeds the limit", u)
		}
		if err := json.Unmarshal(body, &rel); err != nil {
			return rel, fmt.Errorf("GitHub response: %w", err)
		}
		c.mu.Lock()
		c.cached, c.etag, c.lastModified = &rel, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
		c.mu.Unlock()
	default:
		if until := rateLimitedUntil(resp.StatusCode, resp.Header, time.Now()); !until.IsZero() {
			c.mu.Lock()
			c.retryAt = until
			c.mu.Unlock()
		}
		return rel, i18n.E("update.error.http", "host", req.URL.Host, "status", resp.StatusCode)
	}
	if rel.Draft || rel.Prerelease {
		return rel, i18n.E("update.error.not_stable")
	}
	return rel, nil
}

// Stage downloads and verifies the version and leaves the request for the
// applier. It only succeeds if signature, version and hash all check out.
func (c *Checker) Stage(ctx context.Context, version, requestedBy string) error {
	if !c.cfg.Applier {
		return i18n.E("update.error.no_applier")
	}
	if !c.staging.TryLock() {
		return ErrPending
	}
	defer c.staging.Unlock()
	if Pending(c.cfg.Dir) {
		return ErrPending
	}
	rel, err := c.latestRelease(ctx)
	if err != nil {
		return err
	}
	if rel.TagName != version {
		return i18n.E("update.error.version_changed", "available", rel.TagName, "requested", version)
	}
	if ok, err := release.IsUpgrade(c.current, version); err != nil || !ok {
		return release.ErrNotNewer
	}

	assets := map[string]ghAsset{}
	for _, a := range rel.Assets {
		assets[a.Name] = a
	}
	binName := release.AssetName(runtime.GOARCH)
	for _, n := range []string{"release.json", "release.json.sig", binName} {
		if _, ok := assets[n]; !ok {
			return i18n.E("update.error.missing_asset", "version", version, "file", n)
		}
	}

	manifest, err := c.get(ctx, assets["release.json"].URL, "application/octet-stream", maxManifestBytes)
	if err != nil {
		return err
	}
	sig, err := c.get(ctx, assets["release.json.sig"].URL, "application/octet-stream", maxManifestBytes)
	if err != nil {
		return err
	}
	m, err := release.VerifyManifest(manifest, string(sig))
	if err != nil {
		return err
	}
	if m.Version != version {
		return i18n.E("update.error.manifest_version", "manifest", m.Version, "requested", version)
	}

	dir := filepath.Join(c.cfg.Dir, stagingDir, version)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	binPath := filepath.Join(dir, binName)
	if err := c.download(ctx, assets[binName].URL, binPath); err != nil {
		return err
	}
	f, err := os.Open(binPath) //nolint:gosec // path built above, inside data_dir
	if err != nil {
		return err
	}
	err = m.CheckFile(binName, f)
	_ = f.Close()
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "release.json"), manifest, 0o640); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "release.json.sig"), sig, 0o640); err != nil {
		return err
	}

	req, _ := json.Marshal(Request{Version: version, FromVersion: c.current, RequestedBy: requestedBy, At: time.Now().UTC()})
	return writeFileAtomic(filepath.Join(c.cfg.Dir, requestFile), req, 0o640)
}

// ReadStatus reads the result of the last apply (nil if there was none).
func ReadStatus(dir string) (*Status, error) {
	b, err := os.ReadFile(filepath.Join(dir, statusFile)) //nolint:gosec // fixed path inside data_dir
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Pending reports whether a request is waiting for the applier.
func Pending(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, requestFile))
	return err == nil
}

// DropRequest removes a request nobody will apply (no applier here).
func DropRequest(dir string) error {
	err := os.Remove(filepath.Join(dir, requestFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (c *Checker) get(ctx context.Context, u, accept string, limit int64) ([]byte, error) {
	resp, err := c.do(ctx, u, accept)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response from %s exceeds the limit", u)
	}
	return b, nil
}

func (c *Checker) download(ctx context.Context, u, dest string) error {
	resp, err := c.do(ctx, u, "application/octet-stream")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640) //nolint:gosec // path inside data_dir
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBinaryBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxBinaryBytes {
		return errors.New("binary exceeds the size limit")
	}
	return nil
}

func (c *Checker) do(ctx context.Context, u, accept string) (*http.Response, error) {
	req, err := c.newRequest(ctx, u, accept)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query releases: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, i18n.E("update.error.http", "host", req.URL.Host, "status", resp.StatusCode)
	}
	return resp, nil
}

// newRequest is a GET to GitHub with the headers every call sends.
func (c *Checker) newRequest(ctx context.Context, u, accept string) (*http.Request, error) {
	if _, err := url.Parse(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "hangard/"+c.current)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.cfg.Token != "" {
		// Go drops Authorization when following a redirect to another host (the
		// real download comes from objects.githubusercontent.com).
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	return req, nil
}

// writeFileAtomic writes through a fresh temporary file and a rename. The
// root applier writes status here too, in a directory the hangar user owns:
// a fixed temporary name could be a planted symlink, a CreateTemp name
// cannot.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
