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

// Checker looks up and stages updates. Safe for concurrent use.
type Checker struct {
	cfg     Config
	current string
	http    *http.Client

	mu     sync.Mutex
	latest *Available
	err    error
}

// NewChecker creates the checker for the running version.
func NewChecker(cfg Config, current string) *Checker {
	return &Checker{
		cfg: cfg, current: current,
		http: &http.Client{Timeout: 2 * time.Minute},
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

// Check looks up the latest stable release.
func (c *Checker) Check(ctx context.Context) (*Available, error) {
	rel, err := c.latestRelease(ctx)
	if err == nil {
		var newer bool
		newer, err = release.IsUpgrade(c.current, rel.TagName)
		c.mu.Lock()
		c.latest = nil
		if err == nil && newer {
			c.latest = &Available{Version: rel.TagName, Notes: truncate(rel.Body, 4000), URL: rel.HTMLURL, CheckedAt: time.Now()}
		}
		c.err = err
		latest := c.latest
		c.mu.Unlock()
		return latest, err
	}
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
	return nil, err
}

// Run checks every interval until ctx ends.
func (c *Checker) Run(ctx context.Context, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := c.Check(ctx); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Checker) latestRelease(ctx context.Context) (ghRelease, error) {
	u := strings.TrimRight(c.cfg.APIBase, "/") + "/repos/" + c.cfg.Repo + "/releases/latest"
	var rel ghRelease
	body, err := c.get(ctx, u, "application/vnd.github+json", maxManifestBytes)
	if err != nil {
		return rel, err
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return rel, fmt.Errorf("GitHub response: %w", err)
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

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
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
