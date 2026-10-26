// Package gitsrc fetches a service's source code from Git (docs/07): URL
// validation with the anti-SSRF filter (docs/17 #11), a shallow clone with a
// read-only token, and GitHub webhook verification.
//
// Everything runs in-process (go-git): no git binary, no shell, and the
// token never leaves the process memory (it is not on any command line).
package gitsrc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/file"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// Errors the UI translates.
var (
	ErrURL         = &i18n.Error{Key: "git.error.url"}
	ErrBlockedHost = &i18n.Error{Key: "git.error.blocked_host"}
	ErrBranch      = &i18n.Error{Key: "git.error.branch"}
	ErrPath        = &i18n.Error{Key: "git.error.path"}
	ErrAccess      = &i18n.Error{Key: "git.error.access"}
	ErrNoBranch    = &i18n.Error{Key: "git.error.branch_missing"}
	ErrEmptyRepo   = &i18n.Error{Key: "git.error.empty"}
)

// allowLocal lifts the anti-SSRF filter and enables file:// URLs. Only tests
// turn it on (AllowLocalForTesting); the panel never does.
var allowLocal atomic.Bool

func init() {
	// Only HTTPS, through a client that refuses internal addresses. git://,
	// ssh://, file:// and plain http:// do not exist for the panel.
	for _, s := range []string{"http", "ssh", "git", "file"} {
		client.InstallProtocol(s, nil)
	}
	client.InstallProtocol("https", githttp.NewClientWithOptions(safeHTTPClient(), &githttp.ClientOptions{
		RedirectPolicy: githttp.FollowInitialRedirects,
	}))
}

// AllowLocalForTesting accepts file:// URLs and private addresses. Tests use
// it to clone a repository created on disk; it must never run in the panel.
func AllowLocalForTesting() {
	allowLocal.Store(true)
	client.InstallProtocol("file", file.DefaultClient)
}

// safeHTTPClient dials only public addresses. The check runs on the address
// actually being connected (after DNS), so a name that resolves to a public
// IP when validated and to 127.0.0.1 when cloning (DNS rebinding) is still
// refused. Proxies from the environment are ignored on purpose.
func safeHTTPClient() *http.Client {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
			if allowLocal.Load() {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return ErrBlockedHost
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || blockedIP(ip) {
				return ErrBlockedHost
			}
			return nil
		}}
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dial,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" && !allowLocal.Load() {
				return ErrBlockedHost
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can map to anything internal
	netip.MustParsePrefix("2002::/16"),    // 6to4 embeds an IPv4 address
}

// blockedIP is true for anything that is not a public unicast address:
// loopback, private ranges, link-local (169.254.169.254, the cloud metadata
// service) and the special ranges above.
func blockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range extraBlocked {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var (
	hostRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	branchRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	pathRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	repoRE   = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)
)

// ValidateURL checks a repository URL and returns it normalized: HTTPS only,
// no credentials in it (the token has its own field), no query, and a host
// that is not an internal address.
func ValidateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 300 {
		return "", ErrURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrURL
	}
	if u.Scheme == "file" && allowLocal.Load() {
		return raw, nil
	}
	if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", ErrURL
	}
	host := strings.ToLower(u.Hostname())
	p := strings.TrimRight(u.EscapedPath(), "/")
	if !repoRE.MatchString(p) || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return "", ErrURL
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if blockedIP(ip) && !allowLocal.Load() {
			return "", ErrBlockedHost
		}
	} else if !hostRE.MatchString(host) {
		return "", ErrURL
	} else if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return "", ErrBlockedHost
	}
	out := "https://" + host
	if port := u.Port(); port != "" {
		if port != "443" {
			out += ":" + port
		}
	}
	return out + p, nil
}

// ValidateBranch checks a branch name (git check-ref-format, simplified).
func ValidateBranch(b string) (string, error) {
	b = strings.TrimSpace(b)
	if !branchRE.MatchString(b) || strings.Contains(b, "..") || strings.Contains(b, "//") ||
		strings.HasPrefix(b, "-") || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") ||
		strings.HasSuffix(b, ".lock") || strings.HasSuffix(b, ".") {
		return "", ErrBranch
	}
	return b, nil
}

// CleanPath checks a path inside the repository (subdirectory or
// Dockerfile): relative, no "..", only ordinary characters. "" stays "".
func CleanPath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" || p == "." {
		return "", nil
	}
	if len(p) > 200 || !pathRE.MatchString(p) {
		return "", ErrPath
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." {
			return "", ErrPath
		}
	}
	return path.Clean(p), nil
}

// Display is how the panel shows a repository: host/owner/name.
func Display(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil || u.Host == "" {
		return strings.TrimSuffix(repoURL, ".git")
	}
	return strings.ToLower(u.Host) + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git")
}

// SameRepo compares two repository URLs ignoring scheme, case, ".git" and a
// trailing slash.
func SameRepo(a, b string) bool {
	return strings.EqualFold(Display(a), Display(b))
}

// Source is what to fetch.
type Source struct {
	URL    string
	Branch string
	Token  string // empty for a public repository
}

func (s Source) auth() transport.AuthMethod {
	if s.Token == "" {
		return nil
	}
	// GitHub takes the token as the password with any user name; GitLab and
	// Gitea accept it the same way.
	return &githttp.BasicAuth{Username: "x-access-token", Password: s.Token}
}

// Commit is what was checked out.
type Commit struct {
	SHA     string
	Message string // first line
}

// Check lists the remote's branches with the token (git ls-remote): it
// proves the URL and the token work and the branch exists, without
// downloading anything.
func Check(ctx context.Context, src Source) error {
	rem := git.NewRemote(memory.NewStorage(), &gitconfig.RemoteConfig{Name: "origin", URLs: []string{src.URL}})
	refs, err := rem.ListContext(ctx, &git.ListOptions{Auth: src.auth(), Timeout: 30})
	if err != nil {
		return mapErr(err)
	}
	want := plumbing.NewBranchReferenceName(src.Branch)
	for _, r := range refs {
		if r.Name() == want {
			return nil
		}
	}
	return ErrNoBranch
}

// Clone makes a shallow clone of the branch into dir (which must not exist
// or be empty): one commit, no tags, no submodules.
func Clone(ctx context.Context, dir string, src Source) (Commit, error) {
	repo, err := git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:               src.URL,
		Auth:              src.auth(),
		ReferenceName:     plumbing.NewBranchReferenceName(src.Branch),
		SingleBranch:      true,
		Depth:             1,
		Tags:              git.NoTags,
		RecurseSubmodules: git.NoRecurseSubmodules,
	})
	if err != nil {
		return Commit{}, mapErr(err)
	}
	if err := shareReadable(dir); err != nil {
		return Commit{}, fmt.Errorf("source permissions: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return Commit{}, fmt.Errorf("read HEAD: %w", err)
	}
	c := Commit{SHA: head.Hash().String()}
	if obj, err := repo.CommitObject(head.Hash()); err == nil {
		c.Message, _, _ = strings.Cut(strings.TrimSpace(obj.Message), "\n")
		if len(c.Message) > 200 {
			c.Message = c.Message[:200]
		}
	}
	return c, nil
}

// shareReadable gives the checkout the permissions Git itself would (dirs
// 0755, files 0644, executables 0755). The panel runs with umask 077, so
// the clone came out 0700/0600 and owned by the panel; a Dockerfile's COPY
// keeps those modes, and an app that switches to an unprivileged user
// (USER 10001) could not read its own code. The checkout itself stays
// private: it lives under the panel's data directory, which only the panel
// reaches.
// The changes go through an os.Root, so a symlink in the repository can
// never make them land outside the checkout.
func shareReadable(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return fs.SkipDir
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if d.IsDir() || info.Mode()&0o100 != 0 {
			mode = 0o755
		}
		return root.Chmod(p, mode)
	})
}

// mapErr turns go-git's errors into messages the user can act on. Anything
// unknown keeps its text (the caller masks secrets before showing it).
func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrBlockedHost):
		return ErrBlockedHost
	case errors.Is(err, transport.ErrAuthenticationRequired), errors.Is(err, transport.ErrAuthorizationFailed),
		errors.Is(err, transport.ErrRepositoryNotFound), errors.Is(err, transport.ErrInvalidAuthMethod):
		return ErrAccess
	case errors.Is(err, transport.ErrEmptyRemoteRepository):
		return ErrEmptyRepo
	case errors.Is(err, plumbing.ErrReferenceNotFound), errors.Is(err, git.NoMatchingRefSpecError{}):
		return ErrNoBranch
	}
	return fmt.Errorf("git: %w", err)
}
