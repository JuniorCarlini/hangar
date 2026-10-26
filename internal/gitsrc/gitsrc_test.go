package gitsrc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateURL(t *testing.T) {
	ok := map[string]string{
		"https://github.com/acme/minhaloja.git":     "https://github.com/acme/minhaloja.git",
		" https://GitHub.com/a/b/ ":                 "https://github.com/a/b",
		"https://gitlab.example.com:8443/grupo/app": "https://gitlab.example.com:8443/grupo/app",
		"https://github.com:443/a/b":                "https://github.com/a/b",
	}
	for in, want := range ok {
		got, err := ValidateURL(in)
		if err != nil || got != want {
			t.Errorf("ValidateURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "github.com/a/b", "http://github.com/a/b", "git://github.com/a/b", "ssh://git@github.com/a/b",
		"file:///etc", "https://user:token@github.com/a/b", "https://github.com", "https://github.com/a/b?x=1",
		"https://github.com/a/b#x", "https://github.com/a/../b", "https://github.com/a b",
		"https://" + strings.Repeat("a", 300) + ".com/x",
	}
	for _, in := range bad {
		if _, err := ValidateURL(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	// The anti-SSRF filter: internal addresses and names.
	for _, in := range []string{
		"https://127.0.0.1/a/b", "https://10.0.0.5/a/b", "https://192.168.1.1/a/b", "https://169.254.169.254/latest/x",
		"https://[::1]/a/b", "https://100.64.0.1/a/b", "https://localhost/a/b", "https://db.internal/a/b", "https://0.0.0.0/a/b",
	} {
		if _, err := ValidateURL(in); !errors.Is(err, ErrBlockedHost) && !errors.Is(err, ErrURL) {
			t.Errorf("internal address accepted: %q (%v)", in, err)
		}
	}
}

func TestBlockedIP(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.17.0.1", "192.168.0.10", "169.254.169.254", "100.100.0.1",
		"::1", "fd00::1", "fe80::1", "0.0.0.0", "::ffff:127.0.0.1", "64:ff9b::a00:1", "224.0.0.1",
	} {
		if !blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"140.82.112.3", "2606:50c0:8000::153"} {
		if blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

// TestDialerRefusesInternalAddress: even with a URL that passed validation,
// the connection itself is checked (DNS rebinding).
func TestDialerRefusesInternalAddress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	c := safeHTTPClient()
	c.Timeout = 5 * time.Second
	resp, err := c.Get(srv.URL) //nolint:noctx // test
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("loopback dial allowed: %v", err)
	}
}

// TestGitRefusesInternalAddress goes through go-git: the error must still
// say "blocked" (and so never become a generic network failure).
func TestGitRefusesInternalAddress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	err := Check(t.Context(), Source{URL: srv.URL + "/dono/app.git", Branch: "main", Token: "x"})
	if !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("clone from loopback: %v", err)
	}
	if _, err := Clone(t.Context(), t.TempDir(), Source{URL: srv.URL + "/dono/app.git", Branch: "main"}); !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("clone from loopback: %v", err)
	}
	for _, u := range []string{"file:///etc", "ssh://git@github.com/a/b", "http://github.com/a/b"} {
		if err := Check(t.Context(), Source{URL: u, Branch: "main"}); err == nil {
			t.Errorf("%s: transport should not exist", u)
		}
	}
}

func TestBranchAndPaths(t *testing.T) {
	for _, b := range []string{"main", "release/2026-10", "v1.2", "feat_x"} {
		if _, err := ValidateBranch(b); err != nil {
			t.Errorf("branch %q refused", b)
		}
	}
	for _, b := range []string{"", "-x", "a..b", "a b", "a/", "/a", "x.lock", "a;rm", strings.Repeat("a", 201)} {
		if _, err := ValidateBranch(b); err == nil {
			t.Errorf("branch %q accepted", b)
		}
	}
	for in, want := range map[string]string{"": "", ".": "", "app": "app", "/apps/web/": "apps/web", "docker/Dockerfile.prod": "docker/Dockerfile.prod"} {
		if got, err := CleanPath(in); err != nil || got != want {
			t.Errorf("CleanPath(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"..", "a/../..", "a/./b", "a b", "a\\b", "$(x)"} {
		if _, err := CleanPath(in); err == nil {
			t.Errorf("path %q accepted", in)
		}
	}
}

func TestSignatureAndPush(t *testing.T) {
	secret := []byte("segredo")
	body := []byte(`{"ref":"refs/heads/main","after":"abc","repository":{"pushed_at":1760000000,"clone_url":"https://github.com/a/b.git"}}`)
	sig := Sign(secret, body)
	if !VerifySignature(secret, body, sig) {
		t.Fatal("valid signature refused")
	}
	for _, bad := range []string{"", "sha256=", "sha1=" + sig[7:], sig[:len(sig)-2] + "00", "sha256=zz"} {
		if VerifySignature(secret, body, bad) {
			t.Errorf("bad signature accepted: %q", bad)
		}
	}
	if VerifySignature(nil, body, sig) || VerifySignature([]byte("outro"), body, sig) {
		t.Error("signature checked with the wrong secret")
	}
	if VerifySignature(secret, append(body, ' '), sig) {
		t.Error("altered body accepted")
	}
	p, err := ParsePush(body)
	if err != nil || p.Branch() != "main" || p.PushedAt.Unix() != 1760000000 || !SameRepo(p.Repo[0], "https://github.com/A/b") {
		t.Fatalf("push: %+v %v", p, err)
	}
	if (Push{Ref: "refs/tags/v1"}).Branch() != "" {
		t.Error("a tag is not a branch")
	}
	if !ValidDelivery("72d3162e-cc78-11e3-81ab-4c9367dc0958") || ValidDelivery("x';--") {
		t.Error("delivery id check")
	}
}

// A checkout made under the panel's umask 077 gets Git's own modes back, so
// an image that runs as an unprivileged user can read its code; .git is
// left alone.
func TestShareReadable(t *testing.T) {
	dir := t.TempDir()
	write := func(p string, mode os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("app/lab/wsgi.py", 0o600)
	write("app/run.sh", 0o700)
	write(".git/config", 0o600)
	if err := os.Symlink("lab/wsgi.py", filepath.Join(dir, "app/link")); err != nil {
		t.Fatal(err)
	}
	if err := shareReadable(dir); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{
		"app": 0o755, "app/lab": 0o755, "app/lab/wsgi.py": 0o644, "app/run.sh": 0o755, ".git/config": 0o600,
	} {
		info, err := os.Stat(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: %o, want %o", p, got, want)
		}
	}
}
