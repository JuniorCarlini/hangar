package edge

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// The panel reads the same file the :80 server checks: Caddy's
// certificates/<issuer>/<host>/<host>.crt, whatever the issuer.
func TestHasCertificateReadsCaddyStorage(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(nil, nil, nil, Options{Spec: node.EdgeSpec{DataDir: dir}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if m.HasCertificate("loja.dev") {
		t.Fatal("no certificate stored yet")
	}
	site := filepath.Join(dir, "caddy", "certificates", "acme-v02.api.letsencrypt.org-directory", "loja.dev")
	if err := os.MkdirAll(site, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, "loja.dev.crt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !m.HasCertificate("loja.dev") {
		t.Error("the stored certificate was not found")
	}
	for _, h := range []string{"", "*", "*.dev", "loja.dev/../loja.dev", "lo?a.dev", "blog.dev"} {
		if m.HasCertificate(h) {
			t.Errorf("%q must not count as having a certificate", h)
		}
	}
}

func TestRedactConfigError(t *testing.T) {
	tok := "SECRET-TOKEN-123"
	if got := redactConfigError([]byte("error: api_token "+tok+" invalid"), tok, 1024); bytes.Contains(got, []byte(tok)) {
		t.Errorf("raw token leaked: %q", got)
	}
	// The token straddles the cap: it must be redacted before the cut, so no
	// prefix survives.
	body := append([]byte(strings.Repeat("x", 20)), tok...)
	if got := redactConfigError(body, tok, 25); bytes.Contains(got, []byte("SECRET")) {
		t.Errorf("token prefix leaked past the cap: %q", got)
	}
	// No token configured: body passes through (trimmed, capped).
	if got := redactConfigError([]byte("  plain error  "), "", 1024); string(got) != "plain error" {
		t.Errorf("got %q", got)
	}
}
