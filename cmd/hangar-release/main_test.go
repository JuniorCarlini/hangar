package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/release"
)

// The release workflow trusts a reused edge image only through verify, and
// checks its own output with it before publishing.
func TestSignThenVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	old := release.PublicKeyHex
	release.PublicKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() { release.PublicKeyHex = old })
	t.Setenv("HANGAR_RELEASE_KEY", base64.StdEncoding.EncodeToString(priv))

	dir := t.TempDir()
	for _, n := range []string{"hangard-linux-amd64", "hangard-linux-arm64"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := sign("v1.2.3", dir); err != nil {
		t.Fatal(err)
	}
	if v, err := verify(dir); err != nil || v != "v1.2.3" {
		t.Fatalf("verify = %q, %v", v, err)
	}

	// Only the amd64 binary downloaded (what the workflow fetches): fine.
	only := t.TempDir()
	for _, n := range []string{"release.json", "release.json.sig", "hangard-linux-amd64"} {
		b, _ := os.ReadFile(filepath.Join(dir, n))
		if err := os.WriteFile(filepath.Join(only, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verify(only); err != nil {
		t.Fatalf("partial download: %v", err)
	}

	// A swapped binary, or no binary at all, fails.
	if err := os.WriteFile(filepath.Join(only, "hangard-linux-amd64"), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(only); err == nil {
		t.Error("a swapped binary passed")
	}
	_ = os.Remove(filepath.Join(only, "hangard-linux-amd64"))
	if _, err := verify(only); err == nil {
		t.Error("a directory without any listed file passed")
	}

	// Another key's signature fails.
	other, _, _ := ed25519.GenerateKey(nil)
	release.PublicKeyHex = hex.EncodeToString(other)
	if _, err := verify(dir); err == nil {
		t.Error("a release signed with another key passed")
	}
}
