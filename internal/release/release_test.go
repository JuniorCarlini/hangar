package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func testManifest(t *testing.T, version string, files map[string]string) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Manifest{Version: version, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	return b, pub, priv
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestVerifyManifest(t *testing.T) {
	m, pub, priv := testManifest(t, "v1.2.3", map[string]string{"hangard-linux-amd64": sum("binario")})
	sig := Sign(m, priv)

	got, err := verifyWith(pub, m, sig)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "v1.2.3" {
		t.Errorf("version %q", got.Version)
	}
	if err := got.CheckFile("hangard-linux-amd64", strings.NewReader("binario")); err != nil {
		t.Errorf("correct hash rejected: %v", err)
	}
	if err := got.CheckFile("hangard-linux-amd64", strings.NewReader("binario trocado")); err == nil {
		t.Error("swapped binary accepted")
	}
	if err := got.CheckFile("hangard-linux-arm64", strings.NewReader("binario")); err == nil {
		t.Error("file outside the manifest accepted")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	m, pub, priv := testManifest(t, "v1.2.3", map[string]string{"hangard-linux-amd64": sum("x")})
	sig := Sign(m, priv)

	tampered := []byte(strings.Replace(string(m), "v1.2.3", "v9.9.9", 1))
	if _, err := verifyWith(pub, tampered, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered manifest: %v", err)
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := verifyWith(otherPub, m, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("someone else's key: %v", err)
	}
	if _, err := verifyWith(pub, m, "nao-e-base64!"); !errors.Is(err, ErrBadSignature) {
		t.Errorf("garbage signature: %v", err)
	}
}

func TestEmbeddedKeyIsValid(t *testing.T) {
	if _, err := publicKey(); err != nil {
		t.Fatal(err)
	}
}

func TestIsUpgrade(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
		err       bool
	}{
		{"v1.2.3", "v1.2.4", true, false},
		{"v1.2.3", "v1.3.0", true, false},
		{"v1.2.3", "v2.0.0", true, false},
		{"v1.2.3", "v1.2.3", false, false},
		{"v1.2.3", "v1.2.2", false, false},
		{"v1.10.0", "v1.9.9", false, false},
		{"dev", "v0.1.0", true, false},
		{"ece7230-dirty", "v0.1.0", true, false},
		{"v1.2.3", "v1.2.4-rc1", false, true},
		{"v1.2.3", "latest", false, true},
	}
	for _, c := range cases {
		got, err := IsUpgrade(c.cur, c.cand)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("IsUpgrade(%s, %s) = %v, %v", c.cur, c.cand, got, err)
		}
	}
}

// The installer checks the signature with the key written in it; if that
// key drifts from the binary's, every fresh install would fail.
func TestInstallerUsesEmbeddedKey(t *testing.T) {
	b, err := os.ReadFile("../../deploy/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `RELEASE_PUBKEY_HEX="`+PublicKeyHex+`"`) {
		t.Fatal("deploy/install.sh has a public key different from release.PublicKeyHex")
	}
}
