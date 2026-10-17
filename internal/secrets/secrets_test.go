package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	b, err := NewBox(bytes.Repeat([]byte{7}, keySize))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := b.Seal([]byte("JBSWY3DPEHPK3PXP"), "users|u1|totp_secret_enc")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := b.Open(sealed, "users|u1|totp_secret_enc")
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("decrypted %q", plain)
	}

	again, _ := b.Seal([]byte("JBSWY3DPEHPK3PXP"), "users|u1|totp_secret_enc")
	if bytes.Equal(sealed, again) {
		t.Error("two Seals of the same value should differ (random nonce)")
	}
}

func TestOpenRejectsMovedOrTamperedValue(t *testing.T) {
	b, _ := NewBox(bytes.Repeat([]byte{7}, keySize))
	sealed, _ := b.Seal([]byte("segredo"), "users|u1|totp_secret_enc")

	if _, err := b.Open(sealed, "users|u2|totp_secret_enc"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("value copied to another record: err = %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := b.Open(tampered, "users|u1|totp_secret_enc"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered value: err = %v", err)
	}
	other, _ := NewBox(bytes.Repeat([]byte{8}, keySize))
	if _, err := other.Open(sealed, "users|u1|totp_secret_enc"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: err = %v", err)
	}
	if _, err := b.Open([]byte{1, 2, 3}, "x"); !errors.Is(err, ErrDecrypt) {
		t.Errorf("short value: err = %v", err)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "master.key")

	b1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o400 {
		t.Errorf("key mode = %o, want 400", perm)
	}

	b2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := b1.Seal([]byte("x"), "a")
	if _, err := b2.Open(sealed, "a"); err != nil {
		t.Error("the reread key should be the same")
	}
}

func TestLoadRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, keySize), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("a key with mode 0644 should be refused")
	}
}
