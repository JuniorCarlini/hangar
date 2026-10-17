// Package secrets encrypts the secrets stored in the panel database (TOTP
// secrets, secret variables, Git tokens, backup credentials) with the master
// key, which lives in a file outside the database.
package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

const (
	keySize = chacha20poly1305.KeySize
	// version prefixes every encrypted value, so the algorithm or key can be
	// rotated without ambiguity.
	version byte = 1
)

// ErrDecrypt is returned when the value was tampered with, came from another
// record, or the key is not the one that encrypted it.
var ErrDecrypt = errors.New("secret could not be decrypted")

// Box encrypts and decrypts with XChaCha20-Poly1305.
type Box struct{ key []byte }

// LoadOrCreateKey reads the master key at path. If the file does not exist
// it creates a new key with mode 0400. It refuses a file readable by other
// users: an exposed key protects nothing.
func LoadOrCreateKey(path string) (*Box, error) {
	key, err := os.ReadFile(path) //nolint:gosec // path comes from the configuration
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return createKey(path)
	case err != nil:
		return nil, fmt.Errorf("read master key: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, i18n.E("secrets.error.key_mode", "path", path, "mode", fmt.Sprintf("%o", perm))
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("master key %s has %d bytes, want %d", path, len(key), keySize)
	}
	return &Box{key: key}, nil
}

// NewKeyFile creates a new random key at path (mode 0400), refusing to
// overwrite an existing file. Used by the master key rotation.
func NewKeyFile(path string) (*Box, error) { return createKey(path) }

func createKey(path string) (*Box, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create master key directory: %w", err)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// O_EXCL: if another process created the key meanwhile, do not overwrite it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // path comes from the configuration
	if err != nil {
		return nil, fmt.Errorf("create master key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return &Box{key: key}, nil
}

// NewBox builds a Box from an in-memory key (tests).
func NewBox(key []byte) (*Box, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("key has %d bytes, want %d", len(key), keySize)
	}
	return &Box{key: append([]byte(nil), key...)}, nil
}

// Seal encrypts plaintext. ad (associated data) binds the value to where it
// lives, as "table|id|column": copying the ciphertext into another record
// makes Open fail.
func (b *Box) Seal(plaintext []byte, ad string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(b.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, version)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, []byte(ad)), nil
}

// Open decrypts a value produced by Seal with the same ad.
func (b *Box) Open(sealed []byte, ad string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(b.key)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(sealed) < 1+n+aead.Overhead() || sealed[0] != version {
		return nil, ErrDecrypt
	}
	plain, err := aead.Open(nil, sealed[1:1+n], sealed[1+n:], []byte(ad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}
