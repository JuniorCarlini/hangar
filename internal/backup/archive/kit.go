package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// The recovery kit (hangar-kit.txt) is generated in the browser
// (internal/web/assets/kit.js) and never reaches the server. It is a valid
// age identity file: comment lines starting with "#" and one
// AGE-SECRET-KEY-1... line, so `age -d -i hangar-kit.txt` opens backups
// too. It may be protected with a passphrase (hangar-cofre kit protect),
// which wraps the whole file in age's scrypt format.

// confirmLabel and codeLabel domain-separate the hashes below. kit.js uses
// the same strings: changing them breaks every kit already printed.
const (
	confirmLabel = "hangar-kit-confirm-v1\n"
	codeLabel    = "hangar-kit-code-v1\n"
)

// ErrKitPassphrase means the kit is passphrase-protected and the
// passphrase is missing or wrong.
var ErrKitPassphrase = errors.New("archive: the kit is protected and the passphrase does not open it")

// ParseKit reads the private keys from a recovery kit. A protected kit is
// opened with passphrase first.
func ParseKit(data []byte, passphrase string) ([]*age.X25519Identity, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("age-encryption.org/v1")) || bytes.HasPrefix(trimmed, []byte(armor.Header)) {
		if passphrase == "" {
			return nil, ErrKitPassphrase
		}
		id, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return nil, err
		}
		var in io.Reader = bytes.NewReader(trimmed)
		if bytes.HasPrefix(trimmed, []byte(armor.Header)) {
			in = armor.NewReader(in)
		}
		pr, err := age.Decrypt(in, id)
		if err != nil {
			return nil, ErrKitPassphrase
		}
		plain, err := io.ReadAll(io.LimitReader(pr, 1<<20))
		if err != nil {
			return nil, ErrKitPassphrase
		}
		return ParseKit(plain, "")
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	var out []*age.X25519Identity
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
			continue // prose a user may have added; never echo it (it may hold key material)
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, errors.New("archive: the kit has a damaged private key line")
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, errors.New("archive: no private key found in the kit")
	}
	return out, nil
}

// Identities converts parsed kit keys for Open.
func Identities(keys []*age.X25519Identity) []age.Identity {
	out := make([]age.Identity, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

// ConfirmCode is printed in the kit and typed back into the panel to prove
// the kit was kept. It is derived from the private key, so it cannot be
// guessed from the public key, and it reveals nothing useful about the
// private key (60 bits of a hash).
func ConfirmCode(id *age.X25519Identity) string {
	sum := sha256.Sum256([]byte(confirmLabel + id.String()))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])[:12]
	return enc[0:4] + "-" + enc[4:8] + "-" + enc[8:12]
}

// NormalizeCode uppercases a typed code and drops spaces and hyphens.
func NormalizeCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CodeHash is what the panel stores to check a confirmation code later.
func CodeHash(code string) string {
	sum := sha256.Sum256([]byte(codeLabel + NormalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// KitMatches reports whether one of the kit's keys belongs to publicKey.
func KitMatches(keys []*age.X25519Identity, publicKey string) bool {
	for _, k := range keys {
		if k.Recipient().String() == publicKey {
			return true
		}
	}
	return false
}

// ProtectKit wraps a kit in age's passphrase (scrypt) format, ASCII-armored
// so it can still be printed.
func ProtectKit(kit []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, fmt.Errorf("passphrase too short")
	}
	if _, err := ParseKit(kit, ""); err != nil {
		return nil, err
	}
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(kit); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
