package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// MinPasswordLen is the minimum password length (docs/04).
const MinPasswordLen = 14

// Argon2Params are the argon2id costs. The defaults follow the current OWASP
// recommendation with headroom; tests use smaller values.
type Argon2Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
}

// DefaultArgon2 costs ~64 MiB and a few hundred ms per verification.
var DefaultArgon2 = Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 2}

const (
	saltLen = 16
	hashLen = 32
)

// CheckPasswordStrength applies the minimum password rules.
func CheckPasswordStrength(password, email string) error {
	n := utf8.RuneCountInString(password)
	switch {
	case n < MinPasswordLen:
		return i18n.E("password.too_short", "min", MinPasswordLen)
	case n > 256:
		return i18n.E("password.too_long", "max", 256)
	case strings.EqualFold(password, email):
		return i18n.E("password.same_as_email")
	case distinctRunes(password) < 6:
		return i18n.E("password.low_variety")
	case isCommonPassword(password):
		return i18n.E("password.common")
	}
	return nil
}

func distinctRunes(s string) int {
	seen := map[rune]struct{}{}
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}

// HashPassword produces the argon2id hash in PHC format
// ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
func HashPassword(password string, p Argon2Params) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, hashLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// VerifyPassword compares in constant time. The parameters come from the
// hash itself, so raising the cost later does not invalidate old passwords.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return false, errBadHash
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want))) //nolint:gosec // small, positive len
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// commonPasswords is a short list of the most leaked long passwords. The full
// check against breach databases (k-anonymity) comes once the panel has
// internet egress configured; this list covers the obvious offline.
var commonPasswords = map[string]struct{}{
	"senha123456789":            {},
	"12345678901234":            {},
	"123456789012345":           {},
	"1234567890123456":          {},
	"qwertyuiopasdfgh":          {},
	"passwordpassword":          {},
	"senhasenhasenha":           {},
	"administrador123":          {},
	"administrator123":          {},
	"iloveyouiloveyou":          {},
	"abcdefghijklmnop":          {},
	"qwertyqwertyqwerty":        {},
	"correcthorsebatterystaple": {},
}

func isCommonPassword(p string) bool {
	_, ok := commonPasswords[strings.ToLower(p)]
	return ok
}
