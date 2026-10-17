package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 uses HMAC-SHA1; it is what every authenticator app implements
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP follows RFC 6238: 30 s step, 6 digits, HMAC-SHA1. It is what Google
// Authenticator, Authy, 1Password and Bitwarden accept.
const (
	totpStep   = 30
	totpDigits = 6
	// totpSkew accepts one step before and one after, for slightly skewed
	// clocks.
	totpSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret generates a 160-bit secret in base32, as apps expect.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// TOTPURI builds the otpauth:// URI that becomes a QR code in the app.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpStep))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// totpCode computes the code for one step.
func totpCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // step is always positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, bin%1_000_000), nil
}

// matchTOTP looks for the code in the window around now and returns the step
// that matched. Callers must make sure that step is newer than the last one
// accepted (replay protection).
func matchTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	current := now.Unix() / totpStep
	matched, found := int64(0), false
	// Always walk the whole window so response time does not reveal which step
	// matched.
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		want, err := totpCode(secret, current+d)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && !found {
			matched, found = current+d, true
		}
	}
	return matched, found
}

// TOTPCode computes the code valid at instant t (used by tests and CLI
// diagnostics).
func TOTPCode(secret string, t time.Time) (string, error) {
	return totpCode(secret, t.Unix()/totpStep)
}
