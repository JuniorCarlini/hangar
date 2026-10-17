// Package ids generates random identifiers with a type prefix ("prj_",
// "svc_"...), readable in logs and the audit trail.
package ids

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// New returns prefix + 96 random bits in lowercase base32.
func New(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // without entropy there is no safe way forward
	}
	return prefix + strings.ToLower(enc.EncodeToString(b))
}
