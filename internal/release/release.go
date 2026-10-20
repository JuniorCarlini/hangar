// Package release describes and verifies Hangar's published versions.
//
// Each release carries a manifest (release.json) with the version and the
// SHA-256 of every binary, signed with Ed25519 (release.json.sig). The public
// key is embedded in the binary; the private key exists only as a CI secret.
// Nothing is installed unless manifest, signature and hash all check out
// (docs/21).
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// PublicKeyHex is the release public key. Test builds may override it with
// -ldflags "-X github.com/JuniorCarlini/hangar/internal/release.PublicKeyHex=...";
// the release workflow never does.
var PublicKeyHex = "3c84b55c17438e93d4fd0a11dde9e88de3d00cf2bab5fad52589b841c6d49121"

// Manifest is the signed content of a release.
type Manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"` // file name -> hex sha256
}

// Verification errors.
var (
	ErrBadSignature = &i18n.Error{Key: "release.error.bad_signature"}
	ErrNotNewer     = &i18n.Error{Key: "release.error.not_newer"}
)

// AssetName is the binary name for the architecture.
func AssetName(goarch string) string { return "hangard-linux-" + goarch }

// Sign signs the manifest (used only by the release CI).
func Sign(manifest []byte, priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest))
}

// VerifyManifest checks the signature with the embedded key and parses the
// manifest.
func VerifyManifest(manifest []byte, sigB64 string) (Manifest, error) {
	pub, err := publicKey()
	if err != nil {
		return Manifest{}, err
	}
	return verifyWith(pub, manifest, sigB64)
}

func verifyWith(pub ed25519.PublicKey, manifest []byte, sigB64 string) (Manifest, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Manifest{}, ErrBadSignature
	}
	if !ed25519.Verify(pub, manifest, sig) {
		return Manifest{}, ErrBadSignature
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(manifest)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("invalid manifest: %w", err)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return Manifest{}, err
	}
	for name, sum := range m.Files {
		if b, err := hex.DecodeString(sum); err != nil || len(b) != sha256.Size {
			return Manifest{}, fmt.Errorf("manifest: invalid hash for %s", name)
		}
	}
	return m, nil
}

func publicKey() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(PublicKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid release public key in the binary")
	}
	return ed25519.PublicKey(b), nil
}

// CheckFile checks the SHA-256 of the content read from r against the
// manifest.
func (m Manifest) CheckFile(name string, r io.Reader) error {
	want, ok := m.Files[name]
	if !ok {
		return i18n.E("release.error.not_in_manifest", "file", name)
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return i18n.E("release.error.hash_mismatch", "file", name)
	}
	return nil
}

// Version is a semantic version vMAJOR.MINOR.PATCH.
type Version struct{ Major, Minor, Patch int }

var versionRE = regexp.MustCompile(`^v(\d{1,6})\.(\d{1,6})\.(\d{1,6})$`)

// ParseVersion accepts only vX.Y.Z (no pre-release: only stable versions can
// be installed by the button).
func ParseVersion(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, i18n.E("release.error.bad_version", "version", s)
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	return v, nil
}

// Newer reports whether v is newer than o.
func (v Version) Newer(o Version) bool {
	if v.Major != o.Major {
		return v.Major > o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor > o.Minor
	}
	return v.Patch > o.Patch
}

func (v Version) String() string { return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch) }

// describeRE is a build made after a release tag, as `git describe` names
// it: v0.5.13-1-gc34d8c1, optionally -dirty.
var describeRE = regexp.MustCompile(`^(v\d{1,6}\.\d{1,6}\.\d{1,6})-\d+-g[0-9a-f]{4,40}(-dirty)?$`)

// IsUpgrade reports whether candidate is a valid upgrade over current. A
// build made after a tag is ahead of that tag, so only a newer release
// upgrades it; any other development build ("dev", a bare commit) accepts
// any stable version.
func IsUpgrade(current, candidate string) (bool, error) {
	cand, err := ParseVersion(candidate)
	if err != nil {
		return false, err
	}
	if m := describeRE.FindStringSubmatch(current); m != nil {
		current = m[1]
	}
	cur, err := ParseVersion(current)
	if err != nil {
		return true, nil
	}
	return cand.Newer(cur), nil
}
