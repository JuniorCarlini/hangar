// Command hangar-release generates the signing key and signs releases. It
// runs in CI (sign) and once on the maintainer's machine (keygen).
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/JuniorCarlini/hangar/internal/release"
)

const usage = `Usage:
  hangar-release keygen <private-key-file>
      generates the Ed25519 pair; writes the private key (0600) and prints the public key in hex
  hangar-release sign <version> <dir>
      creates <dir>/release.json with the hash of every hangard-linux-* and
      signs it with the key in HANGAR_RELEASE_KEY (base64)
  hangar-release verify <dir>
      checks <dir>/release.json.sig with the embedded public key and the hash
      of every listed file present in <dir>; prints the version
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("missing command")
	}
	switch args[0] {
	case "keygen":
		if len(args) != 2 {
			return errors.New("keygen needs the file path")
		}
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path chosen by the maintainer on the command line
		if err != nil {
			return err
		}
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Fprintln(out, hex.EncodeToString(pub))
		return nil

	case "sign":
		if len(args) != 3 {
			return errors.New("sign needs the version and the directory")
		}
		return sign(args[1], args[2])

	case "verify":
		if len(args) != 2 {
			return errors.New("verify needs the directory")
		}
		v, err := verify(args[1])
		if err != nil {
			return err
		}
		fmt.Fprintln(out, v)
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func sign(version, dir string) error {
	if _, err := release.ParseVersion(version); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("HANGAR_RELEASE_KEY"))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return errors.New("HANGAR_RELEASE_KEY missing or invalid")
	}
	priv := ed25519.PrivateKey(raw)

	// The CI key must pair with the key embedded in the binary; otherwise the
	// release would be impossible to install.
	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != release.PublicKeyHex {
		return errors.New("the signing key does not match the embedded public key")
	}

	paths, err := filepath.Glob(filepath.Join(dir, "hangard-linux-*"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("no hangard-linux-* binary found")
	}
	sort.Strings(paths)
	m := release.Manifest{Version: version, Files: map[string]string{}}
	for _, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // path comes from the glob in the build directory
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		m.Files[filepath.Base(p)] = hex.EncodeToString(h[:])
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "release.json"), manifest, 0o644); err != nil { //nolint:gosec // public release file
		return err
	}
	return os.WriteFile(filepath.Join(dir, "release.json.sig"), []byte(release.Sign(manifest, priv)+"\n"), 0o644) //nolint:gosec // public release file
}

// verify checks a release directory the way a server does: the manifest's
// signature against the embedded public key, then the hash of every listed
// file found in dir (at least one must be there). The release workflow uses
// it on the previous release, to trust an image digest only when a signed
// binary already shipped it, and on its own output before publishing.
func verify(dir string) (string, error) {
	manifest, err := os.ReadFile(filepath.Join(dir, "release.json")) //nolint:gosec // directory named on the command line
	if err != nil {
		return "", err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "release.json.sig")) //nolint:gosec // directory named on the command line
	if err != nil {
		return "", err
	}
	m, err := release.VerifyManifest(manifest, string(sig))
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(m.Files))
	for n := range m.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	checked := 0
	for _, n := range names {
		if n != filepath.Base(n) {
			return "", fmt.Errorf("manifest lists %q outside the directory", n)
		}
		f, err := os.Open(filepath.Join(dir, n)) //nolint:gosec // name checked above
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		err = m.CheckFile(n, f)
		_ = f.Close()
		if err != nil {
			return "", err
		}
		checked++
	}
	if checked == 0 {
		return "", errors.New("none of the files in release.json is in the directory")
	}
	return m.Version, nil
}
