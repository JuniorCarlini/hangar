package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// templateCmd checks and packs service templates (docs/08). check and pack
// run in the community catalog's CI; keygen runs once, on the maintainer's
// machine.
func templateCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, tr("cli.template.usage"))
		return i18n.E("cli.missing_subcommand")
	}
	switch args[0] {
	case "check":
		return templateCheck(args[1:], stdout, stderr)
	case "pack":
		return templatePack(args[1:], stdout, stderr)
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cli.template.keygen", "public", hex.EncodeToString(pub), "private", base64.StdEncoding.EncodeToString(priv)))
		return nil
	}
	fmt.Fprint(stderr, tr("cli.template.usage"))
	return i18n.E("cli.unknown_subcommand", "command", args[0])
}

// templateCheck validates template folders with exactly the panel's rules.
// Each argument is one template folder (it has a template.toml) or a
// catalog with one folder per template. The problems are printed in
// English, with the file and key, for the template's author.
func templateCheck(dirs []string, stdout, stderr io.Writer) error {
	if len(dirs) == 0 {
		fmt.Fprint(stderr, tr("cli.template.usage"))
		return i18n.E("cli.template.no_dir")
	}
	ok, bad := 0, 0
	report := func(prefix string, err error) {
		bad++
		for _, line := range strings.Split(err.Error(), "\n") {
			fmt.Fprintf(stderr, "%s/%s\n", prefix, line)
		}
	}
	// Warnings do not fail the check: the loader adjusted something (a
	// value above a cap) and says so.
	warn := func(prefix string, t *templates.Template) {
		for _, w := range t.Warnings {
			fmt.Fprintf(stdout, "%s/%s (warning)\n", prefix, w)
		}
	}
	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		if _, err := os.Stat(filepath.Join(dir, templates.FileMeta)); err == nil { //nolint:gosec // directories named by the operator on the command line
			if t, err := templates.ParseDir(os.DirFS(filepath.Dir(dir)), filepath.Base(dir)); err != nil {
				report(dir, err)
			} else {
				warn(dir, t)
				ok++
			}
			continue
		}
		list, errs := templates.LoadEach(os.DirFS(dir), ".")
		for _, err := range errs {
			report(dir, err)
		}
		for _, t := range list {
			warn(filepath.Join(dir, t.ID), t)
		}
		ok += len(list)
		if len(list)+len(errs) == 0 {
			report(dir, errors.New("no template folders found"))
		}
	}
	if bad > 0 {
		return i18n.E("cli.template.check_failed", "bad", bad, "ok", ok)
	}
	fmt.Fprintln(stdout, tr("cli.template.check_ok", "n", ok))
	return nil
}

// templatePack builds catalog.tar.gz and its signature from a catalog
// directory; every template must be valid.
func templatePack(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("hangard template pack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", tr("cli.template.flag_key"))
	out := fs.String("out", ".", tr("cli.template.flag_out"))
	// The Unix time grows with every publication, so the CI needs no state
	// to keep the sequence monotonic.
	sequence := fs.Int64("sequence", time.Now().Unix(), tr("cli.template.flag_sequence"))
	validDays := fs.Int("valid-days", int(templates.DefaultCatalogValidity/(24*time.Hour)), tr("cli.template.flag_valid_days"))
	var dir string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if dir == "" {
		dir = fs.Arg(0)
	}
	if dir == "" {
		fmt.Fprint(stderr, tr("cli.template.usage"))
		return i18n.E("cli.template.no_dir")
	}
	raw := os.Getenv("HANGAR_CATALOG_KEY")
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile) //nolint:gosec // path chosen by the maintainer on the command line
		if err != nil {
			return err
		}
		raw = string(b)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return i18n.E("cli.template.bad_key")
	}
	priv := ed25519.PrivateKey(key)
	// Signed with a key the panels do not know, the catalog would be refused
	// everywhere: better to fail here.
	if pub := templates.CatalogPublicKeyHex; pub != "" && hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != pub {
		return i18n.E("cli.template.key_mismatch")
	}
	tarball, err := templates.Pack(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil { //nolint:gosec // public release files
		return err
	}
	tgz := filepath.Join(*out, "catalog.tar.gz")
	if err := os.WriteFile(tgz, tarball, 0o644); err != nil { //nolint:gosec // public release file
		return err
	}
	if err := os.WriteFile(tgz+".sig", []byte(templates.SignCatalog(tarball, priv)+"\n"), 0o644); err != nil { //nolint:gosec // public release file
		return err
	}
	// The metadata binds the tarball to a sequence and an expiry; panels
	// refuse a catalog without it, an older one, or an expired one.
	meta, metaSig, err := templates.SignCatalogMeta(tarball, *sequence, time.Now(), time.Duration(*validDays)*24*time.Hour, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tgz+".meta", meta, 0o644); err != nil { //nolint:gosec // public release file
		return err
	}
	if err := os.WriteFile(tgz+".meta.sig", []byte(metaSig+"\n"), 0o644); err != nil { //nolint:gosec // public release file
		return err
	}
	fmt.Fprintln(stdout, tr("cli.template.packed", "file", tgz, "bytes", len(tarball)))
	return nil
}
