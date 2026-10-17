// Command hangar-cofre is the operator's backup tool (docs/09): it runs on
// your computer, with a read-only bucket credential and the recovery kit,
// and works even when the server is gone.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/cofre"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// version is set at build time.
var version = "dev"

var loc = i18n.FromEnv(os.Getenv)

func tr(key string, args ...any) string { return i18n.Tl(loc, key, args...) }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, tr("cli.error_prefix"), i18n.Message(loc, err))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if err := i18n.Init(); err != nil {
		return err
	}
	if f, ok := stdin.(*os.File); !ok || !term.IsTerminal(int(f.Fd())) { //nolint:gosec // a file descriptor fits an int
		stdin = bufio.NewReader(stdin) // one reader for every prompt
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, tr("cofre.usage"))
		return i18n.E("cli.missing_command")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, tr("cofre.usage"))
		return nil
	case "init":
		return initCmd(rest, stdout, stderr)
	case "kit":
		return kitCmd(rest, stdin, stdout, stderr)
	case "decrypt":
		return decryptCmd(rest, stdin, stdout, stderr)
	case "sync", "list", "restore-local", "test":
		return vaultCmd(ctx, cmd, rest, stdin, stdout, stderr)
	case "setup-bucket":
		return setupBucketCmd(ctx, rest, stdout, stderr)
	}
	fmt.Fprint(stderr, tr("cofre.usage"))
	return i18n.E("cli.unknown_command", "command", cmd)
}

// common flags of the commands that talk to the bucket.
type common struct {
	config   *string
	identity *string
	from     *string
}

func commonFlags(fs *flag.FlagSet) common {
	return common{
		config:   fs.String("config", cofre.DefaultConfigPath(), tr("cofre.flag_config")),
		identity: fs.String("identity", "", tr("cofre.flag_identity")),
		from:     fs.String("from", "", tr("cofre.flag_from")),
	}
}

func initCmd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", cofre.DefaultConfigPath(), tr("cofre.flag_config"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return i18n.E("cofre.error.config_exists", "path", *path)
	}
	_, werr := io.WriteString(f, cofre.ExampleConfig)
	if err := f.Close(); werr == nil {
		werr = err
	}
	if werr != nil {
		return werr
	}
	fmt.Fprintln(stdout, tr("cofre.init_done", "path", *path))
	return nil
}

// readSecret asks for a passphrase without echo (or reads a line when
// stdin is not a terminal).
func readSecret(stdin io.Reader, stderr io.Writer, prompt string) (string, error) {
	if v := os.Getenv("HANGAR_COFRE_PASSPHRASE"); v != "" {
		return v, nil
	}
	fmt.Fprint(stderr, prompt)
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // a file descriptor fits an int
		b, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // as above
		fmt.Fprintln(stderr)
		return string(b), err
	}
	br, ok := stdin.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(stdin)
	}
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// loadKit reads the recovery kit, asking for the passphrase when it is
// protected.
func loadKit(path string, stdin io.Reader, stderr io.Writer) ([]*age.X25519Identity, error) {
	if path == "" {
		return nil, i18n.E("cofre.error.no_identity")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's own kit
	if err != nil {
		return nil, i18n.E("cofre.error.read_kit", "path", path, "error", err)
	}
	keys, err := archive.ParseKit(raw, "")
	if errors.Is(err, archive.ErrKitPassphrase) {
		pass, perr := readSecret(stdin, stderr, tr("cofre.passphrase_prompt"))
		if perr != nil {
			return nil, perr
		}
		keys, err = archive.ParseKit(raw, pass)
	}
	if errors.Is(err, archive.ErrKitPassphrase) {
		return nil, i18n.E("cofre.error.passphrase")
	}
	if err != nil {
		return nil, i18n.E("cofre.error.kit", "error", err)
	}
	return keys, nil
}

func kitCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 2 || (args[0] != "protect" && args[0] != "check") {
		fmt.Fprint(stderr, tr("cofre.usage"))
		return i18n.E("cofre.error.kit_usage")
	}
	path := args[1]
	keys, err := loadKit(path, stdin, stderr)
	if err != nil {
		return err
	}
	if args[0] == "check" {
		for _, k := range keys {
			fmt.Fprintln(stdout, tr("cofre.kit_key", "public", k.Recipient().String(), "code", archive.ConfirmCode(k)))
		}
		return nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's own kit
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "-----BEGIN AGE") {
		return i18n.E("cofre.error.already_protected")
	}
	pass, err := readSecret(stdin, stderr, tr("cofre.new_passphrase_prompt"))
	if err != nil {
		return err
	}
	again, err := readSecret(stdin, stderr, tr("cofre.repeat_passphrase_prompt"))
	if err != nil {
		return err
	}
	if pass != again {
		return i18n.E("cofre.error.passphrase_mismatch")
	}
	if len(pass) < 12 {
		return i18n.E("cofre.error.passphrase_short")
	}
	out, err := archive.ProtectKit(raw, pass)
	if err != nil {
		return err
	}
	dest := path + ".protegido"
	if err := os.WriteFile(dest, out, 0o600); err != nil { //nolint:gosec // next to the kit the operator named
		return err
	}
	fmt.Fprintln(stdout, tr("cofre.kit_protected", "path", dest))
	return nil
}

func decryptCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := commonFlags(fs)
	out := fs.String("o", "", tr("cofre.flag_out"))
	file, flagArgs := splitFirst(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if file == "" {
		file = fs.Arg(0)
	}
	if file == "" {
		return i18n.E("cofre.error.decrypt_usage")
	}
	cfg, err := cofre.LoadConfig(*c.config)
	if err != nil {
		return err
	}
	kitPath := firstNonEmpty(*c.identity, cfg.Identity)
	keys, err := loadKit(kitPath, stdin, stderr)
	if err != nil {
		return err
	}
	v := cofre.New(nil, archive.Identities(keys))
	dest := *out
	if dest == "" {
		dest = cofre.DecryptedName(file)
	}
	n, err := v.DecryptFile(file, dest)
	if errors.Is(err, archive.ErrWrongKey) {
		return i18n.E("cofre.error.wrong_key")
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, tr("cofre.decrypted", "path", dest, "size", humanBytes(n)))
	return nil
}

// splitFirst lets the file come before or after the flags.
func splitFirst(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func vaultCmd(ctx context.Context, cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := commonFlags(fs)
	at := fs.String("at", "", tr("cofre.flag_at"))
	dump := fs.Bool("dump", false, tr("cofre.flag_dump"))
	port := fs.Int("port", 54329, tr("cofre.flag_port"))
	positional, flagArgs := splitFirst(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if positional == "" {
		positional = fs.Arg(0)
	}
	cfg, err := cofre.LoadConfig(*c.config)
	if err != nil {
		return err
	}
	var src cofre.Source
	var bucket *cofre.Bucket
	if *c.from != "" && cmd != "sync" {
		src = cofre.Dir{Root: *c.from}
	} else {
		if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
			return i18n.E("cofre.error.no_bucket", "path", *c.config)
		}
		if bucket, err = cofre.NewBucket(cfg); err != nil {
			return err
		}
		src = bucket
	}
	v := cofre.New(src, nil)
	v.Progress = func(key string, args ...any) { fmt.Fprintln(stderr, tr(key, args...)) }
	switch cmd {
	case "sync":
		if positional == "" {
			return i18n.E("cofre.error.sync_usage")
		}
		st, err := v.Sync(ctx, bucket, positional)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cofre.synced", "new", st.New, "skipped", st.Skipped, "size", humanBytes(st.Bytes), "dir", positional))
		return nil
	case "list":
		entries, err := v.List(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Fprintln(stdout, tr("cofre.list_empty"))
		}
		for _, e := range entries {
			line := tr("cofre.list_dumps", "label", e.Label, "n", e.Dumps, "latest", fmtTime(e.Latest))
			if !e.WALFrom.IsZero() {
				line += " · " + tr("cofre.list_wal", "from", fmtTime(e.WALFrom), "to", fmtTime(e.WALTo))
			}
			fmt.Fprintln(stdout, line)
		}
		return nil
	}

	keys, err := loadKit(firstNonEmpty(*c.identity, cfg.Identity), stdin, stderr)
	if err != nil {
		return err
	}
	v.SetIdentities(archive.Identities(keys))
	switch cmd {
	case "restore-local":
		if positional == "" {
			return i18n.E("cofre.error.restore_usage")
		}
		project, service, err := cofre.ParseService(positional)
		if err != nil {
			return i18n.E("cofre.error.restore_usage")
		}
		opt := cofre.RestoreOptions{Project: project, Service: service, Dump: *dump, Port: *port}
		if *at != "" {
			if opt.At, err = parseAt(*at); err != nil {
				return i18n.E("cofre.error.at", "value", *at)
			}
		}
		r, err := v.RestoreLocal(ctx, opt)
		if err != nil {
			v.Remove(ctx, r)
			return err
		}
		if r.Mode == "pitr" {
			if r.ToEnd {
				fmt.Fprintln(stdout, tr("cofre.restored_end", "label", positional))
			} else {
				fmt.Fprintln(stdout, tr("cofre.restored_at", "label", positional, "at", r.Target.Local().Format("02/01/2006 15:04:05")))
			}
		} else {
			fmt.Fprintln(stdout, tr("cofre.restored_dump", "label", positional, "key", r.Key))
		}
		fmt.Fprintln(stdout, tr("cofre.restored_connect", "container", r.Container, "user", r.User, "db", r.DB, "port", r.Port))
		if r.Password != "" {
			fmt.Fprintln(stdout, tr("cofre.restored_password", "password", r.Password))
		}
		fmt.Fprintln(stdout, tr("cofre.restored_cleanup", "container", r.Container, "volume", r.Volume))
		return nil
	case "test":
		results, err := v.Test(ctx, positional)
		if err != nil {
			return err
		}
		failed := 0
		for _, r := range results {
			if r.OK {
				if r.Label == "painel" {
					fmt.Fprintln(stdout, tr("cofre.test_panel_ok", "key", r.Key, "took", r.Took.Round(time.Second)))
				} else {
					fmt.Fprintln(stdout, tr("cofre.test_ok", "label", r.Label, "tables", r.Tables, "rows", r.Rows, "took", r.Took.Round(time.Second)))
				}
				continue
			}
			failed++
			fmt.Fprintln(stdout, tr("cofre.test_failed", "label", r.Label, "error", r.Err))
		}
		if failed > 0 {
			return i18n.E("cofre.error.test_failed", "n", failed)
		}
		fmt.Fprintln(stdout, tr("cofre.test_all_ok"))
		return nil
	}
	return nil
}

// parseAt reads "2026-10-15 14:32" (local time) or RFC 3339.
func parseAt(v string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04", "2006-01-02 15:04:05", "02/01/2006 15:04"} {
		if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			if layout != "2006-01-02 15:04:05" {
				t = t.Add(59 * time.Second) // the whole minute
			}
			return t, nil
		}
	}
	return time.Parse(time.RFC3339, v)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("02/01/2006 15:04")
}

func humanBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// setupBucketCmd applies the lifecycle rules with an administrator
// credential given only through the environment.
func setupBucketCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("setup-bucket", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", cofre.DefaultConfigPath(), tr("cofre.flag_config"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := cofre.LoadConfig(*path)
	if err != nil {
		return err
	}
	ak, sk := os.Getenv("HANGAR_COFRE_ADMIN_ACCESS_KEY"), os.Getenv("HANGAR_COFRE_ADMIN_SECRET_KEY")
	if ak == "" || sk == "" || cfg.Endpoint == "" || cfg.Bucket == "" {
		return i18n.E("cofre.error.admin_credentials")
	}
	admin, err := s3.New(s3.Config{Endpoint: cfg.Endpoint, Region: cfg.Region, Bucket: cfg.Bucket, AccessKey: ak, SecretKey: sk, PathStyle: cfg.PathStyle}, nil)
	if err != nil {
		return err
	}
	rules, err := cofre.SetupBucket(ctx, admin, cfg.Prefix)
	if err != nil {
		return i18n.E("cofre.error.setup", "error", err)
	}
	for _, r := range rules {
		fmt.Fprintln(stdout, tr("cofre.rule", "prefix", r.Prefix, "days", r.Days))
	}
	fmt.Fprintln(stdout, tr("cofre.setup_done"))
	return nil
}
