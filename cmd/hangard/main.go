// Command hangard is the Hangar panel: a single binary running as a systemd
// service on the server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/JuniorCarlini/hangar/internal/app"
	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/config"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/secrets"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// edgeImage is the edge Caddy image baked at build time (the release's
// hangar-caddy, pinned by digest): -ldflags "-X main.edgeImage=...". It becomes
// the default when [edge] image is not set. Empty in dev builds, which fall
// back to the stock Caddy and cannot do DNS-01 until a custom image is built.
var edgeImage string

func init() {
	if edgeImage != "" {
		config.DefaultEdgeImage = edgeImage
	}
}

// loc is the CLI language, from LC_ALL/LC_MESSAGES/LANG (docs/22).
var loc = i18n.FromEnv(os.Getenv)

// tr translates a CLI message.
func tr(key string, args ...any) string { return i18n.Tl(loc, key, args...) }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, tr("cli.error_prefix"), i18n.Message(loc, err))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, tr("cli.usage"))
		return i18n.E("cli.missing_command")
	}

	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return nil

	case "serve":
		cfg, err := loadConfig(args[1:], stderr)
		if err != nil {
			return err
		}
		return app.Serve(ctx, cfg, version, log)

	case "system":
		return systemCmd(ctx, args[1:], stdout, stderr)

	case "self-update":
		return selfUpdateCmd(ctx, args[1:], stdout, stderr)

	case "user":
		return userCmd(ctx, args[1:], stdout, stderr, log)

	case "lockdown":
		return lockdownCmd(ctx, args[1:], stdout, stderr, log)
	case "secrets":
		return secretsCmd(ctx, args[1:], stdout, stderr, log)
	case "template":
		return templateCmd(args[1:], stdout, stderr)
	case "restore":
		return restoreCmd(ctx, args[1:], os.Stdin, stdout, stderr, log)

	case "audit":
		if len(args) < 2 || args[1] != "verify" {
			fmt.Fprint(stderr, tr("cli.usage"))
			return i18n.E("cli.audit_usage")
		}
		cfg, err := loadConfig(args[2:], stderr)
		if err != nil {
			return err
		}
		st, err := app.OpenStore(ctx, cfg, log)
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()
		// The chain is keyed by the master key (SEC-010). Only read it when
		// it exists: verifying must never create a new key.
		var box *secrets.Box
		if _, err := os.Stat(cfg.MasterKeyFile); err == nil {
			if box, err = secrets.LoadOrCreateKey(cfg.MasterKeyFile); err != nil {
				return err
			}
		}
		n, err := audit.Verify(ctx, st.Q, box)
		var te *audit.TamperError
		if errors.As(err, &te) {
			return i18n.E("cli.audit_tampered", "id", te.ID, "reason", tr("audit.tamper."+te.Reason))
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cli.audit_ok", "n", n))
		return nil

	case "help", "-h", "--help":
		fmt.Fprint(stdout, tr("cli.usage"))
		return nil
	}

	fmt.Fprint(stderr, tr("cli.usage"))
	return i18n.E("cli.unknown_command", "command", args[0])
}

func loadConfig(args []string, stderr io.Writer) (config.Config, error) {
	fs := flag.NewFlagSet("hangard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "/etc/hangar/hangar.toml", tr("cli.flag_config"))
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	return loadConfigFile(*path)
}

func loadConfigFile(path string) (config.Config, error) {
	// A config the service cannot read is almost always a manual edit that
	// left it root:root; the next start fixes it (ExecStartPre), and the
	// message says how to fix it by hand meanwhile.
	if f, err := os.Open(path); errors.Is(err, fs.ErrPermission) { //nolint:gosec // the operator's config path
		return config.Config{}, i18n.E("cli.config_permission", "path", path, "error", err.Error())
	} else if err == nil {
		_ = f.Close()
	}
	return config.Load(path)
}

// configPath reads -config from args without loading the file.
func configPath(args []string) string {
	fs := flag.NewFlagSet("hangard", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "/etc/hangar/hangar.toml", "")
	_ = fs.Parse(args)
	return *path
}
