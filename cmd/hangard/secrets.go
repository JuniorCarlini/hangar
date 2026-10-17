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
	"path/filepath"

	"github.com/JuniorCarlini/hangar/internal/app"
	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/update"
)

// secretsCmd: "hangard secrets rotate-key" re-encrypts every secret in the
// database with a new master key (docs/24). It runs as the hangar user with
// the panel stopped; the new key is written to data_dir (the hangar user
// cannot write /etc/hangar) and root moves it into place.
func secretsCmd(ctx context.Context, args []string, stdout, stderr io.Writer, log *slog.Logger) error {
	if len(args) == 0 || args[0] != "rotate-key" {
		fmt.Fprint(stderr, tr("cli.secrets.usage"))
		return i18n.E("cli.missing_subcommand")
	}
	fl := flag.NewFlagSet("hangard secrets rotate-key", flag.ContinueOnError)
	fl.SetOutput(stderr)
	cfgPath := fl.String("config", "/etc/hangar/hangar.toml", tr("cli.flag_config"))
	out := fl.String("out", "", tr("cli.secrets.flag_out"))
	if err := fl.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := loadConfigFile(*cfgPath)
	if err != nil {
		return err
	}
	// A running panel keeps the old key in memory and would stop reading
	// every secret the moment the database changes.
	if _, err := os.Stat(filepath.Join(cfg.DataDir, update.ReadyFile)); err == nil {
		return i18n.E("cli.secrets.panel_running")
	}
	if *out == "" {
		*out = filepath.Join(cfg.DataDir, "master.key.new")
	}
	if _, err := os.Stat(*out); !errors.Is(err, fs.ErrNotExist) {
		return i18n.E("cli.secrets.out_exists", "path", *out)
	}
	core, err := app.Open(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = core.Close() }()

	// The new key is on disk (synced) before the database changes: if the
	// command dies after the commit, the right key is still there.
	newBox, err := secrets.NewKeyFile(*out)
	if err != nil {
		return err
	}
	n, err := secrets.Rotate(ctx, core.Store.DB, core.Box, newBox)
	if err != nil {
		_ = os.Remove(*out)
		return err
	}
	_ = core.Audit.Record(ctx, audit.Entry{
		Action: "system.master_key.rotate", Outcome: audit.OK,
		Summary: map[string]any{"values": n, "via": "cli"},
	})
	fmt.Fprintln(stdout, tr("cli.secrets.rotated", "n", n, "out", *out, "key", cfg.MasterKeyFile))
	return nil
}
