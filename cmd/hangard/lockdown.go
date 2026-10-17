package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/JuniorCarlini/hangar/internal/app"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// lockdownCmd is the panic button from the server (docs/17 § 1.6):
// "hangard lockdown" locks, "hangard lockdown off" is the only way to
// unlock, "hangard lockdown status" tells which.
func lockdownCmd(ctx context.Context, args []string, stdout, stderr io.Writer, log *slog.Logger) error {
	action := "on"
	if len(args) > 0 && (args[0] == "on" || args[0] == "off" || args[0] == "status") {
		action, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("hangard lockdown", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/hangar/hangar.toml", tr("cli.flag_config"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fmt.Fprint(stderr, tr("cli.lockdown.usage"))
		return i18n.E("cli.unknown_subcommand", "command", fs.Arg(0))
	}
	cfg, err := loadConfigFile(*cfgPath)
	if err != nil {
		return err
	}
	core, err := app.Open(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = core.Close() }()

	switch action {
	case "on":
		n, err := core.Lock.Engage(ctx, "", "", "cli")
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cli.lockdown.locked", "n", n))
	case "off":
		if err := core.Lock.Release(ctx, "cli"); err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cli.lockdown.unlocked"))
	default:
		st, err := core.Lock.State(ctx)
		if err != nil {
			return err
		}
		if st.Locked {
			fmt.Fprintln(stdout, tr("cli.lockdown.status_locked", "time", time.Unix(st.At, 0).Format("02/01/2006 15:04")))
		} else {
			fmt.Fprintln(stdout, tr("cli.lockdown.status_unlocked"))
		}
	}
	return nil
}
