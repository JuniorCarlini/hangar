package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/JuniorCarlini/hangar/internal/app"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/update"
)

func selfUpdateCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, tr("cli.selfupdate.usage"))
		return i18n.E("cli.missing_subcommand")
	}
	cfg, err := loadConfig(args[1:], stderr)
	if err != nil {
		return err
	}

	switch args[0] {
	case "check", "stage":
		checker, err := app.NewChecker(cfg, version)
		if err != nil {
			return err
		}
		av, err := checker.Check(ctx)
		if err != nil {
			return err
		}
		if av == nil {
			fmt.Fprintln(stdout, tr("cli.selfupdate.up_to_date", "version", version))
			return nil
		}
		fmt.Fprintln(stdout, tr("cli.selfupdate.available", "version", av.Version, "installed", version))
		if args[0] == "check" {
			return nil
		}
		if err := checker.Stage(ctx, av.Version, "cli"); err != nil {
			return err
		}
		fmt.Fprintln(stdout, tr("cli.selfupdate.staged"))
		return nil

	case "apply":
		if os.Geteuid() != 0 {
			return i18n.E("cli.selfupdate.need_root")
		}
		a := &update.Applier{
			DataDir:    cfg.DataDir,
			BinaryPath: cfg.Update.BinaryPath,
			Service:    update.Systemd{Unit: cfg.Update.Service + ".service"},
			ReadyWait:  90 * time.Second,
			ConfigPath: configPath(args[1:]),
		}
		st, err := a.Apply(ctx)
		if st == nil && err == nil {
			fmt.Fprintln(stdout, tr("cli.selfupdate.nothing_pending"))
			return nil
		}
		if err != nil {
			return fmt.Errorf("update %s: %w", st.State, err)
		}
		fmt.Fprintln(stdout, tr("cli.selfupdate.applied", "from", st.From, "to", st.Version))
		return nil
	}
	fmt.Fprint(stderr, tr("cli.selfupdate.usage"))
	return i18n.E("cli.unknown_subcommand", "command", args[0])
}
