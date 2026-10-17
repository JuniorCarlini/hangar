package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/JuniorCarlini/hangar/deploy"
	"github.com/JuniorCarlini/hangar/internal/app"
	"github.com/JuniorCarlini/hangar/internal/config"
	"github.com/JuniorCarlini/hangar/internal/firewall"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// unitTargets maps each embedded file to its destination.
var unitTargets = map[string]string{
	"hangard.service":         "/etc/systemd/system/hangard.service",
	"hangar-updater.service":  "/etc/systemd/system/hangar-updater.service",
	"hangar-updater.path":     "/etc/systemd/system/hangar-updater.path",
	"hangar-firewall.service": "/etc/systemd/system/hangar-firewall.service",
	"hangar-firewall.path":    "/etc/systemd/system/hangar-firewall.path",
	"journald-hangar.conf":    "/etc/systemd/journald.conf.d/hangar.conf",
}

func systemCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) >= 1 && args[0] == "firewall-apply" {
		return firewallApply(ctx, args[1:])
	}
	if len(args) != 1 || args[0] != "install-units" {
		fmt.Fprint(stderr, tr("cli.system.usage"))
		return i18n.E("cli.unknown_subcommand", "command", strings.Join(args, " "))
	}
	if os.Geteuid() != 0 {
		return i18n.E("cli.need_root")
	}
	for name, dst := range unitTargets {
		b, err := fs.ReadFile(deploy.Systemd, "systemd/"+name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // system directories
			return err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil { //nolint:gosec // units must be readable by systemd
			return err
		}
		fmt.Fprintln(stdout, tr("cli.system.written", "path", dst))
	}
	// The firewall unit is new in v0.5.0: an update must turn it on, not only
	// write it.
	for _, cmd := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "restart", "systemd-journald"},
		{"systemctl", "enable", "--now", "hangar-firewall.path"},
		{"systemctl", "enable", "hangar-firewall.service"},
	} {
		if out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput(); err != nil { //nolint:gosec // fixed commands
			return fmt.Errorf("%v: %w: %s", cmd, err, out)
		}
	}
	return nil
}

// firewallApply loads the port restrictions written by the panel (root,
// started by hangar-firewall.service).
func firewallApply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("firewall-apply", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/hangar/hangar.toml", tr("cli.flag_config"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return i18n.E("cli.need_root")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	return firewall.Apply(ctx, app.FirewallDir(cfg))
}
