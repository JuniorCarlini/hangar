package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/app"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/cofre"
	"github.com/JuniorCarlini/hangar/internal/config"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/update"
)

// restoreCmd is disaster recovery (docs/09): on a new server, bring the
// panel back from the bucket with the recovery kit, then the databases.
//
//	hangard restore -cofre cofre.toml            panel, config, master key, certificates
//	hangard restore databases -cofre cofre.toml  every PostgreSQL to the last minute, then the services
func restoreCmd(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, log *slog.Logger) error {
	databases := len(args) > 0 && args[0] == "databases"
	if databases {
		args = args[1:]
	}
	fs := flag.NewFlagSet("hangard restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "/etc/hangar/hangar.toml", tr("cli.flag_config"))
	cofrePath := fs.String("cofre", "", tr("cli.restore.flag_cofre"))
	endpoint := fs.String("endpoint", "", tr("cli.restore.flag_endpoint"))
	bucket := fs.String("bucket", "", tr("cli.restore.flag_bucket"))
	region := fs.String("region", "", tr("cli.restore.flag_region"))
	prefix := fs.String("prefix", "", tr("cli.restore.flag_prefix"))
	pathStyle := fs.Bool("path-style", true, tr("cli.restore.flag_path_style"))
	identity := fs.String("identity", "", tr("cli.restore.flag_identity"))
	at := fs.String("at", "", tr("cli.restore.flag_at"))
	force := fs.Bool("force", false, tr("cli.restore.flag_force"))
	unverified := fs.Bool("allow-unverified", false, tr("cli.restore.flag_unverified"))
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfigFile(*cfgPath)
	if err != nil {
		return err
	}
	src := cofre.Config{}
	if *cofrePath != "" {
		if src, err = cofre.LoadConfig(*cofrePath); err != nil {
			return err
		}
	}
	src.Endpoint = firstSet(*endpoint, src.Endpoint)
	src.Bucket = firstSet(*bucket, src.Bucket)
	src.Region = firstSet(*region, src.Region)
	src.Prefix = firstSet(*prefix, src.Prefix)
	src.Identity = firstSet(*identity, src.Identity)
	if *endpoint != "" {
		src.PathStyle = *pathStyle
	}
	if v := os.Getenv("HANGAR_RESTORE_ACCESS_KEY"); v != "" {
		src.AccessKey = v
	}
	if v := os.Getenv("HANGAR_RESTORE_SECRET_KEY"); v != "" {
		src.SecretKey = v
	}
	var when time.Time
	if *at != "" {
		if when, err = time.ParseInLocation("2006-01-02 15:04", *at, time.Local); err != nil {
			return i18n.E("cli.restore.at", "value", *at)
		}
		when = when.Add(59 * time.Second)
	}
	ids, err := restoreKit(src.Identity, stdin, stderr)
	if err != nil {
		return err
	}
	if databases {
		return restoreDatabases(ctx, cfg, ids, when, backup.RecoverOptions{AllowUnverified: *unverified}, stdout, log)
	}

	if _, err := os.Stat(filepath.Join(cfg.DataDir, update.ReadyFile)); err == nil {
		return i18n.E("cli.restore.panel_running")
	}
	if src.Endpoint == "" || src.Bucket == "" || src.AccessKey == "" || src.SecretKey == "" {
		return i18n.E("cli.restore.no_bucket")
	}
	b, err := cofre.NewBucket(src)
	if err != nil {
		return err
	}
	res, err := backup.RestorePanel(ctx, b, ids, when, backup.PanelRestoreOptions{
		DataDir: cfg.DataDir, MasterKeyFile: cfg.MasterKeyFile, ConfigFile: cfg.Path, Force: *force,
	})
	if errors.Is(err, backup.ErrPanelExists) {
		return i18n.E("cli.restore.exists")
	}
	if err != nil {
		return err
	}
	// Run as root (the master key lives in a root-owned directory), the
	// restored files must still belong to the panel's user.
	if os.Geteuid() == 0 {
		chownLike(cfg.DataDir, filepath.Join(cfg.DataDir, backup.PanelDB), cfg.MasterKeyFile, res.ConfigCopy, filepath.Join(cfg.DataDir, "edge"))
	}
	fmt.Fprintln(stdout, tr("cli.restore.done", "key", res.Key, "when", res.Manifest.CreatedAt.Local().Format("02/01/2006 15:04"), "version", res.Manifest.Version))
	for _, p := range res.Aside {
		fmt.Fprintln(stdout, tr("cli.restore.aside", "path", p))
	}
	if res.ConfigCopy != "" {
		fmt.Fprintln(stdout, tr("cli.restore.config_copy", "path", res.ConfigCopy))
	}
	fmt.Fprint(stdout, tr("cli.restore.next"))
	return nil
}

func firstSet(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func restoreKit(path string, stdin io.Reader, stderr io.Writer) ([]age.Identity, error) {
	if path == "" {
		return nil, i18n.E("cli.restore.no_identity")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's kit, named on the command line
	if err != nil {
		return nil, i18n.E("cli.restore.read_kit", "error", err)
	}
	keys, err := archive.ParseKit(raw, "")
	if errors.Is(err, archive.ErrKitPassphrase) {
		pass := os.Getenv("HANGAR_KIT_PASSPHRASE")
		if pass == "" {
			fmt.Fprint(stderr, tr("cli.restore.passphrase"))
			pass, err = readLine(stdin)
			if err != nil {
				return nil, err
			}
		}
		keys, err = archive.ParseKit(raw, pass)
	}
	if err != nil {
		return nil, i18n.E("cli.restore.kit", "error", err)
	}
	return archive.Identities(keys), nil
}

func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// chownLike gives files the owner of ref (the data directory).
func chownLike(ref string, paths ...string) {
	info, err := os.Stat(ref)
	if err != nil {
		return
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		_ = filepath.Walk(p, func(path string, _ os.FileInfo, err error) error {
			if err == nil {
				_ = os.Lchown(path, int(st.Uid), int(st.Gid)) //nolint:gosec // our own freshly restored files, Lchown never follows links
			}
			return nil
		})
	}
}

// restoreDatabases runs RecoverAll with the restored panel database: the
// destinations and their credentials come back with it.
func restoreDatabases(ctx context.Context, cfg config.Config, ids []age.Identity, at time.Time, opt backup.RecoverOptions, stdout io.Writer, log *slog.Logger) error {
	if _, err := os.Stat(filepath.Join(cfg.DataDir, update.ReadyFile)); err == nil {
		return i18n.E("cli.restore.panel_running")
	}
	core, err := app.Open(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = core.Close() }()
	d, err := app.ConnectDocker(ctx, core, cfg.Docker.Host)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	pm := projects.New(core.Store.DB, core.Box, d, core.Audit, log)
	defer pm.Wait()
	bm, err := app.NewBackups(core, pm, cfg, version, log)
	if err != nil {
		return err
	}
	err = bm.RecoverAll(ctx, ids, at, func(key string, args ...any) { fmt.Fprintln(stdout, tr(key, args...)) }, opt)
	if err != nil {
		return i18n.E("cli.restore.databases_failed", "error", err)
	}
	fmt.Fprintln(stdout, tr("cli.restore.databases_done"))
	return nil
}
