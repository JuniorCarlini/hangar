package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/config"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/update"
)

// UpdateDir is where the panel and the applier exchange request and result.
func UpdateDir(cfg config.Config) string { return filepath.Join(cfg.DataDir, "update") }

// FirewallDir holds the port rules the panel writes and the root unit applies.
func FirewallDir(cfg config.Config) string { return filepath.Join(cfg.DataDir, "firewall") }

// NewChecker creates the version checker with the token (if any).
func NewChecker(cfg config.Config, version string) (*update.Checker, error) {
	token := ""
	if cfg.Update.TokenFile != "" {
		info, err := os.Stat(cfg.Update.TokenFile)
		if err != nil {
			return nil, i18n.E("app.error.token_read", "error", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, i18n.E("app.error.token_mode", "path", cfg.Update.TokenFile, "mode", fmt.Sprintf("%o", info.Mode().Perm()))
		}
		b, err := os.ReadFile(cfg.Update.TokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	return update.NewChecker(update.Config{
		Repo: cfg.Update.Repo, APIBase: cfg.Update.APIBase, Token: token, Dir: UpdateDir(cfg),
	}, version), nil
}

// markReady tells the applier this version is up (database migrated and
// listeners open).
func markReady(dataDir, version string) error {
	dir := filepath.Join(dataDir, "run")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, update.ReadyFile), []byte(version+"\n"), 0o640) //nolint:gosec // content is just the version
}

const lastUpdateKey = "update.last_status_at"

// auditUpdateResult records the result of the last update in the audit log,
// exactly once (the applier runs as root and does not write to the
// database).
func auditUpdateResult(ctx context.Context, core *Core, cfg config.Config, log *slog.Logger) {
	st, err := update.ReadStatus(UpdateDir(cfg))
	if err != nil || st == nil || st.State == "applying" {
		return
	}
	stamp := st.At.UTC().Format(time.RFC3339Nano)
	seen, err := core.Store.Q.GetSetting(ctx, lastUpdateKey)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Error("read update status", "error", err)
		return
	}
	if seen == `"`+stamp+`"` {
		return
	}
	outcome := audit.OK
	if st.State != "ok" {
		outcome = audit.Error
		log.Warn("last update was not applied", "state", st.State, "version", st.Version, "reason", st.Message)
	}
	_ = core.Audit.Record(ctx, audit.Entry{
		Action: "system.update." + st.State, Outcome: outcome, TargetType: "hangar", TargetID: st.Version,
		Summary: map[string]any{"from": st.From, "to": st.Version, "message": st.Message},
	})
	_ = core.Store.Q.SetSetting(ctx, dbq.SetSettingParams{Key: lastUpdateKey, ValueJson: `"` + stamp + `"`})
}
