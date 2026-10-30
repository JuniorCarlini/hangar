package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Mandatory second factor (docs/04, docs/17 § 1.4).
//
// Owners and admins always need a second factor: they reach every project,
// its secrets and the server itself. The panel setting "require 2FA of
// everyone" extends that to operators and viewers; it lives in the database
// (Team → Security), not in hangar.toml, so nobody needs a shell to change
// it. hangar.toml's [auth] require_2fa only seeds it once, on the first
// start of a panel that already had accounts (an upgrade); a brand-new
// panel starts with it on.
//
// An account that must have a second factor and has none is not turned
// away at the door (that used to need a shell on the server to fix): it
// signs in with its password and lands on the enrollment page, and every
// other route answers "enroll first" until it does (Principal.MustEnroll).

const require2FAKey = "auth.require_2fa"

type require2FASetting struct {
	On bool `json:"on"`
	// Seeded tells how the value was first chosen: "new" (fresh panel,
	// on) or "config" (an upgrade, from hangar.toml). It only documents the
	// row; the panel reads On.
	Seeded string `json:"seeded,omitempty"`
}

// SeedRequire2FA writes the setting the first time the panel (or the
// command line) opens the database with this version: on for a panel
// without accounts, hangar.toml's value for one that already has them. An
// existing row is never touched. app.Open calls it before anything can
// create a user; Require2FA does it too when the row is missing.
func (s *Service) SeedRequire2FA(ctx context.Context) error {
	return s.initRequire2FA(ctx, s.require2FA)
}

func (s *Service) initRequire2FA(ctx context.Context, fromConfig bool) error {
	if _, err := s.q.GetSetting(ctx, require2FAKey); err == nil || !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	n, err := s.q.CountUsers(ctx)
	if err != nil {
		return err
	}
	v := require2FASetting{On: true, Seeded: "new"}
	if n > 0 {
		v = require2FASetting{On: fromConfig, Seeded: "config"}
	}
	raw, _ := json.Marshal(v)
	return s.q.SetSetting(ctx, dbq.SetSettingParams{Key: require2FAKey, ValueJson: string(raw)})
}

// Require2FA reports whether every account (operators and viewers too)
// must have a second factor. Owners and admins always must (see
// RequiredFor). A read error answers true: when in doubt, ask for more.
func (s *Service) Require2FA(ctx context.Context) bool {
	s.twoFAMu.Lock()
	defer s.twoFAMu.Unlock()
	if s.twoFA != nil {
		return *s.twoFA
	}
	raw, err := s.q.GetSetting(ctx, require2FAKey)
	if errors.Is(err, sql.ErrNoRows) {
		if err := s.initRequire2FA(ctx, s.require2FA); err != nil {
			return true
		}
		raw, err = s.q.GetSetting(ctx, require2FAKey)
	}
	if err != nil {
		return true
	}
	var v require2FASetting
	if json.Unmarshal([]byte(raw), &v) != nil {
		return true
	}
	s.twoFA = &v.On
	return v.On
}

// RequiredFor reports whether an account with this role must have a second
// factor.
func (s *Service) RequiredFor(ctx context.Context, r Role) bool {
	return r >= RoleAdmin || s.Require2FA(ctx)
}

// SetRequire2FA turns "require 2FA of everyone" on or off. Turning it off
// is the owner's, with a fresh confirmation (the route asks for sudo).
func (s *Service) SetRequire2FA(ctx context.Context, userID string, on bool, c Client) error {
	old := s.Require2FA(ctx)
	raw, _ := json.Marshal(require2FASetting{On: on})
	if err := s.q.SetSetting(ctx, dbq.SetSettingParams{Key: require2FAKey, ValueJson: string(raw)}); err != nil {
		return err
	}
	s.twoFAMu.Lock()
	s.twoFA = &on
	s.twoFAMu.Unlock()
	s.record(ctx, audit.Entry{
		ActorID: userID, IP: c.IP, Action: "security.require_2fa", Outcome: audit.OK,
		Summary: map[string]any{"from": old, "to": on},
	})
	return nil
}

// hasSecondFactor reports whether the account has a factor besides the
// password. Today that is TOTP; a passkey credential, once the panel has
// them, counts the same (this is the one place to add it).
func hasSecondFactor(hasTOTP bool) bool { return hasTOTP }
