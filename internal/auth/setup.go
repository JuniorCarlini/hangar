package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// First-run setup: while the panel has no user, whoever reaches it can create
// the owner account from the browser, like other self-hosted panels. Reaching
// the panel is not enough, though: the form also asks for a one-time setup
// code that only someone with a shell on the server can read (the installer
// prints it). The code file is created when the panel starts with no user and
// removed as soon as the owner exists; the owner is inserted only if the users
// table is still empty, so two requests racing each other cannot both win.

// Setup errors the handlers translate for the UI.
var (
	ErrSetupClosed = &i18n.Error{Key: "setup.error.closed"}
	ErrSetupCode   = &i18n.Error{Key: "setup.error.code"}
)

// setupCodeLen is the number of base32 characters in a setup code (80 bits),
// shown in groups of four.
const setupCodeLen = 16

// SetupOpen reports whether the first-run setup is available: browser setup
// configured and no user yet.
func (s *Service) SetupOpen(ctx context.Context) bool {
	if s.setupFile == "" {
		return false
	}
	n, err := s.q.CountUsers(ctx)
	return err == nil && n == 0
}

// PrepareSetup creates the setup code file when the panel has no user and
// there is no code yet. It returns whether setup is open. With no file
// configured (development, tests) setup stays closed: the owner comes from
// the command line.
func (s *Service) PrepareSetup(ctx context.Context) (bool, error) {
	if !s.SetupOpen(ctx) {
		return false, nil
	}
	f, err := os.OpenFile(s.setupFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("setup code: %w", err)
	}
	_, werr := f.WriteString(newSetupCode() + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(s.setupFile)
		return false, fmt.Errorf("setup code: %w", werr)
	}
	return true, nil
}

// CreateOwner creates the first account (owner) from the setup page and
// opens its session. It checks the setup code first, with the same attempt
// limits as the login.
func (s *Service) CreateOwner(ctx context.Context, code, email, password string, c Client) (string, error) {
	ipKey := "ip:" + c.IP
	if err := s.checkLimits(ipKey, "setup"); err != nil {
		return "", err
	}
	defer s.limits.end(ipKey, "setup")

	if !s.SetupOpen(ctx) {
		return "", ErrSetupClosed
	}
	want, err := os.ReadFile(s.setupFile)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrSetupClosed
	}
	if err != nil {
		return "", fmt.Errorf("setup code: %w", err)
	}
	wantCode := normalizeSetupCode(string(want))
	if len(wantCode) != setupCodeLen {
		// A damaged or emptied file must never match an empty answer.
		return "", ErrSetupClosed
	}
	if subtle.ConstantTimeCompare([]byte(normalizeSetupCode(code)), []byte(wantCode)) != 1 {
		s.fail(ctx, c, "", "wrong_setup_code", ipKey, "setup")
		return "", ErrSetupCode
	}

	email, hash, err := s.newAccount(email, password, RoleOwner)
	if err != nil {
		return "", err
	}
	id := "usr_" + randomID()
	now := s.now().Unix()
	n, err := s.q.CreateFirstUser(ctx, dbq.CreateFirstUserParams{
		ID: id, Email: email, PasswordHash: hash, Role: RoleOwner.String(), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return "", fmt.Errorf("create owner: %w", err)
	}
	if n == 0 {
		return "", ErrSetupClosed
	}
	// The code has done its job; a leftover file would only mislead.
	_ = os.Remove(s.setupFile)
	s.limits.reset(ipKey)
	s.limits.reset("setup")
	s.record(ctx, audit.Entry{
		ActorID: id, IP: c.IP, UserAgent: c.UserAgent, Action: "user.create", Outcome: audit.OK,
		TargetType: "user", TargetID: id, Summary: map[string]any{"role": RoleOwner.String(), "via": "setup"},
	})
	token, err := s.createSession(ctx, id, "active", c, s.now().Add(SessionMax), 0)
	if err != nil {
		return "", err
	}
	s.record(ctx, audit.Entry{
		ActorID: id, IP: c.IP, UserAgent: c.UserAgent, Action: "auth.login.ok", Outcome: audit.OK,
		Summary: map[string]any{"second_factor": "none", "via": "setup"},
	})
	return token, nil
}

// newSetupCode returns 80 random bits as XXXX-XXXX-XXXX-XXXX.
func newSetupCode() string {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	c := b32.EncodeToString(raw)[:setupCodeLen]
	return c[0:4] + "-" + c[4:8] + "-" + c[8:12] + "-" + c[12:16]
}

// normalizeSetupCode ignores case, spaces and dashes, so a code read aloud or
// pasted with a line break still matches.
func normalizeSetupCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
