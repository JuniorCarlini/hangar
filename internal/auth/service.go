package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Session lifetimes and attempt limits (docs/17 § 1.4).
const (
	SessionIdle   = 30 * time.Minute
	SessionMax    = 12 * time.Hour
	PendingTTL    = 5 * time.Minute
	SudoTTL       = 5 * time.Minute
	LockAfter     = 20
	LimitFailures = 5
	LimitWindow   = 15 * time.Minute
	touchEvery    = time.Minute
	recoveryCount = 10
	issuer        = "Hangar"
)

// Errors the handlers translate for the UI. The login page shows the same
// message for invalid credentials and a locked account, so it never reveals
// which accounts exist.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrLocked             = errors.New("account locked")
	ErrNoTOTP             = errors.New("2FA not configured")
	ErrInvalidCode        = errors.New("invalid code")
	ErrPendingExpired     = errors.New("login step expired")
	ErrEmailTaken         = &i18n.Error{Key: "user.error.email_taken"}
	ErrTOTPAlreadyOn      = &i18n.Error{Key: "account.totp.error.already_on"}
	ErrTOTPRequired       = &i18n.Error{Key: "account.totp.error.required"}
)

// RateLimitedError tells how long until new attempts are allowed.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("too many attempts; retry in %d min", e.Minutes())
}

// Minutes is the wait rounded up, for the UI.
func (e *RateLimitedError) Minutes() int { return int(e.RetryAfter.Minutes()) + 1 }

// Service implements login, sessions and re-authentication.
type Service struct {
	db     *sql.DB
	q      *dbq.Queries
	box    *secrets.Box
	audit  *audit.Logger
	now    func() time.Time
	argon  Argon2Params
	limits *limiter
	argon2 *argonPool
	// dummyHash equalizes response time when the e-mail does not exist.
	dummyHash  string
	require2FA bool
	// firstRun lets the owner be created from the browser while there is
	// no user, until setupUntil.
	firstRun   bool
	setupUntil setupDeadline
}

// Options tunes the Service (tests use cheap argon and a fixed clock).
type Options struct {
	Argon Argon2Params
	Now   func() time.Time
	// Require2FA refuses login to accounts without 2FA. Off, 2FA is per
	// account (like Easypanel): whoever turned it on is asked for the code.
	Require2FA bool
	// FirstRunSetup lets the owner be created from the browser while there
	// is no user, for SetupWindow after start. Off, only the command line
	// creates users.
	FirstRunSetup bool
}

// NewService creates the authentication service.
func NewService(db *sql.DB, box *secrets.Box, al *audit.Logger, opt Options) (*Service, error) {
	if opt.Argon == (Argon2Params{}) {
		opt.Argon = DefaultArgon2
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	dummy, err := HashPassword(randomToken(), opt.Argon)
	if err != nil {
		return nil, err
	}
	debug.FreeOSMemory() // give back the ~64 MiB used by the reference hash
	return &Service{
		db: db, q: dbq.New(db), box: box, audit: al, now: opt.Now, argon: opt.Argon,
		limits: newLimiter(LimitFailures, LimitWindow, opt.Now), dummyHash: dummy, argon2: newArgonPool(),
		require2FA: opt.Require2FA, firstRun: opt.FirstRunSetup,
	}, nil
}

// --- users ------------------------------------------------------------------

// CreateUser creates a user without 2FA. They can only log in after
// EnrollTOTP.
func (s *Service) CreateUser(ctx context.Context, email, password string, role Role) (string, error) {
	email, hash, err := s.newAccount(email, password, role)
	if err != nil {
		return "", err
	}
	id := "usr_" + randomID()
	now := s.now().Unix()
	err = s.q.CreateUser(ctx, dbq.CreateUserParams{
		ID: id, Email: email, PasswordHash: hash, Role: role.String(), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", ErrEmailTaken
		}
		return "", fmt.Errorf("create user: %w", err)
	}
	s.record(ctx, audit.Entry{
		ActorID: id, Action: "user.create", Outcome: audit.OK,
		TargetType: "user", TargetID: id, Summary: map[string]any{"role": role.String(), "via": "cli"},
	})
	return id, nil
}

// newAccount validates a new account's e-mail, role and password and returns
// the trimmed e-mail and the password hash.
func (s *Service) newAccount(email, password string, role Role) (string, string, error) {
	email = strings.TrimSpace(email)
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || len(email) > 254 {
		return "", "", i18n.E("user.error.email_invalid", "email", email)
	}
	if role == RoleNone {
		return "", "", i18n.E("user.error.role_required")
	}
	if err := CheckPasswordStrength(password, email); err != nil {
		return "", "", err
	}
	hash, err := HashPassword(password, s.argon)
	if err != nil {
		return "", "", err
	}
	return email, hash, nil
}

// UserIDByEmail resolves the id (CLI).
func (s *Service) UserIDByEmail(ctx context.Context, email string) (string, error) {
	u, err := s.q.GetUserByEmail(ctx, strings.TrimSpace(email))
	if errors.Is(err, sql.ErrNoRows) {
		return "", i18n.E("user.error.not_found", "email", email)
	}
	return u.ID, err
}

// CountUsers returns how many users exist.
func (s *Service) CountUsers(ctx context.Context) (int64, error) { return s.q.CountUsers(ctx) }

// EnrollTOTP stores the secret after checking that the user's app produces
// the right code. It never stores an unconfirmed secret.
func (s *Service) EnrollTOTP(ctx context.Context, userID, secret, code string) error {
	return s.enrollTOTP(ctx, userID, secret, code, "")
}

// enrollTOTP stores the secret. Every session of the user is closed except
// keepToken (the one turning 2FA on from "My account").
func (s *Service) enrollTOTP(ctx context.Context, userID, secret, code, keepToken string) error {
	step, ok := matchTOTP(secret, code, s.now())
	if !ok {
		return ErrInvalidCode
	}
	sealed, err := s.box.Seal([]byte(secret), totpAD(userID))
	if err != nil {
		return err
	}
	if err := s.q.SetTOTPSecret(ctx, dbq.SetTOTPSecretParams{TotpSecretEnc: sealed, UpdatedAt: s.now().Unix(), ID: userID}); err != nil {
		return fmt.Errorf("store 2FA: %w", err)
	}
	if _, err := s.q.AdvanceTOTPStep(ctx, dbq.AdvanceTOTPStepParams{Step: step, ID: userID}); err != nil {
		return err
	}
	// Changing 2FA kills the sessions opened with the old factor.
	if keepToken != "" {
		if err := s.q.DeleteOtherSessions(ctx, dbq.DeleteOtherSessionsParams{UserID: userID, IDHash: hashToken(keepToken)}); err != nil {
			return err
		}
	} else if err := s.q.DeleteUserSessions(ctx, userID); err != nil {
		return err
	}
	s.record(ctx, audit.Entry{ActorID: userID, Action: "user.totp.enroll", Outcome: audit.OK, TargetType: "user", TargetID: userID})
	return nil
}

// NewRecoveryCodes replaces the user's recovery codes and returns the new
// ones in clear text (shown only once).
func (s *Service) NewRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)
	if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
		return nil, err
	}
	codes := make([]string, recoveryCount)
	for i := range codes {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		c := strings.ToLower(b32.EncodeToString(raw)) // 16 characters, 80 bits
		codes[i] = c[:8] + "-" + c[8:]
		if err := q.InsertRecoveryCode(ctx, dbq.InsertRecoveryCodeParams{UserID: userID, CodeHash: hashRecovery(codes[i])}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.record(ctx, audit.Entry{ActorID: userID, Action: "user.recovery.regenerate", Outcome: audit.OK, TargetType: "user", TargetID: userID})
	return codes, nil
}

// Unlock unlocks an account (only through the CLI on the server).
func (s *Service) Unlock(ctx context.Context, email string) error {
	n, err := s.q.UnlockUser(ctx, dbq.UnlockUserParams{UpdatedAt: s.now().Unix(), Email: strings.TrimSpace(email)})
	if err != nil {
		return err
	}
	if n == 0 {
		return i18n.E("user.error.not_found", "email", email)
	}
	s.limits.reset("email:" + strings.ToLower(strings.TrimSpace(email)))
	s.record(ctx, audit.Entry{Action: "user.unlock", Outcome: audit.OK, TargetType: "user", Summary: map[string]any{"via": "cli"}})
	return nil
}

// --- login ------------------------------------------------------------------

// Client identifies where an attempt came from.
type Client struct {
	IP        string
	UserAgent string
}

// Login checks the password. For an account with 2FA it returns the
// pending-step token (valid for 5 min and only good for submitting the code)
// and complete=false; for an account without 2FA (allowed when Require2FA is
// off) it returns the active session token and complete=true.
func (s *Service) Login(ctx context.Context, email, password string, c Client) (token string, complete bool, err error) {
	token, complete, err = s.login(ctx, email, password, c)
	return token, complete, err
}

func (s *Service) login(ctx context.Context, email, password string, c Client) (string, bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	ipKey, emailKey := "ip:"+c.IP, "email:"+email
	if err := s.checkLimits(ipKey, emailKey); err != nil {
		return "", false, err
	}
	defer s.limits.end(ipKey, emailKey)

	u, err := s.q.GetUserByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		if perr := s.argon2.do(ctx, func() { _, _ = VerifyPassword(password, s.dummyHash) }); perr != nil {
			return "", false, perr
		}
		s.fail(ctx, c, "", "unknown_user", ipKey, emailKey)
		return "", false, ErrInvalidCredentials
	}
	if err != nil {
		return "", false, err
	}

	var ok bool
	if perr := s.argon2.do(ctx, func() { ok, err = VerifyPassword(password, u.PasswordHash) }); perr != nil {
		return "", false, perr
	}
	if err != nil {
		return "", false, err
	}
	if u.LockedAt.Valid {
		s.fail(ctx, c, u.ID, "account_locked", ipKey, emailKey)
		return "", false, ErrLocked
	}
	if !ok {
		row, err := s.q.RecordLoginFailure(ctx, dbq.RecordLoginFailureParams{LockAfter: LockAfter, Now: s.now().Unix(), ID: u.ID})
		if err != nil {
			return "", false, err
		}
		s.fail(ctx, c, u.ID, "wrong_password", ipKey, emailKey)
		if row.LockedAt.Valid && row.FailedLogins == LockAfter {
			s.record(ctx, audit.Entry{
				ActorID: u.ID, IP: c.IP, Action: "auth.account.locked", Outcome: audit.Denied,
				TargetType: "user", TargetID: u.ID, Summary: map[string]any{"failures": row.FailedLogins},
			})
		}
		return "", false, ErrInvalidCredentials
	}
	if len(u.TotpSecretEnc) == 0 {
		if s.require2FA {
			s.record(ctx, audit.Entry{
				ActorID: u.ID, IP: c.IP, Action: "auth.login.password", Outcome: audit.Denied,
				Summary: map[string]any{"reason": "totp_not_configured"},
			})
			return "", false, ErrNoTOTP
		}
		// No 2FA on this account: the password alone opens the session.
		if err := s.q.ResetLoginFailures(ctx, u.ID); err != nil {
			return "", false, err
		}
		s.limits.reset(ipKey)
		s.limits.reset(emailKey)
		token, err := s.createSession(ctx, u.ID, "active", c, s.now().Add(SessionMax), 0)
		if err != nil {
			return "", false, err
		}
		s.record(ctx, audit.Entry{
			ActorID: u.ID, IP: c.IP, UserAgent: c.UserAgent, Action: "auth.login.ok", Outcome: audit.OK,
			Summary: map[string]any{"second_factor": "none"},
		})
		return token, true, nil
	}

	token, err := s.createSession(ctx, u.ID, "pending_2fa", c, s.now().Add(PendingTTL), 0)
	if err != nil {
		return "", false, err
	}
	s.record(ctx, audit.Entry{ActorID: u.ID, IP: c.IP, UserAgent: c.UserAgent, Action: "auth.login.password", Outcome: audit.OK})
	return token, false, nil
}

// LoginSecondFactor is the second step: authenticator code or recovery code.
// On success it returns the active session token.
func (s *Service) LoginSecondFactor(ctx context.Context, pendingToken, code string, c Client) (string, error) {
	ipKey := "ip:" + c.IP
	pendKey := "pending:" + hashString(pendingToken)
	if err := s.checkLimits(ipKey, pendKey); err != nil {
		return "", err
	}
	defer s.limits.end(ipKey, pendKey)

	sess, err := s.q.GetSession(ctx, hashToken(pendingToken))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (sess.Stage != "pending_2fa" || s.now().Unix() >= sess.ExpiresAt)) {
		return "", ErrPendingExpired
	}
	if err != nil {
		return "", err
	}

	method, err := s.checkSecondFactor(ctx, sess.UserID, code)
	if err != nil {
		if errors.Is(err, ErrInvalidCode) {
			if _, ferr := s.q.RecordLoginFailure(ctx, dbq.RecordLoginFailureParams{LockAfter: LockAfter, Now: s.now().Unix(), ID: sess.UserID}); ferr != nil {
				return "", ferr
			}
			if s.fail(ctx, c, sess.UserID, "wrong_2fa_code", ipKey, pendKey) >= LimitFailures {
				// Out of attempts for this step: back to the password.
				_ = s.q.DeleteSession(ctx, sess.IDHash)
			}
		}
		return "", err
	}

	if err := s.q.DeleteSession(ctx, sess.IDHash); err != nil {
		return "", err
	}
	if err := s.q.ResetLoginFailures(ctx, sess.UserID); err != nil {
		return "", err
	}
	s.limits.reset(ipKey)
	s.limits.reset(pendKey)

	token, err := s.createSession(ctx, sess.UserID, "active", c, s.now().Add(SessionMax), 0)
	if err != nil {
		return "", err
	}
	s.record(ctx, audit.Entry{
		ActorID: sess.UserID, IP: c.IP, UserAgent: c.UserAgent, Action: "auth.login.ok",
		Outcome: audit.OK, Summary: map[string]any{"factor": method},
	})
	return token, nil
}

// checkSecondFactor accepts a TOTP code (6 digits) or a recovery code.
func (s *Service) checkSecondFactor(ctx context.Context, userID, code string) (string, error) {
	code = strings.TrimSpace(code)
	if strings.Contains(code, "-") {
		n, err := s.q.UseRecoveryCode(ctx, dbq.UseRecoveryCodeParams{
			UsedAt: sql.NullInt64{Int64: s.now().Unix(), Valid: true}, UserID: userID, CodeHash: hashRecovery(code),
		})
		if err != nil {
			return "", err
		}
		if n != 1 {
			return "", ErrInvalidCode
		}
		return "recovery", nil
	}
	if err := s.verifyTOTP(ctx, userID, code); err != nil {
		return "", err
	}
	return "totp", nil
}

func (s *Service) verifyTOTP(ctx context.Context, userID, code string) error {
	u, err := s.q.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if len(u.TotpSecretEnc) == 0 {
		return ErrNoTOTP
	}
	secret, err := s.box.Open(u.TotpSecretEnc, totpAD(userID))
	if err != nil {
		return fmt.Errorf("2FA: %w", err)
	}
	step, ok := matchTOTP(string(secret), code, s.now())
	if !ok {
		return ErrInvalidCode
	}
	// Only accept if the step is newer than the last one used: a code someone
	// saw (over a shoulder, in a video) is never valid again.
	n, err := s.q.AdvanceTOTPStep(ctx, dbq.AdvanceTOTPStepParams{Step: step, ID: userID})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrInvalidCode
	}
	return nil
}

// --- sessions ---------------------------------------------------------------

// Authenticate validates the cookie token and counts as activity (extends
// the idle deadline). It returns nil without error when there is no valid
// session.
func (s *Service) Authenticate(ctx context.Context, token string) (*Principal, error) {
	return s.authenticate(ctx, token, true)
}

// StillValid checks the session WITHOUT counting as activity. Used by long
// connections (live logs): a forgotten open tab must not keep the session
// alive.
func (s *Service) StillValid(ctx context.Context, token string) bool {
	p, err := s.authenticate(ctx, token, false)
	return err == nil && p != nil
}

func (s *Service) authenticate(ctx context.Context, token string, touch bool) (*Principal, error) {
	if token == "" {
		return nil, nil
	}
	sess, err := s.q.GetSession(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if sess.Stage != "active" || sess.LockedAt.Valid ||
		now.Unix() >= sess.ExpiresAt || now.Sub(time.Unix(sess.LastSeenAt, 0)) >= SessionIdle {
		if sess.Stage == "active" {
			_ = s.q.DeleteSession(ctx, sess.IDHash)
		}
		return nil, nil
	}
	if touch && now.Sub(time.Unix(sess.LastSeenAt, 0)) >= touchEvery {
		if err := s.q.TouchSession(ctx, dbq.TouchSessionParams{LastSeenAt: now.Unix(), IDHash: sess.IDHash}); err != nil {
			return nil, err
		}
	}
	role, err := ParseRole(sess.Role)
	if err != nil {
		return nil, err
	}
	p := &Principal{
		UserID: sess.UserID, Role: role, SudoUntil: time.Unix(sess.SudoUntil, 0),
		CSRFToken: sess.CsrfToken, SessionToken: token,
		Email: sess.Email, Name: sess.Name, Locale: sess.Locale.String, Theme: sess.Theme, HasTOTP: sess.HasTotp == 1,
		AllProjects: sess.AllProjects == 1 || role >= RoleAdmin,
	}
	if !p.AllProjects {
		slugs, err := s.q.UserProjectSlugs(ctx, sess.UserID)
		if err != nil {
			return nil, err
		}
		p.Projects = make(map[string]bool, len(slugs))
		for _, sl := range slugs {
			p.Projects[sl] = true
		}
	}
	return p, nil
}

// Sudo checks 2FA again and swaps the session for a new one with sudo valid
// for SudoTTL. The old token stops working.
func (s *Service) Sudo(ctx context.Context, p *Principal, code string, c Client) (string, error) {
	key := "sudo:" + p.UserID
	if err := s.checkLimits(key); err != nil {
		return "", err
	}
	defer s.limits.end(key)
	old, err := s.q.GetSession(ctx, hashToken(p.SessionToken))
	if err != nil {
		return "", err
	}
	if err := s.confirm(ctx, p.UserID, code); err != nil {
		if errors.Is(err, ErrInvalidCode) {
			s.fail(ctx, c, p.UserID, "wrong_sudo_code", key)
		}
		return "", err
	}
	s.limits.reset(key)

	token, err := s.createSession(ctx, p.UserID, "active", c, time.Unix(old.ExpiresAt, 0), s.now().Add(SudoTTL).Unix())
	if err != nil {
		return "", err
	}
	if err := s.q.DeleteSession(ctx, old.IDHash); err != nil {
		return "", err
	}
	s.record(ctx, audit.Entry{ActorID: p.UserID, IP: c.IP, Action: "auth.sudo", Outcome: audit.OK})
	return token, nil
}

// confirm re-checks who is at the keyboard: the 2FA code (or a recovery
// code) for accounts with 2FA, the password for accounts without it.
func (s *Service) confirm(ctx context.Context, userID, secret string) error {
	u, err := s.q.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if len(u.TotpSecretEnc) > 0 {
		_, err := s.checkSecondFactor(ctx, userID, secret)
		return err
	}
	var ok bool
	if perr := s.argon2.do(ctx, func() { ok, err = VerifyPassword(secret, u.PasswordHash) }); perr != nil {
		return perr
	}
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCode
	}
	return nil
}

// EnableTOTP turns 2FA on from "My account": the code proves the app has the
// secret. It returns fresh recovery codes, shown once.
func (s *Service) EnableTOTP(ctx context.Context, p *Principal, secret, code string, c Client) ([]string, error) {
	if p.HasTOTP {
		return nil, ErrTOTPAlreadyOn
	}
	if err := s.enrollTOTP(ctx, p.UserID, secret, code, p.SessionToken); err != nil {
		return nil, err
	}
	codes, err := s.NewRecoveryCodes(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Entry{ActorID: p.UserID, IP: c.IP, Action: "auth.totp.enable", Outcome: audit.OK})
	return codes, nil
}

// DisableTOTP turns 2FA off; it needs a current code (or a recovery code).
func (s *Service) DisableTOTP(ctx context.Context, p *Principal, code string, c Client) error {
	key := "sudo:" + p.UserID
	if err := s.checkLimits(key); err != nil {
		return err
	}
	defer s.limits.end(key)
	if s.require2FA {
		return ErrTOTPRequired
	}
	if _, err := s.checkSecondFactor(ctx, p.UserID, code); err != nil {
		if errors.Is(err, ErrInvalidCode) {
			s.fail(ctx, c, p.UserID, "wrong_totp_disable_code", key)
		}
		return err
	}
	if err := s.q.ClearTOTP(ctx, dbq.ClearTOTPParams{UpdatedAt: s.now().Unix(), ID: p.UserID}); err != nil {
		return err
	}
	if err := s.q.DeleteRecoveryCodes(ctx, p.UserID); err != nil {
		return err
	}
	if err := s.q.DeleteOtherSessions(ctx, dbq.DeleteOtherSessionsParams{UserID: p.UserID, IDHash: hashToken(p.SessionToken)}); err != nil {
		return err
	}
	s.record(ctx, audit.Entry{ActorID: p.UserID, IP: c.IP, Action: "auth.totp.disable", Outcome: audit.OK})
	return nil
}

// ResetPassword sets a new password from the server's command line (there is
// no "forgot my password" by e-mail, docs/17 § 1.4). It also unlocks the
// account and ends every session, so a stolen session dies with the old
// password. 2FA stays as it is.
func (s *Service) ResetPassword(ctx context.Context, email, password string) error {
	id, err := s.UserIDByEmail(ctx, email)
	if err != nil {
		return err
	}
	if err := CheckPasswordStrength(password, strings.TrimSpace(email)); err != nil {
		return err
	}
	hash, err := HashPassword(password, s.argon)
	if err != nil {
		return err
	}
	if err := s.q.SetPassword(ctx, dbq.SetPasswordParams{PasswordHash: hash, UpdatedAt: s.now().Unix(), ID: id}); err != nil {
		return err
	}
	if _, err := s.q.UnlockUser(ctx, dbq.UnlockUserParams{UpdatedAt: s.now().Unix(), Email: strings.TrimSpace(email)}); err != nil {
		return err
	}
	s.limits.reset("email:" + strings.ToLower(strings.TrimSpace(email)))
	if err := s.q.DeleteUserSessions(ctx, id); err != nil {
		return err
	}
	s.record(ctx, audit.Entry{
		Action: "user.password.reset", Outcome: audit.OK, TargetType: "user", TargetID: id,
		Summary: map[string]any{"via": "cli"},
	})
	return nil
}

// ResetTOTP turns 2FA off from the server's command line (lost phone, or
// 2FA not wanted while require_2fa is off). It closes every session.
func (s *Service) ResetTOTP(ctx context.Context, email string) error {
	id, err := s.UserIDByEmail(ctx, email)
	if err != nil {
		return err
	}
	if err := s.q.ClearTOTP(ctx, dbq.ClearTOTPParams{UpdatedAt: s.now().Unix(), ID: id}); err != nil {
		return err
	}
	if err := s.q.DeleteRecoveryCodes(ctx, id); err != nil {
		return err
	}
	if err := s.q.DeleteUserSessions(ctx, id); err != nil {
		return err
	}
	s.record(ctx, audit.Entry{
		Action: "auth.totp.reset", Outcome: audit.OK, TargetType: "user", TargetID: id,
		Summary: map[string]any{"via": "cli"},
	})
	return nil
}

// SessionInfo is an open session as "My account" lists it.
type SessionInfo struct {
	ID       string // hex of the token hash; never the token
	IP       string
	Device   string
	Created  time.Time
	LastSeen time.Time
	Current  bool
}

// ListSessions lists the user's open sessions, the current one marked.
func (s *Service) ListSessions(ctx context.Context, p *Principal) ([]SessionInfo, error) {
	rows, err := s.q.ListUserSessions(ctx, dbq.ListUserSessionsParams{UserID: p.UserID, ExpiresAt: s.now().Unix()})
	if err != nil {
		return nil, err
	}
	cur := hashToken(p.SessionToken)
	out := make([]SessionInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, SessionInfo{
			ID: hex.EncodeToString(r.IDHash), IP: r.Ip.String, Device: deviceOf(r.UserAgent.String),
			Created: time.Unix(r.CreatedAt, 0), LastSeen: time.Unix(r.LastSeenAt, 0),
			Current: string(r.IDHash) == string(cur),
		})
	}
	return out, nil
}

// EndSession closes one of the user's other sessions.
func (s *Service) EndSession(ctx context.Context, p *Principal, id string, c Client) error {
	h, err := hex.DecodeString(id)
	if err != nil || string(h) == string(hashToken(p.SessionToken)) {
		return ErrInvalidCode
	}
	n, err := s.q.DeleteUserSession(ctx, dbq.DeleteUserSessionParams{UserID: p.UserID, IDHash: h})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInvalidCode
	}
	s.record(ctx, audit.Entry{ActorID: p.UserID, IP: c.IP, Action: "auth.session.end", Outcome: audit.OK})
	return nil
}

// deviceOf turns a User-Agent into "Chrome · macOS".
func deviceOf(ua string) string {
	browser, os := "", ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	case strings.Contains(ua, "curl/"):
		browser = "curl"
	}
	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Mac OS X"):
		os = "macOS"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}
	switch {
	case browser != "" && os != "":
		return browser + " · " + os
	case browser != "":
		return browser
	case os != "":
		return os
	}
	return "?"
}

// Require2FA reports whether every account must have 2FA.
func (s *Service) Require2FA() bool { return s.require2FA }

// SetName stores the display name shown in the account menu.
func (s *Service) SetName(ctx context.Context, userID, name string, c Client) error {
	name = strings.Join(strings.Fields(name), " ")
	if len([]rune(name)) > 60 || strings.ContainsAny(name, "<>") {
		return i18n.E("account.error.name")
	}
	if err := s.q.SetUserName(ctx, dbq.SetUserNameParams{Name: name, UpdatedAt: s.now().Unix(), ID: userID}); err != nil {
		return err
	}
	s.record(ctx, audit.Entry{ActorID: userID, IP: c.IP, Action: "user.name", Outcome: audit.OK})
	return nil
}

// Themes a user can pick (docs/22).
var Themes = []string{"system", "dark", "light"}

// SetPreferences stores the user's language and theme. An empty locale means
// "follow the browser".
func (s *Service) SetPreferences(ctx context.Context, userID, locale, theme string, c Client) error {
	if locale != "" && !i18n.Supported(locale) {
		return i18n.E("account.error.locale")
	}
	if !slices.Contains(Themes, theme) {
		return i18n.E("account.error.theme")
	}
	err := s.q.SetPreferences(ctx, dbq.SetPreferencesParams{
		Locale: sql.NullString{String: locale, Valid: locale != ""}, Theme: theme, UpdatedAt: s.now().Unix(), ID: userID,
	})
	if err != nil {
		return err
	}
	s.record(ctx, audit.Entry{
		ActorID: userID, IP: c.IP, Action: "user.preferences", Outcome: audit.OK,
		TargetType: "user", TargetID: userID, Summary: map[string]any{"locale": locale, "theme": theme},
	})
	return nil
}

// Logout ends the token's session.
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.q.DeleteSession(ctx, hashToken(token))
}

// CleanupSessions deletes expired sessions.
func (s *Service) CleanupSessions(ctx context.Context) (int64, error) {
	now := s.now()
	return s.q.DeleteExpiredSessions(ctx, dbq.DeleteExpiredSessionsParams{
		Now: now.Unix(), IdleBefore: now.Add(-SessionIdle).Unix(),
	})
}

func (s *Service) createSession(ctx context.Context, userID, stage string, c Client, expires time.Time, sudoUntil int64) (string, error) {
	token := randomToken()
	now := s.now().Unix()
	err := s.q.CreateSession(ctx, dbq.CreateSessionParams{
		IDHash: hashToken(token), UserID: userID, Stage: stage, CsrfToken: randomToken(),
		Ip:        sql.NullString{String: c.IP, Valid: c.IP != ""},
		UserAgent: sql.NullString{String: truncate(c.UserAgent, 256), Valid: c.UserAgent != ""},
		CreatedAt: now, LastSeenAt: now, ExpiresAt: expires.Unix(), SudoUntil: sudoUntil,
	})
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return token, nil
}

// --- limits and audit -------------------------------------------------------

// checkLimits reserves one attempt on every key (released with
// limits.end): attempts running at the same time count, so a burst of
// parallel requests cannot all slip past the limit before the first
// failure is recorded.
func (s *Service) checkLimits(keys ...string) error {
	if ok, wait := s.limits.begin(keys...); !ok {
		return &RateLimitedError{RetryAfter: wait}
	}
	return nil
}

// fail records the failure in the limiters and the audit log. After
// LimitFailures in the window the key is blocked and later attempts never
// get here: that is what keeps an attack from flooding the log (docs/20).
func (s *Service) fail(ctx context.Context, c Client, userID, reason string, keys ...string) int {
	worst := 0
	for _, k := range keys {
		if n := s.limits.fail(k); n > worst {
			worst = n
		}
	}
	summary := map[string]any{"reason": reason}
	if worst >= LimitFailures {
		summary["limit_reached"] = true
	}
	s.record(ctx, audit.Entry{
		ActorID: userID, IP: c.IP, UserAgent: c.UserAgent,
		Action: "auth.login.fail", Outcome: audit.Denied, Summary: summary,
	})
	return worst
}

func (s *Service) record(ctx context.Context, e audit.Entry) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(context.WithoutCancel(ctx), e)
}

// --- helpers ----------------------------------------------------------------

func totpAD(userID string) string { return "users|" + userID + "|totp_secret_enc" }

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // without entropy there is no safe way forward
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return strings.ToLower(b32.EncodeToString(b))
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

func hashString(t string) string { return base64.RawURLEncoding.EncodeToString(hashToken(t)) }

func hashRecovery(code string) []byte {
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	h := sha256.Sum256([]byte("hangar-recovery|" + norm))
	return h[:]
}

// EqualCSRF compares CSRF tokens in constant time.
func EqualCSRF(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
