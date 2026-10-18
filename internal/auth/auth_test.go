package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
)

// cheap keeps tests fast; the hash format is the same.
var cheap = Argon2Params{Memory: 1024, Time: 1, Threads: 1}

const goodPassword = "pista-de-pouso-norte-27"

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

type fixture struct {
	svc   *Service
	clock *clock
	st    *store.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{9}, 32))
	c := &clock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	svc, err := NewService(st.DB, box, audit.New(st.DB), Options{Argon: cheap, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, clock: c, st: st}
}

// userWithTOTP creates a user with 2FA and returns the secret.
func (f *fixture) userWithTOTP(t *testing.T, email string, role Role) (string, string) {
	t.Helper()
	ctx := context.Background()
	id, err := f.svc.CreateUser(ctx, email, goodPassword, role)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := NewTOTPSecret()
	if err := f.svc.EnrollTOTP(ctx, id, secret, f.code(t, secret)); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(totpStep * time.Second) // the enrollment code is not valid for login
	return id, secret
}

func (f *fixture) code(t *testing.T, secret string) string {
	t.Helper()
	c, err := totpCode(secret, f.clock.t.Unix()/totpStep)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var cli = Client{IP: "189.10.20.30", UserAgent: "teste"}

func (f *fixture) login(t *testing.T, email, secret string) string {
	t.Helper()
	ctx := context.Background()
	pending, _, err := f.svc.Login(ctx, email, goodPassword, cli)
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.svc.LoginSecondFactor(ctx, pending, f.code(t, secret), cli)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// RFC 6238, appendix B (SHA1, secret "12345678901234567890"), last 6 digits.
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := totpCode(secret, unix/totpStep)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("t=%d: code %s, want %s", unix, got, want)
		}
	}
}

func TestPasswordHashAndStrength(t *testing.T) {
	h, err := HashPassword(goodPassword, cheap)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword(goodPassword, h); !ok {
		t.Error("correct password rejected")
	}
	if ok, _ := VerifyPassword(goodPassword+"x", h); ok {
		t.Error("wrong password accepted")
	}
	for _, weak := range []string{"curta", "aaaaaaaaaaaaaaaaaa", "passwordpassword", "junior@hangar.dev"} {
		if CheckPasswordStrength(weak, "junior@hangar.dev") == nil {
			t.Errorf("weak password accepted: %q", weak)
		}
	}
}

func TestFullLoginFlow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, secret := f.userWithTOTP(t, "junior@hangar.dev", RoleOwner)

	token := f.login(t, "JUNIOR@hangar.dev ", secret) // e-mail is case-insensitive
	p, err := f.svc.Authenticate(ctx, token)
	if err != nil || p == nil {
		t.Fatalf("new session did not authenticate: %v", err)
	}
	if p.Role != RoleOwner || p.CSRFToken == "" {
		t.Errorf("unexpected principal: %+v", p)
	}

	if err := f.svc.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.svc.Authenticate(ctx, token); p != nil {
		t.Error("session still valid after logout")
	}
}

func TestPendingTokenIsNotASession(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	pending, _, err := f.svc.Login(context.Background(), "a@hangar.dev", goodPassword, cli)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := f.svc.Authenticate(context.Background(), pending); p != nil {
		t.Fatal("the password-step token must not open the panel")
	}
}

func TestTOTPCodeCannotBeReused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, secret := f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)

	code := f.code(t, secret)
	p1, _, _ := f.svc.Login(ctx, "a@hangar.dev", goodPassword, cli)
	if _, err := f.svc.LoginSecondFactor(ctx, p1, code, cli); err != nil {
		t.Fatal(err)
	}
	p2, _, _ := f.svc.Login(ctx, "a@hangar.dev", goodPassword, cli)
	if _, err := f.svc.LoginSecondFactor(ctx, p2, code, cli); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("same code reused: err = %v", err)
	}
}

func TestRecoveryCodeWorksOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, _ := f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	codes, err := f.svc.NewRecoveryCodes(ctx, id)
	if err != nil || len(codes) != recoveryCount {
		t.Fatalf("codes: %v %v", codes, err)
	}

	p1, _, _ := f.svc.Login(ctx, "a@hangar.dev", goodPassword, cli)
	if _, err := f.svc.LoginSecondFactor(ctx, p1, codes[0], cli); err != nil {
		t.Fatalf("recovery code rejected: %v", err)
	}
	p2, _, _ := f.svc.Login(ctx, "a@hangar.dev", goodPassword, cli)
	if _, err := f.svc.LoginSecondFactor(ctx, p2, codes[0], cli); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("recovery code used twice: err = %v", err)
	}
}

func TestSameErrorForUnknownUserAndWrongPassword(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	ctx := context.Background()

	_, _, errUnknown := f.svc.Login(ctx, "ninguem@hangar.dev", goodPassword, Client{IP: "1.1.1.1"})
	_, _, errWrong := f.svc.Login(ctx, "a@hangar.dev", "senha-errada-qualquer", Client{IP: "2.2.2.2"})
	if !errors.Is(errUnknown, ErrInvalidCredentials) || !errors.Is(errWrong, ErrInvalidCredentials) {
		t.Fatalf("different errors reveal which accounts exist: %v / %v", errUnknown, errWrong)
	}
}

// Found by the load test: 300 parallel wrong logins from one
// address got 20 password checks through, because all passed the limit
// check before the first failure was recorded. Attempts in flight count
// now: at most LimitFailures guesses per window, however they are sent.
func TestParallelAttemptsRespectTheLimit(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	ctx := context.Background()
	var mu sync.Mutex
	checked := 0
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			_, _, err := f.svc.Login(ctx, "a@hangar.dev", "senha-errada-qualquer", cli)
			if errors.Is(err, ErrInvalidCredentials) {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if checked > LimitFailures || checked == 0 {
		t.Fatalf("%d passwords checked in parallel, want 1..%d", checked, LimitFailures)
	}
	// The address is now blocked even for the right password.
	if _, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, cli); err == nil {
		t.Fatal("limit not applied after the burst")
	}
}

// The only password recovery is on the server (hangard user password): it
// unlocks the account and ends every session of the old password.
func TestResetPasswordUnlocksAndEndsSessions(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	ctx := context.Background()
	for i := range LockAfter {
		if i > 0 && i%LimitFailures == 0 {
			f.clock.advance(LimitWindow)
		}
		_, _, _ = f.svc.Login(ctx, "a@hangar.dev", "senha-errada-qualquer", Client{IP: "10.0.0.1"})
	}
	if err := f.svc.ResetPassword(ctx, "a@hangar.dev", "curta"); err == nil {
		t.Fatal("weak password accepted")
	}
	const fresh = "outra-pista-de-pouso-sul-31"
	if err := f.svc.ResetPassword(ctx, "a@hangar.dev", fresh); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, Client{IP: "10.0.0.3"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password: %v", err)
	}
	if _, _, err := f.svc.Login(ctx, "a@hangar.dev", fresh, Client{IP: "10.0.0.4"}); err != nil {
		t.Fatalf("new password after a lock: %v", err)
	}
	if err := f.svc.ResetPassword(ctx, "ninguem@hangar.dev", fresh); err == nil {
		t.Error("unknown e-mail accepted")
	}
}

func TestRateLimitPerIPAndRecovery(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	ctx := context.Background()

	for range LimitFailures {
		_, _, _ = f.svc.Login(ctx, "a@hangar.dev", "senha-errada-qualquer", cli)
	}
	_, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, cli)
	var rl *RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("after %d failures expected the limit, got %v", LimitFailures, err)
	}

	f.clock.advance(LimitWindow)
	if _, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, cli); err != nil {
		t.Fatalf("after the window it should be released: %v", err)
	}
}

// failLogins sends n wrong passwords for email, each from its own address
// and with the in-memory e-mail limit cleared, so only the account counter
// (and not the per-IP or per-e-mail limits) decides, with no time passing.
func (f *fixture) failLogins(t *testing.T, email string, n int) {
	t.Helper()
	for i := range n {
		f.svc.limits.reset("email:" + email)
		ip := fmt.Sprintf("10.9.%d.%d", i/250, i%250+1)
		if _, _, err := f.svc.Login(context.Background(), email, "senha-errada-qualquer", Client{IP: ip}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password %d: %v", i, err)
		}
	}
	f.svc.limits.reset("email:" + email)
}

func (f *fixture) countAudit(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := f.st.DB.QueryRow("SELECT count(*) FROM audit_log WHERE action = ?", action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// lockedFor returns how long the account is locked from now, failing when
// the right password is not refused with a *LockedError.
func (f *fixture) lockedFor(t *testing.T, email string) time.Duration {
	t.Helper()
	_, _, err := f.svc.Login(context.Background(), email, goodPassword, Client{IP: "10.8.0.1"})
	var le *LockedError
	if !errors.As(err, &le) || !errors.Is(err, ErrLocked) {
		t.Fatalf("right password on a locked account: %v", err)
	}
	f.svc.limits.reset("email:" + email)
	f.svc.limits.reset("ip:10.8.0.1")
	return le.Until.Sub(f.clock.now())
}

func TestAccountLocksAfterManyFailures(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	ctx := context.Background()

	f.failLogins(t, "a@hangar.dev", LockAfter-1)
	if _, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, Client{IP: "10.0.0.1"}); err != nil {
		t.Fatalf("one failure short of the limit: %v", err)
	}
	// Only a finished login clears the count (the password step alone does
	// not, or the 2FA step could be guessed forever): one more failure locks.
	f.failLogins(t, "a@hangar.dev", 1)
	if got := f.lockedFor(t, "a@hangar.dev"); got != LockBase {
		t.Fatalf("first lock lasts %s, want %s", got, LockBase)
	}
	if n := f.countAudit(t, "auth.account.locked"); n != 1 {
		t.Fatalf("%d lock audit records, want 1", n)
	}

	// A wrong password while locked gets the generic error (no hint that the
	// account exists or is locked) and does not stretch the lock.
	f.failLogins(t, "a@hangar.dev", LockAfter)
	if got := f.lockedFor(t, "a@hangar.dev"); got != LockBase {
		t.Fatalf("lock after more failures while locked: %s, want %s", got, LockBase)
	}

	// The lock ends by itself: no SSH needed.
	f.clock.advance(LockBase)
	if _, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, Client{IP: "10.0.0.2"}); err != nil {
		t.Fatalf("after the lock expired: %v", err)
	}
}

func TestUnlockByCLIEndsTheLock(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	ctx := context.Background()
	f.failLogins(t, "a@hangar.dev", LockAfter)
	f.lockedFor(t, "a@hangar.dev")
	if err := f.svc.Unlock(ctx, "a@hangar.dev"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, Client{IP: "10.0.0.3"}); err != nil {
		t.Fatalf("after unlocking: %v", err)
	}
}

func TestLockDoublesAndCaps(t *testing.T) {
	for n, want := range map[int64]time.Duration{
		1: 15 * time.Minute, 2: 30 * time.Minute, 3: time.Hour, 6: 8 * time.Hour,
		7: 16 * time.Hour, 8: LockMax, 9: LockMax, 1000: LockMax,
	} {
		if got := lockDuration(n); got != want {
			t.Errorf("lock %d: %s, want %s", n, got, want)
		}
	}

	f := newFixture(t)
	_, secret := f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	for i, want := range []time.Duration{LockBase, 2 * LockBase, 4 * LockBase} {
		f.failLogins(t, "a@hangar.dev", LockAfter)
		got := f.lockedFor(t, "a@hangar.dev")
		if got != want {
			t.Fatalf("lock %d in a row: %s, want %s", i+1, got, want)
		}
		f.clock.advance(got)
	}
	// A finished login starts the doubling over.
	f.login(t, "a@hangar.dev", secret)
	f.failLogins(t, "a@hangar.dev", LockAfter)
	if got := f.lockedFor(t, "a@hangar.dev"); got != LockBase {
		t.Fatalf("lock after a success: %s, want %s", got, LockBase)
	}
	// So does a long quiet time after the last lock.
	f.clock.advance(LockBase + LockMax + time.Second)
	f.failLogins(t, "a@hangar.dev", LockAfter)
	if got := f.lockedFor(t, "a@hangar.dev"); got != LockBase {
		t.Fatalf("lock long after the previous one: %s, want %s", got, LockBase)
	}
}

func TestOldFailuresAreForgotten(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	f.failLogins(t, "a@hangar.dev", LockAfter-1)
	f.clock.advance(LockWindow)
	f.failLogins(t, "a@hangar.dev", LockAfter-1)
	if _, _, err := f.svc.Login(context.Background(), "a@hangar.dev", goodPassword, Client{IP: "10.0.0.5"}); err != nil {
		t.Fatalf("failures from another window added up: %v", err)
	}
}

// Wrong 2FA codes count toward the lock too, and a pending step that meets
// a lock is ended with the lock's end time.
func TestSecondFactorFailuresLock(t *testing.T) {
	f := newFixture(t)
	f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	ctx := context.Background()
	f.failLogins(t, "a@hangar.dev", LockAfter-1)
	pending, _, err := f.svc.Login(ctx, "a@hangar.dev", goodPassword, Client{IP: "10.0.0.6"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.LoginSecondFactor(ctx, pending, "000000", Client{IP: "10.0.0.6"}); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong code: %v", err)
	}
	var le *LockedError
	if _, err := f.svc.LoginSecondFactor(ctx, pending, "000000", Client{IP: "10.0.0.6"}); !errors.As(err, &le) {
		t.Fatalf("pending step on a locked account: %v", err)
	}
	if n := f.countAudit(t, "auth.account.locked"); n != 1 {
		t.Fatalf("%d lock audit records, want 1", n)
	}
}

func TestLoginRequiresTOTPWhenConfigured(t *testing.T) {
	f := newFixture(t)
	f.svc.require2FA = true
	ctx := context.Background()
	if _, err := f.svc.CreateUser(ctx, "sem2fa@hangar.dev", goodPassword, RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Login(ctx, "sem2fa@hangar.dev", goodPassword, cli); !errors.Is(err, ErrNoTOTP) {
		t.Fatalf("login without 2FA should be refused, got %v", err)
	}
}

func TestOptionalTOTP(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CreateUser(ctx, "sem2fa@hangar.dev", goodPassword, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	token, complete, err := f.svc.Login(ctx, "sem2fa@hangar.dev", goodPassword, cli)
	if err != nil || !complete {
		t.Fatalf("an account without 2FA signs in with the password: %v %v", complete, err)
	}
	p, err := f.svc.Authenticate(ctx, token)
	if err != nil || p == nil || p.HasTOTP {
		t.Fatalf("principal: %+v %v", p, err)
	}
	if _, _, err := f.svc.Login(ctx, "sem2fa@hangar.dev", "senha-errada-qualquer", cli); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password: %v", err)
	}

	// Sudo without 2FA asks for the password.
	if _, err := f.svc.Sudo(ctx, p, "123456", cli); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("a code is not the password: %v", err)
	}
	sudoCSRF := p.CSRFToken
	token, err = f.svc.Sudo(ctx, p, goodPassword, cli)
	if err != nil {
		t.Fatal(err)
	}
	p, _ = f.svc.Authenticate(ctx, token)
	// Sudo rotates the session token but keeps the CSRF token, so forms already
	// open in the browser keep working instead of failing as "request refused".
	if p.CSRFToken != sudoCSRF {
		t.Errorf("sudo changed the CSRF token: %q -> %q", sudoCSRF, p.CSRFToken)
	}

	// Turning 2FA on from My account.
	secret, _ := NewTOTPSecret()
	if _, err := f.svc.EnableTOTP(ctx, p, secret, "000000", cli); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("wrong code enabling 2FA: %v", err)
	}
	code, _ := totpCode(secret, f.clock.now().Unix()/totpStep)
	codes, err := f.svc.EnableTOTP(ctx, p, secret, code, cli)
	if err != nil || len(codes) != recoveryCount {
		t.Fatalf("enable: %v %d codes", err, len(codes))
	}
	p, _ = f.svc.Authenticate(ctx, token)
	if !p.HasTOTP {
		t.Fatal("the session must see 2FA on")
	}
	if _, complete, err := f.svc.Login(ctx, "sem2fa@hangar.dev", goodPassword, cli); err != nil || complete {
		t.Fatalf("with 2FA on, the password alone must not open a session: %v %v", complete, err)
	}
	if _, err := f.svc.Sudo(ctx, p, goodPassword, cli); err == nil {
		t.Error("with 2FA on, sudo must ask for the code, not the password")
	}

	// Turning it off needs a valid code; then the password works again.
	f.clock.advance(time.Minute)
	if err := f.svc.DisableTOTP(ctx, p, "000000", cli); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("disable with a wrong code: %v", err)
	}
	code, _ = totpCode(secret, f.clock.now().Unix()/totpStep)
	if err := f.svc.DisableTOTP(ctx, p, code, cli); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := f.svc.Login(ctx, "sem2fa@hangar.dev", goodPassword, cli); err != nil || !complete {
		t.Fatalf("after turning 2FA off: %v %v", complete, err)
	}

	f.svc.require2FA = true
	if err := f.svc.DisableTOTP(ctx, p, code, cli); !errors.Is(err, ErrTOTPRequired) {
		t.Errorf("require_2fa forbids turning it off: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, secret := f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)

	idle := f.login(t, "a@hangar.dev", secret)
	f.clock.advance(SessionIdle)
	if p, _ := f.svc.Authenticate(ctx, idle); p != nil {
		t.Error("session idle for 30 min stayed valid")
	}

	f.clock.advance(totpStep * time.Second)
	active := f.login(t, "a@hangar.dev", secret)
	for elapsed := time.Duration(0); elapsed < SessionMax-time.Minute; elapsed += 20 * time.Minute {
		f.clock.advance(20 * time.Minute)
		if p, _ := f.svc.Authenticate(ctx, active); p == nil && elapsed+20*time.Minute < SessionMax {
			t.Fatalf("session in use died before the absolute limit (%v)", elapsed)
		}
	}
	f.clock.advance(time.Hour)
	if p, _ := f.svc.Authenticate(ctx, active); p != nil {
		t.Error("session outlived the 12 h absolute limit")
	}
}

func TestSudoRotatesSession(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, secret := f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	token := f.login(t, "a@hangar.dev", secret)
	p, _ := f.svc.Authenticate(ctx, token)
	if !p.SudoUntil.Before(f.clock.t) && !p.SudoUntil.Equal(time.Unix(0, 0)) {
		t.Fatal("a new session must not start in sudo")
	}

	if _, err := f.svc.Sudo(ctx, p, "000000", cli); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong sudo code: %v", err)
	}
	f.clock.advance(totpStep * time.Second)
	newToken, err := f.svc.Sudo(ctx, p, f.code(t, secret), cli)
	if err != nil {
		t.Fatal(err)
	}
	if old, _ := f.svc.Authenticate(ctx, token); old != nil {
		t.Error("old token should die when entering sudo")
	}
	np, _ := f.svc.Authenticate(ctx, newToken)
	if np == nil || !np.SudoUntil.After(f.clock.t) {
		t.Fatal("new session should be in sudo")
	}
	f.clock.advance(SudoTTL)
	np, _ = f.svc.Authenticate(ctx, newToken)
	if np == nil || np.SudoUntil.After(f.clock.t) {
		t.Error("sudo should expire after 5 min, keeping the session")
	}
}

func TestTOTPSecretIsEncryptedAtRest(t *testing.T) {
	f := newFixture(t)
	id, secret := f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	var stored []byte
	if err := f.st.DB.QueryRow("SELECT totp_secret_enc FROM users WHERE id = ?", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(secret)) {
		t.Fatal("TOTP secret stored in clear text")
	}
}

func TestStillValidDoesNotExtendIdle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, secret := f.userWithTOTP(t, "a@hangar.dev", RoleAdmin)
	token := f.login(t, "a@hangar.dev", secret)

	for range 5 { // 25 min just "watching logs"
		f.clock.advance(5 * time.Minute)
		if !f.svc.StillValid(ctx, token) {
			t.Fatal("session should stay valid within the 30 min")
		}
	}
	f.clock.advance(6 * time.Minute)
	if f.svc.StillValid(ctx, token) {
		t.Fatal("checking the session must not extend the idle timer")
	}
}

func TestArgonPoolBoundsConcurrency(t *testing.T) {
	p := newArgonPool()
	release := make(chan struct{})
	started := make(chan struct{}, argonConcurrent+argonQueue)
	// Fill every running and queue slot.
	for range argonConcurrent + argonQueue {
		go func() {
			_ = p.do(context.Background(), func() { started <- struct{}{}; <-release })
		}()
	}
	for range argonConcurrent {
		<-started
	}
	time.Sleep(50 * time.Millisecond) // let the rest enter the queue
	if err := p.do(context.Background(), func() {}); !errors.Is(err, ErrBusy) {
		t.Fatalf("with a full queue expected ErrBusy, got %v", err)
	}
	close(release)
}
