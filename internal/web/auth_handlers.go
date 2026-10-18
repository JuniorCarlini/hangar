package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/JuniorCarlini/hangar/internal/alerts"
	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/errpages"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/lockdown"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/statuspage"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// Cookies with the __Host- prefix: browsers only accept them with Secure,
// Path=/ and no Domain, so they never leak to subdomains or travel without
// TLS.
const (
	sessionCookie = "__Host-hangar_session"
	pendingCookie = "__Host-hangar_pending"
	langCookie    = "__Host-hangar_lang"
	// loginCookie holds the login form's double-submit CSRF token. Another
	// site cannot set or read a __Host- cookie of the panel, so it cannot
	// forge a matching form (login CSRF: logging the victim into the
	// attacker's account).
	loginCookie = "__Host-hangar_login"
	loginTTL    = time.Hour
)

// withLoginToken makes sure the browser has a login token (cookie) and
// returns the request carrying it, for rendering the form.
func withLoginToken(w http.ResponseWriter, r *http.Request) *http.Request {
	tok := ""
	if c, err := r.Cookie(loginCookie); err == nil && len(c.Value) == 43 {
		tok = c.Value
	} else {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		tok = base64.RawURLEncoding.EncodeToString(b)
		setCookie(w, loginCookie, tok, loginTTL)
	}
	return r.WithContext(views.WithLoginCSRF(r.Context(), tok))
}

// validLoginToken checks the form's token against the cookie.
func validLoginToken(r *http.Request) bool {
	c, err := r.Cookie(loginCookie)
	return err == nil && auth.EqualCSRF(r.PostFormValue("csrf"), c.Value)
}

type handlers struct {
	errorPages func(map[string][]byte) error
	brand      *errpages.Store
	serverIP   string
	baseDomain string
	autoLinkIP string
	auth       *auth.Service
	updates    updates
	updateDir  string
	panelURL   string
	projects   *projects.Manager
	metrics    *metrics.Collector
	audit      *audit.Logger
	deps       *deps.Monitor
	status     *statuspage.Service
	pub        *publicStatus
	// statusBase is the public base URL of status links ("" = the panel's).
	statusBase string
	alerts     *alerts.Service
	lock       *lockdown.Lock
	hooksBase  string
	// hookFails counts failed webhook deliveries per address.
	hookFails *ipRate
	backups   *backup.Manager
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(maxAge.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		loggerFrom(r.Context()).Error("render page", "error", err)
	}
}

func client(r *http.Request) auth.Client {
	return auth.Client{IP: clientIP(r), UserAgent: r.UserAgent()}
}

func (h *handlers) loginPage(w http.ResponseWriter, r *http.Request) {
	if p, _ := h.auth.Authenticate(r.Context(), sessionToken(r)); p != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// ?lang= picks the language before login; it lives in a cookie.
	if l := r.URL.Query().Get("lang"); l != "" {
		if i18n.Supported(l) {
			setCookie(w, langCookie, l, 365*24*time.Hour)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// No account yet: the first visit creates the owner.
	if st, _ := h.auth.Setup(r.Context()); st != auth.SetupDone {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	msg := ""
	if r.URL.Query().Get("expired") == "1" {
		msg = i18n.T(r.Context(), "login.error.expired")
	}
	render(w, withLoginToken(w, r), http.StatusOK, views.Login("", msg, h.lockNotice(r)))
}

func (h *handlers) setupForm(r *http.Request, until time.Time) views.SetupForm {
	return views.SetupForm{
		Email: strings.TrimSpace(r.PostFormValue("email")), TwoFA: true,
		Required: h.auth.Require2FA(), MinLen: auth.MinPasswordLen,
		MinutesLeft: max(1, int(time.Until(until).Minutes()+0.999)),
	}
}

// setupClosed answers a setup request once the owner can no longer be
// created there: to the login when someone already has an account, or the
// "window closed" page while there is still no user.
func (h *handlers) setupClosed(w http.ResponseWriter, r *http.Request, st auth.SetupState) {
	if st == auth.SetupExpired {
		render(w, r, http.StatusForbidden, views.SetupExpired(auth.SetupWindow))
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *handlers) setupPage(w http.ResponseWriter, r *http.Request) {
	st, until := h.auth.Setup(r.Context())
	if st != auth.SetupAvailable {
		h.setupClosed(w, r, st)
		return
	}
	// ?lang= picks the language, as on the login page.
	if l := r.URL.Query().Get("lang"); l != "" {
		if i18n.Supported(l) {
			setCookie(w, langCookie, l, 365*24*time.Hour)
		}
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	render(w, withLoginToken(w, r), http.StatusOK, views.Setup(h.setupForm(r, until), ""))
}

func (h *handlers) setupSubmit(w http.ResponseWriter, r *http.Request) {
	st, until := h.auth.Setup(r.Context())
	if st != auth.SetupAvailable {
		h.setupClosed(w, r, st)
		return
	}
	valid := validLoginToken(r)
	form := withLoginToken(w, r)
	f := h.setupForm(r, until)
	f.TwoFA = f.Required || r.PostFormValue("twofa") == "1"
	if !valid {
		render(w, form, http.StatusForbidden, views.Setup(f, i18n.T(r.Context(), "login.error.form_expired")))
		return
	}
	password := r.PostFormValue("password")
	if password != r.PostFormValue("confirm") {
		render(w, form, http.StatusUnprocessableEntity, views.Setup(f, i18n.T(r.Context(), "setup.error.mismatch")))
		return
	}
	token, err := h.auth.CreateOwner(r.Context(), f.Email, password, client(r))

	var rl *auth.RateLimitedError
	var ie *i18n.Error
	switch {
	case err == nil:
		setCookie(w, sessionCookie, token, auth.SessionMax)
		if f.TwoFA {
			// Straight to the 2FA card of "My account", where the QR code is.
			http.Redirect(w, r, "/account#totp", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case errors.Is(err, auth.ErrSetupClosed):
		st, _ := h.auth.Setup(r.Context())
		h.setupClosed(w, r, st)
	case errors.As(err, &rl):
		render(w, form, http.StatusTooManyRequests, views.Setup(f, i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes())))
	case errors.As(err, &ie):
		render(w, form, http.StatusUnprocessableEntity, views.Setup(f, i18n.Message(i18n.Locale(r.Context()), err)))
	default:
		loggerFrom(r.Context()).Error("setup", "error", err)
		render(w, form, http.StatusInternalServerError, views.Setup(f, i18n.T(r.Context(), "error.internal")))
	}
}

// lockNotice tells whoever reaches the login page (only possible from the
// server itself) that the panel is locked.
func (h *handlers) lockNotice(r *http.Request) string {
	if h.lock == nil || !h.lock.Locked(r.Context()) {
		return ""
	}
	return i18n.T(r.Context(), "lock.login_notice")
}

func (h *handlers) loginSubmit(w http.ResponseWriter, r *http.Request) {
	valid := validLoginToken(r)
	form := withLoginToken(w, r) // renders the form again with the token
	email := strings.TrimSpace(r.PostFormValue("email"))
	if !valid {
		// Not counted as a failed login: nothing was checked yet.
		render(w, form, http.StatusForbidden, views.Login(email, i18n.T(r.Context(), "login.error.form_expired"), ""))
		return
	}
	token, complete, err := h.auth.Login(r.Context(), email, r.PostFormValue("password"), client(r))

	var rl *auth.RateLimitedError
	switch {
	case err == nil && complete:
		// Account without 2FA: the session is already active.
		setCookie(w, sessionCookie, token, auth.SessionMax)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case err == nil:
		setCookie(w, pendingCookie, token, auth.PendingTTL)
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
	case errors.As(err, &rl):
		render(w, form, http.StatusTooManyRequests, views.Login(email, i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes()), ""))
	case errors.Is(err, auth.ErrBusy):
		render(w, form, http.StatusServiceUnavailable, views.Login(email, i18n.T(r.Context(), "login.error.busy"), ""))
	case errors.Is(err, auth.ErrNoTOTP):
		render(w, form, http.StatusUnauthorized, views.Login(email, i18n.T(r.Context(), "login.error.no_totp", "email", email), ""))
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrLocked):
		// One message for wrong credentials and a locked account: it never
		// reveals which accounts exist.
		render(w, form, http.StatusUnauthorized, views.Login(email, i18n.T(r.Context(), "login.error.bad_credentials"), ""))
	default:
		loggerFrom(r.Context()).Error("login", "error", err)
		render(w, form, http.StatusInternalServerError, views.Login(email, i18n.T(r.Context(), "error.internal"), ""))
	}
}

func (h *handlers) twoFactorPage(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(pendingCookie); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	render(w, r, http.StatusOK, views.TwoFactor(""))
}

func (h *handlers) twoFactorSubmit(w http.ResponseWriter, r *http.Request) {
	pending, err := r.Cookie(pendingCookie)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	token, err := h.auth.LoginSecondFactor(r.Context(), pending.Value, r.PostFormValue("code"), client(r))

	var rl *auth.RateLimitedError
	switch {
	case err == nil:
		clearCookie(w, pendingCookie)
		setCookie(w, sessionCookie, token, auth.SessionMax)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case errors.Is(err, auth.ErrPendingExpired):
		clearCookie(w, pendingCookie)
		http.Redirect(w, r, "/login?expired=1", http.StatusSeeOther)
	case errors.As(err, &rl):
		render(w, r, http.StatusTooManyRequests, views.TwoFactor(i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes())))
	case errors.Is(err, auth.ErrInvalidCode):
		render(w, r, http.StatusUnauthorized, views.TwoFactor(i18n.T(r.Context(), "twofa.error.invalid")))
	default:
		loggerFrom(r.Context()).Error("2fa", "error", err)
		render(w, r, http.StatusInternalServerError, views.TwoFactor(i18n.T(r.Context(), "error.internal")))
	}
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.Logout(r.Context(), sessionToken(r)); err != nil {
		loggerFrom(r.Context()).Error("logout", "error", err)
	}
	clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// sudo confirms 2FA again and sends the user back where they were.
func (h *handlers) sudo(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	token, err := h.auth.Sudo(r.Context(), p, r.PostFormValue("code"), client(r))

	var rl *auth.RateLimitedError
	switch {
	case err == nil:
		setCookie(w, sessionCookie, token, auth.SessionMax)
		http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther) //nolint:gosec // safeNext only accepts a local path
	case errors.As(err, &rl):
		http.Error(w, i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes()), http.StatusTooManyRequests)
	case errors.Is(err, auth.ErrInvalidCode):
		http.Error(w, i18n.T(r.Context(), "twofa.error.invalid"), http.StatusUnauthorized)
	default:
		loggerFrom(r.Context()).Error("sudo", "error", err)
		http.Error(w, i18n.T(r.Context(), "error.internal"), http.StatusInternalServerError)
	}
}

// safeNext only accepts a local path: it prevents an open redirect to a
// phishing site (/sudo?next=https://evil).
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return "/"
	}
	return next
}
