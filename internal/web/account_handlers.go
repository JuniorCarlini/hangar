package web

import (
	"encoding/base64"
	"errors"
	"net/http"

	"rsc.io/qr"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

func (h *handlers) accountPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch r.URL.Query().Get("ok") {
	case "saved":
		flash = i18n.T(r.Context(), "account.saved")
	case "totp-off":
		flash = i18n.T(r.Context(), "account.totp.disabled")
	case "session-ended":
		flash = i18n.T(r.Context(), "account.sessions.ended")
	case "security":
		flash = i18n.T(r.Context(), "security.saved")
	}
	h.renderAccount(w, r, http.StatusOK, flash, "", nil)
}

func (h *handlers) renderAccount(w http.ResponseWriter, r *http.Request, status int, flash, errMsg string, recovery []string) {
	p := PrincipalFrom(r.Context())
	d := views.AccountData{
		CSRF: p.CSRFToken, Email: p.Email, Name: p.Name, Role: p.Role.String(),
		Locale: p.Locale, Theme: p.Theme, Flash: flash, Error: errMsg,
		TOTP:     views.TOTPSection{On: p.HasTOTP || len(recovery) > 0, Required: h.auth.RequiredFor(r.Context(), p.Role), Recovery: recovery},
		Security: h.securityCard(r),
	}
	if list, err := h.auth.ListSessions(r.Context(), p); err == nil {
		for _, ss := range list {
			d.Sessions = append(d.Sessions, views.SessionRow{
				ID: ss.ID, Device: ss.Device, IP: ss.IP, Current: ss.Current, LastSeen: ss.LastSeen.Local().Format("02/01 15:04"),
			})
		}
	}
	if !d.TOTP.On {
		d.TOTP.Secret, d.TOTP.URI, d.TOTP.QR = newTOTPSetup(r, p.Email)
	}
	render(w, r, status, views.Account(d))
}

// newTOTPSetup makes a fresh secret, its otpauth link and its QR code (PNG
// data URI). A fresh secret on every visit: it is only stored once a code
// from the app proves it was scanned.
func newTOTPSetup(r *http.Request, email string) (secret, uri, qrURI string) {
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		loggerFrom(r.Context()).Error("totp secret", "error", err)
		return "", "", ""
	}
	uri = auth.TOTPURI("Hangar", email, secret)
	if code, err := qr.Encode(uri, qr.M); err == nil {
		qrURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}
	return secret, uri, qrURI
}

// enrollPage is where an account that must have a second factor and has
// none lands after signing in (the router sends every other page here).
// Anyone else is sent to the 2FA card of "My account".
func (h *handlers) enrollPage(w http.ResponseWriter, r *http.Request) {
	h.renderEnroll(w, r, http.StatusOK, "")
}

func (h *handlers) renderEnroll(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	p := PrincipalFrom(r.Context())
	if !p.MustEnroll {
		http.Redirect(w, r, "/account#totp", http.StatusSeeOther)
		return
	}
	d := views.EnrollData{CSRF: p.CSRFToken, Email: p.Email, Role: p.Role.String(), Error: errMsg}
	d.Secret, d.URI, d.QR = newTOTPSetup(r, p.Email)
	render(w, r, status, views.Enroll(d))
}

func (h *handlers) enableTOTP(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	codes, err := h.auth.EnableTOTP(r.Context(), p, r.PostFormValue("password"), r.PostFormValue("secret"), r.PostFormValue("code"), client(r))
	if err != nil {
		var rl *auth.RateLimitedError
		msg := i18n.T(r.Context(), "account.totp.error.code")
		switch {
		case errors.As(err, &rl):
			msg = i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes())
		case !errors.Is(err, auth.ErrInvalidCode):
			msg = i18n.Message(i18n.Locale(r.Context()), err)
		}
		if p.MustEnroll {
			h.renderEnroll(w, r, http.StatusUnprocessableEntity, msg)
			return
		}
		h.renderAccount(w, r, http.StatusUnprocessableEntity, "", msg, nil)
		return
	}
	if p.MustEnroll {
		// The panel opens from the next request on; the recovery codes are
		// shown once, here.
		render(w, r, http.StatusOK, views.EnrollDone(codes))
		return
	}
	// This response already reflects 2FA on: no banner, and the codes shown once.
	h.renderAccount(w, r.WithContext(views.WithTOTP(r.Context())), http.StatusOK, i18n.T(r.Context(), "account.totp.enabled"), "", codes)
}

func (h *handlers) disableTOTP(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if err := h.auth.DisableTOTP(r.Context(), p, r.PostFormValue("password"), r.PostFormValue("code"), client(r)); err != nil {
		var rl *auth.RateLimitedError
		msg := i18n.T(r.Context(), "account.totp.error.code")
		switch {
		case errors.As(err, &rl):
			msg = i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes())
		case !errors.Is(err, auth.ErrInvalidCode):
			msg = i18n.Message(i18n.Locale(r.Context()), err)
		}
		h.renderAccount(w, r, http.StatusUnprocessableEntity, "", msg, nil)
		return
	}
	http.Redirect(w, r, "/account?ok=totp-off", http.StatusSeeOther)
}

func (h *handlers) savePreferences(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	locale := r.PostFormValue("locale")
	if locale == "auto" { // "follow the browser" (an empty value is a placeholder for the Tucano select)
		locale = ""
	}
	err := h.auth.SetPreferences(r.Context(), p.UserID, locale, r.PostFormValue("theme"), client(r))
	if err == nil && r.PostForm.Has("name") {
		err = h.auth.SetName(r.Context(), p.UserID, r.PostFormValue("name"), client(r))
	}
	if err != nil {
		h.renderAccount(w, r, http.StatusUnprocessableEntity, "", i18n.Message(i18n.Locale(r.Context()), err), nil)
		return
	}
	// The account menu's quick choices go back to the page they came from.
	if next := r.PostFormValue("next"); next != "" {
		http.Redirect(w, r, safeNext(next), http.StatusSeeOther) //nolint:gosec // safeNext only accepts a local path
		return
	}
	http.Redirect(w, r, "/account?ok=saved", http.StatusSeeOther)
}

func (h *handlers) endSession(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if err := h.auth.EndSession(r.Context(), p, r.PostFormValue("id"), client(r)); err != nil {
		h.renderAccount(w, r, http.StatusUnprocessableEntity, "", i18n.T(r.Context(), "error.bad_request"), nil)
		return
	}
	http.Redirect(w, r, "/account?ok=session-ended", http.StatusSeeOther)
}
