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
	}
	h.renderAccount(w, r, http.StatusOK, flash, "", nil)
}

func (h *handlers) renderAccount(w http.ResponseWriter, r *http.Request, status int, flash, errMsg string, recovery []string) {
	p := PrincipalFrom(r.Context())
	d := views.AccountData{
		CSRF: p.CSRFToken, Email: p.Email, Name: p.Name, Role: p.Role.String(),
		Locale: p.Locale, Theme: p.Theme, Flash: flash, Error: errMsg,
		TOTP: views.TOTPSection{On: p.HasTOTP || len(recovery) > 0, Required: h.auth.Require2FA(), Recovery: recovery},
	}
	if list, err := h.auth.ListSessions(r.Context(), p); err == nil {
		for _, ss := range list {
			d.Sessions = append(d.Sessions, views.SessionRow{
				ID: ss.ID, Device: ss.Device, IP: ss.IP, Current: ss.Current, LastSeen: ss.LastSeen.Local().Format("02/01 15:04"),
			})
		}
	}
	if !d.TOTP.On {
		// A fresh secret on every visit; it is only stored once a code from
		// the app proves it was scanned.
		secret, err := auth.NewTOTPSecret()
		if err != nil {
			loggerFrom(r.Context()).Error("totp secret", "error", err)
		} else {
			d.TOTP.Secret = secret
			d.TOTP.URI = auth.TOTPURI("Hangar", p.Email, secret)
			if code, err := qr.Encode(d.TOTP.URI, qr.M); err == nil {
				d.TOTP.QR = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
			}
		}
	}
	render(w, r, status, views.Account(d))
}

func (h *handlers) enableTOTP(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	codes, err := h.auth.EnableTOTP(r.Context(), p, r.PostFormValue("secret"), r.PostFormValue("code"), client(r))
	if err != nil {
		msg := i18n.T(r.Context(), "account.totp.error.code")
		if !errors.Is(err, auth.ErrInvalidCode) {
			msg = i18n.Message(i18n.Locale(r.Context()), err)
		}
		h.renderAccount(w, r, http.StatusUnprocessableEntity, "", msg, nil)
		return
	}
	// This response already reflects 2FA on: no banner, and the codes shown once.
	h.renderAccount(w, r.WithContext(views.WithTOTP(r.Context())), http.StatusOK, i18n.T(r.Context(), "account.totp.enabled"), "", codes)
}

func (h *handlers) disableTOTP(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if err := h.auth.DisableTOTP(r.Context(), p, r.PostFormValue("code"), client(r)); err != nil {
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
