package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

func (h *handlers) securityPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	if r.URL.Query().Get("ok") == "saved" {
		flash = i18n.T(r.Context(), "security.saved")
	}
	h.renderSecurity(w, r, http.StatusOK, "", flash)
}

func (h *handlers) renderSecurity(w http.ResponseWriter, r *http.Request, status int, errMsg, flash string) {
	p := PrincipalFrom(r.Context())
	render(w, r, status, views.Security(views.SecurityData{
		CSRF: p.CSRFToken, Level: string(h.auth.Level(r.Context())),
		SudoActive: p.SudoFor(auth.SudoAlways, time.Now()), Error: errMsg, Flash: flash,
	}))
}

func (h *handlers) saveSecurity(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	err := h.auth.SetLevel(r.Context(), p.UserID, auth.Level(r.PostFormValue("level")), client(r))
	if errors.Is(err, auth.ErrUnknownLevel) {
		h.renderSecurity(w, r, http.StatusUnprocessableEntity, i18n.Message(i18n.Locale(r.Context()), err), "")
		return
	}
	if err != nil {
		loggerFrom(r.Context()).Error("security level", "error", err)
		h.renderSecurity(w, r, http.StatusInternalServerError, i18n.T(r.Context(), "error.internal"), "")
		return
	}
	http.Redirect(w, r, "/security?ok=saved", http.StatusSeeOther)
}
