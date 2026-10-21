package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// securityCard is the security level card of "My account", for the owner
// only (nil for everyone else).
func (h *handlers) securityCard(r *http.Request) *views.SecurityData {
	p := PrincipalFrom(r.Context())
	if p.Role < auth.RoleOwner {
		return nil
	}
	return &views.SecurityData{
		CSRF: p.CSRFToken, Level: string(h.auth.Level(r.Context())),
		SudoActive: p.SudoFor(auth.SudoAlways, time.Now()),
	}
}

func (h *handlers) saveSecurity(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	err := h.auth.SetLevel(r.Context(), p.UserID, auth.Level(r.PostFormValue("level")), client(r))
	if errors.Is(err, auth.ErrUnknownLevel) {
		h.renderAccount(w, r, http.StatusUnprocessableEntity, "", i18n.Message(i18n.Locale(r.Context()), err), nil)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).Error("security level", "error", err)
		h.renderAccount(w, r, http.StatusInternalServerError, "", i18n.T(r.Context(), "error.internal"), nil)
		return
	}
	http.Redirect(w, r, "/account?ok=security#security", http.StatusSeeOther)
}
