package web

import (
	"context"
	"net/http"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/update"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// updates is what the update page uses from the checker.
type updates interface {
	Current() string
	Latest() (*update.Available, error)
	Check(ctx context.Context) (*update.Available, error)
	Stage(ctx context.Context, version, requestedBy string) error
}

func (h *handlers) updatePage(w http.ResponseWriter, r *http.Request) {
	h.renderUpdate(w, r, http.StatusOK, "", false)
}

func (h *handlers) renderUpdate(w http.ResponseWriter, r *http.Request, status int, flash string, flashErr bool) {
	p := PrincipalFrom(r.Context())
	d := views.UpdateData{
		CSRF:       p.CSRFToken,
		Current:    h.updates.Current(),
		Pending:    update.Pending(h.updateDir),
		SudoActive: time.Now().Before(p.SudoUntil),
		Flash:      flash,
		FlashError: flashErr,
	}
	if av, err := h.updates.Latest(); av != nil {
		d.Available, d.Notes, d.ReleaseURL = av.Version, av.Notes, av.URL
	} else if err != nil {
		d.CheckError = i18n.Message(i18n.Locale(r.Context()), err)
	}
	if st, err := update.ReadStatus(h.updateDir); err == nil && st != nil {
		d.Last = &views.UpdateStatus{
			State: st.State, Version: st.Version, From: st.From, Message: st.Message,
			At: st.At.Local().Format("02/01/2006 15:04"),
		}
	}
	render(w, r, status, views.Update(d))
}

func (h *handlers) updateCheck(w http.ResponseWriter, r *http.Request) {
	if _, err := h.updates.Check(r.Context()); err != nil {
		h.renderUpdate(w, r, http.StatusBadGateway, i18n.T(r.Context(), "update.error.check", "error", i18n.Message(i18n.Locale(r.Context()), err)), true)
		return
	}
	http.Redirect(w, r, "/update", http.StatusSeeOther)
}

func (h *handlers) updateApply(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	version := r.PostFormValue("version")
	if update.Pending(h.updateDir) {
		h.renderUpdate(w, r, http.StatusConflict, i18n.T(r.Context(), "update.error.pending"), true)
		return
	}
	if err := h.updates.Stage(r.Context(), version, p.UserID); err != nil {
		h.renderUpdate(w, r, http.StatusUnprocessableEntity, i18n.T(r.Context(), "update.error.refused", "error", i18n.Message(i18n.Locale(r.Context()), err)), true)
		return
	}
	http.Redirect(w, r, "/update", http.StatusSeeOther)
}
