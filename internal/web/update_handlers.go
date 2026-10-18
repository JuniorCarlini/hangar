package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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
	// The status file only holds the last apply; every finished one is in
	// the audit log (recorded when the new version starts).
	d.Busy = d.Pending
	if st, err := update.ReadStatus(h.updateDir); err == nil && st != nil && st.State == "applying" {
		d.Busy = true
		d.History = append(d.History, views.UpdateStatus{
			State: st.State, Version: st.Version, From: st.From, Message: st.Message,
			At: st.At.Local().Format("02/01/2006 15:04"),
		})
	}
	rows, err := h.audit.Recent(r.Context(), []string{"system.update.ok", "system.update.rolled_back", "system.update.failed"}, 50)
	if err != nil {
		loggerFrom(r.Context()).Error("update history", "error", err)
	}
	for _, row := range rows {
		var s struct{ From, To, Message string }
		_ = json.Unmarshal([]byte(row.SummaryJson), &s)
		d.History = append(d.History, views.UpdateStatus{
			State: strings.TrimPrefix(row.Action, "system.update."), Version: s.To, From: s.From, Message: s.Message,
			At: auditTime(row.Ts),
		})
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

// auditTime formats an audit record's timestamp for a table.
func auditTime(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ""
	}
	return t.Local().Format("02/01/2006 15:04")
}
