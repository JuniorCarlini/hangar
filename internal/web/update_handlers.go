package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/release"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/update"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// updates is what the update page uses from the checker.
type updates interface {
	Current() string
	Latest() (*update.Available, error)
	Check(ctx context.Context) (*update.Available, error)
	Stage(ctx context.Context, version, requestedBy string) error
	CanApply() bool
}

func (h *handlers) updatePage(w http.ResponseWriter, r *http.Request) {
	h.renderUpdate(w, r, http.StatusOK, "", false)
}

func (h *handlers) renderUpdate(w http.ResponseWriter, r *http.Request, status int, flash string, flashErr bool) {
	p := PrincipalFrom(r.Context())
	// A request left where no applier looks (a panel run by hand) would
	// keep the page waiting forever.
	if !h.updates.CanApply() && update.Pending(h.updateDir) {
		if err := update.DropRequest(h.updateDir); err != nil {
			loggerFrom(r.Context()).Error("drop update request", "error", err)
		}
	}
	d := views.UpdateData{
		CSRF:       p.CSRFToken,
		Current:    h.updates.Current(),
		NoApplier:  !h.updates.CanApply(),
		Pending:    update.Pending(h.updateDir),
		SudoActive: p.SudoFor(auth.SudoStrict, time.Now()),
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
	st, stErr := update.ReadStatus(h.updateDir)
	if ask := h.updateAsked.Load(); ask != nil && ask.waiting(d.Current, st, time.Now()) {
		d.Busy = true
	}
	if err := stErr; err == nil && st != nil && st.State == "applying" {
		d.Busy = true
		d.History = append(d.History, views.UpdateStatus{
			State: st.State, Version: st.Version, From: st.From, Message: st.Message,
			At: st.At.Local().Format("02/01/2006 15:04"),
		})
	}
	rows, err := h.audit.Recent(r.Context(), []string{"system.update.request", "system.start", "system.update.rolled_back", "system.update.failed"}, 500)
	if err != nil {
		loggerFrom(r.Context()).Error("update history", "error", err)
	}
	d.History = append(d.History, updateHistory(rows)...)
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
	// A click that comes while that update is on its way, or after it was
	// applied (a second click, a page left open), just shows where it is:
	// the request is already in, there is nothing to refuse.
	if up, err := release.IsUpgrade(h.updates.Current(), version); update.Pending(h.updateDir) || (err == nil && !up) {
		http.Redirect(w, r, "/update", http.StatusSeeOther)
		return
	}
	if err := h.updates.Stage(r.Context(), version, p.UserID); err != nil {
		if errors.Is(err, update.ErrPending) {
			http.Redirect(w, r, "/update", http.StatusSeeOther)
			return
		}
		h.renderUpdate(w, r, http.StatusUnprocessableEntity, i18n.T(r.Context(), "update.error.refused", "error", i18n.Message(i18n.Locale(r.Context()), err)), true)
		return
	}
	h.updateAsked.Store(&updateAsk{version: version, at: time.Now()})
	http.Redirect(w, r, "/update", http.StatusSeeOther)
}

// updateAsk is an update this process requested.
type updateAsk struct {
	version string
	at      time.Time
}

// waiting reports whether the page should still wait for the update: it is
// not running yet, the applier has not finished it (no result written
// after the request) and it was asked recently (a lost request must not
// keep the page waiting forever).
func (a *updateAsk) waiting(current string, st *update.Status, now time.Time) bool {
	if current == a.version || now.Sub(a.at) > 15*time.Minute {
		return false
	}
	return st == nil || st.At.Before(a.at) || st.State == "applying"
}

// auditTime formats an audit record's timestamp for a table.
func auditTime(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ""
	}
	return t.Local().Format("02/01/2006 15:04")
}

// updateHistory rebuilds the updates applied from the panel out of the
// audit log, newest first: each update request, the version running before
// it and the version that started after it (the same one = rolled back).
// Updates installed from the command line have no request and are left
// out. A rolled_back or failed record adds its reason.
func updateHistory(rows []dbq.RecentActivityRow) []views.UpdateStatus {
	var out []views.UpdateStatus
	running, pending := "", -1
	for i := len(rows) - 1; i >= 0; i-- { // oldest first
		row := rows[i]
		var sum struct{ Version, To, Message string }
		_ = json.Unmarshal([]byte(row.SummaryJson), &sum)
		switch row.Action {
		case "system.update.rolled_back", "system.update.failed":
			// Recorded once the old version is back: it names the
			// version that was tried and why it was undone.
			if n := len(out); n > 0 && out[n-1].State == "rolled_back" {
				out[n-1].Version, out[n-1].Message = sum.To, sum.Message
				if row.Action == "system.update.failed" {
					out[n-1].State = "failed"
				}
			}
		case "system.update.request":
			out = append(out, views.UpdateStatus{From: running, At: auditTime(row.Ts), State: "applying"})
			pending = len(out) - 1
		case "system.start":
			if pending >= 0 {
				u := &out[pending]
				u.Version = sum.Version
				u.State = "ok"
				if sum.Version == u.From {
					u.State = "rolled_back"
				}
				pending = -1
			}
			running = sum.Version
		}
	}
	// Requests that never got a start (the panel is still on its way up)
	// are not history yet.
	done := out[:0]
	for _, u := range out {
		if u.State != "applying" {
			done = append(done, u)
		}
	}
	for i, j := 0, len(done)-1; i < j; i, j = i+1, j-1 {
		done[i], done[j] = done[j], done[i]
	}
	return done
}
