package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/JuniorCarlini/hangar/internal/alerts"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

const (
	historySize    = 50
	deliveriesSize = 30
	bellSize       = 6
)

// alertFlashes are the ?ok= values the page confirms with a toast.
var alertFlashes = []string{"channel-added", "channel-deleted", "channel-paused", "channel-resumed", "tested", "rules", "muted", "unmuted"}

func alertActor(r *http.Request) alerts.Actor {
	p := PrincipalFrom(r.Context())
	return alerts.Actor{UserID: p.UserID, IP: clientIP(r)}
}

// alertRow renders a stored alert in the reader's language.
func alertRow(r *http.Request, a dbq.Alert) views.AlertRow {
	params := map[string]string{}
	_ = json.Unmarshal([]byte(a.ParamsJson), &params)
	title, text := alerts.Texts(i18n.Locale(r.Context()), a.Kind, a.Resolved == 1, params)
	return views.AlertRow{
		Title: title, Text: text, Severity: a.Severity, When: time.Unix(a.CreatedAt, 0).Format("02/01 15:04"),
		Security: a.Category == string(alerts.Security), Resolved: a.Resolved == 1, Muted: a.Muted == 1,
		Repeats: int(a.Repeats),
	}
}

// bell fills the top bar's alert dropdown.
func (h *handlers) bell(r *http.Request, p *auth.Principal, n *views.Nav) {
	if h.alerts == nil {
		return
	}
	sec := p.Role >= auth.RoleAdmin
	list, err := h.alerts.Recent(r.Context(), sec, bellSize)
	if err != nil {
		return
	}
	for _, a := range list {
		n.Alerts = append(n.Alerts, alertRow(r, a))
	}
	n.AlertsUnread, _ = h.alerts.Unread(r.Context(), p.UserID, sec)
}

type alertsView struct {
	status   int
	errMsg   string
	flash    string
	revealed *views.RevealedSecret
	form     views.ChannelForm
}

func (h *handlers) alertsPage(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	flash := ""
	if ok := r.URL.Query().Get("ok"); slices.Contains(alertFlashes, ok) {
		flash = i18n.T(r.Context(), "alerts.flash."+ok)
	}
	h.renderAlerts(w, r, alertsView{status: http.StatusOK, flash: flash})
	// Opening the page counts as having seen the alerts.
	p := PrincipalFrom(r.Context())
	_ = h.alerts.MarkSeen(r.Context(), p.UserID, p.Role >= auth.RoleAdmin)
}

func (h *handlers) renderAlerts(w http.ResponseWriter, r *http.Request, v alertsView) {
	ctx := r.Context()
	p := PrincipalFrom(ctx)
	admin := p.Role >= auth.RoleAdmin
	d := views.AlertsData{
		CSRF: p.CSRFToken, CanAdmin: admin, SudoActive: time.Now().Before(p.SudoUntil),
		Security: alerts.SecurityKinds, Revealed: v.revealed, Form: v.form, Error: v.errMsg, Flash: v.flash,
	}
	if until := h.alerts.MutedUntil(ctx); !until.IsZero() {
		d.MutedUntil = until.Format("02/01 15:04")
	}
	if rules, err := h.alerts.RuleSettings(ctx); err == nil {
		for _, rs := range rules {
			d.Rules = append(d.Rules, views.RuleRow{
				Kind: rs.Kind, Enabled: rs.Enabled, Threshold: rs.Threshold > 0, Value: rs.Value, Min: rs.Min, Max: rs.Max,
			})
		}
	}
	if list, err := h.alerts.Recent(ctx, admin, historySize); err == nil {
		for _, a := range list {
			d.History = append(d.History, alertRow(r, a))
		}
	}
	if admin {
		if chans, err := h.alerts.Channels(ctx); err == nil {
			for _, c := range chans {
				d.Channels = append(d.Channels, views.ChannelRow{
					ID: c.ID, Name: c.Name, Kind: c.Kind, Target: c.Target, MinSeverity: c.MinSeverity, Enabled: c.Enabled == 1,
				})
			}
		}
		if dl, err := h.alerts.Deliveries(ctx, deliveriesSize); err == nil {
			for _, x := range dl {
				title := i18n.T(ctx, "alert.title.test")
				if x.Kind != "test" {
					title, _ = alerts.Texts(i18n.Locale(ctx), x.Kind, false, nil)
				}
				d.Deliveries = append(d.Deliveries, views.DeliveryRow{
					When: time.Unix(x.CreatedAt, 0).Format("02/01 15:04:05"), Channel: x.ChannelName, Kind: x.ChannelKind,
					Alert: title, Status: x.Status, Attempts: int(x.Attempts), Error: x.Error,
				})
			}
		}
	}
	render(w, r, v.status, views.Alerts(d))
}

// alertsError shows a failed action on the page.
func (h *handlers) alertsError(w http.ResponseWriter, r *http.Request, err error) {
	code, msg := alertsUserError(r, err)
	h.renderAlerts(w, r, alertsView{status: code, errMsg: msg})
}

func alertsUserError(r *http.Request, err error) (int, string) {
	loc := i18n.Locale(r.Context())
	if errors.Is(err, alerts.ErrChannelNotFound) {
		return http.StatusNotFound, i18n.Message(loc, err)
	}
	return userError(r, err)
}

func (h *handlers) createChannel(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	kind := r.PostFormValue("kind")
	form := views.ChannelForm{
		Kind: kind, Name: r.PostFormValue("name"), MinSeverity: r.PostFormValue("min_severity"),
		ChatID: r.PostFormValue("chat_id"), Host: r.PostFormValue("host"), Port: r.PostFormValue("port"),
		Security: r.PostFormValue("security"), Username: r.PostFormValue("username"), From: r.PostFormValue("from"),
		To: r.PostFormValue("to"), URL: r.PostFormValue("url"),
	}
	port, err := alerts.ParsePort(form.Port)
	if err == nil {
		_, err = h.alerts.CreateChannel(r.Context(), alertActor(r), alerts.NewChannel{
			Kind: kind, Name: form.Name, MinSeverity: form.MinSeverity,
			Config: alerts.Config{
				BotToken: r.PostFormValue("bot_token"), ChatID: form.ChatID,
				Host: form.Host, Port: port, Security: form.Security, Username: form.Username,
				Password: r.PostFormValue("password"), From: form.From, To: alerts.ParseRecipients(form.To),
				URL: form.URL, Secret: r.PostFormValue("secret"),
			},
		})
	}
	if err != nil {
		code, msg := alertsUserError(r, err)
		if !slices.Contains(views.ChannelKinds, kind) {
			h.renderAlerts(w, r, alertsView{status: code, errMsg: msg})
			return
		}
		form.Error = msg
		h.renderAlerts(w, r, alertsView{status: code, form: form})
		return
	}
	redirectLocal(w, r, "/alerts?ok=channel-added#channels")
}

func (h *handlers) testChannel(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	if err := h.alerts.TestChannel(r.Context(), alertActor(r), r.PathValue("id")); err != nil {
		h.alertsError(w, r, err)
		return
	}
	redirectLocal(w, r, "/alerts?ok=tested#deliveries")
}

func (h *handlers) revealChannel(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	v, err := h.alerts.RevealSecret(r.Context(), alertActor(r), id)
	if err != nil {
		h.alertsError(w, r, err)
		return
	}
	name := id
	if chans, err := h.alerts.Channels(r.Context()); err == nil {
		for _, c := range chans {
			if c.ID == id {
				name = c.Name
			}
		}
	}
	h.renderAlerts(w, r, alertsView{status: http.StatusOK, revealed: &views.RevealedSecret{Name: name, Value: v}})
}

func (h *handlers) toggleChannel(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	on := r.PostFormValue("enabled") == "1"
	if err := h.alerts.SetChannelEnabled(r.Context(), alertActor(r), r.PathValue("id"), on); err != nil {
		h.alertsError(w, r, err)
		return
	}
	ok := "channel-paused"
	if on {
		ok = "channel-resumed"
	}
	redirectLocal(w, r, "/alerts?ok="+ok+"#channels")
}

func (h *handlers) deleteChannel(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	if err := h.alerts.DeleteChannel(r.Context(), alertActor(r), r.PathValue("id")); err != nil {
		h.alertsError(w, r, err)
		return
	}
	redirectLocal(w, r, "/alerts?ok=channel-deleted#channels")
}

func (h *handlers) saveAlertRules(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	var in []alerts.RuleInput
	for _, kind := range r.PostForm["rule"] {
		ri := alerts.RuleInput{Kind: kind, Enabled: r.PostFormValue("on_"+kind) == "1"}
		if v := r.PostFormValue("v_" + kind); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				h.alertsError(w, r, i18n.E("alerts.error.rule"))
				return
			}
			ri.Value = n
		}
		in = append(in, ri)
	}
	if err := h.alerts.SaveRules(r.Context(), alertActor(r), in); err != nil {
		h.alertsError(w, r, err)
		return
	}
	redirectLocal(w, r, "/alerts?ok=rules#rules")
}

func (h *handlers) muteAlerts(w http.ResponseWriter, r *http.Request) {
	if h.alerts == nil {
		http.NotFound(w, r)
		return
	}
	minutes, err := strconv.Atoi(r.PostFormValue("minutes"))
	if err != nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	if err := h.alerts.Mute(r.Context(), alertActor(r), time.Duration(minutes)*time.Minute); err != nil {
		h.alertsError(w, r, err)
		return
	}
	ok := "muted"
	if minutes == 0 {
		ok = "unmuted"
	}
	redirectLocal(w, r, "/alerts?ok="+ok)
}

func (h *handlers) markAlertsSeen(w http.ResponseWriter, r *http.Request) {
	if h.alerts != nil {
		p := PrincipalFrom(r.Context())
		if err := h.alerts.MarkSeen(r.Context(), p.UserID, p.Role >= auth.RoleAdmin); err != nil {
			loggerFrom(r.Context()).Error("mark alerts seen", "error", err)
		}
	}
	http.Redirect(w, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther) //nolint:gosec // safeNext only accepts a local path
}

// lockPanel is the panic button: every session ends (this one too) and the
// panel only answers on the server itself until `hangard lockdown off`.
func (h *handlers) lockPanel(w http.ResponseWriter, r *http.Request) {
	if h.lock == nil {
		http.NotFound(w, r)
		return
	}
	p := PrincipalFrom(r.Context())
	if _, err := h.lock.Engage(r.Context(), p.UserID, clientIP(r), "panel"); err != nil {
		loggerFrom(r.Context()).Error("lockdown", "error", err)
		http.Error(w, i18n.T(r.Context(), "error.internal"), http.StatusInternalServerError)
		return
	}
	clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
