package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

func (h *handlers) teamPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch r.URL.Query().Get("ok") {
	case "updated":
		flash = i18n.T(r.Context(), "team.updated")
	case "removed":
		flash = i18n.T(r.Context(), "team.removed")
	case "cancelled":
		flash = i18n.T(r.Context(), "team.cancelled")
	case "2fa-required":
		flash = i18n.T(r.Context(), "team.twofa.required_on")
	case "2fa-optional":
		flash = i18n.T(r.Context(), "team.twofa.required_off")
	}
	h.renderTeam(w, r, http.StatusOK, views.TeamData{Flash: flash})
}

func (h *handlers) renderTeam(w http.ResponseWriter, r *http.Request, status int, d views.TeamData) {
	ctx := r.Context()
	p := PrincipalFrom(ctx)
	d.CSRF, d.SudoActive = p.CSRFToken, p.SudoFor(auth.SudoCritical, time.Now())
	d.Require2FA, d.SudoAlways = h.auth.Require2FA(ctx), p.SudoFor(auth.SudoAlways, time.Now())
	members, invites, err := h.auth.Team(ctx)
	if err != nil {
		loggerFrom(ctx).Error("team", "error", err)
	}
	for _, m := range members {
		row := views.TeamMember{
			ID: m.ID, Email: m.Email, Name: m.Name, Role: m.Access.Role.String(), AllProjects: m.Access.AllProjects,
			Projects: m.Access.Projects, HasTOTP: m.HasTOTP, Locked: m.Locked, Self: m.ID == p.UserID,
			TwoFAPending: !m.HasTOTP && h.auth.RequiredFor(ctx, m.Access.Role),
		}
		if !m.LastSeen.IsZero() {
			row.LastSeen = m.LastSeen.Local().Format("02/01 15:04")
		}
		if m.Access.Role >= auth.RoleAdmin {
			row.AllProjects = true
		}
		d.Members = append(d.Members, row)
	}
	for _, inv := range invites {
		d.Invites = append(d.Invites, views.TeamInvite{
			ID: inv.ID, Email: inv.Email, Role: inv.Access.Role.String(), AllProjects: inv.Access.AllProjects,
			Projects: inv.Access.Projects, Expires: inv.ExpiresAt.Local().Format("02/01 15:04"),
		})
	}
	if list, err := h.projects.ListProjects(ctx); err == nil {
		for _, pr := range list {
			d.Projects = append(d.Projects, views.TeamProject{Slug: pr.Slug, Name: pr.Name, Services: int(pr.Services)})
		}
	}
	render(w, r, status, views.Team(d))
}

// teamRequire2FA makes every account need a second factor, the owner's
// included; the ones without it (the caller too) enroll at their next page.
func (h *handlers) teamRequire2FA(w http.ResponseWriter, r *http.Request) {
	h.setRequire2FA(w, r, true)
}

// teamOptional2FA lets every account sign in without a second factor (it
// stays recommended). The route asks for sudo at
// every level, and the page asks for a red confirmation first.
func (h *handlers) teamOptional2FA(w http.ResponseWriter, r *http.Request) {
	h.setRequire2FA(w, r, false)
}

func (h *handlers) setRequire2FA(w http.ResponseWriter, r *http.Request, on bool) {
	p := PrincipalFrom(r.Context())
	if err := h.auth.SetRequire2FA(r.Context(), p.UserID, on, client(r)); err != nil {
		loggerFrom(r.Context()).Error("require 2FA", "error", err)
		h.renderTeam(w, r, http.StatusInternalServerError, views.TeamData{Error: i18n.T(r.Context(), "error.internal")})
		return
	}
	ok := "2fa-optional"
	if on {
		ok = "2fa-required"
	}
	http.Redirect(w, r, "/team?ok="+ok+"#security", http.StatusSeeOther)
}

// accessFromForm reads the role and project pickers.
func accessFromForm(r *http.Request) (auth.Access, error) {
	role, err := auth.ParseRole(r.PostFormValue("role"))
	if err != nil {
		return auth.Access{}, err
	}
	a := auth.Access{Role: role, AllProjects: r.PostFormValue("scope") != "some"}
	if !a.AllProjects {
		a.Projects = r.PostForm["projects"]
	}
	return a, nil
}

func (h *handlers) teamInvite(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	a, err := accessFromForm(r)
	if err == nil {
		var token string
		token, err = h.auth.CreateInvite(r.Context(), p, strings.TrimSpace(r.PostFormValue("email")), a, client(r))
		if err == nil {
			h.renderTeam(w, r, http.StatusOK, views.TeamData{InviteLink: h.panelBase(r) + "/invite/" + token})
			return
		}
	}
	h.renderTeam(w, r, http.StatusUnprocessableEntity, views.TeamData{Error: i18n.Message(i18n.Locale(r.Context()), err), InviteOpen: true})
}

func (h *handlers) teamCancelInvite(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.CancelInvite(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), client(r)); err != nil {
		h.renderTeam(w, r, http.StatusUnprocessableEntity, views.TeamData{Error: i18n.Message(i18n.Locale(r.Context()), err)})
		return
	}
	http.Redirect(w, r, "/team?ok=cancelled", http.StatusSeeOther)
}

func (h *handlers) teamUpdate(w http.ResponseWriter, r *http.Request) {
	a, err := accessFromForm(r)
	if err == nil {
		err = h.auth.UpdateMember(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), a, client(r))
	}
	if err != nil {
		h.renderTeam(w, r, http.StatusUnprocessableEntity, views.TeamData{Error: i18n.Message(i18n.Locale(r.Context()), err)})
		return
	}
	http.Redirect(w, r, "/team?ok=updated", http.StatusSeeOther)
}

func (h *handlers) teamRemove(w http.ResponseWriter, r *http.Request) {
	if err := h.auth.RemoveMember(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), client(r)); err != nil {
		h.renderTeam(w, r, http.StatusUnprocessableEntity, views.TeamData{Error: i18n.Message(i18n.Locale(r.Context()), err)})
		return
	}
	http.Redirect(w, r, "/team?ok=removed", http.StatusSeeOther)
}

// panelBase is the panel's own address for links sent to people: the
// public one when the panel is public, else the address in use.
func (h *handlers) panelBase(r *http.Request) string {
	if h.panelURL != "" {
		return h.panelURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// --- the invited person's side ------------------------------------------

func (h *handlers) inviteForm(r *http.Request, inv auth.Invite) views.InviteForm {
	return views.InviteForm{
		Token: r.PathValue("token"), Email: inv.Email, Role: inv.Access.Role.String(),
		AllProjects: inv.Access.AllProjects, Projects: inv.Access.Projects, TwoFA: true,
		Required: h.auth.RequiredFor(r.Context(), inv.Access.Role), MinLen: auth.MinPasswordLen,
	}
}

// inviteFailed answers an invitation link that cannot be used: too many
// tries from this address, or an unknown, used or expired link.
func inviteFailed(w http.ResponseWriter, r *http.Request, err error) {
	var rl *auth.RateLimitedError
	if errors.As(err, &rl) {
		http.Error(w, i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes()), http.StatusTooManyRequests)
		return
	}
	render(w, r, http.StatusNotFound, views.InviteInvalid())
}

func (h *handlers) invitePage(w http.ResponseWriter, r *http.Request) {
	inv, err := h.auth.CheckInvite(r.Context(), r.PathValue("token"), client(r))
	if err != nil {
		inviteFailed(w, r, err)
		return
	}
	render(w, withLoginToken(w, r), http.StatusOK, views.InvitePage(h.inviteForm(r, inv), ""))
}

func (h *handlers) inviteSubmit(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	inv, err := h.auth.CheckInvite(r.Context(), token, client(r))
	if err != nil {
		inviteFailed(w, r, err)
		return
	}
	valid := validLoginToken(r)
	form := withLoginToken(w, r)
	f := h.inviteForm(r, inv)
	f.TwoFA = f.Required || r.PostFormValue("twofa") == "1"
	if !valid {
		render(w, form, http.StatusForbidden, views.InvitePage(f, i18n.T(r.Context(), "login.error.form_expired")))
		return
	}
	password := r.PostFormValue("password")
	if password != r.PostFormValue("confirm") {
		render(w, form, http.StatusUnprocessableEntity, views.InvitePage(f, i18n.T(r.Context(), "setup.error.mismatch")))
		return
	}
	sess, err := h.auth.AcceptInvite(r.Context(), token, password, client(r))
	var rl *auth.RateLimitedError
	var ie *i18n.Error
	switch {
	case err == nil:
		setCookie(w, sessionCookie, sess, auth.SessionMax)
		if f.Required {
			http.Redirect(w, r, enrollPath, http.StatusSeeOther)
			return
		}
		if f.TwoFA {
			http.Redirect(w, r, "/account#totp", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case errors.Is(err, auth.ErrInviteInvalid):
		render(w, r, http.StatusNotFound, views.InviteInvalid())
	case errors.As(err, &rl):
		render(w, form, http.StatusTooManyRequests, views.InvitePage(f, i18n.T(r.Context(), "login.error.rate_limited", "min", rl.Minutes())))
	case errors.As(err, &ie):
		render(w, form, http.StatusUnprocessableEntity, views.InvitePage(f, i18n.Message(i18n.Locale(r.Context()), err)))
	default:
		loggerFrom(r.Context()).Error("accept invite", "error", err)
		render(w, form, http.StatusInternalServerError, views.InvitePage(f, i18n.T(r.Context(), "error.internal")))
	}
}
