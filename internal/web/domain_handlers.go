package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- service domains --------------------------------------------------------

func (h *handlers) domainsDone(w http.ResponseWriter, r *http.Request, ok string, err error) {
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=network&ok="+ok+"#domains")
}

func (h *handlers) addDomain(w http.ResponseWriter, r *http.Request) {
	// The form sends the hostname and a "wildcard" switch; "*." typed by
	// hand counts as the switch too.
	host, wild := strings.CutPrefix(strings.TrimSpace(r.PostFormValue("hostname")), "*.")
	if wild || r.PostFormValue("wildcard") == "1" {
		host = "*." + host
	}
	err := h.projects.AddDomain(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), host, r.PostFormValue("endpoint"))
	h.domainsDone(w, r, "domain", err)
}

func (h *handlers) removeDomain(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	h.domainsDone(w, r, "domain-deleted", h.projects.RemoveDomain(r.Context(), actor(r), s.ID, r.PostFormValue("id")))
}

func (h *handlers) dynamicDomains(w http.ResponseWriter, r *http.Request) {
	switch r.PostFormValue("action") {
	case "enable":
		h.domainsDone(w, r, "dynamic-on",
			h.projects.EnableDynamicDomains(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service")))
	case "disable":
		s, ok := h.withService(w, r)
		if !ok {
			return
		}
		h.domainsDone(w, r, "dynamic-off", h.projects.DisableDynamicDomains(r.Context(), actor(r), s.ID))
	default:
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
	}
}

// setEndpointPublic puts a service's endpoint on the internet (it gets an
// external link); the route takes an admin with sudo.
func (h *handlers) setEndpointPublic(w http.ResponseWriter, r *http.Request) {
	err := h.projects.SetEndpointPublic(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("id"), true)
	h.endpointDone(w, r, err)
}

// setEndpointInternal keeps a service's endpoint on the project network only.
func (h *handlers) setEndpointInternal(w http.ResponseWriter, r *http.Request) {
	err := h.projects.SetEndpointPublic(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("id"), false)
	h.endpointDone(w, r, err)
}

// endpointSslipOn turns the automatic link of a public endpoint back on;
// the route takes an admin with sudo.
func (h *handlers) endpointSslipOn(w http.ResponseWriter, r *http.Request) {
	err := h.projects.SetEndpointSslip(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("id"), true)
	h.endpointDone(w, r, err)
}

// endpointSslipOff turns the automatic link off (nothing is removed).
func (h *handlers) endpointSslipOff(w http.ResponseWriter, r *http.Request) {
	err := h.projects.SetEndpointSslip(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("id"), false)
	h.endpointDone(w, r, err)
}

// endpointDone returns to the Network tab after an endpoint change.
func (h *handlers) endpointDone(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=network&ok=endpoint#domains")
}

// setMaintenance turns the maintenance page on or off for every host of
// the service; the container keeps running.
func (h *handlers) setMaintenance(w http.ResponseWriter, r *http.Request) {
	var on bool
	switch r.PostFormValue("action") {
	case "on":
		on = true
	case "off":
	default:
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	if err := h.projects.SetMaintenance(r.Context(), actor(r), s.ID, on); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=maintenance-"+r.PostFormValue("action")+"#maintenance")
}

// revealCheckSecret shows the HMAC secret once, in this response.
func (h *handlers) revealCheckSecret(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	v, err := h.projects.RevealCheckSecret(r.Context(), actor(r), s.ID)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	h.renderService(w, r, serviceView{
		status: http.StatusOK, checkSecret: v,
		flash: i18n.T(r.Context(), "service.env.revealed"),
	})
}

// rotateCheckSecret replaces the HMAC secret and shows the new one once, so
// the operator can copy it and redeploy.
func (h *handlers) rotateCheckSecret(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	v, err := h.projects.RotateCheckSecret(r.Context(), actor(r), s.ID)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	h.renderService(w, r, serviceView{
		status: http.StatusOK, checkSecret: v,
		flash: i18n.T(r.Context(), "domain.dynamic.rotated"),
	})
}

// --- dynamic domains page ---------------------------------------------------

func (h *handlers) domainsPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch r.URL.Query().Get("ok") {
	case "blocked":
		flash = i18n.T(r.Context(), "flash.domains-blocked")
	case "unblocked":
		flash = i18n.T(r.Context(), "flash.domains-unblocked")
	}
	h.renderDomains(w, r, http.StatusOK, "", flash)
}

func (h *handlers) renderDomains(w http.ResponseWriter, r *http.Request, status int, errMsg, flash string) {
	pr := PrincipalFrom(r.Context())
	d := views.DomainsData{
		CSRF: pr.CSRFToken, EdgeEnabled: h.projects.EdgeEnabled(), CanAdmin: pr.Role >= auth.RoleAdmin,
		Error: errMsg, Flash: flash,
	}
	if p, s, ok := h.projects.DynamicServiceRef(r.Context()); ok {
		d.Dynamic, d.DynamicURL = p+"/"+s, servicePath(p, s)
	}
	d.Filter = r.URL.Query().Get("f")
	if d.Filter == "all" {
		d.Filter = ""
	}
	act, err := h.projects.DomainActivity(r.Context(), d.Filter)
	d.Certified, d.NewThisHour, d.HourCap, d.DeniedToday = act.Certified, act.NewThisHour, act.HourCap, act.DeniedToday
	if err != nil {
		code, msg := userError(r, err)
		status, d.Error = code, msg
	}
	blocked := map[string]bool{}
	for _, b := range act.Blocked {
		blocked[b.Hostname] = true
		d.Blocked = append(d.Blocked, views.BlockedRow{
			Hostname: b.Hostname, Reason: b.Reason, When: time.Unix(b.CreatedAt, 0).Format("02/01 15:04"),
		})
	}
	for _, a := range act.Recent {
		d.Recent = append(d.Recent, views.AskRow{
			Hostname: a.Hostname, Allowed: a.Decision == "allow", Reason: a.Reason, Count: a.Count,
			When: time.Unix(a.LastAt, 0).Format("02/01 15:04"), Blocked: blocked[a.Hostname],
		})
	}
	render(w, r, status, views.Domains(d))
}

func (h *handlers) blockHostname(w http.ResponseWriter, r *http.Request) {
	if err := h.projects.BlockHostname(r.Context(), actor(r), r.PostFormValue("hostname"), r.PostFormValue("reason")); err != nil {
		code, msg := userError(r, err)
		h.renderDomains(w, r, code, msg, "")
		return
	}
	redirectLocal(w, r, "/domains?ok=blocked")
}

func (h *handlers) unblockHostname(w http.ResponseWriter, r *http.Request) {
	if err := h.projects.UnblockHostname(r.Context(), actor(r), r.PostFormValue("hostname")); err != nil {
		code, msg := userError(r, err)
		h.renderDomains(w, r, code, msg, "")
		return
	}
	redirectLocal(w, r, "/domains?ok=unblocked")
}
