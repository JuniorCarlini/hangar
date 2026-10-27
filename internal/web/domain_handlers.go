package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/edge"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
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
	// "mode" is how the domain works: normal (one hostname), wildcard
	// (*.domain, a certificate per subdomain on first visit) or scale
	// (*.domain under one DNS-01 wildcard certificate, with the DNS
	// provider's token). "*." typed by hand means wildcard. Forms from
	// before the modes send wildcard=1.
	host, wild := strings.CutPrefix(strings.TrimSpace(r.PostFormValue("hostname")), "*.")
	mode := r.PostFormValue("mode")
	if mode == "" && (wild || r.PostFormValue("wildcard") == "1") {
		mode = "wildcard"
	}
	ctx, project, service, endpoint := r.Context(), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("endpoint")
	var err error
	switch mode {
	case "scale":
		err = h.projects.AddScaledDomain(ctx, actor(r), project, service, host, endpoint,
			r.PostFormValue("dns_provider"), []byte(strings.TrimSpace(r.PostFormValue("dns_token"))), r.PostFormValue("replace_base") == "1")
	case "wildcard":
		err = h.projects.AddDomain(ctx, actor(r), project, service, "*."+host, endpoint)
	default:
		if wild {
			host = "*." + host
		}
		err = h.projects.AddDomain(ctx, actor(r), project, service, host, endpoint)
	}
	h.domainsDone(w, r, "domain", err)
}

// rotateDNSToken replaces the DNS provider token of the base domain
// (admin + sudo, like every edge setting).
func (h *handlers) rotateDNSToken(w http.ResponseWriter, r *http.Request) {
	err := h.projects.RotateEdgeDNSToken(r.Context(), actor(r), []byte(strings.TrimSpace(r.PostFormValue("dns_token"))))
	h.domainsDone(w, r, "dns-token", err)
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
	project, service, id := r.PathValue("project"), r.PathValue("service"), r.PostFormValue("id")
	err := h.projects.SetEndpointPublic(r.Context(), actor(r), project, service, id, true)
	// One switch on the page: "public" brings the automatic link with it.
	if err == nil {
		err = h.projects.SetEndpointSslip(r.Context(), actor(r), project, service, id, true)
	}
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
	case "limit":
		flash = i18n.T(r.Context(), "flash.domains-limit")
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
	if d.EdgeEnabled && d.Dynamic != "" {
		d.EntryHost = h.entryHost()
		d.EntryPath = h.entryPath(r.Context(), d.EntryHost)
	}
	d.MinCap, d.MaxCap = projects.MinHourCap, projects.MaxHourCap
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
			When: time.Unix(a.LastAt, 0).Format("02/01 15:04"), Blocked: blocked[a.Hostname], Via: a.Via,
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

// entryLabel names the address customers point their domains at.
const entryLabel = "entrada"

// entryHost is that address: entrada.<base domain>, or, without one,
// entrada.<ip>.sslip.io, which resolves to the server by itself.
func (h *handlers) entryHost() string {
	ip, _ := netip.ParseAddr(h.autoLinkIP)
	return edge.AutoHost(h.projects.BaseDomain(), ip, entryLabel)
}

// entryPath checks how the entry address reaches the server ("" when it
// cannot be told). An sslip.io name always resolves to its IP.
func (h *handlers) entryPath(ctx context.Context, host string) string {
	ip, err := netip.ParseAddr(h.autoLinkIP)
	if host == "" || err != nil {
		return ""
	}
	if strings.HasSuffix(host, ".sslip.io") {
		return string(edge.PathDirect)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return string(edge.PathElsewhere)
	}
	return string(edge.ClassifyPath([]netip.Addr{ip}, ips))
}

// setHourCap changes how many new domains may get a certificate per hour.
func (h *handlers) setHourCap(w http.ResponseWriter, r *http.Request) {
	if err := h.projects.SetHourCap(r.Context(), actor(r), r.PostFormValue("cap")); err != nil {
		code, msg := userError(r, err)
		h.renderDomains(w, r, code, msg, "")
		return
	}
	redirectLocal(w, r, "/domains?ok=limit")
}

// domainTXT turns the ownership TXT of new customer domains on or off.
func (h *handlers) domainTXT(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	on := r.PostFormValue("on") == "1"
	flash := "txt-off"
	if on {
		flash = "txt-on"
	}
	h.domainsDone(w, r, flash, h.projects.SetDomainRequireTXT(r.Context(), actor(r), s.ID, on))
}
