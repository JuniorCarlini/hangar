package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/statuspage"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- status links (docs/15, docs/17 § 3.11) ---------------------------------

func statusActor(r *http.Request) statuspage.Actor {
	p := PrincipalFrom(r.Context())
	return statuspage.Actor{UserID: p.UserID, IP: clientIP(r)}
}

func (h *handlers) statusLinksPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch r.URL.Query().Get("ok") {
	case "revoked":
		flash = i18n.T(r.Context(), "statuslink.flash.revoked")
	case "alias":
		flash = i18n.T(r.Context(), "statuslink.flash.alias")
	}
	h.renderStatusLinks(w, r, statusView{status: http.StatusOK, flash: flash})
}

type statusView struct {
	status  int
	errMsg  string
	flash   string
	created string // the new link's token, shown once
	open    bool   // reopen the "new link" dialog (form error)
}

// serviceRefs lists every service as "project/service" with its id.
func (h *handlers) serviceRefs(ctx context.Context) ([]views.StatusServiceRef, map[string]bool) {
	var refs []views.StatusServiceRef
	known := map[string]bool{}
	list, err := h.projects.ListProjects(ctx)
	if err != nil {
		loggerFrom(ctx).Error("status links: projects", "error", err)
	}
	for _, p := range list {
		svcs, err := h.projects.ListServices(ctx, p.ID)
		if err != nil {
			continue
		}
		for _, s := range svcs {
			refs = append(refs, views.StatusServiceRef{ID: s.ID, Name: p.Slug + "/" + s.Slug})
			known[s.ID] = true
		}
	}
	return refs, known
}

func (h *handlers) renderStatusLinks(w http.ResponseWriter, r *http.Request, v statusView) {
	ctx := r.Context()
	pr := PrincipalFrom(ctx)
	d := views.StatusLinksData{
		CSRF: pr.CSRFToken, SudoActive: time.Now().Before(pr.SudoUntil), Error: v.errMsg, Flash: v.flash,
		Open: v.open, Enabled: h.status != nil,
	}
	refs, _ := h.serviceRefs(ctx)
	if h.status != nil {
		aliases, err := h.status.Aliases(ctx)
		if err != nil {
			loggerFrom(ctx).Error("status aliases", "error", err)
		}
		for i := range refs {
			refs[i].Alias = aliases[refs[i].ID]
		}
		links, err := h.status.List(ctx)
		if err != nil {
			v.status, d.Error = userError(r, err)
		}
		now := time.Now()
		for _, l := range links {
			row := views.StatusLinkRow{
				ID: l.ID, Name: l.Name, Naming: l.Naming, Services: l.Services, IPs: strings.Join(l.CIDRs, ", "),
				Expired: l.Expired, Today: l.AccessToday, Total: l.AccessCount, LastIP: l.LastIP,
			}
			if !l.ExpiresAt.IsZero() {
				row.Expires = l.ExpiresAt.Local().Format("02/01/2006 15:04")
			}
			if !l.LastAccess.IsZero() {
				row.LastAccess = ago(ctx, l.LastAccess.Format(time.RFC3339Nano), now)
			}
			d.Links = append(d.Links, row)
		}
	}
	d.Services = refs
	if v.created != "" {
		base := h.statusBase
		if base == "" {
			base = panelBase(r)
		}
		d.Created = base + "/s/" + v.created
		d.CreatedJSON = d.Created + ".json"
		d.CreatedMetrics = d.Created + "/metrics"
	}
	render(w, r, v.status, views.StatusLinks(d))
}

// panelBase is the panel's own origin, for showing a new link when no
// separate status domain is configured. Loopback is plain HTTP (local
// development); anything else is behind Caddy with HTTPS.
func panelBase(r *http.Request) string {
	host := r.Host
	if strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "[::1]") {
		return "http://" + host
	}
	return "https://" + host
}

func (h *handlers) createStatusLink(w http.ResponseWriter, r *http.Request) {
	if h.status == nil {
		http.NotFound(w, r)
		return
	}
	_, known := h.serviceRefs(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	token, _, err := h.status.Create(r.Context(), statusActor(r), statuspage.Input{
		Name: r.PostFormValue("name"), Naming: r.PostFormValue("naming"), ServiceIDs: r.PostForm["service"],
		Expiry: r.PostFormValue("expiry"), CIDRs: r.PostFormValue("ips"),
	}, known)
	if err != nil {
		code, msg := userError(r, err)
		h.renderStatusLinks(w, r, statusView{status: code, errMsg: msg, open: true})
		return
	}
	// The token is shown in this response only: it is not stored anywhere
	// readable, so a reload cannot show it again.
	h.renderStatusLinks(w, r, statusView{status: http.StatusOK, created: token})
}

func (h *handlers) revokeStatusLink(w http.ResponseWriter, r *http.Request) {
	if h.status == nil {
		http.NotFound(w, r)
		return
	}
	if err := h.status.Revoke(r.Context(), statusActor(r), r.PostFormValue("id")); err != nil {
		code, msg := userError(r, err)
		h.renderStatusLinks(w, r, statusView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, "/status-links?ok=revoked")
}

func (h *handlers) setStatusAlias(w http.ResponseWriter, r *http.Request) {
	if h.status == nil {
		http.NotFound(w, r)
		return
	}
	_, known := h.serviceRefs(r.Context())
	if err := h.status.SetAlias(r.Context(), statusActor(r), r.PostFormValue("service"), r.PostFormValue("alias"), known); err != nil {
		code, msg := userError(r, err)
		h.renderStatusLinks(w, r, statusView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, "/status-links?ok=alias#aliases")
}
