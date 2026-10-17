package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- templates --------------------------------------------------------------

// templatePage keeps old links working: the form now lives on the
// new-service page, under the catalog.
func (h *handlers) templatePage(w http.ResponseWriter, r *http.Request) {
	project, id := r.PathValue("project"), r.PathValue("template")
	if !node.SlugRE.MatchString(project) || !templateIDRE.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	redirectLocal(w, r, "/p/"+project+"/new?template="+id+"#template-form")
}

var templateIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// logoCSP lets a logo opened on its own draw, and nothing else: no
// scripts, no outside loads. The SVG was already checked when the catalog
// loaded (templates.CheckSVG); this is the second wall.
const logoCSP = "default-src 'none'; style-src 'unsafe-inline'"

// templateLogo serves a template's logo.svg. The ETag carries the
// template's version and the logo's hash; the URL the pages use
// (Template.LogoURL) carries it too, so that URL is cached for good.
func (h *handlers) templateLogo(w http.ResponseWriter, r *http.Request) {
	tp, ok := h.projects.Template(r.PathValue("template"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := tp.LogoETag()
	hd := w.Header()
	hd.Set("Content-Type", "image/svg+xml")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", logoCSP)
	hd.Set("ETag", etag)
	if r.URL.Query().Get("v") == strings.Trim(etag, `"`) {
		hd.Set("Cache-Control", "private, max-age=31536000, immutable")
	} else {
		hd.Set("Cache-Control", "private, no-cache")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(tp.Logo) //nolint:gosec // validated SVG (templates.CheckSVG), served with a CSP that forbids scripts
}

// htmlPattern drops the anchors: the browser anchors pattern="" by itself.
func htmlPattern(p string) string {
	return strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$")
}

func (h *handlers) createFromTemplate(w http.ResponseWriter, r *http.Request) {
	tp, ok := h.projects.Template(r.PostFormValue("template"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	inputs := map[string]string{}
	for _, in := range tp.Inputs {
		inputs[in.Key] = r.PostFormValue("in_" + in.Key)
	}
	name := r.PostFormValue("name")
	svcs, err := h.projects.CreateFromTemplate(r.Context(), actor(r), r.PathValue("project"), tp.ID, name, inputs)
	if err != nil && len(svcs) == 0 {
		code, msg := userError(r, err)
		h.renderNew(w, r, code, nsState{tab: "template", template: tp.ID, tplName: name, inputs: inputs, err: msg})
		return
	}
	h.placeNew(r, svcs[0].Slug)
	redirectLocal(w, r, servicePath(r.PathValue("project"), svcs[0].Slug)+"?ok=deploy")
}

// --- project links ----------------------------------------------------------

func (h *handlers) projectLink(w http.ResponseWriter, r *http.Request) {
	h.linksDone(w, r, h.projects.LinkProjects(r.Context(), actor(r), r.PathValue("project"), r.PostFormValue("other")))
}

func (h *handlers) projectUnlink(w http.ResponseWriter, r *http.Request) {
	h.linksDone(w, r, h.projects.UnlinkProjects(r.Context(), actor(r), r.PathValue("project"), r.PostFormValue("other")))
}

func (h *handlers) linksDone(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		code, msg := userError(r, err)
		h.renderProject(w, r, code, msg)
		return
	}
	project := r.PathValue("project")
	if !node.SlugRE.MatchString(project) {
		project = ""
	}
	redirectLocal(w, r, "/p/"+project+"/settings")
}

// --- exports and backup -----------------------------------------------------

func (h *handlers) revealExport(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	key := r.PostFormValue("key")
	v, err := h.projects.RevealExport(r.Context(), actor(r), s.ID, key)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	h.renderService(w, r, serviceView{
		status: http.StatusOK, exportKey: key, exportValue: v,
		flash: i18n.T(r.Context(), "service.env.revealed"),
	})
}

// --- ports ------------------------------------------------------------------

func (h *handlers) addPort(w http.ResponseWriter, r *http.Request) {
	in := projects.PortInput{
		Protocol: r.PostFormValue("protocol"), Access: r.PostFormValue("access"),
		IPs: strings.FieldsFunc(r.PostFormValue("ips"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' }),
	}
	var err error
	if in.HostPort, err = strconv.Atoi(strings.TrimSpace(r.PostFormValue("host_port"))); err == nil {
		in.ContainerPort, err = strconv.Atoi(strings.TrimSpace(r.PostFormValue("container_port")))
	}
	if err != nil {
		h.renderService(w, r, serviceView{status: http.StatusUnprocessableEntity, errMsg: i18n.T(r.Context(), "project.form.number_invalid")})
		return
	}
	switch r.PostFormValue("expires") {
	case "1h":
		in.ExpiresIn = time.Hour
	case "24h":
		in.ExpiresIn = 24 * time.Hour
	case "168h":
		in.ExpiresIn = 7 * 24 * time.Hour
	}
	err = h.projects.AddPort(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), in)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=network&ok=port#ports")
}

func (h *handlers) removePort(w http.ResponseWriter, r *http.Request) {
	err := h.projects.RemovePort(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("id"))
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	if r.PostFormValue("back") == "ports" {
		redirectLocal(w, r, "/ports?ok=port-closed")
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=network&ok=port-closed#ports")
}

func portRow(p projects.Port) (ips, expires string) {
	ips = strings.Join(p.IPs, ", ")
	if p.ExpiresAt.Valid {
		expires = time.Unix(p.ExpiresAt.Int64, 0).Format("02/01 15:04")
	}
	return ips, expires
}

func (h *handlers) openPortsPage(w http.ResponseWriter, r *http.Request) {
	pr := PrincipalFrom(r.Context())
	d := views.OpenPortsData{CSRF: pr.CSRFToken, CanAdmin: pr.Role >= auth.RoleAdmin}
	if r.URL.Query().Get("ok") == "port-closed" {
		d.Flash = i18n.T(r.Context(), "flash.port-closed")
	}
	var at time.Time
	d.FirewallPending, d.FirewallError, at = h.projects.FirewallStatus()
	if !at.IsZero() {
		d.FirewallAt = at.Local().Format("02/01 15:04")
	}
	ports, err := h.projects.ListAllPorts(r.Context())
	status := http.StatusOK
	if err != nil {
		code, msg := userError(r, err)
		status, d.FirewallError = code, msg
	}
	for _, p := range ports {
		ips, exp := portRow(p)
		owner := p.Owner
		if owner == "" {
			owner = i18n.T(r.Context(), "ports.system")
		}
		d.Ports = append(d.Ports, views.OpenPortRow{
			ID: p.ID, Project: p.Project, Service: p.Service, HostPort: p.HostPort, ContainerPort: p.ContainerPort,
			Protocol: p.Protocol, Access: p.Access, IPs: ips, Expires: exp, Owner: owner,
			Created: time.Unix(p.CreatedAt, 0).Format("02/01 15:04"),
		})
	}
	render(w, r, status, views.OpenPorts(d))
}

// --- deploy pipeline --------------------------------------------------------

func (h *handlers) rollback(w http.ResponseWriter, r *http.Request) {
	if _, err := h.projects.Rollback(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("deploy")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=rollback")
}

func (h *handlers) saveDeploySettings(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	in := projects.DeploySettings{
		PreDeploy: r.PostFormValue("predeploy"), HealthPath: r.PostFormValue("health_path"),
	}
	// The validation command and its limit (minutes) are optional fields:
	// a form without them keeps what is stored.
	cur := h.projects.GetDeploySettings(s)
	in.Validate, in.ValidateTimeout = cur.Validate, cur.ValidateTimeout
	if _, ok := r.PostForm["validate"]; ok {
		in.Validate = r.PostFormValue("validate")
	}
	if v := strings.TrimSpace(r.PostFormValue("validate_timeout")); v != "" {
		mins, err := strconv.Atoi(v)
		if err != nil || mins < 1 {
			mins = -1 // out of range: SetDeploySettings refuses it with the message
		}
		in.ValidateTimeout = time.Duration(mins) * time.Minute
	}
	err := h.projects.SetDeploySettings(r.Context(), actor(r), s.ID, in)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=deploy-settings#deploy-settings")
}
