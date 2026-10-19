package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/edge"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

func actor(r *http.Request) projects.Actor {
	p := PrincipalFrom(r.Context())
	return projects.Actor{UserID: p.UserID, IP: clientIP(r), Sudo: time.Now().Before(p.SudoUntil)}
}

// userError turns an error into a status and a message in the user's
// language. Translatable errors (validation, known states) are shown as is;
// anything else goes to the log and the page gets a generic message with the
// technical detail.
func userError(r *http.Request, err error) (int, string) {
	loc := i18n.Locale(r.Context())
	switch {
	case errors.Is(err, projects.ErrNotFound):
		return http.StatusNotFound, i18n.Message(loc, err)
	case errors.Is(err, projects.ErrExists), errors.Is(err, projects.ErrHasServices), errors.Is(err, projects.ErrDeployRunning):
		return http.StatusConflict, i18n.Message(loc, err)
	case errors.Is(err, projects.ErrDockerDisabled):
		return http.StatusServiceUnavailable, i18n.Message(loc, err)
	}
	var ie *i18n.Error
	if errors.As(err, &ie) {
		return http.StatusUnprocessableEntity, ie.In(loc)
	}
	loggerFrom(r.Context()).Error("action failed", "route", r.URL.Path, "error", err)
	return http.StatusBadGateway, i18n.Tl(loc, "error.action_failed", "error", err.Error())
}

// --- projects ---------------------------------------------------------------

func (h *handlers) createProject(w http.ResponseWriter, r *http.Request) {
	slug, name := r.PostFormValue("slug"), r.PostFormValue("name")
	p, err := h.projects.CreateProject(r.Context(), actor(r), slug, name)
	if err != nil {
		code, msg := userError(r, err)
		// Back on the overview with the dialog open, showing the error.
		n := views.NavFrom(r.Context())
		n.NewProject = views.NewProjectForm{Open: true, Error: msg, Slug: slug, Name: name}
		h.renderOverview(w, r.WithContext(views.WithNav(r.Context(), n)), code)
		return
	}
	redirectLocal(w, r, "/p/"+p.Slug)
}

// projectPage is the canvas (default) or the list view of a project.
func (h *handlers) projectPage(w http.ResponseWriter, r *http.Request) {
	p, err := h.projects.GetProject(r.Context(), r.PathValue("project"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cd, err := h.canvasFor(r, p, "")
	status := http.StatusOK
	if err != nil {
		status, cd.Error = userError(r, err)
	}
	switch r.URL.Query().Get("ok") {
	case "deploy":
		cd.Flash = i18n.T(r.Context(), "flash.deploy")
	case "compose":
		cd.Flash = i18n.T(r.Context(), "flash.compose")
	}
	render(w, r, status, views.ProjectCanvas(cd, nil))
}

// newServicePage is the canvas with the new-service dialog open (links,
// the palette, and the canvas without JavaScript land here).
func (h *handlers) newServicePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tab := ""
	switch {
	case q.Get("template") != "":
		tab = "template"
	case q.Get("tab") == "git" || q.Get("tab") == "image" || q.Get("tab") == "compose":
		// Back from saving a Git credential: "Meus repositórios" with the
		// new credential selected.
		tab = q.Get("tab")
	}
	h.renderNew(w, r, http.StatusOK, nsState{tab: tab, template: q.Get("template"), github: q.Get("credential")})
}

func (h *handlers) projectSettingsPage(w http.ResponseWriter, r *http.Request) {
	h.renderProject(w, r, http.StatusOK, "")
}

// canvasFor builds the canvas with the viewer's permissions.
func (h *handlers) canvasFor(r *http.Request, p dbq.Project, selected string) (views.CanvasData, error) {
	pr := PrincipalFrom(r.Context())
	cd, err := h.buildCanvas(r, p, selected)
	cd.CSRF, cd.Project, cd.ProjectName = pr.CSRFToken, p.Slug, p.Name
	cd.CanCreate, cd.CanOperate = pr.Role >= auth.RoleAdmin, pr.Role >= auth.RoleOperator
	if cd.CanCreate {
		cd.New = h.newServiceData(r, p, nsState{})
	}
	return cd, err
}

// renderProject renders the project settings ("settings").
func (h *handlers) renderProject(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	h.renderProjectPage(w, r, status, errMsg, false)
}

// renderProjectCreds shows the settings again after a credential form
// failed (open: reopen the "new credential" dialog with the error).
func (h *handlers) renderProjectCreds(w http.ResponseWriter, r *http.Request, status int, errMsg string, open bool) {
	h.renderProjectPage(w, r, status, errMsg, open)
}

func (h *handlers) renderProjectPage(w http.ResponseWriter, r *http.Request, status int, errMsg string, credOpen bool) {
	pr := PrincipalFrom(r.Context())
	p, err := h.projects.GetProject(r.Context(), r.PathValue("project"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	svcs, err := h.projects.ListServices(r.Context(), p.ID)
	if err != nil {
		code, msg := userError(r, err)
		status, errMsg = code, msg
	}
	d := views.ProjectData{
		CSRF: pr.CSRFToken, Slug: p.Slug, Name: p.Name, CanCreate: pr.Role >= auth.RoleAdmin, Error: errMsg,
		SudoActive: time.Now().Before(pr.SudoUntil), CredOpen: credOpen, Flash: credFlash(r),
	}
	if creds, err := h.projects.ListGitCredentials(r.Context()); err == nil {
		var own []projects.GitCredential
		for _, c := range creds {
			switch c.ProjectID {
			case p.ID:
				own = append(own, c)
			case "":
				d.ServerCreds++
			}
		}
		d.GitCreds = gitCredRows(r.Context(), own)
	}
	linked := map[string]bool{p.Slug: true}
	if ls, err := h.projects.LinkedProjects(r.Context(), p.ID); err == nil {
		for _, l := range ls {
			d.Linked = append(d.Linked, l.Slug)
			linked[l.Slug] = true
		}
	}
	if all, err := h.projects.ListProjects(r.Context()); err == nil {
		for _, o := range all {
			if !linked[o.Slug] {
				d.Linkable = append(d.Linkable, o.Slug)
			}
		}
	}
	for _, s := range svcs {
		d.Services = append(d.Services, views.ServiceRow{Slug: s.Slug, Image: s.Image, State: h.serviceState(r.Context(), p.Slug, s)})
	}
	render(w, r, status, views.ProjectSettings(d))
}

// deleteProject removes an empty project (sudo, typing its name).
func (h *handlers) deleteProject(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") != r.PathValue("project") {
		h.renderProject(w, r, http.StatusUnprocessableEntity, i18n.T(r.Context(), "service.danger.name_mismatch"))
		return
	}
	if err := h.projects.DeleteProject(r.Context(), actor(r), r.PathValue("project")); err != nil {
		code, msg := userError(r, err)
		h.renderProject(w, r, code, msg)
		return
	}
	redirectLocal(w, r, "/")
}

// serviceState combines the container state with the deploy history.
func (h *handlers) serviceState(ctx context.Context, project string, s dbq.Service) string {
	if deps, err := h.projects.Deployments(ctx, s.ID, 1); err == nil && len(deps) > 0 {
		if deps[0].Status == "running" {
			return "deploying"
		}
	}
	st, err := h.projects.Status(ctx, project, s.Slug)
	switch {
	case err != nil:
		return "unknown"
	case !st.Exists:
		if deps, _ := h.projects.Deployments(ctx, s.ID, 1); len(deps) > 0 && deps[0].Status == "failed" {
			return "failed"
		}
		return "missing"
	}
	return st.State
}

func (h *handlers) createService(w http.ResponseWriter, r *http.Request) {
	form := views.ServiceForm{
		Name: r.PostFormValue("name"), Slug: r.PostFormValue("slug"), Image: r.PostFormValue("image"), Port: r.PostFormValue("port"),
		MemoryMB: r.PostFormValue("memory_mb"), CPUs: r.PostFormValue("cpus"),
	}
	in := projects.ServiceInput{Name: form.Name, Slug: form.Slug, Image: form.Image}
	var err error
	if in.Port, err = optInt(form.Port); err == nil {
		if in.MemoryMB, err = optInt(form.MemoryMB); err == nil {
			in.CPUs, err = optFloat(form.CPUs)
		}
	}
	if err != nil {
		h.renderNew(w, r, http.StatusUnprocessableEntity, nsState{tab: "image", form: form, err: i18n.T(r.Context(), "project.form.number_invalid")})
		return
	}
	if strings.TrimSpace(form.Port) == "" {
		in.Port = projects.KnownImagePort(form.Image)
	}
	s, err := h.projects.CreateService(r.Context(), actor(r), r.PathValue("project"), in)
	if err != nil && s.ID == "" {
		code, msg := userError(r, err)
		h.renderNew(w, r, code, nsState{tab: "image", form: form, err: msg})
		return
	}
	h.placeNew(r, s.Slug)
	redirectLocal(w, r, servicePath(r.PathValue("project"), s.Slug))
}

func optInt(s string) (int, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return strconv.Atoi(strings.TrimSpace(s))
}

func optFloat(s string) (float64, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(s), ",", "."), 64)
}

// --- service ----------------------------------------------------------------

type serviceView struct {
	errMsg, flash string
	revealKey     string
	revealValue   string
	checkSecret   string
	exportKey     string
	exportValue   string
	gitToken      string            // the clone token, right after a sudo reveal
	hook          *projects.Webhook // webhook URL token and secret, right after rotate or reveal
	status        int
}

func (h *handlers) servicePage(w http.ResponseWriter, r *http.Request) {
	h.renderService(w, r, serviceView{status: http.StatusOK, flash: flashFrom(r)})
}

// flashFrom maps the ?ok= of redirects to a fixed message (URL text never
// reaches the page directly).
func flashFrom(r *http.Request) string {
	switch ok := r.URL.Query().Get("ok"); ok {
	case "deploy", "image", "env", "env-deleted", "action", "domain", "domain-deleted", "dynamic-on", "dynamic-off", "dns-token", "port", "port-closed", "rollback", "deploy-settings", "git", "git-token", "webhook-off",
		"maintenance-on", "maintenance-off", "backup-policy", "backup-queued", "backup-preparing", "restore-started", "volume", "volume-removed":
		return i18n.T(r.Context(), "flash."+ok)
	}
	return ""
}

func (h *handlers) renderService(w http.ResponseWriter, r *http.Request, v serviceView) {
	pr := PrincipalFrom(r.Context())
	p, s, err := h.projects.GetService(r.Context(), r.PathValue("project"), r.PathValue("service"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := views.ServiceData{
		CSRF: pr.CSRFToken, Project: p.Slug, ProjectName: p.Name, Slug: s.Slug, Image: s.Image,
		Port: s.InternalPort, MemoryMB: s.MemoryBytes >> 20, CPUs: strconv.FormatFloat(float64(s.NanoCpus)/1e9, 'f', -1, 64),
		CanOperate: pr.Role >= auth.RoleOperator, CanAdmin: pr.Role >= auth.RoleAdmin,
		SudoActive: time.Now().Before(pr.SudoUntil), Error: v.errMsg, Flash: v.flash,
	}
	if d.Git = h.gitView(r, s.ID, s.ProjectID, v); d.Git != nil {
		d.Image = d.Git.Display + "@" + d.Git.Branch
	} else if !strings.Contains(s.Image, "@") {
		d.ImageRepo, d.ImageTag = projects.SplitImage(s.Image)
	}
	d.State = h.serviceState(r.Context(), p.Slug, s)
	d.Deploying = d.State == "deploying"
	if st, err := h.projects.Status(r.Context(), p.Slug, s.Slug); err == nil {
		d.Health, d.Restarts, d.OOMKilled = st.Health, st.RestartCount, st.OOMKilled
	}
	d.Pending, _ = h.projects.PendingChanges(r.Context(), s.ID)
	if vols, err := h.projects.ListServiceVolumes(r.Context(), p.Slug, s); err == nil {
		for _, v := range vols {
			d.Volumes = append(d.Volumes, views.VolumeRow{Name: v.Name, Path: v.Path, Docker: v.Docker, Fixed: v.Fixed})
		}
	}
	if deps, err := h.projects.Deployments(r.Context(), s.ID, 10); err == nil {
		targets := h.projects.RollbackTargets(r.Context(), s.ID, deps)
		for _, dp := range deps {
			d.Deploys = append(d.Deploys, views.DeployRow{
				ID: dp.ID, Status: dp.Status, Phase: dp.Phase, Image: dp.Image, Trigger: dp.Trigger,
				When: time.Unix(dp.StartedAt, 0).Format("02/01 15:04"), Error: dp.Error.String,
				Log: dp.Log, Ref: shortRef(dp.ImageRef), CanRollback: targets[dp.ID],
				Commit: shortCommit(dp.CommitSha), CommitMessage: dp.CommitMessage,
			})
		}
	}
	d.Strategy = h.projects.ServiceStrategy(r.Context(), p, s)
	ds := h.projects.GetDeploySettings(s)
	d.PreDeploy, d.HealthPath, d.Validate = ds.PreDeploy, ds.HealthPath, ds.Validate
	if ds.ValidateTimeout > 0 {
		d.ValidateMinutes = strconv.Itoa(int(ds.ValidateTimeout.Minutes()))
	}
	if env, err := h.projects.ListEnv(r.Context(), s.ID); err == nil {
		for _, e := range env {
			row := views.EnvRow{Key: e.Key, Value: e.Value, Secret: e.Secret}
			if e.Key == v.revealKey {
				row.Value, row.Revealed = v.revealValue, true
			}
			d.Env = append(d.Env, row)
		}
	}
	if broken, err := h.projects.BrokenRefs(r.Context(), p); err == nil {
		for _, b := range broken {
			if b.ServiceID == s.ID {
				d.RefWarnings = append(d.RefWarnings, views.RefWarning{
					Key: b.Key, Project: b.Project, Service: b.Target, TargetKey: b.TargetKey, Problem: string(b.Problem),
				})
			}
		}
	}
	if sg, ok, err := h.projects.EnvSuggestions(r.Context(), s.ID); err == nil && ok {
		d.EnvSuggest = &views.EnvSuggest{File: sg.File}
		for _, v := range sg.Vars {
			d.EnvSuggest.Vars = append(d.EnvSuggest.Vars, views.SuggestedVar{Key: v.Key, Example: v.Value})
		}
	}
	d.Domains = views.DomainsSection{
		EdgeEnabled: h.projects.EdgeEnabled(), Dynamic: s.DynamicDomains == 1,
		CheckPath: s.DomainCheckPath, CheckSecret: v.checkSecret,
	}
	if info, err := h.projects.EdgeDNSInfo(r.Context()); err == nil {
		d.Domains.Base = views.EdgeBase{Domain: info.BaseDomain, Provider: info.Provider, Scaled: info.HasToken, FromConfig: info.FromConfig}
	}
	d.Domains.DNSProviders = edge.DNSProviders
	d.CanBackup, d.Stateful = h.projects.CanDownloadBackup(s.Template), s.Stateful == 1
	d.Maintenance = s.Maintenance == 1
	d.ServerHint = i18n.T(r.Context(), "port.ssh_target")
	if exps, err := h.projects.ListExports(r.Context(), s.ID); err == nil {
		for _, e := range exps {
			row := views.ExportRow{Key: e.Key, Value: e.Value, Secret: e.Secret}
			if e.Key == v.exportKey {
				row.Value, row.Revealed = v.exportValue, true
			}
			d.Exports = append(d.Exports, row)
		}
	}
	if ports, err := h.projects.ListPorts(r.Context(), s.ID); err == nil {
		for _, pt := range ports {
			ips, exp := portRow(pt)
			d.Ports = append(d.Ports, views.PortRow{
				ID: pt.ID, HostPort: pt.HostPort, ContainerPort: pt.ContainerPort, Protocol: pt.Protocol,
				Access: pt.Access, IPs: ips, Expires: exp,
			})
		}
	}
	if dp, ds, ok := h.projects.DynamicServiceRef(r.Context()); ok && (dp != p.Slug || ds != s.Slug) {
		d.Domains.DynamicElsewhere = dp + "/" + ds
	}
	if eps, err := h.projects.ListEndpoints(r.Context(), s.ID); err == nil {
		ip, _ := netip.ParseAddr(h.autoLinkIP)
		for _, e := range eps {
			host, cert := "", ""
			// With the edge off nothing routes the link: showing it would
			// promise an address that does not open.
			if e.Public && d.Domains.EdgeEnabled {
				host = edge.AutoHost(h.projects.BaseDomain(), ip, e.HostLabel)
				if host == "" && e.SslipEnabled {
					d.Domains.NoAutoLink = true
				} else if host != "" {
					cert = h.projects.CertificateState(host)
				}
			}
			d.Domains.Endpoints = append(d.Domains.Endpoints, views.EndpointRow{
				ID: e.ID, Label: e.Label, Port: e.Port, Public: e.Public, SslipEnabled: e.SslipEnabled, AutoHost: host, Cert: cert,
			})
		}
	}
	internal := map[string]bool{}
	for _, e := range d.Domains.Endpoints {
		internal[e.ID] = !e.Public
	}
	if doms, err := h.projects.ListDomains(r.Context(), s.ID); err == nil {
		for _, dm := range doms {
			d.Domains.Fixed = append(d.Domains.Fixed, views.DomainRow{
				ID: dm.ID, Hostname: dm.Hostname, Cert: h.projects.CertificateState(dm.Hostname),
				// A domain on an internal port, or an older one left on a
				// service without a port, is not served; say so.
				Offline: (dm.EndpointID.Valid && internal[dm.EndpointID.String]) || (!dm.EndpointID.Valid && s.InternalPort == 0),
			})
		}
	}
	d.Tab = serviceTab(r, d.CanBackup)
	d.OpenTerminal = r.URL.Query().Get("terminal") == "1"
	if d.Tab == "overview" {
		d.Metrics = h.serviceMetrics(r, s, len(d.Volumes) > 0)
	}
	if d.Tab == "backups" {
		d.Backups = h.serviceBackups(r, p, s)
	}
	if ip, err := netip.ParseAddr(client(r).IP); err == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
		d.ClientIP = ip.String() // pre-filled as "your IP" when opening a port
	}
	// The canvas opens a service in its drawer by asking only for the
	// drawer: no canvas, no menu, no dialogs (a fraction of the page).
	if r.Header.Get("X-Hangar-Fragment") == "panel" {
		render(w, r, v.status, views.ServicePanel(d))
		return
	}
	cd, err := h.canvasFor(r, p, s.Slug)
	if err != nil {
		loggerFrom(r.Context()).Error("canvas", "error", err)
	}
	render(w, r, v.status, views.ProjectCanvas(cd, &d))
}

// legacyTabs maps the tabs of the previous panel to where their content
// lives now, so old links and bookmarks still land on it.
var legacyTabs = map[string]string{
	"deploys": "overview", "metrics": "overview", "terminal": "overview",
	"connection": "variables", "domains": "network", "ports": "network",
}

// serviceTab picks the panel tab: the ?tab= asked for, else the one the
// action that just ran belongs to. Backups only exists on services that
// can be backed up.
func serviceTab(r *http.Request, canBackup bool) string {
	tab := inferTab(r)
	if to, ok := legacyTabs[tab]; ok {
		tab = to
	}
	if !slices.Contains(views.ServiceTabsFor(canBackup), tab) {
		return "overview"
	}
	return tab
}

func inferTab(r *http.Request) string {
	if t := r.URL.Query().Get("tab"); t != "" {
		return t
	}
	path := r.URL.Path
	switch {
	case strings.Contains(path, "/env"), strings.Contains(path, "/exports"):
		return "variables"
	case strings.Contains(path, "/domains"), strings.Contains(path, "/ports"):
		return "network"
	case strings.HasSuffix(path, "/backup"), strings.Contains(path, "/backups"):
		return "backups"
	case strings.HasSuffix(path, "/deploy-settings"), strings.HasSuffix(path, "/delete"), strings.Contains(path, "/git"), strings.Contains(path, "/volumes"),
		strings.HasSuffix(path, "/maintenance"), strings.HasSuffix(path, "/image"):
		return "settings"
	}
	switch r.URL.Query().Get("ok") {
	case "env", "env-deleted":
		return "variables"
	case "domain", "domain-deleted", "dynamic-on", "dynamic-off", "dns-token", "port", "port-closed":
		return "network"
	case "deploy-settings", "git", "git-token", "webhook-off", "volume", "volume-removed", "maintenance-on", "maintenance-off":
		return "settings"
	case "backup-policy", "backup-queued", "backup-preparing", "restore-started":
		return "backups"
	}
	return "overview"
}

func (h *handlers) serviceBase(r *http.Request) string {
	return servicePath(r.PathValue("project"), r.PathValue("service"))
}

// servicePath builds a service's local path only from valid slugs; anything
// else becomes "/" (no open redirect).
func servicePath(project, service string) string {
	if !node.SlugRE.MatchString(project) || !node.SlugRE.MatchString(service) {
		return "/"
	}
	return "/p/" + project + "/s/" + service
}

func redirectLocal(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path, http.StatusSeeOther) //nolint:gosec // path always comes from servicePath/fixed paths
}

func (h *handlers) deployService(w http.ResponseWriter, r *http.Request) {
	if _, err := h.projects.Deploy(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), "manual"); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=deploy")
}

// changeImage points the service at another tag of its image and deploys
// it (from the Settings tab, or from the updates page when a newer tag
// fixes a vulnerability). A deploy that fails puts the previous tag back.
func (h *handlers) changeImage(w http.ResponseWriter, r *http.Request) {
	if _, err := h.projects.ChangeImageTag(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("tag")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=image")
}

// rebuildService deploys from scratch: no build cache, base images and the
// service image pulled again (the trigger shows as "rebuild").
func (h *handlers) rebuildService(w http.ResponseWriter, r *http.Request) {
	if _, err := h.projects.Rebuild(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=deploy")
}

func (h *handlers) serviceAction(w http.ResponseWriter, r *http.Request) {
	action := r.PostFormValue("action")
	if action != "start" && action != "stop" && action != "restart" {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	if err := h.projects.Action(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), action); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=action")
}

func (h *handlers) withService(w http.ResponseWriter, r *http.Request) (dbq.Service, bool) {
	_, s, err := h.projects.GetService(r.Context(), r.PathValue("project"), r.PathValue("service"))
	if err != nil {
		http.NotFound(w, r)
		return s, false
	}
	return s, true
}

func (h *handlers) setEnv(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	err := h.projects.SetEnv(r.Context(), actor(r), s.ID, r.PostFormValue("key"), r.PostFormValue("value"), projects.LooksSecret(r.PostFormValue("key")))
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=env")
}

// setEnvBulk imports a pasted .env.
func (h *handlers) setEnvBulk(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	if _, err := h.projects.SetEnvBulk(r.Context(), actor(r), s.ID, r.PostFormValue("env"), false); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=env")
}

// dismissEnvSuggestions hides the repository's suggested variables.
func (h *handlers) dismissEnvSuggestions(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	if err := h.projects.DismissEnvSuggestions(r.Context(), actor(r), s.ID); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=variables")
}

func (h *handlers) deleteEnv(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	if err := h.projects.DeleteEnv(r.Context(), actor(r), s.ID, r.PostFormValue("key")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=env-deleted")
}

// revealEnv shows the secret once, in this response (it never lands in a URL
// or a cache: the page has Cache-Control: no-store).
func (h *handlers) revealEnv(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	key := r.PostFormValue("key")
	v, err := h.projects.RevealEnv(r.Context(), actor(r), s.ID, key)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	h.renderService(w, r, serviceView{
		status: http.StatusOK, revealKey: key, revealValue: v,
		flash: i18n.T(r.Context(), "service.env.revealed"),
	})
}

func (h *handlers) deleteService(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") != r.PathValue("service") {
		h.renderService(w, r, serviceView{status: http.StatusUnprocessableEntity, errMsg: i18n.T(r.Context(), "service.danger.name_mismatch")})
		return
	}
	if err := h.projects.DeleteService(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	project := r.PathValue("project")
	if !node.SlugRE.MatchString(project) {
		project = ""
	}
	redirectLocal(w, r, "/p/"+project)
}

// --- live logs (SSE) --------------------------------------------------------

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

const (
	logStreamMax = 30 * time.Minute
	logLineMax   = 8 << 10
)

func (h *handlers) serviceLogs(w http.ResponseWriter, r *http.Request) {
	svc, ok := h.withService(w, r)
	if !ok {
		return
	}
	rc := http.NewResponseController(w)
	// Long-lived connection: lift the server write deadline for this response only.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		http.Error(w, i18n.T(r.Context(), "error.internal"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ctx, cancel := context.WithTimeout(r.Context(), logStreamMax)
	defer cancel()

	var mu sync.Mutex
	send := func(s string) error {
		mu.Lock()
		defer mu.Unlock()
		if _, err := fmt.Fprint(w, s); err != nil {
			return err
		}
		return rc.Flush()
	}

	// Every 30 s check the session without extending it; if it is gone, stop.
	token := sessionToken(r)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !h.auth.StillValid(ctx, token) {
					_ = send("event: end\ndata: session_ended\n\n")
					cancel()
					return
				}
				_ = send(": ping\n\n")
			}
		}
	}()

	opt := node.LogOptions{Tail: 300, Follow: true}
	if last := r.Header.Get("Last-Event-ID"); last != "" {
		if ns, err := strconv.ParseInt(last, 10, 64); err == nil {
			opt.Tail, opt.Since = 0, time.Unix(0, ns)
		}
	}
	_ = send("retry: 3000\n\n")
	// The marks users dropped (last 24 h, or since the resume point); the
	// browser places each one at its moment among the lines.
	since := time.Now().Add(-24 * time.Hour)
	if !opt.Since.IsZero() {
		since = opt.Since
	}
	if marks, err := h.projects.LogMarks(ctx, svc.ID, since); err == nil {
		for _, mk := range marks {
			_ = send("event: mark\ndata: " + markJSON(mk) + "\n\n")
		}
	}
	err := h.projects.Logs(ctx, r.PathValue("project"), r.PathValue("service"), opt, func(ln node.LogLine) error {
		text := ansiRE.ReplaceAllString(ln.Text, "")
		if len(text) > logLineMax {
			text = text[:logLineMax] + " …"
		}
		b, _ := json.Marshal(map[string]any{"s": ln.Stream, "t": ln.Time.Local().Format("15:04:05"), "n": ln.Time.UnixNano(), "m": text})
		return send(fmt.Sprintf("id: %d\ndata: %s\n\n", ln.Time.UnixNano(), b))
	})
	if ctx.Err() == nil {
		reason := "container_stopped"
		if err != nil {
			reason = "unavailable"
		}
		_ = send("event: end\ndata: " + reason + "\n\n")
	}
}

// shortCommit is the 7-character commit id GitHub shows.
func shortCommit(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// shortRef shortens a pinned image for the history: sha256:0887661008.
func shortRef(ref string) string {
	if i := strings.LastIndex(ref, "sha256:"); i >= 0 && len(ref) >= i+17 {
		return ref[i : i+17]
	}
	return ref
}

// deployPending applies every pending change of the project (the canvas bar).
func (h *handlers) deployPending(w http.ResponseWriter, r *http.Request) {
	if _, err := h.projects.DeployPending(r.Context(), actor(r), r.PathValue("project")); err != nil {
		code, msg := userError(r, err)
		p, gerr := h.projects.GetProject(r.Context(), r.PathValue("project"))
		if gerr != nil {
			http.NotFound(w, r)
			return
		}
		cd, _ := h.canvasFor(r, p, "")
		cd.Error = msg
		render(w, r, code, views.ProjectCanvas(cd, nil))
		return
	}
	project := r.PathValue("project")
	if !node.SlugRE.MatchString(project) {
		project = ""
	}
	redirectLocal(w, r, "/p/"+project+"?ok=deploy")
}

func templateKind(id, category string) string {
	switch {
	case id == "postgres":
		return "db"
	case strings.HasPrefix(id, "redis"):
		return "cache"
	case category == "database":
		return "db"
	}
	return "app"
}

// markLog drops a separator in the service's log, at this moment, signed by
// the user (answers the mark as JSON for the page to draw it).
func (h *handlers) markLog(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	p := PrincipalFrom(r.Context())
	name := p.Name
	if name == "" {
		name, _, _ = strings.Cut(p.Email, "@")
	}
	mk, err := h.projects.AddLogMark(r.Context(), actor(r), s.ID, name)
	if err != nil {
		http.Error(w, i18n.T(r.Context(), "error.internal"), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(markJSON(mk)))
}

func markJSON(mk projects.LogMark) string {
	b, _ := json.Marshal(map[string]any{"n": mk.At.UnixNano(), "t": mk.At.Local().Format("15:04:05"), "by": mk.By})
	return string(b)
}
