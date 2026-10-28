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
	"github.com/JuniorCarlini/hangar/internal/volumes"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

func actor(r *http.Request) projects.Actor {
	p := PrincipalFrom(r.Context())
	return projects.Actor{UserID: p.UserID, IP: clientIP(r), Sudo: p.SudoFor(auth.SudoStrict, time.Now())}
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
	name := r.PostFormValue("name")
	p, err := h.projects.CreateProjectNamed(r.Context(), actor(r), name)
	if err != nil {
		code, msg := userError(r, err)
		// Back on the overview with the dialog open, showing the error.
		n := views.NavFrom(r.Context())
		n.NewProject = views.NewProjectForm{Open: true, Error: msg, Name: name}
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
		SudoActive: pr.SudoFor(auth.SudoStrict, time.Now()), SudoCritical: pr.SudoFor(auth.SudoCritical, time.Now()), CredOpen: credOpen, Flash: credFlash(r),
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
	case "deploy", "image", "env", "env-deleted", "action", "domain", "domain-deleted", "dynamic-on", "dynamic-off", "txt-on", "txt-off", "dns-token", "port", "port-closed", "rollback", "deploy-settings", "git", "git-token", "webhook-off", "auto-on", "auto-off",
		"maintenance-on", "maintenance-off", "backup-policy", "backup-queued", "backup-preparing", "restore-started", "volume", "volume-removed", "volume-edit",
		"volume-limit", "volume-unlimit", "connected", "offered", "unoffered", "resources":
		return i18n.T(r.Context(), "flash."+ok)
	}
	return ""
}

// serviceAddresses lists how the service is reached, for the Variables
// table: on the project network (one per web port), its public links and
// domains, and its published ports (the server's IP and the open port,
// while it stays open).
func (h *handlers) serviceAddresses(r *http.Request, p dbq.Project, s dbq.Service, d *views.ServiceData) []views.AddressRow {
	ctx := r.Context()
	host := node.ContainerName(p.Slug, s.Slug)
	var out []views.AddressRow
	if len(d.Domains.Endpoints) > 1 {
		for _, e := range d.Domains.Endpoints {
			out = append(out, views.AddressRow{Name: i18n.T(ctx, "address.internal_named", "label", e.Label), Value: host + ":" + strconv.Itoa(e.Port)})
		}
	} else {
		out = append(out, views.AddressRow{Name: i18n.T(ctx, "address.internal"), Value: projects.ServiceAddress(p, s)})
	}
	for _, e := range d.Domains.Endpoints {
		if e.Public && e.SslipEnabled && e.AutoHost != "" {
			name := i18n.T(ctx, "address.public")
			if len(d.Domains.Endpoints) > 1 {
				name = i18n.T(ctx, "address.public_named", "label", e.Label)
			}
			out = append(out, views.AddressRow{Name: name, Value: "https://" + e.AutoHost})
		}
	}
	for _, dm := range d.Domains.Fixed {
		if !strings.HasPrefix(dm.Hostname, "*.") && !dm.Offline {
			out = append(out, views.AddressRow{Name: i18n.T(ctx, "address.domain"), Value: "https://" + dm.Hostname})
		}
	}
	for _, pt := range d.Ports {
		// A port open to this server only answers on its loopback.
		v := strconv.FormatInt(pt.HostPort, 10)
		switch {
		case pt.Access == projects.AccessLocalhost:
			v = "127.0.0.1:" + v
		case h.serverIP != "":
			v = h.serverIP + ":" + v
		}
		out = append(out, views.AddressRow{Name: i18n.T(ctx, "address.published"), Value: v})
	}
	return out
}

// clientsOpen reports whether the page answers a change made in the
// customers' domains modal (a switch, the secret, or an error from them).
func clientsOpen(r *http.Request) bool {
	switch r.URL.Query().Get("ok") {
	case "dynamic-on", "txt-on", "txt-off":
		return true
	}
	if r.Method == http.MethodPost {
		for _, p := range []string{"/domains/dynamic", "/domains/txt", "/domains/secret/rotate"} {
			if strings.HasSuffix(r.URL.Path, p) {
				return true
			}
		}
	}
	return false
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
		SudoActive: pr.SudoFor(auth.SudoStrict, time.Now()), SudoCritical: pr.SudoFor(auth.SudoCritical, time.Now()), Error: v.errMsg, Flash: v.flash,
	}
	if d.Git = h.gitView(r, s.ID, s.ProjectID, v); d.Git != nil {
		d.Image = d.Git.Display + "@" + d.Git.Branch
	}
	d.State = h.serviceState(r.Context(), p.Slug, s)
	d.Deploying = d.State == "deploying"
	if st, err := h.projects.Status(r.Context(), p.Slug, s.Slug); err == nil {
		d.Health, d.Restarts, d.OOMKilled = st.Health, st.RestartCount, st.OOMKilled
	}
	d.Pending, _ = h.projects.PendingChanges(r.Context(), s.ID)
	if vols, err := h.projects.ListServiceVolumes(r.Context(), p.Slug, s); err == nil {
		d.LimitsAvailable = h.projects.VolumeLimitsAvailable()
		free := h.projects.HostFree()
		d.HostFree, d.HostFreeGB = fmtBytes(r.Context(), uint64(max(free, 0))), int(free/volumes.GiB)
		for _, v := range vols {
			d.Volumes = append(d.Volumes, volumeRow(r.Context(), v, d.HostFreeGB))
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
	ds := h.projects.GetDeploySettings(s)
	d.PreDeploy, d.HealthPath, d.Validate = ds.PreDeploy, ds.HealthPath, ds.Validate
	if ds.ValidateTimeout > 0 {
		d.ValidateMinutes = strconv.Itoa(int(ds.ValidateTimeout.Minutes()))
	}
	if deps, err := h.projects.Dependents(r.Context(), p.Slug, s.Slug); err == nil {
		d.UsedBy = dependentsLabel(r, deps)
		for _, dep := range deps {
			name := dep.Service
			if dep.Project != "" {
				name = dep.Project + "/" + dep.Service
			}
			if !slices.Contains(d.UsedByNames, name) {
				d.UsedByNames = append(d.UsedByNames, name)
			}
		}
	}
	d.ConnectOffers = h.connectOffers(r, p, s.Slug)
	// Admins see every value, in the table and in the .env editor; the
	// table follows the order of the .env file.
	if text, _, err := h.projects.EnvText(r.Context(), s.ID, d.CanAdmin); err == nil {
		d.EnvText = text
	}
	if d.CanAdmin {
		if text, err := h.projects.ResolvedEnvText(r.Context(), p, s.ID); err == nil {
			d.EnvCopy = text
		}
	}
	if env, err := h.projects.EnvInFileOrder(r.Context(), s.ID, d.CanAdmin); err == nil {
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
		RequireTXT:  s.DomainRequireTxt == 1,
		ClientsOpen: clientsOpen(r),
	}
	// Admins see the app's signing secret as it is (it reaches the app's
	// environment anyway); a rotation just put the new one in v.
	if d.Domains.Dynamic && d.CanAdmin && d.Domains.CheckSecret == "" {
		if secret, err := h.projects.CheckSecret(r.Context(), s.ID); err == nil {
			d.Domains.CheckSecret = secret
		}
	}
	if d.Domains.Dynamic && d.Domains.EdgeEnabled {
		d.Domains.EntryHost = h.entryHost()
	}
	if info, err := h.projects.EdgeDNSInfo(r.Context()); err == nil {
		d.Domains.Base = views.EdgeBase{Domain: info.BaseDomain, Provider: info.Provider, Scaled: info.HasToken, FromConfig: info.FromConfig}
	}
	d.Domains.DNSProviders = edge.DNSProviders
	d.CanBackup, d.Stateful = h.projects.BackupMethod(r.Context(), s) != "", s.Stateful == 1
	d.FixedPort = s.Template != ""
	d.Maintenance = s.Maintenance == 1
	d.ServerHint = i18n.T(r.Context(), "port.ssh_target")
	// What the copy buttons give. Admins get every value with references
	// resolved; below admin, only plain values that are not secret.
	if d.CanAdmin {
		env := make(map[string]string, len(d.Env))
		for _, e := range d.Env {
			env[e.Key] = e.Value
		}
		resolved := h.projects.ResolvedValues(r.Context(), p, env)
		for i := range d.Env {
			d.Env[i].Copy = resolved[d.Env[i].Key]
		}
	} else {
		for i, e := range d.Env {
			if !e.Secret && !strings.Contains(e.Value, "${{") {
				d.Env[i].Copy = e.Value
			}
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
		// A user limited to some projects does not learn the names of the
		// others (the router answers 404 for them, policy.go).
		if pr := PrincipalFrom(r.Context()); pr == nil || !pr.CanSeeProject(dp) {
			d.Domains.DynamicElsewhere = i18n.T(r.Context(), "domain.dynamic.other_project")
		}
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
	d.Addresses = h.serviceAddresses(r, p, s, &d)
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
	case strings.Contains(path, "/env"), strings.Contains(path, "/exports"), strings.HasSuffix(path, "/connect"):
		return "variables"
	case strings.Contains(path, "/domains"), strings.Contains(path, "/ports"):
		return "network"
	case strings.HasSuffix(path, "/backup"), strings.Contains(path, "/backups"):
		return "backups"
	case strings.HasSuffix(path, "/deploy-settings"), strings.HasSuffix(path, "/delete"), strings.Contains(path, "/git"), strings.Contains(path, "/volumes"),
		strings.HasSuffix(path, "/maintenance"), strings.HasSuffix(path, "/image"), strings.HasSuffix(path, "/resources"):
		return "settings"
	}
	switch r.URL.Query().Get("ok") {
	case "env", "env-deleted", "connected", "offered", "unoffered":
		return "variables"
	case "domain", "domain-deleted", "dynamic-on", "dynamic-off", "txt-on", "txt-off", "dns-token", "port", "port-closed":
		return "network"
	case "deploy-settings", "git", "git-token", "webhook-off", "volume", "volume-removed", "volume-edit", "volume-limit", "volume-unlimit", "maintenance-on", "maintenance-off", "resources":
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

// changeImage points the service at another image (the Settings tab sends
// the whole reference) or another tag of its image (the updates page, when
// a newer tag fixes a vulnerability) and deploys it. A deploy that fails
// puts the previous image back.
func (h *handlers) changeImage(w http.ResponseWriter, r *http.Request) {
	project, service := r.PathValue("project"), r.PathValue("service")
	var err error
	if image := r.PostFormValue("image"); image != "" {
		_, err = h.projects.ChangeImage(r.Context(), actor(r), project, service, image)
	} else {
		_, err = h.projects.ChangeImageTag(r.Context(), actor(r), project, service, r.PostFormValue("tag"))
	}
	if err != nil {
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

// allowStopGrace lets a request that stops a container outlive the
// server's write timeout: a service may take up to node.MaxStopGrace to
// stop after SIGTERM (its stop_grace_period).
func allowStopGrace(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(node.MaxStopGrace + time.Minute))
}

func (h *handlers) serviceAction(w http.ResponseWriter, r *http.Request) {
	action := r.PostFormValue("action")
	if action != "start" && action != "stop" && action != "restart" {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	allowStopGrace(w)
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
	// "replace" comes from the .env editor: the text is the whole file and
	// a line taken out is deleted (a secret it could not show stays).
	var err error
	if r.PostFormValue("mode") == "replace" {
		_, err = h.projects.SetEnvFile(r.Context(), actor(r), s.ID, r.PostFormValue("env"))
	} else {
		_, err = h.projects.SetEnvBulk(r.Context(), actor(r), s.ID, r.PostFormValue("env"), false)
	}
	if err != nil {
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
	allowStopGrace(w)
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

// pinProject pins the project to the top of the sidebar, or unpins it, and
// returns to the page the person was on.
func (h *handlers) pinProject(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if err := h.projects.PinProject(r.Context(), p.UserID, r.PathValue("project"), r.PostFormValue("on") == "1"); err != nil {
		if errors.Is(err, projects.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		loggerFrom(r.Context()).Error("pin project", "error", err)
		http.Error(w, i18n.T(r.Context(), "error.internal"), http.StatusInternalServerError)
		return
	}
	// safeNext keeps the redirect on this panel (a local path, never //host).
	redirectLocal(w, r, safeNext(r.PostFormValue("next")))
}
