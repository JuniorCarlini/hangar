// Package web builds the panel's HTTP interface.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/alerts"
	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/errpages"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/lockdown"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/statuspage"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

//go:embed assets
var assetsFS embed.FS

// Deps are the panel handler's dependencies.
type Deps struct {
	Hosts []string
	Log   *slog.Logger
	Audit *audit.Logger
	Auth  *auth.Service
	// Updates and UpdateDir feed the update page (docs/21).
	Updates   updates
	UpdateDir string
	// SetupCodeFile is shown on the first-run page, to find the code again.
	SetupCodeFile string
	Projects      *projects.Manager
	// Metrics feeds the overview and the service metrics; nil shows zeros.
	Metrics *metrics.Collector
	// Deps is the dependency and vulnerability monitor (docs/14); nil
	// shows an empty updates page.
	Deps *deps.Monitor
	// Status manages the public status links (docs/15); nil answers 404 on
	// every /s/ URL.
	Status *statuspage.Service
	// StatusHosts are extra Host values (status.example.com) that may only
	// reach the public status pages and their assets, never the panel.
	StatusHosts []string
	// Alerts feeds the bell and the alerts page; nil hides them.
	Alerts *alerts.Service
	// Lock is the lockdown switch; nil disables the "Lock panel" action.
	Lock *lockdown.Lock
	// HooksBase is the public address GitHub posts webhooks to
	// (https://<edge.hooks_hostname>); empty when none is configured.
	HooksBase string
	// Backups is the backup engine (docs/09).
	Backups *backup.Manager
	// Brand keeps the identity and texts of the error pages.
	Brand *errpages.Store
	// ErrorPages writes the rendered error pages where Caddy serves them;
	// nil when the edge is off (the brand is still saved).
	ErrorPages func(map[string][]byte) error
	// ServerIP is the server's address shown (with a copy button) at the
	// bottom of the sidebar; empty hides it.
	ServerIP string
	// BaseDomain is the operator's own domain for automatic links; empty
	// falls back to sslip.io built from AutoLinkIP (docs/28).
	BaseDomain string
	// AutoLinkIP is the public IP the sslip.io link is built from — the same
	// one the edge uses, so the panel never shows a link the proxy will not
	// serve. Empty (private/absent IP) means no automatic link.
	AutoLinkIP string
}

// New returns the panel handler, or an error if any route has an invalid
// policy. In that case the server does not start.
func New(d Deps) (http.Handler, error) {
	if err := i18n.Init(); err != nil {
		return nil, fmt.Errorf("web: language catalogs: %w", err)
	}
	if d.Auth == nil || d.Updates == nil || d.Projects == nil || d.Backups == nil || d.Brand == nil {
		return nil, errors.New("web: auth, updates, projects, backups and brand are required")
	}
	views.AssetVersion = assetVersion()
	rt := newRouter(d.Auth, d.Audit)
	hs := &handlers{
		auth: d.Auth, updates: d.Updates, updateDir: d.UpdateDir, setupFile: d.SetupCodeFile, projects: d.Projects, metrics: d.Metrics, audit: d.Audit,
		deps: d.Deps, status: d.Status, pub: newPublicStatus(d.Status), alerts: d.Alerts, lock: d.Lock, hooksBase: d.HooksBase, backups: d.Backups,
		hookFails: newHookFails(), serverIP: d.ServerIP, baseDomain: d.BaseDomain, autoLinkIP: d.AutoLinkIP, errorPages: d.ErrorPages, brand: d.Brand,
	}
	if len(d.StatusHosts) > 0 {
		hs.statusBase = "https://" + d.StatusHosts[0]
	}
	rt.nav = hs.navFor
	routes(rt, hs)
	if err := rt.Validate(); err != nil {
		return nil, err
	}

	cop := http.NewCrossOriginProtection()
	var h http.Handler = rt.mux
	h = cop.Handler(h)
	h = lockGate(d.Lock, h)
	h = withLocale(h)
	h = limitBody(h)
	h = hostCheck(d.Hosts, d.StatusHosts, h)
	h = securityHeaders(h)
	h = withLogger(d.Log, h)
	return h, nil
}

// routes is the only place where routes are registered.
func routes(rt *Router, h *handlers) {
	public := Policy{Public: true}

	rt.HandleFunc("GET /healthz", healthz, public)
	rt.Handle("GET /assets/", assets(), public)

	// GitHub's webhook: no session, authenticated by the HMAC signature.
	rt.HandleFunc("POST "+projects.HookPath+"{token}", h.gitHook, Policy{Public: true, Audit: "service.webhook", AuditByHandler: true})

	// First-run setup: only while there is no user, and only with the
	// one-time code from the server.
	rt.HandleFunc("GET /setup", h.setupPage, public)
	rt.HandleFunc("POST /setup", h.setupSubmit, Policy{Public: true, Audit: "user.create", AuditByHandler: true})
	rt.HandleFunc("GET /login", h.loginPage, public)
	rt.HandleFunc("POST /login", h.loginSubmit, Policy{Public: true, Audit: "auth.login.password", AuditByHandler: true})
	rt.HandleFunc("GET /login/2fa", h.twoFactorPage, public)
	rt.HandleFunc("POST /login/2fa", h.twoFactorSubmit, Policy{Public: true, Audit: "auth.login.2fa", AuditByHandler: true})

	rt.HandleFunc("POST /logout", h.logout, Policy{Role: auth.RoleViewer, Audit: "auth.logout"})
	rt.HandleFunc("POST /sudo", h.sudo, Policy{Role: auth.RoleViewer, Audit: "auth.sudo", AuditByHandler: true})

	viewer := Policy{Role: auth.RoleViewer}
	rt.HandleFunc("GET /{$}", h.overviewPage, viewer)
	rt.HandleFunc("GET /palette.json", h.palette, viewer)
	rt.HandleFunc("POST /projects", h.createProject, Policy{Role: auth.RoleAdmin, Audit: "project.create", AuditByHandler: true})
	rt.HandleFunc("GET /p/{project}", h.projectPage, viewer)
	rt.HandleFunc("POST /p/{project}/services", h.createService, Policy{Role: auth.RoleAdmin, Audit: "service.create", AuditByHandler: true})
	rt.HandleFunc("POST /p/{project}/services/git", h.createGitService, Policy{Role: auth.RoleAdmin, Audit: "service.create", AuditByHandler: true})

	svc := "/p/{project}/s/{service}"
	rt.HandleFunc("GET "+svc, h.servicePage, viewer)
	rt.HandleFunc("GET "+svc+"/logs", h.serviceLogs, viewer)
	rt.HandleFunc("POST "+svc+"/logs/mark", h.markLog, Policy{Role: auth.RoleOperator, Audit: "service.logs.mark"})
	rt.HandleFunc("POST "+svc+"/deploy", h.deployService, Policy{Role: auth.RoleOperator, Audit: "service.deploy", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/rebuild", h.rebuildService, Policy{Role: auth.RoleOperator, Audit: "service.deploy", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/position", h.moveCard, Policy{Role: auth.RoleOperator, Audit: "service.move"})
	rt.HandleFunc("POST "+svc+"/action", h.serviceAction, Policy{Role: auth.RoleOperator, Audit: "service.action", AuditByHandler: true})
	// Maintenance takes every domain of the service off the air.
	rt.HandleFunc("POST "+svc+"/maintenance", h.setMaintenance, Policy{Role: auth.RoleAdmin, Audit: "service.maintenance", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/env", h.setEnv, Policy{Role: auth.RoleOperator, Audit: "service.env.set", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/env/bulk", h.setEnvBulk, Policy{Role: auth.RoleOperator, Audit: "service.env.set", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/env/suggestions/dismiss", h.dismissEnvSuggestions, Policy{Role: auth.RoleOperator, Audit: "service.env.suggestions_dismiss", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/env/delete", h.deleteEnv, Policy{Role: auth.RoleOperator, Audit: "service.env.delete", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/env/reveal", h.revealEnv, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "secret.reveal", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/delete", h.deleteService, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.delete", AuditByHandler: true})

	rt.HandleFunc("POST "+svc+"/domains", h.addDomain, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "domain.add", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/domains/delete", h.removeDomain, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "domain.remove", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/domains/dynamic", h.dynamicDomains, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "domain.dynamic", AuditByHandler: true})
	// Putting a port on the internet takes what adding a domain takes;
	// taking it off only lowers exposure.
	rt.HandleFunc("POST "+svc+"/endpoints/public", h.setEndpointPublic, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.endpoint.public", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/endpoints/internal", h.setEndpointInternal, Policy{Role: auth.RoleOperator, Audit: "service.endpoint.internal", AuditByHandler: true})
	// Turning an automatic link on adds a new address on the internet (as
	// publishing does); turning it off only removes one.
	rt.HandleFunc("POST "+svc+"/endpoints/sslip-on", h.endpointSslipOn, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.endpoint.sslip_on", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/endpoints/sslip-off", h.endpointSslipOff, Policy{Role: auth.RoleOperator, Audit: "service.endpoint.sslip_off", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/domains/secret", h.revealCheckSecret, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "secret.reveal", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/domains/secret/rotate", h.rotateCheckSecret, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "domain.dynamic.rotate_secret", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/exports/reveal", h.revealExport, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "secret.reveal", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/backup", h.downloadBackup, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.backup.download", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/ports", h.addPort, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "port.open", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/ports/delete", h.removePort, Policy{Role: auth.RoleAdmin, Audit: "port.close", AuditByHandler: true})
	rt.HandleFunc("POST /p/{project}/tidy", h.tidyCanvas, Policy{Role: auth.RoleOperator, Audit: "project.tidy"})
	rt.HandleFunc("POST /p/{project}/deploy-pending", h.deployPending, Policy{Role: auth.RoleOperator, Audit: "service.deploy", AuditByHandler: true})
	rt.HandleFunc("GET /p/{project}/new", h.newServicePage, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("GET /p/{project}/settings", h.projectSettingsPage, viewer)
	rt.HandleFunc("POST /p/{project}/delete", h.deleteProject, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "project.delete", AuditByHandler: true})
	rt.HandleFunc("GET /p/{project}/new/{template}", h.templatePage, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("GET /p/{project}/github/repos", h.githubRepos, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("GET /p/{project}/github/branches", h.githubBranches, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("GET /templates/{template}/logo.svg", h.templateLogo, viewer)
	rt.HandleFunc("POST /p/{project}/templates", h.createFromTemplate, Policy{Role: auth.RoleAdmin, Audit: "service.create", AuditByHandler: true})
	// The preview creates nothing (it may save a new Git credential, which
	// audits itself); the import audits each service it creates.
	rt.HandleFunc("GET "+views.ComposeSampleURL, h.composeSample, viewer)
	rt.HandleFunc("POST /p/{project}/compose/preview", h.composePreview, Policy{Role: auth.RoleAdmin, Audit: "service.compose.preview"})
	rt.HandleFunc("POST /p/{project}/compose", h.composeCreate, Policy{Role: auth.RoleAdmin, Audit: "service.create", AuditByHandler: true})
	// Opening a way in (port, domain, link to another project) needs sudo
	// (docs/17 § 1.3); closing one does not: in a hurry, reducing exposure
	// must stay one click away.
	rt.HandleFunc("POST /p/{project}/links", h.projectLink, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "project.link", AuditByHandler: true})
	rt.HandleFunc("POST /p/{project}/links/delete", h.projectUnlink, Policy{Role: auth.RoleAdmin, Audit: "project.unlink", AuditByHandler: true})
	rt.HandleFunc("GET /overview", h.overviewRedirect, viewer)
	rt.HandleFunc("GET /ports", h.openPortsPage, viewer)
	rt.HandleFunc("POST "+svc+"/rollback", h.rollback, Policy{Role: auth.RoleOperator, Audit: "service.rollback", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/deploy-settings", h.saveDeploySettings, Policy{Role: auth.RoleAdmin, Audit: "service.deploy_settings", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/git", h.saveGitSource, Policy{Role: auth.RoleAdmin, Audit: "service.git.source", AuditByHandler: true})
	// A shell in the container: full access to it, so admin and sudo.
	rt.HandleFunc("GET "+svc+"/terminal/ws", h.terminalWS, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.terminal.open", AuditByHandler: true})
	// The terminal page opens nothing by itself (the WebSocket above does);
	// saved commands run only through it, so saving one needs no sudo.
	rt.HandleFunc("GET "+svc+"/terminal", h.terminalPage, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("POST "+svc+"/terminal/commands", h.saveCommand, Policy{Role: auth.RoleAdmin, Audit: "service.command.save", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/terminal/commands/delete", h.deleteCommand, Policy{Role: auth.RoleAdmin, Audit: "service.command.delete", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/volumes", h.addVolume, Policy{Role: auth.RoleAdmin, Audit: "service.volume.add", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/volumes/remove", h.removeVolume, Policy{Role: auth.RoleAdmin, Audit: "service.volume.remove", AuditByHandler: true})
	// Deleting a disk's data cannot be undone.
	rt.HandleFunc("POST "+svc+"/volumes/wipe", h.wipeVolume, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.volume.wipe", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/git/credential", h.saveGitCredential, Policy{Role: auth.RoleAdmin, Audit: "service.git.token", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/git/token", h.saveGitToken, Policy{Role: auth.RoleAdmin, Audit: "service.git.token", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/git/token/reveal", h.revealGitToken, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "secret.reveal", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/git/webhook", h.gitWebhook, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.git.webhook", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/git/webhook/reveal", h.revealWebhook, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "secret.reveal", AuditByHandler: true})
	rt.HandleFunc("GET /domains", h.domainsPage, viewer)
	rt.HandleFunc("POST /domains/block", h.blockHostname, Policy{Role: auth.RoleAdmin, Audit: "domain.block", AuditByHandler: true})
	rt.HandleFunc("POST /domains/unblock", h.unblockHostname, Policy{Role: auth.RoleAdmin, Audit: "domain.unblock", AuditByHandler: true})

	rt.HandleFunc("GET /updates", h.updatesPage, viewer)
	rt.HandleFunc("POST /updates/scan", h.updatesScan, Policy{Role: auth.RoleOperator, Audit: "deps.scan"})
	rt.HandleFunc("POST /updates/ignore", h.updatesIgnore, Policy{Role: auth.RoleOperator, Audit: "deps.ignore", AuditByHandler: true})
	rt.HandleFunc("POST /updates/unignore", h.updatesUnignore, Policy{Role: auth.RoleOperator, Audit: "deps.unignore", AuditByHandler: true})

	// Git credentials: admins create, replace and delete them; the token is
	// never shown again (a new one replaces it), so no sudo is involved.
	rt.HandleFunc("GET /git-credentials", h.gitCredsPage, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("POST /git-credentials", h.createGitCred, Policy{Role: auth.RoleAdmin, Audit: "git.credential.create", AuditByHandler: true})
	rt.HandleFunc("POST /git-credentials/check", h.checkGitCred, Policy{Role: auth.RoleAdmin, Audit: "git.credential.check", AuditByHandler: true})
	rt.HandleFunc("POST /git-credentials/{id}/token", h.replaceGitCred, Policy{Role: auth.RoleAdmin, Audit: "git.credential.replace", AuditByHandler: true})
	rt.HandleFunc("POST /git-credentials/{id}/delete", h.deleteGitCred, Policy{Role: auth.RoleAdmin, Audit: "git.credential.delete", AuditByHandler: true})
	// The pages visitors see when a site cannot answer: they show on every
	// domain of the server, so changing them needs sudo.
	rt.HandleFunc("GET /brand", h.brandPage, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("GET /brand/preview/{kind}", h.brandPreview, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("POST /brand", h.saveBrand, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "brand.save"})
	rt.HandleFunc("POST /brand/pages/{kind}", h.saveBrandPage, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "brand.save"})
	rt.HandleFunc("GET /status-links", h.statusLinksPage, Policy{Role: auth.RoleAdmin})
	rt.HandleFunc("POST /status-links", h.createStatusLink, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "status_link.create", AuditByHandler: true})
	rt.HandleFunc("POST /status-links/revoke", h.revokeStatusLink, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "status_link.revoke", AuditByHandler: true})
	rt.HandleFunc("POST /status-links/alias", h.setStatusAlias, Policy{Role: auth.RoleAdmin, Audit: "status_link.alias", AuditByHandler: true})

	// Public status links (docs/15): no session, unguessable token, rate
	// limited, a snapshot without any real name. "/s/{token}" also serves
	// "/s/{token}.json".
	rt.HandleFunc("GET /s/{token}", h.pub.page, public)
	rt.HandleFunc("GET /s/{token}/metrics", h.pub.prometheus, public)

	rt.HandleFunc("GET /alerts", h.alertsPage, viewer)
	rt.HandleFunc("POST /alerts/seen", h.markAlertsSeen, Policy{Role: auth.RoleViewer, Audit: "alerts.seen"})
	rt.HandleFunc("POST /alerts/channels", h.createChannel, Policy{Role: auth.RoleAdmin, Audit: "alerts.channel.create", AuditByHandler: true})
	rt.HandleFunc("POST /alerts/channels/{id}/test", h.testChannel, Policy{Role: auth.RoleAdmin, Audit: "alerts.channel.test", AuditByHandler: true})
	rt.HandleFunc("POST /alerts/channels/{id}/reveal", h.revealChannel, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "secret.reveal", AuditByHandler: true})
	rt.HandleFunc("POST /alerts/channels/{id}/toggle", h.toggleChannel, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "alerts.channel.toggle", AuditByHandler: true})
	rt.HandleFunc("POST /alerts/channels/{id}/delete", h.deleteChannel, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "alerts.channel.delete", AuditByHandler: true})
	rt.HandleFunc("POST /alerts/rules", h.saveAlertRules, Policy{Role: auth.RoleAdmin, Audit: "alerts.rules.update", AuditByHandler: true})
	rt.HandleFunc("POST /alerts/mute", h.muteAlerts, Policy{Role: auth.RoleAdmin, Audit: "alerts.mute", AuditByHandler: true})
	rt.HandleFunc("POST /lock", h.lockPanel, Policy{Role: auth.RoleOwner, Audit: "system.lockdown", AuditByHandler: true})

	// Backups (docs/09). Keys and destinations decide who can read the
	// backups and where they go: owner and sudo. Restoring and downloading
	// hand data out: admin and sudo (docs/17 § 2).
	rt.HandleFunc("GET /backups", h.backupsPage, viewer)
	rt.HandleFunc("POST /backups/panel", h.backupPanelNow, Policy{Role: auth.RoleOperator, Audit: "backup.run.request"})
	rt.HandleFunc("GET /backups/kit", h.kitPage, Policy{Role: auth.RoleOwner})
	rt.HandleFunc("POST /backups/keys", h.addKey, Policy{Role: auth.RoleOwner, Sudo: true, Audit: "backup.key.add", AuditByHandler: true})
	rt.HandleFunc("POST /backups/keys/confirm", h.confirmKey, Policy{Role: auth.RoleOwner, Sudo: true, Audit: "backup.key.confirm", AuditByHandler: true})
	rt.HandleFunc("POST /backups/keys/delete", h.deleteKey, Policy{Role: auth.RoleOwner, Sudo: true, Audit: "backup.key.remove", AuditByHandler: true})
	rt.HandleFunc("GET /backups/targets/new", h.targetPage, Policy{Role: auth.RoleOwner})
	rt.HandleFunc("POST /backups/targets", h.addTarget, Policy{Role: auth.RoleOwner, Sudo: true, Audit: "backup.target.add", AuditByHandler: true})
	rt.HandleFunc("POST /backups/targets/check", h.checkTarget, Policy{Role: auth.RoleAdmin, Audit: "backup.target.check", AuditByHandler: true})
	rt.HandleFunc("POST /backups/targets/delete", h.deleteTarget, Policy{Role: auth.RoleOwner, Sudo: true, Audit: "backup.target.remove", AuditByHandler: true})
	rt.HandleFunc("GET /backups/runs/{id}/download", h.runDownload, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "backup.download_link", AuditByHandler: true})
	rt.HandleFunc("GET /backups/download/{token}", h.takeDownload, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "service.backup.download", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/backups/policy", h.setBackupPolicy, Policy{Role: auth.RoleAdmin, Audit: "backup.policy.set", AuditByHandler: true})
	rt.HandleFunc("POST "+svc+"/backups/run", h.runBackupNow, Policy{Role: auth.RoleOperator, Audit: "backup.run.request"})
	rt.HandleFunc("POST "+svc+"/backups/restore", h.restoreBackup, Policy{Role: auth.RoleAdmin, Sudo: true, Audit: "backup.restore.start", AuditByHandler: true})

	rt.HandleFunc("GET /_pista", h.pistaPage, viewer)

	rt.HandleFunc("GET /account", h.accountPage, viewer)
	rt.HandleFunc("POST /account/sessions/end", h.endSession, Policy{Role: auth.RoleViewer, Audit: "auth.session.end", AuditByHandler: true})
	rt.HandleFunc("POST /account/totp/enable", h.enableTOTP, Policy{Role: auth.RoleViewer, Audit: "auth.totp.enable", AuditByHandler: true})
	rt.HandleFunc("POST /account/totp/disable", h.disableTOTP, Policy{Role: auth.RoleViewer, Audit: "auth.totp.disable", AuditByHandler: true})
	rt.HandleFunc("POST /account/preferences", h.savePreferences, Policy{Role: auth.RoleViewer, Audit: "user.preferences", AuditByHandler: true})

	rt.HandleFunc("GET /update", h.updatePage, Policy{Role: auth.RoleOwner})
	rt.HandleFunc("POST /update/check", h.updateCheck, Policy{Role: auth.RoleOwner, Audit: "system.update.check"})
	rt.HandleFunc("POST /update", h.updateApply, Policy{Role: auth.RoleOwner, Sudo: true, Audit: "system.update.request"})
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// assets serves CSS and icons embedded in the binary. They are not secret:
// they can be cached, unlike the pages.
// assetVersion hashes every embedded asset.
func assetVersion() string {
	h := sha256.New()
	_ = fs.WalkDir(assetsFS, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(assetsFS, path)
		if err != nil {
			return err
		}
		h.Write([]byte(path))
		h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func assets() http.Handler {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic(err) // the directory is embedded at compile time; failing here is a build bug
	}
	files := http.StripPrefix("/assets/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r) // no directory listing
			return
		}
		// A versioned URL never changes content: cache it for good.
		if r.URL.Query().Get("v") == views.AssetVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
