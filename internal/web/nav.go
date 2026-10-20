package web

import (
	"net/http"
	"os"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// navFor builds the sidebar: server pages, then every project. The active
// item comes from the path.
func (h *handlers) navFor(r *http.Request, p *auth.Principal) views.Nav {
	n := views.Nav{Email: p.Email, Name: p.Name, Theme: p.Theme, Locale: p.Locale, IsOwner: p.Role >= auth.RoleOwner, Path: "/", CSRF: p.CSRFToken, Role: p.Role.String(), CanCreate: p.Role >= auth.RoleAdmin}
	n.NewProject.Open = r.URL.Query().Get("new") == "1"
	n.ModKey = "Ctrl "
	if ua := r.UserAgent(); strings.Contains(ua, "Macintosh") || strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
		n.ModKey = "⌘"
	}
	n.Host, _ = os.Hostname()
	n.ServerIP = h.serverIP
	if h.updates != nil {
		n.Version = h.updates.Current()
	}
	if r.Method == http.MethodGet {
		n.Path = r.URL.RequestURI()
	}
	path := r.URL.Path
	switch {
	case path == "/":
		n.Active = "overview"
	case strings.HasPrefix(path, "/domains"):
		n.Active = "domains"
	case strings.HasPrefix(path, "/ports"):
		n.Active = "ports"
	case strings.HasPrefix(path, "/updates"):
		n.Active = "updates"
	case strings.HasPrefix(path, "/brand"):
		n.Active = "brand"
	case strings.HasPrefix(path, "/git-credentials"):
		n.Active = "git-credentials"
	case strings.HasPrefix(path, "/status-links"):
		n.Active = "status-links"
	case strings.HasPrefix(path, "/backups"):
		n.Active = "backups"
	case strings.HasPrefix(path, "/update"):
		n.Active = "update"
	case strings.HasPrefix(path, "/alerts"):
		n.Active = "alerts"
	case strings.HasPrefix(path, "/security"):
		n.Active = "security"
	case strings.HasPrefix(path, "/team"):
		n.Active = "team"
	case strings.HasPrefix(path, "/account"):
		n.Active = "account"
	case strings.HasPrefix(path, "/p/"):
		slug, _, _ := strings.Cut(strings.TrimPrefix(path, "/p/"), "/")
		n.Active = "p:" + slug
	}
	n.Limited = p.Limited()
	if list, err := h.projects.ListProjects(r.Context()); err == nil {
		for _, pr := range list {
			if !p.CanSeeProject(pr.Slug) {
				continue
			}
			n.Projects = append(n.Projects, views.NavProject{Slug: pr.Slug, Name: pr.Name, Services: pr.Services})
		}
	}
	if ports, err := h.projects.ListAllPorts(r.Context()); err == nil {
		n.PortsOpen = len(ports)
	}
	vc := h.depsCounts(r.Context())
	n.VulnCritical, n.VulnSecurity = vc["critical"], vc["security"]
	n.CanStatus = p.Role >= auth.RoleAdmin
	if !n.Limited {
		h.bell(r, p, &n)
	}
	n.CanLock = h.lock != nil && n.IsOwner
	if h.lock != nil {
		n.Locked = h.lock.Locked(r.Context())
	}
	n.BackupAlerts = h.backups.AlertCount(r.Context())
	n.KitCheckDue = n.IsOwner && h.backups.KitCheckDue(r.Context())
	if n.IsOwner && h.updates != nil {
		if av, _ := h.updates.Latest(); av != nil {
			n.Update = true
		}
	}
	return n
}
