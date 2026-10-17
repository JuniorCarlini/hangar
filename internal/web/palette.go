package web

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// The command palette (⌘K) asks this endpoint, once per page, for what the
// signed-in user can open or run. Only names, paths and translated labels go
// out: no secrets, no CSRF token (the page already has it), and every action
// is filtered by the same minimum role its route requires.

type paletteGroup struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type paletteConfirm struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	OK    string `json:"ok"`
	Tone  string `json:"tone"`
}

// palettePost is an action that submits a form (with the page's CSRF token).
type palettePost struct {
	URL     string            `json:"url"`
	Fields  map[string]string `json:"fields,omitempty"`
	Next    bool              `json:"next,omitempty"` // send the current page as "next"
	Confirm *paletteConfirm   `json:"confirm,omitempty"`
}

type paletteItem struct {
	Group string `json:"group"`
	Label string `json:"label"`
	Hint  string `json:"hint,omitempty"`
	Icon  string `json:"icon"`
	// Deep items (service tabs, per-service actions) only show once the
	// user types, so the empty palette stays short.
	Deep  bool         `json:"deep,omitempty"`
	Tone  string       `json:"tone,omitempty"`
	Href  string       `json:"href,omitempty"`
	Modal string       `json:"modal,omitempty"` // id of a dialog on the page
	Post  *palettePost `json:"post,omitempty"`
}

type paletteData struct {
	Groups []paletteGroup `json:"groups"`
	Items  []paletteItem  `json:"items"`
}

// tabIcons gives each service tab its icon in the palette.
var tabIcons = map[string]string{
	"overview": "gauge", "variables": "braces", "network": "globe",
	"logs": "file-text", "settings": "settings",
	"backups": "database-backup",
}

func (h *handlers) palette(w http.ResponseWriter, r *http.Request) {
	d := h.paletteFor(r.Context(), PrincipalFrom(r.Context()))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(d); err != nil {
		loggerFrom(r.Context()).Error("palette", "error", err)
	}
}

func (h *handlers) paletteFor(ctx context.Context, p *auth.Principal) paletteData {
	tr := func(key string, args ...any) string { return i18n.T(ctx, key, args...) }
	operate, admin, owner := p.Role >= auth.RoleOperator, p.Role >= auth.RoleAdmin, p.Role >= auth.RoleOwner
	d := paletteData{Groups: []paletteGroup{
		{ID: "pages", Label: tr("palette.group.pages")},
		{ID: "projects", Label: tr("palette.group.projects")},
		{ID: "services", Label: tr("palette.group.services")},
		{ID: "actions", Label: tr("palette.group.actions")},
	}}
	add := func(it paletteItem) { d.Items = append(d.Items, it) }

	add(paletteItem{Group: "pages", Label: tr("nav.overview"), Icon: "gauge", Href: "/"})
	add(paletteItem{Group: "pages", Label: tr("nav.domains"), Icon: "globe", Href: "/domains"})
	add(paletteItem{Group: "pages", Label: tr("nav.ports"), Icon: "plug", Href: "/ports"})
	add(paletteItem{Group: "pages", Label: tr("nav.updates"), Icon: "shield-alert", Href: "/updates"})
	if admin {
		add(paletteItem{Group: "pages", Label: tr("nav.status_links"), Icon: "wifi", Href: "/status-links"})
	}
	add(paletteItem{Group: "pages", Label: tr("nav.alerts"), Icon: "bell", Href: "/alerts"})
	add(paletteItem{Group: "pages", Label: tr("nav.backups"), Icon: "database-backup", Href: "/backups"})
	if owner {
		add(paletteItem{Group: "pages", Label: tr("nav.update"), Icon: "refresh-cw", Href: "/update"})
	}
	add(paletteItem{Group: "pages", Label: tr("nav.account"), Icon: "user", Href: "/account"})

	if admin {
		add(paletteItem{Group: "actions", Label: tr("nav.new_project"), Icon: "folder-plus", Modal: "new-project"})
	}
	list, err := h.projects.ListProjects(ctx)
	if err != nil {
		loggerFrom(ctx).Error("palette: projects", "error", err)
	}
	for _, pr := range list {
		if !node.SlugRE.MatchString(pr.Slug) {
			continue
		}
		hint := ""
		if pr.Name != "" && pr.Name != pr.Slug {
			hint = pr.Name
		}
		add(paletteItem{Group: "projects", Label: pr.Slug, Hint: hint, Icon: "folder", Href: "/p/" + pr.Slug})
		if admin {
			add(paletteItem{Group: "actions", Label: tr("palette.new_service", "project", pr.Slug), Icon: "plus", Deep: true, Href: "/p/" + pr.Slug + "/new"})
		}
		svcs, err := h.projects.ListServices(ctx, pr.ID)
		if err != nil {
			loggerFrom(ctx).Error("palette: services", "project", pr.Slug, "error", err)
			continue
		}
		for _, s := range svcs {
			base := servicePath(pr.Slug, s.Slug)
			if base == "/" {
				continue
			}
			add(paletteItem{Group: "services", Label: s.Slug, Hint: pr.Slug, Icon: "box", Href: base})
			for _, tab := range views.ServiceTabsFor(h.projects.CanDownloadBackup(s.Template)) {
				add(paletteItem{
					Group: "services", Label: tr("palette.service_tab", "service", s.Slug, "tab", tr("service.tab."+tab)),
					Hint: pr.Slug, Icon: tabIcons[tab], Deep: true, Href: base + "?tab=" + tab,
				})
			}
			if operate {
				add(paletteItem{
					Group: "actions", Label: tr("palette.deploy", "service", s.Slug), Hint: pr.Slug, Icon: "rocket", Deep: true,
					Post: &palettePost{URL: base + "/deploy", Confirm: &paletteConfirm{
						Title: tr("confirm.deploy.title", "service", s.Slug), Text: tr("confirm.deploy.text"), OK: tr("confirm.deploy.ok"), Tone: "default",
					}},
				})
				add(paletteItem{
					Group: "actions", Label: tr("palette.restart", "service", s.Slug), Hint: pr.Slug, Icon: "rotate-ccw", Deep: true,
					Post: &palettePost{URL: base + "/action", Fields: map[string]string{"action": "restart"}, Confirm: &paletteConfirm{
						Title: tr("confirm.restart.title"), Text: tr("confirm.restart.text"), OK: tr("confirm.restart.ok"), Tone: "warning",
					}},
				})
			}
		}
	}

	current := p.Theme
	if current == "" {
		current = "system"
	}
	for _, th := range []string{"system", "dark", "light"} {
		if th == current {
			continue
		}
		add(paletteItem{
			Group: "actions", Label: tr("palette.theme", "theme", tr("theme."+th)), Icon: views.ThemeIcon(th),
			Post: &palettePost{URL: "/account/preferences", Next: true, Fields: map[string]string{"theme": th, "locale": p.Locale}},
		})
	}
	add(paletteItem{
		Group: "actions", Label: tr("nav.logout"), Icon: "log-out", Tone: "danger",
		Post: &palettePost{URL: "/logout", Confirm: &paletteConfirm{
			Title: tr("confirm.logout.title"), Text: tr("confirm.logout.text"), OK: tr("confirm.logout.ok"), Tone: "danger",
		}},
	})
	return d
}
