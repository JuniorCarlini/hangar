package views

import (
	"context"
	"strings"

	"github.com/a-h/templ"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// t translates a UI key in the request's language (docs/22).
func t(ctx context.Context, key string, args ...any) string { return i18n.T(ctx, key, args...) }

// lang is the request's language, for <html lang>.
func lang(ctx context.Context) string { return i18n.Locale(ctx) }

type themeKey struct{}

// AssetVersion is a hash of the embedded assets, set once at start. It goes
// in every asset URL, so an update never leaves a browser on stale CSS or JS.
var AssetVersion = "dev"

func asset(path string) string { return "/assets/" + path + "?v=" + AssetVersion }

type navKey struct{}

// Nav is what the sidebar shows on every authenticated page.
type Nav struct {
	ServerIP  string // shown with a copy button in the sidebar footer
	Active    string // "projects", "domains", "ports", "update", "account" or a project slug
	Email     string
	Name      string
	Theme     string
	Locale    string // the saved choice ("" = follow the browser)
	Path      string // where the account menu's quick choices return to
	IsOwner   bool
	Projects  []NavProject
	PortsOpen int
	Update    bool
	// Open findings of the dependency monitor, for the sidebar badge.
	VulnCritical int
	VulnSecurity int
	// CanStatus may manage the public status links (admin+).
	CanStatus bool
	CSRF      string // for the forms in the account menu
	CanCreate bool   // may create projects
	// BackupAlerts counts backup problems (docs/09 alerts).
	BackupAlerts int
	// KitCheckDue asks the owner to confirm the recovery kit is still kept.
	KitCheckDue bool
	// NewProject is the "new project" dialog in the frame: open after
	// ?new=1, or again with the error when creating failed.
	NewProject NewProjectForm
	Role       string
	// ModKey is the shortcut modifier shown for the command palette: "⌘" on
	// Apple devices, "Ctrl " elsewhere (from the User-Agent).
	ModKey string

	// Server footer of the sidebar.
	Host    string
	Version string
	CPU     int    // percent
	RAM     string // "1,9 / 8 GB"
	RAMPct  int

	// The bell: newest alerts and whether any is unseen.
	Alerts       []AlertRow
	AlertsUnread bool
	// CanLock shows "Lock panel" (owner only); Locked shows the banner.
	CanLock bool
	Locked  bool
}

// widths lists every bar width as a literal class, so Tailwind generates
// them (the CSP forbids inline styles).
var widths = [...]string{
	"w-0", "w-[5%]", "w-[10%]", "w-[15%]", "w-[20%]", "w-[25%]", "w-[30%]", "w-[35%]", "w-[40%]",
	"w-[45%]", "w-[50%]", "w-[55%]", "w-[60%]", "w-[65%]", "w-[70%]", "w-[75%]", "w-[80%]", "w-[85%]", "w-[90%]",
	"w-[95%]", "w-full",
}

// pctWidth is the width class of a bar filled to pct percent (5% steps).
func pctWidth(pct int) string {
	return widths[max(0, min(pct, 100)+2)/5]
}

// NewProjectForm keeps the "new project" dialog's state.
type NewProjectForm struct {
	Open       bool
	Error      string
	Slug, Name string
}

// NavProject is a project in the sidebar.
type NavProject struct {
	Slug     string
	Name     string
	Services int64
}

// WithNav stores the sidebar data in ctx.
func WithNav(ctx context.Context, n Nav) context.Context { return context.WithValue(ctx, navKey{}, n) }

// NavFrom returns the sidebar data stored in ctx.
func NavFrom(ctx context.Context) Nav { return navFrom(ctx) }

func navFrom(ctx context.Context) Nav {
	n, _ := ctx.Value(navKey{}).(Nav)
	return n
}

func navItem(n Nav, key string) string {
	if n.Active == key {
		return "tuc-menu__item is-active"
	}
	return "tuc-menu__item"
}

// displayName is the name, or the e-mail's first part capitalized.
func displayName(n Nav) string {
	if n.Name != "" {
		first, _, _ := strings.Cut(n.Name, " ")
		return first
	}
	local, _, _ := strings.Cut(n.Email, "@")
	local, _, _ = strings.Cut(local, ".")
	if local == "" {
		return ""
	}
	return strings.ToUpper(local[:1]) + local[1:]
}

// fullName is the name, or the e-mail's first part capitalized.
func fullName(n Nav) string {
	if n.Name != "" {
		return n.Name
	}
	return displayName(n)
}

func navInitials(n Nav) string {
	if n.Name != "" {
		parts := strings.Fields(n.Name)
		out := strings.ToUpper(string([]rune(parts[0])[:1]))
		if len(parts) > 1 {
			out += strings.ToUpper(string([]rune(parts[len(parts)-1])[:1]))
		}
		return out
	}
	return initials(n.Email)
}

// initials are the account button's letters (from the e-mail).
func initials(email string) string {
	name, _, _ := strings.Cut(email, "@")
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '.' || r == '_' || r == '-' || r == '+' })
	out := ""
	for _, p := range parts {
		if p != "" && len(out) < 2 {
			out += strings.ToUpper(p[:1])
		}
	}
	if len(out) == 1 && len(name) > 1 {
		out += strings.ToUpper(name[1:2])
	}
	return out
}

type no2FAKey struct{}

// WithoutTOTP marks that the signed-in account has no 2FA: pages show a
// banner asking to turn it on, and re-confirmation asks for the password.
func WithoutTOTP(ctx context.Context) context.Context {
	return context.WithValue(ctx, no2FAKey{}, true)
}

// WithTOTP clears the mark (2FA was just turned on in this request).
func WithTOTP(ctx context.Context) context.Context {
	return context.WithValue(ctx, no2FAKey{}, false)
}

func noTOTP(ctx context.Context) bool {
	v, _ := ctx.Value(no2FAKey{}).(bool)
	return v
}

// WithTheme stores the user's theme ("system", "dark" or "light") in ctx.
func WithTheme(ctx context.Context, theme string) context.Context {
	return context.WithValue(ctx, themeKey{}, theme)
}

// Theme returns the theme stored in ctx ("system" if none).
func Theme(ctx context.Context) string {
	if th, ok := ctx.Value(themeKey{}).(string); ok && th != "" {
		return th
	}
	return "system"
}

// themeAttrs renders data-theme only for an explicit choice; "system" leaves
// it out and the CSS follows prefers-color-scheme. The server already knows
// the choice, so the page never flashes the wrong theme and needs no inline
// script (forbidden by the CSP).
func themeAttrs(ctx context.Context) templ.Attributes {
	if th := Theme(ctx); th == "dark" || th == "light" {
		return templ.Attributes{"data-theme": th}
	}
	return templ.Attributes{}
}

// Locales lists the languages offered in the UI.
func Locales() []string { return i18n.Locales() }

// deleteProjectModal is the dialog the "delete project" button opens: the
// confirmation itself in sudo mode, the "confirm it's you" dialog before.
func deleteProjectModal(sudo bool) string {
	if sudo {
		return "#delete-project"
	}
	return "#sudo-dialog"
}

type loginCSRFKey struct{}

// WithLoginCSRF carries the token the login form must send back: the panel
// has no session yet, so it is a double-submit token (docs/17 § 3.1, login
// CSRF).
func WithLoginCSRF(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, loginCSRFKey{}, token)
}

func loginCSRF(ctx context.Context) string {
	v, _ := ctx.Value(loginCSRFKey{}).(string)
	return v
}

// plainNotes turns the release notes (a CHANGELOG section in Markdown) into
// plain text for the update page: no "**", "###" or list dashes.
func plainNotes(s string) string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n"), "\n")
	for i, l := range lines {
		l = strings.ReplaceAll(l, "**", "")
		l = strings.ReplaceAll(l, "`", "")
		switch {
		case strings.HasPrefix(l, "### "):
			l = strings.TrimPrefix(l, "### ")
		case strings.HasPrefix(l, "- "):
			l = "• " + strings.TrimPrefix(l, "- ")
		}
		lines[i] = l
	}
	return strings.Join(lines, "\n")
}
