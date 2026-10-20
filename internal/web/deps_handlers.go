package web

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- updates and vulnerabilities page (docs/14, docs/17 § 3.8) ---------------

const (
	// rowsPerSection is how many rows a section shows on the full page; the
	// rest are behind its filter.
	rowsPerSection = 10
	// rowsPerPage is one page of a filtered section: a real server can have
	// hundreds of rows waiting for a fix.
	rowsPerPage = 25
	// advisoriesPerRow bounds the list in a row's dialog.
	advisoriesPerRow = 200
)

// sectionOrder is the page's sections: the vulnerability buckets, then the
// newer image tags with no known vulnerability.
var sectionOrder = append(append([]string{}, deps.Buckets...), deps.BucketUpdates)

func (h *handlers) updatesPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch r.URL.Query().Get("ok") {
	case "scan":
		flash = i18n.T(r.Context(), "deps.flash.scan")
	case "ignored":
		flash = i18n.T(r.Context(), "deps.flash.ignored")
	case "unignored":
		flash = i18n.T(r.Context(), "deps.flash.unignored")
	}
	h.renderUpdates(w, r, http.StatusOK, "", flash)
}

func (h *handlers) renderUpdates(w http.ResponseWriter, r *http.Request, status int, errMsg, flash string) {
	ctx := r.Context()
	pr := PrincipalFrom(ctx)
	d := views.UpdatesData{
		CSRF: pr.CSRFToken, CanOperate: pr.Role >= auth.RoleOperator, CanAdmin: pr.Role >= auth.RoleAdmin,
		CanUpdate: pr.Role >= auth.RoleOwner, SudoActive: pr.SudoFor(auth.SudoStrict, time.Now()),
		Error: errMsg, Flash: flash, Bucket: r.FormValue("bucket"), Running: h.deps.Running(),
	}
	if !validBucket(d.Bucket) {
		d.Bucket = ""
	}
	if h.deps == nil {
		d.Empty = true
		for _, b := range deps.Buckets {
			d.Cards = append(d.Cards, views.BucketCard{Bucket: b})
		}
		render(w, r, status, views.Updates(d))
		return
	}
	last, lastErr := h.deps.LastRun()
	if !last.IsZero() {
		d.LastRun = ago(ctx, last.Format(time.RFC3339Nano), time.Now())
	}
	d.LastError = lastErr != ""
	fs, err := h.deps.Findings(ctx)
	if err != nil {
		status, d.Error = userError(r, err)
	}
	for _, f := range fs {
		if f.Ignored {
			d.IgnoredCount++
		}
	}
	// The edge's image comes with Hangar: a newer release is its "deploy".
	hangarUpdate := false
	if h.updates != nil {
		if av, _ := h.updates.Latest(); av != nil {
			hangarUpdate = true
		}
	}
	groups := deps.GroupFindings(fs, hangarUpdate)
	for _, b := range deps.Buckets {
		d.Cards = append(d.Cards, views.BucketCard{Bucket: b, Count: len(groups[b])})
	}
	d.Empty = true
	page, _ := strconv.Atoi(r.FormValue("page"))
	for _, b := range sectionOrder {
		rows := groups[b]
		if len(rows) > 0 {
			d.Empty = false
		}
		if d.Bucket != "" && b != d.Bucket || d.Bucket == "" && len(rows) == 0 {
			continue
		}
		s := views.UpdatesSection{Bucket: b, Total: len(rows)}
		shown := rows
		if d.Bucket == "" {
			if len(rows) > rowsPerSection {
				shown, s.More = rows[:rowsPerSection], true
			}
		} else {
			q := url.Values{"bucket": {b}}
			s.Pager = views.NewPager("/updates", q, page, len(rows), rowsPerPage)
			shown = rows[s.Pager.Offset():s.Pager.End()]
		}
		for _, g := range shown {
			s.Rows = append(s.Rows, groupRow(ctx, g))
		}
		d.Sections = append(d.Sections, s)
	}
	if d.Bucket != "" {
		d.Empty = false // the filtered section says it is empty itself
	}

	ign, err := h.deps.Ignores(ctx)
	if err != nil {
		loggerFrom(ctx).Error("finding ignores", "error", err)
	}
	for _, i := range ign {
		row := views.IgnoreRow{ID: i.ID, Where: targetLabel(ctx, i.Where), Package: i.Package, Advisory: i.Advisory, Reason: i.Reason}
		switch {
		case i.UntilVersion != "":
			row.Until = i18n.T(ctx, "deps.ignore.until_version", "version", i.UntilVersion)
		case !i.UntilAt.IsZero():
			row.Until = i18n.T(ctx, "deps.ignore.until_date", "date", i.UntilAt.Format("02/01/2006"))
		}
		d.Ignores = append(d.Ignores, row)
	}
	scans, err := h.deps.Scans(ctx)
	if err != nil {
		loggerFrom(ctx).Error("dependency scans", "error", err)
	}
	// After a restart the in-memory last run is gone: use the newest
	// stored inventory.
	if d.LastRun == "" {
		var newest time.Time
		for _, s := range scans {
			if s.At.After(newest) {
				newest = s.At
			}
		}
		if !newest.IsZero() {
			d.LastRun = ago(ctx, newest.Format(time.RFC3339Nano), time.Now())
		}
	}
	d.Problems = h.scanProblems(ctx, scans)
	render(w, r, status, views.Updates(d))
}

func validBucket(b string) bool {
	for _, v := range sectionOrder {
		if v == b {
			return true
		}
	}
	return false
}

// targetLabel names server-level targets in the user's language; services
// keep their "project/service".
func targetLabel(ctx context.Context, where string) string {
	if where == deps.EdgeTarget {
		return i18n.T(ctx, "deps.target.edge")
	}
	return where
}

// scanProblems names the targets whose last inventory could not read
// everything (a distroless image without find/cat, a stopped container).
func (h *handlers) scanProblems(ctx context.Context, scans map[string]deps.ScanInfo) []views.ScanProblem {
	names := map[string]string{deps.EdgeTarget: targetLabel(ctx, deps.EdgeTarget)}
	if list, err := h.projects.ListProjects(ctx); err == nil {
		for _, p := range list {
			svcs, err := h.projects.ListServices(ctx, p.ID)
			if err != nil {
				continue
			}
			for _, s := range svcs {
				names[s.ID] = p.Slug + "/" + s.Slug
			}
		}
	}
	var out []views.ScanProblem
	for key, s := range scans {
		if s.Error == "" || names[key] == "" {
			continue
		}
		out = append(out, views.ScanProblem{Where: names[key], Detail: s.Error, Packages: s.Packages})
	}
	views.SortScanProblems(out)
	return out
}

// groupRow turns a group of findings into a row with the action that deals
// with it.
func groupRow(ctx context.Context, g deps.Group) views.GroupRow {
	top := g.Findings[0]
	row := views.GroupRow{
		ID: g.ID(), IDs: g.IDs(), Severity: g.Severity, Where: targetLabel(ctx, g.Where()),
		Project: g.Project, Service: g.Service, Packages: packagesLabel(g),
		Ecosystem: ecosystemLabel(ctx, g.Ecosystem, g.Source), Current: g.Current, Fixed: g.Fixed,
	}
	if g.Project != "" {
		row.Href = servicePath(g.Project, g.Service)
	}
	// "Until a newer version" needs a version for every package of the row.
	row.IgnoreVersion = g.Fixed
	for _, f := range g.Findings {
		if f.Suggested == "" {
			row.IgnoreVersion = ""
			break
		}
	}
	if len(g.Packages) > 1 {
		row.IgnoreVersion = "" // one per package: the dialog cannot name it
		if g.Bucket != deps.BucketTag {
			row.Current, row.Fixed = "", ""
		}
	}
	seen := map[string]bool{}
	for _, f := range g.Findings {
		if f.Advisory == "" || seen[f.Advisory] {
			continue
		}
		seen[f.Advisory] = true
		row.Count++
		if len(row.Advisories) < advisoriesPerRow {
			a := views.AdvisoryRow{
				ID: f.Advisory, URL: deps.AdvisoryURL(f.Advisory), Summary: f.Summary, Severity: f.Severity,
				Package: f.Package, Current: f.Current, Fixed: f.Suggested,
			}
			if len(f.Aliases) > 0 {
				a.Aliases = strings.Join(f.Aliases, ", ")
			}
			row.Advisories = append(row.Advisories, a)
		}
	}

	switch g.Bucket {
	case deps.BucketDeploy:
		row.Action = views.ActDeploy
		if g.Target == deps.EdgeTarget {
			row.Action = views.ActHangar
		}
	case deps.BucketTag:
		row.Action, row.Tag = views.ActTag, g.RemedyTag
		// One row for the whole image: the tag is the version.
		if ref, ok := deps.ParseImage(g.Image); ok {
			row.Packages = i18n.T(ctx, "deps.row.image", "name", ref.Name())
			row.Current = ref.Tag
		}
		row.Fixed = g.RemedyTag
		all, severe := g.Advisories()
		row.Ecosystem = i18n.T(ctx, "deps.row.severe_other", "severe", severe, "other", all-severe)
		row.IgnoreVersion = ""
	case deps.BucketCode:
		if cmd := deps.FixCommand(g.Source, top.Package, g.Fixed); cmd != "" {
			row.Action, row.Code = views.ActCommand, cmd
		} else {
			f := top
			f.Suggested = g.Fixed
			row.Action = views.ActAdvice
			row.Text, row.Code = actionFor(ctx, f)
		}
	case deps.BucketUpdates:
		row.Severity, row.Kind, row.Fixed = "", top.Kind, top.Suggested
		row.Ecosystem = i18n.T(ctx, "deps.kind."+top.Kind)
		// Patch and minor of a service's image: the panel switches the tag;
		// a major (may break) and the edge's image only get the advice.
		if top.Kind != deps.KindMajor && g.ServiceID != "" && imageOf(g.Image) == top.Package {
			row.Action, row.Tag = views.ActTag, top.Suggested
		} else {
			row.Action = views.ActAdvice
			row.Text, row.Code = actionFor(ctx, top)
		}
	default: // waiting
		switch reason := deps.WaitReason(top); {
		case reason == deps.RemedyNoFix:
			row.Action, row.Text = views.ActBadge, i18n.T(ctx, "deps.wait.no_fix")
		case reason == deps.RemedyWaitImage:
			row.Action, row.Text = views.ActBadge, i18n.T(ctx, "deps.wait.image")
		case reason == deps.RemedyEdge:
			row.Action, row.Text = views.ActBadge, i18n.T(ctx, "deps.wait.hangar")
		case strings.HasPrefix(reason, deps.RemedyMajor):
			row.Action, row.Text = views.ActBadge, i18n.T(ctx, "deps.wait.major", "tag", top.RemedyTag)
		default: // not checked yet: a waiting row is never the user's code, so no command
			row.Action, row.Text = views.ActBadge, i18n.T(ctx, "deps.wait.unchecked")
		}
	}
	return row
}

// imageOf is an image reference without its tag, as findings name it.
func imageOf(image string) string {
	if ref, ok := deps.ParseImage(image); ok {
		return ref.Name()
	}
	return ""
}

// packagesLabel names a row's packages: up to three, and Go's standard
// library with the binary it is compiled into ("stdlib (gosu)").
func packagesLabel(g deps.Group) string {
	names := make([]string, 0, 3)
	for i, p := range g.Packages {
		if i == 3 {
			names = append(names, "…")
			break
		}
		if p == "stdlib" && strings.HasPrefix(g.Ecosystem, "Go") && len(g.Packages) == 1 && g.Source != "" && g.Source != "/" {
			p += " (" + path.Base(g.Source) + ")"
		}
		names = append(names, p)
	}
	return strings.Join(names, ", ")
}

// ecosystemLabel is the second line of a row: "Alpine 3.23", "Debian 13",
// "Python · uv".
func ecosystemLabel(ctx context.Context, eco, source string) string {
	base, rest, _ := strings.Cut(eco, ":")
	label := base
	switch base {
	case "PyPI":
		label = "Python"
	case "npm":
		label = "Node.js"
	case "Packagist":
		label = "PHP"
	case "crates.io":
		label = "Rust"
	case "RubyGems":
		label = "Ruby"
	case "image":
		label = i18n.T(ctx, "deps.row.image_eco")
	default:
		if rest != "" {
			label += " " + strings.TrimPrefix(strings.ReplaceAll(rest, ":", " "), "v")
		}
	}
	if m := deps.Manager(source); m != "" {
		label += " · " + m
	}
	return label
}

// actionFor is "the command or the line to change" (docs/14).
func actionFor(ctx context.Context, f deps.Finding) (text, code string) {
	if f.Kind != deps.KindVuln {
		ref := f.Package + ":" + f.Suggested
		if f.Kind == deps.KindMajor {
			return i18n.T(ctx, "deps.action.image_major"), ref
		}
		return i18n.T(ctx, "deps.action.image"), ref
	}
	if f.Suggested == "" {
		return i18n.T(ctx, "deps.action.no_fix"), ""
	}
	switch eco, _, _ := strings.Cut(f.Ecosystem, ":"); eco {
	case "PyPI":
		return i18n.T(ctx, "deps.action.pypi"), f.Package + "==" + f.Suggested
	case "npm":
		return i18n.T(ctx, "deps.action.npm"), "npm install " + f.Package + "@" + f.Suggested
	case "Packagist":
		return i18n.T(ctx, "deps.action.composer"), "composer require " + f.Package + ":^" + f.Suggested
	case "Go":
		if f.Package == "stdlib" { // the Go toolchain the binary was built with
			return i18n.T(ctx, "deps.action.go_stdlib", "version", f.Suggested), ""
		}
		return i18n.T(ctx, "deps.action.go"), "go get " + f.Package + "@v" + strings.TrimPrefix(f.Suggested, "v")
	case "Maven":
		return i18n.T(ctx, "deps.action.maven"), f.Package + ":" + f.Suggested
	case "crates.io":
		return i18n.T(ctx, "deps.action.cargo"), "cargo update -p " + f.Package + " --precise " + f.Suggested
	case "RubyGems":
		return i18n.T(ctx, "deps.action.rubygems"), "gem \"" + f.Package + "\", \">= " + f.Suggested + "\""
	case "NuGet":
		return i18n.T(ctx, "deps.action.nuget"), "dotnet add package " + f.Package + " --version " + f.Suggested
	case "Pub":
		return i18n.T(ctx, "deps.action.pub"), f.Package + ": ^" + f.Suggested
	case "Hex":
		return i18n.T(ctx, "deps.action.hex"), "{:" + f.Package + ", \"~> " + f.Suggested + "\"}"
	}
	return i18n.T(ctx, "deps.action.os", "version", f.Suggested), ""
}

func (h *handlers) updatesScan(w http.ResponseWriter, r *http.Request) {
	if h.deps == nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	// One scan at a time: a click while one runs just shows it running.
	if !h.deps.ScanAsync(r.Context()) {
		redirectLocal(w, r, "/updates")
		return
	}
	redirectLocal(w, r, "/updates?ok=scan")
}

func depsActor(r *http.Request) deps.Actor {
	p := PrincipalFrom(r.Context())
	return deps.Actor{UserID: p.UserID, IP: clientIP(r)}
}

// updatesIgnore hides a row: every package in it, with one reason.
func (h *handlers) updatesIgnore(w http.ResponseWriter, r *http.Request) {
	if h.deps == nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	err := h.deps.IgnoreGroup(r.Context(), depsActor(r), r.PostForm["id"], r.PostFormValue("mode"), r.PostFormValue("reason"))
	if err != nil {
		code, msg := userError(r, err)
		h.renderUpdates(w, r, code, msg, "")
		return
	}
	// Back to the section and page the row was on (clamped on render if
	// it was the last row of the last page).
	q := url.Values{"ok": {"ignored"}}
	if b := r.PostFormValue("bucket"); validBucket(b) {
		q.Set("bucket", b)
		if n, _ := strconv.Atoi(r.PostFormValue("page")); n > 1 {
			q.Set("page", strconv.Itoa(n))
		}
	}
	redirectLocal(w, r, "/updates?"+q.Encode())
}

func (h *handlers) updatesUnignore(w http.ResponseWriter, r *http.Request) {
	if h.deps == nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	if err := h.deps.Unignore(r.Context(), depsActor(r), r.PostFormValue("id")); err != nil {
		code, msg := userError(r, err)
		h.renderUpdates(w, r, code, msg, "")
		return
	}
	redirectLocal(w, r, "/updates?ok=unignored")
}

// depsCounts is the open findings per level for the overview and the
// sidebar (zero when the monitor is off).
func (h *handlers) depsCounts(ctx context.Context) deps.Counts {
	c, err := h.deps.Count(ctx)
	if err != nil {
		loggerFrom(ctx).Error("dependency counts", "error", err)
	}
	return c
}
