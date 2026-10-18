package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- updates and vulnerabilities page (docs/14, docs/17 § 3.8) ---------------

// findingsPerPage is how many pending findings one page of /updates shows:
// a real server can have hundreds.
const findingsPerPage = 25

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
		CSRF: pr.CSRFToken, CanOperate: pr.Role >= auth.RoleOperator, Error: errMsg, Flash: flash,
		Level: r.FormValue("level"), Counts: map[string]int{}, Running: h.deps.Running(),
	}
	if d.Level != "" && !validLevel(d.Level) {
		d.Level = ""
	}
	if h.deps != nil {
		last, lastErr := h.deps.LastRun()
		if !last.IsZero() {
			d.LastRun = ago(ctx, last.Format(time.RFC3339Nano), time.Now())
		}
		d.LastError = lastErr != ""
		fs, err := h.deps.Findings(ctx)
		if err != nil {
			status, d.Error = userError(r, err)
		}
		var shown []deps.Finding
		for _, f := range fs {
			if f.Ignored {
				d.IgnoredCount++
				continue
			}
			d.Counts[f.Level]++
			if d.Level != "" && f.Level != d.Level {
				continue
			}
			shown = append(shown, f)
		}
		// The cards count everything; the table renders one page of it.
		page, _ := strconv.Atoi(r.FormValue("page"))
		d.Pager = views.NewPager("/updates", updatesQuery(d.Level), page, len(shown), findingsPerPage)
		for _, f := range shown[d.Pager.Offset():d.Pager.End()] {
			d.Findings = append(d.Findings, findingRow(ctx, f))
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
	}
	render(w, r, status, views.Updates(d))
}

// updatesQuery is the query that page links and redirects keep: the
// level filter (the flash "ok" is shown once and dropped).
func updatesQuery(level string) url.Values {
	q := url.Values{}
	if validLevel(level) {
		q.Set("level", level)
	}
	return q
}

// targetLabel names server-level targets in the user's language; services
// keep their "project/service".
func targetLabel(ctx context.Context, where string) string {
	if where == deps.EdgeTarget {
		return i18n.T(ctx, "deps.target.edge")
	}
	return where
}

func validLevel(l string) bool {
	for _, v := range deps.Levels {
		if v == l {
			return true
		}
	}
	return false
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

// findingRow turns a finding into a table row with the suggested action.
func findingRow(ctx context.Context, f deps.Finding) views.FindingRow {
	row := views.FindingRow{
		ID: f.ID, Level: f.Level, Where: targetLabel(ctx, f.Where()), Package: f.Package, Ecosystem: f.Ecosystem,
		Current: f.Current, Suggested: f.Suggested, Advisory: f.Advisory, Summary: f.Summary,
		Severity: f.Severity, Kind: f.Kind, CanIgnoreVersion: f.Suggested != "",
	}
	if f.Project != "" {
		row.Href = servicePath(f.Project, f.Service)
	}
	if f.Advisory != "" {
		row.AdvisoryURL = deps.AdvisoryURL(f.Advisory)
		if len(f.Aliases) > 0 {
			row.Aliases = strings.Join(f.Aliases, ", ")
		}
	}
	row.Action, row.Code = actionFor(ctx, f)
	return row
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
	}
	return i18n.T(ctx, "deps.action.os", "version", f.Suggested), ""
}

func (h *handlers) updatesScan(w http.ResponseWriter, r *http.Request) {
	if h.deps == nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	h.deps.ScanAsync(r.Context())
	redirectLocal(w, r, "/updates?ok=scan")
}

func depsActor(r *http.Request) deps.Actor {
	p := PrincipalFrom(r.Context())
	return deps.Actor{UserID: p.UserID, IP: clientIP(r)}
}

func (h *handlers) updatesIgnore(w http.ResponseWriter, r *http.Request) {
	if h.deps == nil {
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
		return
	}
	err := h.deps.Ignore(r.Context(), depsActor(r), r.PostFormValue("id"), r.PostFormValue("mode"), r.PostFormValue("reason"))
	if err != nil {
		code, msg := userError(r, err)
		h.renderUpdates(w, r, code, msg, "")
		return
	}
	// Back to the filter and page the finding was on (clamped on render
	// if it was the last row of the last page).
	q := updatesQuery(r.PostFormValue("level"))
	q.Set("ok", "ignored")
	if n, _ := strconv.Atoi(r.PostFormValue("page")); n > 1 {
		q.Set("page", strconv.Itoa(n))
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
