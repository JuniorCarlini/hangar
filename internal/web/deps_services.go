package web

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- the updates page per service (docs/14) ----------------------------------
//
// The page lists the services (and the server's own image) with what is
// pending in each, the riskiest first; a service's page lists its rows by
// what to do about them. Copying is per service too, so whoever fixes one
// app gets only that app's findings.

const (
	// targetsPerPage is one "Load more" of the service list.
	targetsPerPage = 50
	// rowsPerChunk is one "Load more" of a section on a service's page: one
	// image can have hundreds of rows waiting for a fix.
	rowsPerChunk = 50
	// serverPath is the page of the server's own images (the edge).
	serverPath = "/updates/server"
)

// sevOrder is the severities from the loudest.
var sevOrder = []string{deps.SevCritical, deps.SevHigh, deps.SevMedium, deps.SevLow, deps.SevUnknown}

// vulnTarget is one service, or the server's edge, with its rows.
type vulnTarget struct {
	Key       string // "project/service", or deps.EdgeTarget
	ServiceID string
	Project   string
	Service   string
	Image     string
	// Sev counts the distinct advisories by severity; Rows the rows per
	// bucket (what the cards count).
	Sev    map[string]int
	Rows   map[string]int
	Groups map[string][]deps.Group
	Scan   deps.ScanInfo
}

func newVulnTarget(key string) *vulnTarget {
	return &vulnTarget{Key: key, Sev: map[string]int{}, Rows: map[string]int{}, Groups: map[string][]deps.Group{}}
}

// sevKey folds the severities the page has no chip for into "unknown".
func sevKey(s string) string {
	switch s {
	case deps.SevCritical, deps.SevHigh, deps.SevMedium, deps.SevLow:
		return s
	}
	return deps.SevUnknown
}

// vulnTargets splits the page's rows by place, keeping each bucket's order
// (loudest first).
func vulnTargets(groups map[string][]deps.Group) map[string]*vulnTarget {
	out := map[string]*vulnTarget{}
	seen := map[string]bool{}
	for _, b := range sectionOrder {
		for _, g := range groups[b] {
			key := g.Where()
			t := out[key]
			if t == nil {
				t = newVulnTarget(key)
				t.ServiceID, t.Project, t.Service, t.Image = g.ServiceID, g.Project, g.Service, g.Image
				out[key] = t
			}
			t.Rows[b]++
			t.Groups[b] = append(t.Groups[b], g)
			if b == deps.BucketUpdates {
				continue // a newer tag: no advisory
			}
			for _, f := range g.Findings {
				if f.Advisory == "" || seen[key+"|"+f.Advisory] {
					continue
				}
				seen[key+"|"+f.Advisory] = true
				t.Sev[sevKey(f.Severity)]++
			}
		}
	}
	return out
}

// riskier orders the list: the most critical advisories first, then high
// and so on, then the most rows, then by name (the server last among
// equals).
func (t *vulnTarget) riskier(o *vulnTarget) bool {
	for _, s := range sevOrder {
		if t.Sev[s] != o.Sev[s] {
			return t.Sev[s] > o.Sev[s]
		}
	}
	if a, b := t.total(), o.total(); a != b {
		return a > b
	}
	if (t.Project == "") != (o.Project == "") {
		return t.Project != ""
	}
	return t.Key < o.Key
}

func (t *vulnTarget) total() int {
	n := 0
	for _, c := range t.Rows {
		n += c
	}
	return n
}

// matches is the list's filters: a severity chip, an action chip and the
// search box (name, project or image).
func (t *vulnTarget) matches(ctx context.Context, sev, bucket, q string) bool {
	if sev != "" && t.Sev[sev] == 0 {
		return false
	}
	if bucket != "" && t.Rows[bucket] == 0 {
		return false
	}
	if q = strings.ToLower(strings.TrimSpace(q)); q != "" {
		hay := strings.ToLower(t.Key + " " + t.Image + " " + targetLabel(ctx, t.Key))
		return strings.Contains(hay, q)
	}
	return true
}

func validSev(s string) bool {
	for _, v := range sevOrder {
		if v == s {
			return true
		}
	}
	return false
}

// targetHref is a place's page on the updates page.
func targetHref(project, service string) string {
	if project == "" {
		return serverPath
	}
	if !node.SlugRE.MatchString(project) || !node.SlugRE.MatchString(service) {
		return "/updates"
	}
	return "/updates/" + project + "/" + service
}

// validTargetPath: a path the ignore form may send the user back to.
func validTargetPath(p string) bool {
	if p == serverPath {
		return true
	}
	rest, ok := strings.CutPrefix(p, "/updates/")
	if !ok {
		return false
	}
	project, service, ok := strings.Cut(rest, "/")
	return ok && node.SlugRE.MatchString(project) && node.SlugRE.MatchString(service)
}

// validScope is the export's service= value: "project/service" or the edge.
func validScope(s string) bool {
	if s == deps.EdgeTarget {
		return true
	}
	project, service, ok := strings.Cut(s, "/")
	return ok && node.SlugRE.MatchString(project) && node.SlugRE.MatchString(service)
}

// exportScope is a place's copy button.
func exportScope(key, bucket string) string {
	q := url.Values{"service": {key}}
	if bucket != "" {
		q.Set("bucket", bucket)
	}
	return "/updates/export?" + q.Encode()
}

// hangarUpdate says a newer Hangar release is out: the edge's image comes
// with it, so its rows are a "deploy".
func (h *handlers) hangarUpdate() bool {
	if h.updates == nil {
		return false
	}
	av, _ := h.updates.Latest()
	return av != nil
}

// knownService is a service the list can name even without findings.
type knownService struct {
	ID, Project, Service, Image string
}

// vulnServices names every service by id (for the scan problems and the
// services scanned clean).
func (h *handlers) vulnServices(ctx context.Context) map[string]knownService {
	out := map[string]knownService{}
	list, err := h.projects.ListProjects(ctx)
	if err != nil {
		return out
	}
	for _, p := range list {
		svcs, err := h.projects.ListServices(ctx, p.ID)
		if err != nil {
			continue
		}
		for _, s := range svcs {
			out[s.ID] = knownService{ID: s.ID, Project: p.Slug, Service: s.Slug, Image: s.Image}
		}
	}
	return out
}

// sevCounts are a place's non-zero severities, the loudest first.
func sevCounts(t *vulnTarget) []views.SevCount {
	var out []views.SevCount
	for _, s := range sevOrder {
		if n := t.Sev[s]; n > 0 {
			out = append(out, views.SevCount{Sev: s, N: n})
		}
	}
	return out
}

// actionCounts are a place's non-zero buckets, in page order.
func actionCounts(t *vulnTarget) []views.ActionCount {
	var out []views.ActionCount
	for _, b := range sectionOrder {
		if n := t.Rows[b]; n > 0 {
			out = append(out, views.ActionCount{Bucket: b, N: n})
		}
	}
	return out
}

// targetSource is the second line of a place: its repository or its
// image.
func (h *handlers) targetSource(ctx context.Context, t *vulnTarget) (string, bool) {
	if t.Project == "" {
		return i18n.T(ctx, "deps.svc.edge_source"), false
	}
	if t.ServiceID != "" {
		if src, ok, err := h.projects.GetGitSource(ctx, t.ServiceID); err == nil && ok {
			repo := src.Display
			if repo == "" {
				repo = cleanRepoURL(src.URL)
			}
			if src.Branch != "" {
				repo += "@" + src.Branch
			}
			return repo, true
		}
	}
	return t.Image, false
}

func (h *handlers) scanAgo(ctx context.Context, s deps.ScanInfo) string {
	if s.At.IsZero() {
		return ""
	}
	return ago(ctx, s.At.Format(time.RFC3339Nano), time.Now())
}

// listTargets is the service list: every place with something pending,
// plus (without a filter) the services scanned clean, the riskiest first.
func (h *handlers) listTargets(ctx context.Context, who *auth.Principal, groups map[string][]deps.Group, scans map[string]deps.ScanInfo,
	known map[string]knownService, sev, bucket, q string,
) []*vulnTarget {
	byKey := vulnTargets(groups)
	for _, t := range byKey {
		id := t.ServiceID
		if t.Project == "" {
			id = deps.EdgeTarget
		}
		t.Scan = scans[id]
	}
	if sev == "" && bucket == "" {
		for id, s := range scans {
			if id == deps.EdgeTarget {
				if _, ok := byKey[deps.EdgeTarget]; !ok && !who.Limited() {
					t := newVulnTarget(deps.EdgeTarget)
					t.Scan = s
					byKey[t.Key] = t
				}
				continue
			}
			k, ok := known[id]
			if !ok || !who.CanSeeProject(k.Project) {
				continue
			}
			key := k.Project + "/" + k.Service
			if _, ok := byKey[key]; ok {
				continue
			}
			t := newVulnTarget(key)
			t.ServiceID, t.Project, t.Service, t.Image, t.Scan = id, k.Project, k.Service, k.Image, s
			byKey[key] = t
		}
	}
	out := make([]*vulnTarget, 0, len(byKey))
	for _, t := range byKey {
		if t.matches(ctx, sev, bucket, q) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].riskier(out[j]) })
	return out
}

// targetRow is a place as a row of the list.
func (h *handlers) targetRow(ctx context.Context, t *vulnTarget) views.VulnServiceRow {
	row := views.VulnServiceRow{
		Key: t.Key, Label: targetLabel(ctx, t.Key), Project: t.Project, Href: targetHref(t.Project, t.Service),
		Export: exportScope(t.Key, ""), Sev: sevCounts(t), Actions: actionCounts(t), Total: t.total(),
		LastScan: h.scanAgo(ctx, t.Scan), ScanError: t.Scan.Error != "",
	}
	row.Source, row.Repo = h.targetSource(ctx, t)
	return row
}

// pageNum is the page asked for (1 when absent or invalid).
func pageNum(r *http.Request) int {
	n, _ := strconv.Atoi(r.FormValue("page"))
	return max(n, 1)
}

// chunk bounds one "Load more" step: rows [from, to) of total, and the
// next page (0 when this is the last one).
func chunk(page, total, size int) (from, to, next int) {
	pages := max(1, (total+size-1)/size)
	page = min(max(page, 1), pages)
	from, to = (page-1)*size, min(page*size, total)
	if to < total {
		next = page + 1
	}
	return from, to, next
}

// withPage is href with page=n (and the other filters kept).
func withPage(path string, q url.Values, n int) string {
	v := url.Values{}
	for k, vals := range q {
		v[k] = vals
	}
	v.Set("page", strconv.Itoa(n))
	return path + "?" + v.Encode()
}

func (h *handlers) updatesServicePage(w http.ResponseWriter, r *http.Request) {
	project, service := r.PathValue("project"), r.PathValue("service")
	if !node.SlugRE.MatchString(project) || !node.SlugRE.MatchString(service) {
		http.NotFound(w, r)
		return
	}
	h.renderVulnTarget(w, r, project, service)
}

func (h *handlers) updatesServerPage(w http.ResponseWriter, r *http.Request) {
	h.renderVulnTarget(w, r, "", "")
}

// renderVulnTarget is one place's page: its rows by what to do, with the same
// actions as before, one "Load more" per section.
func (h *handlers) renderVulnTarget(w http.ResponseWriter, r *http.Request, project, service string) {
	ctx := r.Context()
	pr := PrincipalFrom(ctx)
	// The page of a service sits under /updates, which users limited to
	// some projects do not reach: the route's {project} must not let them
	// in through the side door.
	if pr.Limited() {
		http.NotFound(w, r)
		return
	}
	key, serviceID, image := deps.EdgeTarget, "", ""
	if project != "" {
		_, s, err := h.projects.GetService(ctx, project, service)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		key, serviceID, image = project+"/"+service, s.ID, s.Image
	}
	d := views.UpdatesTargetData{
		UpdatesActions: updatesActions(pr), Running: h.deps.Running(),
		Label: targetLabel(ctx, key), Path: targetHref(project, service), Export: exportScope(key, ""),
		Bucket: r.FormValue("bucket"),
	}
	if !validBucket(d.Bucket) {
		d.Bucket = ""
	}
	switch r.URL.Query().Get("ok") {
	case "ignored":
		d.Flash = i18n.T(ctx, "deps.flash.ignored")
	}
	if project != "" {
		d.ServiceHref = servicePath(project, service)
	}
	t := newVulnTarget(key)
	t.ServiceID, t.Project, t.Service, t.Image = serviceID, project, service, image
	status := http.StatusOK
	if h.deps != nil {
		fs, err := h.deps.Findings(ctx)
		if err != nil {
			status, d.Error = userError(r, err)
		}
		mine := fs[:0:0]
		for _, f := range visibleFindings(pr, fs) {
			if f.Where() == key {
				mine = append(mine, f)
				if f.Ignored {
					d.IgnoredCount++
				}
			}
		}
		if got := vulnTargets(deps.GroupFindings(mine, h.hangarUpdate()))[key]; got != nil {
			got.ServiceID, got.Image = t.ServiceID, t.Image
			t = got
		}
		if scans, err := h.deps.Scans(ctx); err == nil {
			id := serviceID
			if project == "" {
				id = deps.EdgeTarget
			}
			if s, ok := scans[id]; ok {
				t.Scan, d.Scanned = s, true
			}
		}
	}
	d.Source, d.Repo = h.targetSource(ctx, t)
	d.LastScan, d.ScanError = h.scanAgo(ctx, t.Scan), t.Scan.Error
	d.Sev = sevCounts(t)
	for _, b := range deps.Buckets {
		d.Cards = append(d.Cards, views.BucketCard{Bucket: b, Count: t.Rows[b]})
	}
	d.Empty = t.total() == 0
	page := pageNum(r)
	for _, b := range sectionOrder {
		rows := t.Groups[b]
		if len(rows) == 0 || d.Bucket != "" && b != d.Bucket {
			continue
		}
		s := views.UpdatesSection{Bucket: b, Total: len(rows), Export: exportScope(key, b)}
		p := 1
		if b == d.Bucket {
			p = page
		}
		from, to, next := chunk(p, len(rows), rowsPerChunk)
		if next > 0 {
			s.NextHref = withPage(d.Path, url.Values{"bucket": {b}}, next)
		}
		if from > 0 {
			s.From = from + 1
		}
		for _, g := range rows[from:to] {
			s.Rows = append(s.Rows, groupRow(ctx, g))
		}
		d.Sections = append(d.Sections, s)
	}
	render(w, r, status, views.UpdatesTarget(d))
}

func updatesActions(pr *auth.Principal) views.UpdatesActions {
	return views.UpdatesActions{
		CSRF: pr.CSRFToken, CanOperate: pr.Role >= auth.RoleOperator, CanAdmin: pr.Role >= auth.RoleAdmin,
		CanUpdate: pr.Role >= auth.RoleOwner, SudoActive: pr.SudoFor(auth.SudoStrict, time.Now()),
	}
}

// serviceVulns is the summary on a service's Visão tab: what the updates
// page says about it, with its link and its copy button. Nil when the
// monitor is off or the user does not reach the updates page.
func (h *handlers) serviceVulns(ctx context.Context, pr *auth.Principal, project, service, serviceID string) *views.ServiceVulns {
	if h.deps == nil || pr.Limited() {
		return nil
	}
	fs, err := h.deps.Findings(ctx)
	if err != nil {
		loggerFrom(ctx).Error("service findings", "error", err)
		return nil
	}
	key := project + "/" + service
	var mine []deps.Finding
	for _, f := range fs {
		if f.ServiceID == serviceID {
			mine = append(mine, f)
		}
	}
	v := &views.ServiceVulns{Href: targetHref(project, service), Export: exportScope(key, "")}
	if t := vulnTargets(deps.GroupFindings(mine, false))[key]; t != nil {
		v.Sev, v.Actions, v.Total = sevCounts(t), actionCounts(t), t.total()
	}
	if scans, err := h.deps.Scans(ctx); err == nil {
		if s, ok := scans[serviceID]; ok {
			v.Scanned, v.LastScan = true, h.scanAgo(ctx, s)
		}
	}
	return v
}
