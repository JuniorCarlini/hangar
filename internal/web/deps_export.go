package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- "Copy" on the updates page: the findings as Markdown --------------------
//
// The text is meant to be pasted to whoever fixes the code (a developer or
// a coding assistant): per section, per service, per package, with the
// versions, the advisories and where the service's code lives. It carries
// only what the page shows plus the stored advisory ids and summaries:
// never environment values or tokens.

// summaryMax bounds an advisory's one-line summary, in runes.
const summaryMax = 240

// vulnExport is what the Markdown is built from.
type vulnExport struct {
	Host string
	At   time.Time
	// Buckets are the sections to write, in page order.
	Buckets []string
	Groups  map[string][]deps.Group
	// Repos are the Git sources of the services that build from one, by
	// service id.
	Repos map[string]projects.GitSource
}

// updatesExport answers the page's copy buttons: one section (?bucket=) or
// every section, as Markdown.
func (h *handlers) updatesExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bucket := r.FormValue("bucket")
	if bucket != "" && !validBucket(bucket) {
		http.Error(w, i18n.T(ctx, "error.bad_request"), http.StatusBadRequest)
		return
	}
	x := vulnExport{At: time.Now(), Buckets: sectionOrder, Groups: map[string][]deps.Group{}, Repos: map[string]projects.GitSource{}}
	x.Host, _ = os.Hostname()
	if bucket != "" {
		x.Buckets = []string{bucket}
	}
	if h.deps != nil {
		fs, err := h.deps.Findings(ctx)
		if err != nil {
			status, msg := userError(r, err)
			http.Error(w, msg, status)
			return
		}
		hangarUpdate := false
		if h.updates != nil {
			if av, _ := h.updates.Latest(); av != nil {
				hangarUpdate = true
			}
		}
		x.Groups = deps.GroupFindings(visibleFindings(PrincipalFrom(ctx), fs), hangarUpdate)
		for _, b := range x.Buckets {
			for _, g := range x.Groups[b] {
				if g.ServiceID == "" {
					continue
				}
				if _, done := x.Repos[g.ServiceID]; done {
					continue
				}
				if src, ok, err := h.projects.GetGitSource(ctx, g.ServiceID); err == nil && ok {
					x.Repos[g.ServiceID] = src
				}
			}
		}
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(vulnMarkdown(ctx, x)))
}

// visibleFindings keeps what the user may see: a user limited to some
// projects gets only their services, never the server's own targets. The
// route already turns limited users away; this keeps the export safe if
// that ever changes.
func visibleFindings(who *auth.Principal, fs []deps.Finding) []deps.Finding {
	if !who.Limited() {
		return fs
	}
	out := make([]deps.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Project != "" && who.CanSeeProject(f.Project) {
			out = append(out, f)
		}
	}
	return out
}

// vulnMarkdown writes the export: a header that says what to do, then per
// section the services (loudest first), then their packages.
func vulnMarkdown(ctx context.Context, x vulnExport) string {
	var b strings.Builder
	date := x.At.UTC().Format("2006-01-02 15:04 UTC")
	b.WriteString("# " + i18n.T(ctx, "deps.export.title", "host", x.Host) + "\n\n")
	b.WriteString(i18n.T(ctx, "deps.export.intro", "host", x.Host, "date", date) + "\n")

	total := 0
	for _, bucket := range x.Buckets {
		rows := x.Groups[bucket]
		if len(rows) == 0 {
			continue
		}
		total += len(rows)
		b.WriteString("\n## " + i18n.T(ctx, "deps.bucket."+bucket) + " (" + i18n.T(ctx, "deps.rows", "n", len(rows)) + ")\n\n")
		b.WriteString(i18n.T(ctx, "deps.bucket_hint."+bucket) + "\n")
		// Services in the order of their loudest row (rows come sorted).
		var order []string
		byWhere := map[string][]deps.Group{}
		for _, g := range rows {
			w := g.Where()
			if _, ok := byWhere[w]; !ok {
				order = append(order, w)
			}
			byWhere[w] = append(byWhere[w], g)
		}
		for _, w := range order {
			gs := byWhere[w]
			writeExportService(ctx, &b, gs[0], x.Repos)
			for _, g := range gs {
				writeExportRow(ctx, &b, g)
			}
		}
	}
	if total == 0 {
		b.WriteString("\n" + i18n.T(ctx, "deps.export.empty") + "\n")
	}
	return b.String()
}

// writeExportService is a service's heading: where it runs and where its
// code lives.
func writeExportService(ctx context.Context, b *strings.Builder, g deps.Group, repos map[string]projects.GitSource) {
	b.WriteString("\n### " + targetLabel(ctx, g.Where()) + "\n\n")
	if src, ok := repos[g.ServiceID]; ok {
		repo := cleanRepoURL(src.URL)
		if repo == "" {
			repo = src.Display
		}
		line := i18n.T(ctx, "deps.export.repo", "url", repo, "branch", "`"+src.Branch+"`")
		if src.Subdir != "" && src.Subdir != "." {
			line += " · " + i18n.T(ctx, "deps.export.subdir", "dir", src.Subdir)
		}
		b.WriteString("- " + line + "\n")
	} else if g.Image != "" {
		b.WriteString("- " + i18n.T(ctx, "deps.export.image", "image", "`"+g.Image+"`") + "\n")
	}
}

// writeExportRow is one row of the page: the package (or image), its
// versions, what to do and every advisory.
func writeExportRow(ctx context.Context, b *strings.Builder, g deps.Group) {
	row := groupRow(ctx, g)
	title := "`" + strings.Join(g.Packages, "`, `") + "`"
	if g.Bucket == deps.BucketTag {
		title = row.Packages
	}
	head := "\n#### " + title
	if eco := exportEcosystem(ctx, g); eco != "" {
		head += " · " + eco
	}
	if g.Severity != "" && g.Bucket != deps.BucketUpdates {
		head += " — " + i18n.T(ctx, "deps.sev."+g.Severity)
	}
	b.WriteString(head + "\n\n")

	switch {
	case row.Current != "" && row.Fixed != "":
		b.WriteString("- " + i18n.T(ctx, "deps.export.version", "current", "`"+row.Current+"`", "fixed", "`"+row.Fixed+"`") + "\n")
	case row.Current != "":
		b.WriteString("- " + i18n.T(ctx, "deps.export.version_now", "current", "`"+row.Current+"`") + "\n")
	}
	if files := exportSources(g); len(files) > 0 {
		b.WriteString("- " + i18n.T(ctx, "deps.export.file", "file", "`"+strings.Join(files, "`, `")+"`") + "\n")
	}
	if do := exportAction(ctx, g, row); do != "" {
		b.WriteString("- " + i18n.T(ctx, "deps.export.do", "action", do) + "\n")
	}

	if g.Bucket == deps.BucketUpdates {
		return // a newer tag: no advisory
	}
	type adv struct {
		f    deps.Finding
		pkgs []string
	}
	var advs []adv
	index := map[string]int{}
	for _, f := range g.Findings {
		if f.Advisory == "" {
			continue
		}
		if i, ok := index[f.Advisory]; ok {
			advs[i].pkgs = append(advs[i].pkgs, f.Package)
			continue
		}
		index[f.Advisory] = len(advs)
		advs = append(advs, adv{f: f, pkgs: []string{f.Package}})
	}
	if len(advs) == 0 {
		return
	}
	b.WriteString("- " + i18n.T(ctx, "deps.flaws", "n", len(advs)) + ":\n")
	several := len(g.Packages) > 1
	for _, a := range advs {
		f := a.f
		line := "  - [" + f.Advisory + "](" + deps.AdvisoryURL(f.Advisory) + ")"
		if len(f.Aliases) > 0 {
			line += " (" + strings.Join(f.Aliases, ", ") + ")"
		}
		if f.Severity != "" {
			line += " · " + i18n.T(ctx, "deps.sev."+f.Severity)
		}
		if several {
			pkg := "`" + strings.Join(a.pkgs, "`, `") + "`"
			if len(a.pkgs) == 1 && f.Current != "" {
				pkg += " " + f.Current
				if f.Suggested != "" {
					pkg += " → " + f.Suggested
				}
			}
			line += " · " + pkg
		}
		if s := oneLine(f.Summary); s != "" {
			line += " — " + s
		}
		b.WriteString(line + "\n")
	}
}

// exportEcosystem is the page's second line plus the scanner's own name
// for it, which tools understand ("Python · uv (PyPI)").
func exportEcosystem(ctx context.Context, g deps.Group) string {
	if g.Bucket == deps.BucketTag || g.Bucket == deps.BucketUpdates {
		return ""
	}
	label := ecosystemLabel(ctx, g.Ecosystem, g.Source)
	if base, _, _ := strings.Cut(g.Ecosystem, ":"); base != "" && !strings.Contains(strings.ToLower(label), strings.ToLower(base)) {
		label += " (" + base + ")"
	}
	return label
}

// exportSources are the files the scanner found the row's packages in
// (a lockfile, a binary, the OS package database).
func exportSources(g deps.Group) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range g.Findings {
		if f.Source == "" || f.Source == "/" || seen[f.Source] {
			continue
		}
		seen[f.Source] = true
		out = append(out, f.Source)
	}
	return out
}

// exportAction says what fixes the row, in words a developer acts on.
func exportAction(ctx context.Context, g deps.Group, row views.GroupRow) string {
	switch row.Action {
	case views.ActDeploy:
		return i18n.T(ctx, "deps.export.do_deploy")
	case views.ActHangar:
		return i18n.T(ctx, "deps.export.do_hangar")
	case views.ActTag:
		return i18n.T(ctx, "deps.export.do_tag", "image", "`"+imageOf(g.Image)+"`", "tag", "`"+row.Tag+"`")
	case views.ActCommand:
		return "`" + row.Code + "`"
	case views.ActBadge:
		return i18n.T(ctx, "deps.export.waiting", "reason", row.Text)
	}
	text := strings.TrimSuffix(strings.TrimSpace(row.Text), ":")
	if row.Code != "" {
		if text == "" {
			return "`" + row.Code + "`"
		}
		return text + ": `" + row.Code + "`"
	}
	return text
}

// cleanRepoURL drops anything but scheme, host and path: stored URLs never
// carry credentials, and the export makes sure.
func cleanRepoURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.User, u.RawQuery, u.Fragment, u.ForceQuery = nil, "", "", false
	return u.String()
}

// oneLine is an advisory summary as one bounded line.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= summaryMax {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:summaryMax])) + "…"
}
