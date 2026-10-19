package deps

import (
	"path"
	"sort"
	"strings"
)

// Buckets of the updates page (docs/14): what the operator does about a
// vulnerability, the most actionable first.
const (
	BucketDeploy = "deploy" // a deploy (or a Hangar update, for the edge) fixes it
	BucketTag    = "tag"    // switching to a newer tag fixes it
	BucketCode   = "code"   // a dependency of the user's own app
	BucketWait   = "wait"   // nothing to do yet
	// BucketUpdates holds newer image tags with no known vulnerability.
	BucketUpdates = "updates"
)

// Buckets lists the vulnerability buckets in page order.
var Buckets = []string{BucketDeploy, BucketTag, BucketCode, BucketWait}

// BucketOf places a finding. hangarUpdate says a newer Hangar release is
// available: the edge's image comes with it.
func BucketOf(f Finding, hangarUpdate bool) string {
	if f.Kind != KindVuln {
		return BucketUpdates
	}
	if f.Suggested == "" {
		return BucketWait
	}
	switch f.Remedy {
	case RemedyDeploy:
		return BucketDeploy
	case RemedyTag:
		if f.RemedyTag != "" {
			return BucketTag
		}
	case RemedyCode:
		return BucketCode
	case RemedyEdge:
		if hangarUpdate {
			return BucketDeploy
		}
	}
	return BucketWait
}

// Group is one row of the updates page: the findings one action deals
// with. Deploy and code rows are one package of one target (a Go stdlib
// with 58 advisories is one row); a tag row is the whole image (switching
// tags fixes all of it at once); waiting OS packages of one image share a
// row.
type Group struct {
	Bucket    string
	ServiceID string
	Project   string
	Service   string
	Target    string
	Image     string
	Packages  []string // distinct package names, loudest first
	Ecosystem string
	// Current and Fixed: the running version and the one that fixes every
	// advisory of the row (the highest fixed version); for rows of several
	// packages, those of the loudest one.
	Current string
	Fixed   string
	// Severity is the highest of the row; Level the loudest.
	Severity  string
	Level     string
	Remedy    string
	RemedyTag string
	Source    string
	Findings  []Finding
}

// ID identifies the row on the page (its first finding).
func (g Group) ID() string { return g.Findings[0].ID }

// Where names the row's place, like Finding.Where.
func (g Group) Where() string { return g.Findings[0].Where() }

// IDs are the row's finding ids.
func (g Group) IDs() []string {
	out := make([]string, 0, len(g.Findings))
	for _, f := range g.Findings {
		out = append(out, f.ID)
	}
	return out
}

// Advisories counts the row's distinct advisories, and how many of them are
// critical or high.
func (g Group) Advisories() (all, severe int) {
	seen := map[string]bool{}
	for _, f := range g.Findings {
		if seen[f.Advisory] {
			continue
		}
		seen[f.Advisory] = true
		all++
		if f.Severity == SevCritical || f.Severity == SevHigh {
			severe++
		}
	}
	return all, severe
}

// GroupFindings sorts the open, not ignored findings into the page's rows,
// per bucket, loudest first.
func GroupFindings(fs []Finding, hangarUpdate bool) map[string][]Group {
	out := map[string][]Group{}
	index := map[string]int{}
	for _, f := range fs {
		if f.Ignored {
			continue
		}
		b := BucketOf(f, hangarUpdate)
		k := b + "|" + f.ServiceID + "|" + f.Target + "|" + groupKey(b, f)
		i, ok := index[k]
		if !ok {
			i = len(out[b])
			index[k] = i
			out[b] = append(out[b], Group{
				Bucket: b, ServiceID: f.ServiceID, Project: f.Project, Service: f.Service, Target: f.Target,
				Image: f.Image, Ecosystem: f.Ecosystem, Remedy: f.Remedy, RemedyTag: f.RemedyTag, Source: f.Source,
			})
		}
		g := &out[b][i]
		g.Findings = append(g.Findings, f)
	}
	// A newer tag already offered to fix vulnerabilities is not repeated
	// as a plain update of the same target.
	switching := map[string]bool{}
	for _, g := range out[BucketTag] {
		switching[g.ServiceID+"|"+g.Target] = true
	}
	updates := out[BucketUpdates][:0]
	for _, g := range out[BucketUpdates] {
		if !switching[g.ServiceID+"|"+g.Target] {
			updates = append(updates, g)
		}
	}
	if len(updates) == 0 {
		delete(out, BucketUpdates)
	} else {
		out[BucketUpdates] = updates
	}
	for b := range out {
		for i := range out[b] {
			out[b][i].settle()
		}
		sort.SliceStable(out[b], func(i, j int) bool { return out[b][i].louder(out[b][j]) })
	}
	return out
}

// groupKey is what findings of one target share to be one row.
func groupKey(bucket string, f Finding) string {
	switch bucket {
	case BucketTag:
		return f.RemedyTag
	case BucketUpdates:
		return f.Package + "|" + f.Kind
	case BucketWait:
		if !languageEcosystem(f.Ecosystem) {
			return f.Ecosystem + "|" + waitReason(f)
		}
	}
	return f.Ecosystem + "|" + f.Package + "|" + waitReason(f)
}

// WaitReason says why a vulnerability waits: no fixed version yet
// (RemedyNoFix), no image carries the fix yet (RemedyWaitImage), the fix
// is in a newer major (RemedyMajor), comes with Hangar (RemedyEdge), or it
// could not be checked (RemedyUnchecked).
func WaitReason(f Finding) string { return waitReason(f) }

func waitReason(f Finding) string {
	switch {
	case f.Kind != KindVuln:
		return ""
	case f.Suggested == "":
		return RemedyNoFix
	case f.Remedy == RemedyWaitImage, f.Remedy == RemedyEdge:
		return f.Remedy
	case f.Remedy == RemedyMajor:
		return RemedyMajor + ":" + f.RemedyTag
	}
	return RemedyUnchecked
}

// languageEcosystem: a library ecosystem, as opposed to a distribution's
// packages.
func languageEcosystem(eco string) bool {
	switch base, _, _ := strings.Cut(eco, ":"); base {
	case "PyPI", "npm", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist", "Pub", "Hex", "image":
		return true
	}
	return false
}

func (g *Group) settle() {
	sort.SliceStable(g.Findings, func(i, j int) bool { return findingLouder(g.Findings[i], g.Findings[j]) })
	top := g.Findings[0]
	g.Severity, g.Level, g.Current, g.Ecosystem, g.Source = top.Severity, top.Level, top.Current, top.Ecosystem, top.Source
	seen := map[string]bool{}
	for _, f := range g.Findings {
		if !seen[f.Package] {
			seen[f.Package] = true
			g.Packages = append(g.Packages, f.Package)
		}
		if f.Package == top.Package && f.Suggested != "" && (g.Fixed == "" || CompareVersions(f.Suggested, g.Fixed) > 0) {
			g.Fixed = f.Suggested
		}
	}
}

// louder orders rows by the severity the page shows, then by how loud
// the warning is (a fix exists), then by place.
func (g Group) louder(o Group) bool {
	if a, b := sevRank(g.Severity), sevRank(o.Severity); a != b {
		return a > b
	}
	if a, b := levelRank(g.Level), levelRank(o.Level); a != b {
		return a > b
	}
	if g.Where() != o.Where() {
		return g.Where() < o.Where()
	}
	return g.Packages[0] < o.Packages[0]
}

func findingLouder(a, b Finding) bool {
	if x, y := sevRank(a.Severity), sevRank(b.Severity); x != y {
		return x > y
	}
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	return a.Advisory < b.Advisory
}

func sevRank(s string) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

func levelRank(l string) int {
	switch l {
	case LevelCritical:
		return 3
	case LevelSecurity:
		return 2
	case LevelMinor:
		return 1
	}
	return 0
}

// Manager names the package manager of a lockfile or requirements file
// ("" when the path says nothing).
func Manager(source string) string {
	switch base := path.Base(source); {
	case base == "uv.lock":
		return "uv"
	case base == "poetry.lock":
		return "poetry"
	case base == "Pipfile.lock":
		return "pipenv"
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return "pip"
	case base == "package-lock.json":
		return "npm"
	case base == "pnpm-lock.yaml":
		return "pnpm"
	case base == "yarn.lock":
		return "yarn"
	case base == "Gemfile.lock":
		return "bundler"
	}
	return ""
}

// FixCommand is the command that moves the app's package to fixed with the
// package manager its lockfile names ("" when it cannot tell).
func FixCommand(source, pkg, fixed string) string {
	switch Manager(source) {
	case "uv":
		return "uv lock --upgrade-package " + pkg
	case "poetry":
		return "poetry update " + pkg
	case "pipenv":
		return "pipenv update " + pkg
	case "pip":
		return `pip install -U "` + pkg + ">=" + fixed + `"`
	case "npm":
		return "npm install " + pkg + "@" + fixed
	case "pnpm":
		return "pnpm update " + pkg + "@" + fixed
	case "yarn":
		return "yarn up " + pkg + "@" + fixed
	case "bundler":
		return "bundle update " + pkg
	}
	return ""
}
