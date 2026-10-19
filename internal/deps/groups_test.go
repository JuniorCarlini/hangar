package deps

import (
	"fmt"
	"testing"
)

func TestBucketOf(t *testing.T) {
	cases := []struct {
		f      Finding
		hangar bool
		want   string
	}{
		{Finding{Kind: KindMinor}, false, BucketUpdates},
		{Finding{Kind: KindVuln, Remedy: RemedyDeploy}, false, BucketWait}, // no fixed version: nothing to deploy
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyDeploy}, false, BucketDeploy},
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyTag, RemedyTag: "1.31"}, false, BucketTag},
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyTag}, false, BucketWait},
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyCode}, false, BucketCode},
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyEdge}, true, BucketDeploy},
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyEdge}, false, BucketWait},
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyMajor, RemedyTag: "2.0"}, false, BucketWait},
		{Finding{Kind: KindVuln, Suggested: "1.1", Remedy: RemedyUnchecked}, false, BucketWait},
		{Finding{Kind: KindVuln, Suggested: "1.1"}, false, BucketWait}, // found before remedies existed
	}
	for _, c := range cases {
		if got := BucketOf(c.f, c.hangar); got != c.want {
			t.Errorf("BucketOf(%+v, %v) = %s, want %s", c.f, c.hangar, got, c.want)
		}
	}
}

// One row per action: a package with many advisories is one row with the
// version that fixes them all; a tag change is one row for the image;
// waiting distribution packages of one image share a row.
func TestGroupFindings(t *testing.T) {
	var fs []Finding
	n := 0
	add := func(f Finding) {
		n++
		f.ID = fmt.Sprintf("dep_%d", n)
		if f.Kind == "" {
			f.Kind = KindVuln
		}
		f.Advisory = fmt.Sprintf("GHSA-%d", n)
		fs = append(fs, f)
	}
	db := Finding{ServiceID: "svc_db", Project: "lab", Service: "db", Image: "postgres:18.0"}
	for i := range 58 {
		f := db
		f.Ecosystem, f.Package, f.Current, f.Source = "Go", "stdlib", "1.24.6", "/usr/local/bin/gosu"
		f.Severity, f.Level, f.Remedy = SevMedium, LevelSecurity, RemedyWaitImage
		f.Suggested = fmt.Sprintf("1.24.%d", 7+i%5)
		if i == 9 {
			f.Suggested, f.Severity = "1.25.4", SevHigh
		}
		add(f)
	}
	for _, p := range []string{"glibc", "gnutls28", "krb5"} {
		f := db
		f.Ecosystem, f.Package, f.Current, f.Severity, f.Level, f.Remedy = "Debian:13", p, "1.0", SevHigh, LevelSecurity, RemedyNoFix
		add(f)
	}
	web := Finding{ServiceID: "svc_web", Project: "lab", Service: "nginx", Image: "nginx:1.29-alpine"}
	for i, p := range []string{"zlib", "expat", "libx11", "openssl"} {
		f := web
		f.Ecosystem, f.Package, f.Current, f.Suggested = "Alpine:v3.23", p, "1.0", "1.1"
		f.Severity, f.Level, f.Remedy, f.RemedyTag = SevCritical, LevelCritical, RemedyTag, "1.31-alpine"
		if i == 3 {
			f.Ignored = true
		}
		add(f)
	}
	add(Finding{ServiceID: "svc_web", Project: "lab", Service: "nginx", Kind: KindMinor, Ecosystem: "image", Package: "nginx", Current: "1.29-alpine", Suggested: "1.31-alpine", Severity: SevNone, Level: LevelMinor})
	app := Finding{ServiceID: "svc_app", Project: "lab2", Service: "app", Ecosystem: "PyPI", Package: "pillow", Current: "10.0.0", Source: "/app/uv.lock", Remedy: RemedyCode, Level: LevelCritical, Severity: SevHigh}
	for _, v := range []string{"10.2.0", "10.3.0", "10.1.0"} {
		f := app
		f.Suggested = v
		add(f)
	}

	g := GroupFindings(fs, false)
	// The nginx minor update is the same switch as the tag row: not repeated.
	if len(g[BucketDeploy]) != 0 || len(g[BucketTag]) != 1 || len(g[BucketCode]) != 1 || len(g[BucketWait]) != 2 || len(g[BucketUpdates]) != 0 {
		t.Fatalf("rows per bucket: deploy %d tag %d code %d wait %d updates %d",
			len(g[BucketDeploy]), len(g[BucketTag]), len(g[BucketCode]), len(g[BucketWait]), len(g[BucketUpdates]))
	}
	tag := g[BucketTag][0]
	if all, severe := tag.Advisories(); all != 3 || severe != 3 || tag.RemedyTag != "1.31-alpine" || len(tag.Packages) != 3 {
		t.Errorf("tag row = %+v (%d advisories)", tag, all)
	}
	code := g[BucketCode][0]
	if code.Fixed != "10.3.0" || code.Current != "10.0.0" || len(code.Findings) != 3 {
		t.Errorf("code row: %s → %s, %d findings", code.Current, code.Fixed, len(code.Findings))
	}
	if cmd := FixCommand(code.Source, code.Packages[0], code.Fixed); cmd != "uv lock --upgrade-package pillow" {
		t.Errorf("command = %q", cmd)
	}
	std, dist := g[BucketWait][1], g[BucketWait][0] // same severity: by package name
	if std.Packages[0] != "stdlib" || len(std.Findings) != 58 || std.Fixed != "1.25.4" || std.Severity != SevHigh {
		t.Errorf("stdlib row: %v, %d findings, fixed %s, %s", std.Packages, len(std.Findings), std.Fixed, std.Severity)
	}
	if len(dist.Packages) != 3 || dist.Fixed != "" || WaitReason(dist.Findings[0]) != RemedyNoFix {
		t.Errorf("distribution row: %+v", dist.Packages)
	}
}

// The same version read from installed metadata and from the lockfile keeps
// the lockfile: it names the package manager.
func TestDedupePrefersLockfile(t *testing.T) {
	out := dedupe([]Package{
		{Ecosystem: "PyPI", Name: "pillow", Version: "10.0.0", Source: "/app/.venv/lib/python3.13/site-packages/pillow-10.0.0.dist-info/METADATA"},
		{Ecosystem: "PyPI", Name: "pillow", Version: "10.0.0", Source: "/app/uv.lock"},
	})
	if len(out) != 1 || out[0].Source != "/app/uv.lock" {
		t.Errorf("dedupe = %+v", out)
	}
}

func TestFixCommand(t *testing.T) {
	cases := map[[2]string]string{
		{"/app/uv.lock", "pillow"}:              "uv lock --upgrade-package pillow",
		{"/srv/poetry.lock", "django"}:          "poetry update django",
		{"/app/requirements.txt", "jinja2"}:     `pip install -U "jinja2>=9.9"`,
		{"/app/package-lock.json", "lodash"}:    "npm install lodash@9.9",
		{"/app/pnpm-lock.yaml", "vite"}:         "pnpm update vite@9.9",
		{"/app/yarn.lock", "axios"}:             "yarn up axios@9.9",
		{"/usr/lib/python3/site-packages", "x"}: "",
	}
	for in, want := range cases {
		if got := FixCommand(in[0], in[1], "9.9"); got != want {
			t.Errorf("FixCommand(%q) = %q, want %q", in, got, want)
		}
	}
}
