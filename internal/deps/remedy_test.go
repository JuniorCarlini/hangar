package deps

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

const (
	digOld   = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"
	digNew   = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	digMinor = "sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
	digMajor = "sha256:" + "3333333333333333333333333333333333333333333333333333333333333333"
)

// fakeProber serves packages per digest and counts the pulls.
type fakeProber struct {
	mu    sync.Mutex
	pkgs  map[string][]Package // digest → packages
	fail  map[string]error
	calls map[string]int
}

func (f *fakeProber) ProbeImage(_ context.Context, ref string) ([]Package, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, d, _ := strings.Cut(ref, "@")
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[d]++
	if err := f.fail[d]; err != nil {
		return nil, err
	}
	return f.pkgs[d], nil
}

func vuln(eco, name, cur, fixed string) observation {
	return observation{kind: KindVuln, pkg: Package{Ecosystem: eco, Name: name, Version: cur}, advisory: Advisory{ID: "A-" + name, Fixed: fixed}}
}

// The scan decides, per vulnerability, the cheapest thing that fixes it:
// a deploy (newer build of the same tag has the fix), a newer tag of the
// same major, a newer major (hint only), or nothing yet; and it never
// claims a fix it did not see.
func TestClassifyRemedies(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	e.digests["library/nginx:1.29-alpine"] = digNew
	e.digests["library/nginx:1.31-alpine"] = digMinor
	e.digests["library/nginx:2.0-alpine"] = digMajor
	pr := &fakeProber{pkgs: map[string][]Package{
		digNew: {
			{Ecosystem: "Alpine:v3.23", Name: "openssl", Version: "3.5.4-r0"}, // fixed by a deploy
			{Ecosystem: "Alpine:v3.23", Name: "zlib", Version: "1.3.1-r0"},
			{Ecosystem: "Go", Name: "stdlib", Version: "1.24.6"},
		},
		digMinor: {
			{Ecosystem: "Alpine:v3.24", Name: "zlib", Version: "1.3.2-r1"}, // fixed in 1.31
			{Ecosystem: "Go", Name: "stdlib", Version: "1.24.9"},
		},
		digMajor: {
			{Ecosystem: "Go", Name: "stdlib", Version: "1.25.4"}, // only the major has it
		},
	}}
	e.m.o.Prober = pr
	t1 := target{serviceID: "svc_web", project: "lab", service: "web", image: "nginx:1.29-alpine", running: true, imageRef: "nginx@" + digOld}
	tags := []TagUpdate{{Kind: KindMinor, Current: "1.29-alpine", Latest: "1.31-alpine"}, {Kind: KindMajor, Current: "1.29-alpine", Latest: "2.0-alpine"}}
	obs := []observation{
		vuln("Alpine:v3.23", "openssl", "3.5.1-r0", "3.5.4-r0"),
		vuln("Alpine:v3.23", "zlib", "1.3.1-r0", "1.3.2-r1"),
		vuln("Go", "stdlib", "1.24.6", "1.25.4"),
		vuln("Alpine:v3.23", "expat", "2.7.1-r0", "2.7.3-r0"), // gone from the new build: fixed
		vuln("Alpine:v3.23", "glibc-ish", "1.0", ""),
	}
	e.m.classify(ctx, t1, tags, obs)
	want := []struct{ remedy, tag string }{
		{RemedyDeploy, ""}, {RemedyTag, "1.31-alpine"}, {RemedyMajor, "2.0-alpine"}, {RemedyDeploy, ""}, {RemedyNoFix, ""},
	}
	for i, w := range want {
		if obs[i].remedy != w.remedy || obs[i].remedyTag != w.tag {
			t.Errorf("%s: %s %q, want %s %q", obs[i].pkg.Name, obs[i].remedy, obs[i].remedyTag, w.remedy, w.tag)
		}
	}

	// A database never gets a new major, not even as a hint; and each
	// digest is pulled once (the cache answers the second scan).
	db := t1
	db.stateful = true
	obs = []observation{vuln("Go", "stdlib", "1.24.6", "1.25.4")}
	e.m.classify(ctx, db, tags, obs)
	if obs[0].remedy != RemedyWaitImage {
		t.Errorf("database stdlib: %s, want %s", obs[0].remedy, RemedyWaitImage)
	}
	if pr.calls[digNew] != 1 || pr.calls[digMinor] != 1 || pr.calls[digMajor] != 1 {
		t.Errorf("pulls = %v, want each digest once", pr.calls)
	}

	// The running image is the registry's: no newer build to look at.
	same := t1
	same.imageRef = "nginx@" + digNew
	obs = []observation{vuln("Alpine:v3.23", "openssl", "3.5.1-r0", "3.5.4-r0")}
	e.m.classify(ctx, same, nil, obs)
	if obs[0].remedy != RemedyWaitImage {
		t.Errorf("same digest: %s", obs[0].remedy)
	}

	// Built from Git: the app's code; the edge: Hangar's release.
	obs = []observation{vuln("PyPI", "pillow", "10.0.0", "10.3.0")}
	e.m.classify(ctx, target{serviceID: "svc_app", git: true, image: "hangar/lab/app"}, nil, obs)
	if obs[0].remedy != RemedyCode {
		t.Errorf("git service: %s", obs[0].remedy)
	}
	obs = []observation{vuln("Alpine:v3.22", "zlib", "1.3.1-r0", "1.3.2-r1")}
	e.m.classify(ctx, target{name: EdgeTarget, image: "caddy:2.11-alpine"}, nil, obs)
	if obs[0].remedy != RemedyEdge {
		t.Errorf("edge: %s", obs[0].remedy)
	}

	// A probe that fails leaves the answer open (and is not retried on
	// the next scan); a registry that cannot be read too.
	e.digests["library/redis:8"] = digOld
	pr.fail = map[string]error{digOld: errors.New("image too big")}
	red := target{serviceID: "svc_r", image: "redis:8", running: true, imageRef: "redis@" + digMajor}
	for range 2 {
		obs = []observation{vuln("Debian:13", "openssl", "3.5.1-1", "3.5.4-1")}
		e.m.classify(ctx, red, nil, obs)
		if obs[0].remedy != RemedyUnchecked {
			t.Errorf("failed probe: %s, want %s", obs[0].remedy, RemedyUnchecked)
		}
	}
	if pr.calls[digOld] != 1 {
		t.Errorf("a failed probe was retried at once: %d pulls", pr.calls[digOld])
	}
	obs = []observation{vuln("Debian:13", "openssl", "3.5.1-1", "3.5.4-1")}
	e.m.classify(ctx, target{serviceID: "svc_x", image: "unknown/thing:1.0", running: true}, nil, obs)
	if obs[0].remedy != RemedyUnchecked {
		t.Errorf("registry error: %s", obs[0].remedy)
	}
	// Without a prober (no Docker), nothing is claimed.
	e.m.o.Prober = nil
	obs = []observation{vuln("Alpine:v3.23", "openssl", "3.5.1-r0", "3.5.4-r0")}
	e.m.classify(ctx, t1, tags, obs)
	if obs[0].remedy != RemedyUnchecked {
		t.Errorf("no prober: %s", obs[0].remedy)
	}
}

// The remedy goes through the scan to the stored finding.
func TestScanStoresRemedy(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.st.DB.Exec(`INSERT INTO deployments (id, service_id, image, env_hash, trigger, status, started_at, image_ref)
		VALUES ('dep_1', 'svc_web', 'lab/web:1.0', '', 'create', 'live', 1, 'lab/web@` + digOld + `')`); err != nil {
		t.Fatal(err)
	}
	e.digests["lab/web:1.0"] = digNew
	e.m.o.Prober = &fakeProber{pkgs: map[string][]Package{digNew: {
		{Ecosystem: "Debian:13", Name: "openssl", Version: "3.5.1-1+deb13u1"},
		{Ecosystem: "PyPI", Name: "django", Version: "5.2.3"},
	}}}
	_ = e.m.Scan(ctx)
	open := e.open(t)
	if f := open["lab/web|openssl|vuln"]; f.Remedy != RemedyDeploy {
		t.Errorf("openssl remedy = %q", f.Remedy)
	}
	if f := open["lab/web|django|vuln"]; f.Remedy != RemedyWaitImage || f.Image != "lab/web:1.0" {
		t.Errorf("django = %q %q", f.Remedy, f.Image)
	}
	if BucketOf(open["lab/web|openssl|vuln"], false) != BucketDeploy || BucketOf(open["lab/web|django|vuln"], false) != BucketWait {
		t.Error("buckets of the stored findings")
	}
}

func TestFixedIn(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "Go", Name: "stdlib", Version: "1.25.4"},
		{Ecosystem: "Go", Name: "stdlib", Version: "1.24.1"}, // a second binary, older
		{Ecosystem: "PyPI", Name: "pillow", Version: "10.3.0"},
	}
	if FixedIn(pkgs, Package{Ecosystem: "Go", Name: "stdlib"}, "1.25.0") {
		t.Error("one binary still on an old Go: not fixed")
	}
	if !FixedIn(pkgs, Package{Ecosystem: "PyPI", Name: "Pillow"}, "10.3.0") {
		t.Error("pillow 10.3.0 fixes 10.3.0 (names normalized)")
	}
	if !FixedIn(pkgs, Package{Ecosystem: "npm", Name: "left-pad"}, "1.0.1") {
		t.Error("a package gone from the image is fixed")
	}
	if FixedIn(nil, Package{Ecosystem: "npm", Name: "left-pad"}, "1.0.1") || FixedIn(pkgs, Package{Ecosystem: "Go", Name: "stdlib"}, "") {
		t.Error("an empty inventory or no fixed version proves nothing")
	}
}
