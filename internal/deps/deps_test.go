package deps

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"5.2.3", "5.2.7", -1},
		{"5.2.10", "5.2.9", 1},
		{"1.0", "1.0.0", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0.0-beta.2", "1.0.0", -1},
		{"2.0a1", "2.0b1", -1},
		{"1:1.0", "2.0", 1},
		{"3.0.17-1~deb13u1", "3.0.17-1", -1},
		{"3.0.17-1+deb13u1", "3.0.17-1+deb13u2", -1},
		{"3.0.17-1", "3.0.17-1+deb13u1", -1},
		{"1.0+deb1", "1.0.1", -1},
		{"v1.2.3", "1.2.3", 0},
		{"8.2.1-r0", "8.2.1-r1", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCVSS3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.1/AV:X/AC:L":                           -1,
	}
	for v, want := range cases {
		if got := cvss3Score(v); got != want {
			t.Errorf("cvss3Score(%s) = %v, want %v", v, got, want)
		}
	}
}

func TestSeverityAndLevel(t *testing.T) {
	var v osvVuln
	if err := json.Unmarshal([]byte(`{"id":"X","database_specific":{"severity":"MODERATE"}}`), &v); err != nil {
		t.Fatal(err)
	}
	if s := severityOf(v); s != SevMedium {
		t.Errorf("GitHub MODERATE = %s, want medium", s)
	}
	// A database_specific of another shape must not break the decoding.
	v = osvVuln{}
	if err := json.Unmarshal([]byte(`{"id":"X","database_specific":{"severity":[1,2]},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`), &v); err != nil {
		t.Fatal(err)
	}
	if s := severityOf(v); s != SevCritical {
		t.Errorf("CVSS 9.8 = %s, want critical", s)
	}
	if vulnLevel(SevHigh, "1.2") != LevelCritical || vulnLevel(SevHigh, "") != LevelSecurity || vulnLevel(SevLow, "1.2") != LevelSecurity {
		t.Error("only critical/high with a fix is 🔴")
	}
}

func TestParsers(t *testing.T) {
	eco, kind := osEcosystem([]byte("PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n"))
	if eco != "Debian:13" || kind != "dpkg" {
		t.Errorf("debian: %s %s", eco, kind)
	}
	if eco, _ := osEcosystem([]byte("ID=alpine\nVERSION_ID=3.22.1\n")); eco != "Alpine:v3.22" {
		t.Errorf("alpine: %s", eco)
	}
	if eco, _ := osEcosystem([]byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n")); eco != "Ubuntu:24.04:LTS" {
		t.Errorf("ubuntu: %s", eco)
	}

	dpkg := "Package: libssl3t64\nStatus: install ok installed\nSource: openssl (3.5.1-1)\nVersion: 3.5.1-1\n\n" +
		"Package: bash\nStatus: install ok installed\nVersion: 5.2.37-2\n\n" +
		"Package: gone\nStatus: deinstall ok config-files\nVersion: 1\n"
	got := parseDpkgStatus([]byte(dpkg), "Debian:13")
	if len(got) != 2 || got[0].Name != "openssl" || got[0].Version != "3.5.1-1" || got[1].Name != "bash" {
		t.Errorf("dpkg: %+v", got)
	}

	apk := "C:Q1\nP:libcrypto3\nV:3.5.1-r0\no:openssl\n\nP:busybox\nV:1.37.0-r18\n"
	got = parseApkInstalled([]byte(apk), "Alpine:v3.22")
	if len(got) != 2 || got[0].Name != "openssl" || got[1].Name != "busybox" || got[1].Version != "1.37.0-r18" {
		t.Errorf("apk: %+v", got)
	}

	if p, ok := parseDistInfo("/usr/local/lib/python3.13/site-packages/Django-5.2.3.dist-info"); !ok || p.Name != "django" || p.Version != "5.2.3" {
		t.Errorf("dist-info: %+v", p)
	}

	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},
		"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"},"node_modules/jest":{"version":"29.0.0","dev":true},
		"node_modules/local":{"link":true}}}`
	got, err := parsePackageLock([]byte(lock), "/app/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, p := range got {
		names[p.Name] = p.Version
	}
	if len(got) != 2 || names["lodash"] != "4.17.20" || names["@scope/b"] != "1.0.0" {
		t.Errorf("package-lock: %+v", got)
	}

	composer := `{"packages":[{"name":"monolog/monolog","version":"v3.0.0"},{"name":"x/y","version":"dev-main"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.0.0"}]}`
	got, _ = parseComposerLock([]byte(composer), "/var/www/composer.lock")
	if len(got) != 1 || got[0].Version != "3.0.0" {
		t.Errorf("composer: %+v", got)
	}
}

func TestParseImageAndNewerTags(t *testing.T) {
	for in, want := range map[string]ImageRef{
		"postgres:18.0":                {Host: "docker.io", Repo: "library/postgres", Tag: "18.0"},
		"nginx":                        {Host: "docker.io", Repo: "library/nginx", Tag: "latest"},
		"ghcr.io/org/app:1.2@sha256:a": {Host: "ghcr.io", Repo: "org/app", Tag: "1.2"},
		"localhost:5000/x:3":           {Host: "localhost:5000", Repo: "x", Tag: "3"},
		"bitnami/redis:8.0.1":          {Host: "docker.io", Repo: "bitnami/redis", Tag: "8.0.1"},
	} {
		got, ok := ParseImage(in)
		if !ok || got != want {
			t.Errorf("ParseImage(%q) = %+v, want %+v", in, got, want)
		}
	}
	tags := []string{"18.0", "18.1", "18.2", "18.2-alpine", "19.0", "19", "latest", "17.6", "18.10rc1"}
	cur, suffix, _ := numericParts("18.0")
	got := newerTags("18.0", cur, suffix, tags)
	if len(got) != 2 || got[0].Latest != "18.2" || got[0].Kind != "minor" || got[1].Latest != "19.0" || got[1].Kind != "major" {
		t.Errorf("newer tags of 18.0: %+v", got)
	}
	cur, suffix, _ = numericParts("1.29.1-alpine")
	got = newerTags("1.29.1-alpine", cur, suffix, []string{"1.29.2-alpine", "1.30.0-alpine", "1.29.3", "1.29.3-alpine-slim"})
	if len(got) != 1 || got[0].Latest != "1.30.0-alpine" || got[0].Kind != "minor" {
		t.Errorf("newer tags of 1.29.1-alpine: %+v", got)
	}
	cur, suffix, _ = numericParts("8.0.1")
	got = newerTags("8.0.1", cur, suffix, []string{"8.0.2"})
	if len(got) != 1 || got[0].Kind != "patch" {
		t.Errorf("newer tags of 8.0.1: %+v", got)
	}
}

// --- fakes -------------------------------------------------------------------

// fakeOSV answers like api.osv.dev for a small advisory set.
type fakeOSV struct {
	mu       sync.Mutex
	batches  int
	lastBody string
	vulns    map[string]string // package|version → advisory id
	records  map[string]string // id → JSON record
}

func newFakeOSV() *fakeOSV {
	return &fakeOSV{
		vulns: map[string]string{
			"PyPI|django|5.2.3":         "GHSA-test-django",
			"Debian:13|openssl|3.5.1-1": "DEBIAN-CVE-2026-0001",
		},
		records: map[string]string{
			"GHSA-test-django": `{"id":"GHSA-test-django","summary":"SQL injection in <b>QuerySet</b>","aliases":["CVE-2026-1111"],
				"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"affected":[{"package":{"name":"Django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[
					{"introduced":"4.2"},{"fixed":"4.2.25"},{"introduced":"5.2"},{"fixed":"5.2.7"}]}]}]}`,
			"DEBIAN-CVE-2026-0001": `{"id":"DEBIAN-CVE-2026-0001","summary":"openssl flaw",
				"affected":[{"package":{"name":"openssl","ecosystem":"Debian:13"},"ranges":[{"type":"ECOSYSTEM","events":[
					{"introduced":"0"},{"fixed":"3.5.1-1+deb13u1"}]}]}]}`,
		},
	}
}

func (f *fakeOSV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		f.batches++
		raw, _ := io.ReadAll(r.Body)
		f.lastBody = string(raw)
		var body struct {
			Queries []osvQuery `json:"queries"`
		}
		_ = json.Unmarshal(raw, &body)
		type vuln struct {
			ID string `json:"id"`
		}
		type result struct {
			Vulns []vuln `json:"vulns,omitempty"`
		}
		res := struct {
			Results []result `json:"results"`
		}{}
		for _, q := range body.Queries {
			var r result
			if id, ok := f.vulns[q.Package.Ecosystem+"|"+q.Package.Name+"|"+q.Version]; ok {
				r.Vulns = []vuln{{ID: id}}
			}
			res.Results = append(res.Results, r)
		}
		_ = json.NewEncoder(w).Encode(res)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		rec, ok := f.records[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, rec)
	default:
		http.NotFound(w, r)
	}
}

// fakeRegistry needs an anonymous token, pages the tag list and answers
// manifest HEADs with the digest of "repo:tag" in digests.
func fakeRegistry(t *testing.T, tags map[string][]string, digests map[string]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = io.WriteString(w, `{"token":"anon"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer anon" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.test",scope="repository:x:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if repo, tag, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v2/"), "/manifests/"); ok {
			d, found := digests[repo+":"+tag]
			if !found || r.Method != http.MethodHead {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Docker-Content-Digest", d)
			return
		}
		repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/"), "/tags/list")
		list := tags[repo]
		if r.URL.Query().Get("last") == "" && len(list) > 2 {
			w.Header().Set("Link", `</v2/`+repo+`/tags/list?last=x&n=1000>; rel="next"`)
			list = list[:2]
		} else if r.URL.Query().Get("last") != "" {
			list = list[2:]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": list})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fakeExec answers the inventory commands per container.
type fakeExec struct {
	mu    sync.Mutex
	files map[string]map[string]string // "project/service" → command → output
}

func (f *fakeExec) Exec(_ context.Context, project, service string, cmd []string, w io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.files[project+"/"+service]
	if !ok {
		return errors.New("container not running")
	}
	key := cmd[0]
	if cmd[0] == "cat" {
		key = cmd[1]
	}
	out, ok := c[key]
	if !ok {
		return errors.New(cmd[0] + " exited with 1: No such file or directory")
	}
	_, err := io.WriteString(w, out)
	return err
}

type captured struct {
	mu      sync.Mutex
	notices []Notice
}

func (c *captured) Notify(_ context.Context, n Notice) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notices = append(c.notices, n)
	return nil
}

func (c *captured) take() []Notice {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.notices
	c.notices = nil
	return out
}

type testEnv struct {
	st    *store.Store
	m     *Monitor
	osv   *fakeOSV
	exec  *fakeExec
	notes *captured
	now   time.Time
	// digests the fake registry serves, by "repo:tag".
	digests map[string]string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, q := range []string{
		`INSERT INTO projects (id, slug, name, created_at, updated_at) VALUES ('prj_1', 'lab', 'Lab', 1, 1)`,
		`INSERT INTO services (id, project_id, slug, image, memory_bytes, nano_cpus, pids_limit, created_at, updated_at)
		 VALUES ('svc_web', 'prj_1', 'web', 'lab/web:1.0', 1, 1, 1, 1, 1),
		        ('svc_db', 'prj_1', 'postgres', 'postgres:18.0', 1, 1, 1, 1, 1)`,
	} {
		if _, err := st.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	e := &testEnv{st: st, osv: newFakeOSV(), notes: &captured{}, now: time.Date(2026, 10, 16, 6, 0, 0, 0, time.UTC), digests: map[string]string{}}
	osvSrv := httptest.NewServer(e.osv)
	t.Cleanup(osvSrv.Close)
	reg := fakeRegistry(t, map[string][]string{
		"library/postgres": {"17.6", "18.0", "18.1", "18.2", "19.0", "latest"},
		"lab/web":          {"1.0"},
		"library/caddy":    {"2.11-alpine", "2.12-alpine"},
	}, e.digests)
	r := NewRegistry(reg.Client())
	r.Endpoint = func(string) string { return reg.URL }
	e.exec = &fakeExec{files: map[string]map[string]string{
		"lab/web": {
			"/etc/os-release":      "ID=debian\nVERSION_ID=\"13\"\n",
			"/var/lib/dpkg/status": "Package: libssl3t64\nStatus: install ok installed\nSource: openssl\nVersion: 3.5.1-1\n",
			"find":                 "/usr/local/lib/python3.13/site-packages/Django-5.2.3.dist-info\n/usr/local/lib/python3.13/site-packages/requests-2.32.5.dist-info\n",
		},
		// postgres: an image without the tools to read it.
	}}
	e.m = New(st.DB, Options{
		OSV: NewOSV(osvSrv.URL, osvSrv.Client()), Registry: r, Exec: e.exec, EdgeImage: "caddy:2.11-alpine",
		Notifier: e.notes, Log: discard,
	})
	e.m.now = func() time.Time { return e.now }
	return e
}

func (e *testEnv) open(t *testing.T) map[string]Finding {
	t.Helper()
	fs, err := e.m.Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.Where()+"|"+f.Package+"|"+f.Kind] = f
	}
	return out
}

func TestScanFindsVulnerabilitiesAndUpdates(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	err := e.m.Scan(ctx)
	// The postgres container cannot be read: the scan says so, but the rest works.
	if err == nil || !strings.Contains(err.Error(), "svc_db") {
		t.Fatalf("scan error = %v, want the unreadable postgres reported", err)
	}

	open := e.open(t)
	dj, ok := open["lab/web|django|vuln"]
	if !ok {
		t.Fatalf("django vulnerability not found: %+v", open)
	}
	if dj.Level != LevelCritical || dj.Severity != SevCritical || dj.Suggested != "5.2.7" || dj.Advisory != "GHSA-test-django" {
		t.Errorf("django finding = %+v", dj)
	}
	if ssl := open["lab/web|openssl|vuln"]; ssl.Level != LevelSecurity || ssl.Severity != SevUnknown || ssl.Suggested != "3.5.1-1+deb13u1" {
		t.Errorf("openssl finding = %+v", ssl)
	}
	if pg := open["lab/postgres|postgres|minor"]; pg.Suggested != "18.2" || pg.Level != LevelMinor {
		t.Errorf("postgres minor update = %+v", pg)
	}
	if pg := open["lab/postgres|postgres|major"]; pg.Suggested != "19.0" || pg.Level != LevelMajor {
		t.Errorf("postgres major update = %+v", pg)
	}
	if cd := open["edge|caddy|minor"]; cd.Suggested != "2.12-alpine" {
		t.Errorf("caddy update = %+v", cd)
	}
	if _, ok := open["lab/web|requests|vuln"]; ok {
		t.Error("a package without advisories became a finding")
	}

	// Only names and versions go to OSV: never the project or service names.
	if strings.Contains(e.osv.lastBody, "lab") || strings.Contains(e.osv.lastBody, "svc_") {
		t.Errorf("OSV query leaks internal names: %s", e.osv.lastBody)
	}

	notes := e.notes.take()
	levels := map[string]Notice{}
	for _, n := range notes {
		levels[n.Level] = n
	}
	if n, ok := levels["critical"]; !ok || len(n.Lines) != 1 || !strings.Contains(n.Lines[0], "lab/web · django 5.2.3 → 5.2.7 · GHSA-test-django") {
		t.Errorf("critical notice = %+v", n)
	}
	if n := levels["security"]; len(n.Lines) != 1 {
		t.Errorf("daily summary = %+v", n)
	}
	if n := levels["updates"]; len(n.Lines) != 3 {
		t.Errorf("weekly summary = %+v", n)
	}
	c, _ := e.m.Count(ctx)
	if c[LevelCritical] != 1 || c[LevelSecurity] != 1 || c[LevelMinor] != 2 || c[LevelMajor] != 1 {
		t.Errorf("counts = %v", c)
	}

	// Same findings the next day: nothing new is announced.
	e.now = e.now.Add(24 * time.Hour)
	_ = e.m.Scan(ctx)
	if n := e.notes.take(); len(n) != 0 {
		t.Errorf("repeated findings announced again: %+v", n)
	}

	// Django updated: the finding is resolved.
	e.exec.mu.Lock()
	e.exec.files["lab/web"]["find"] = "/usr/local/lib/python3.13/site-packages/Django-5.2.7.dist-info\n"
	e.exec.mu.Unlock()
	e.now = e.now.Add(24 * time.Hour)
	_ = e.m.Scan(ctx)
	if _, ok := e.open(t)["lab/web|django|vuln"]; ok {
		t.Error("django finding still open after the update")
	}
	// The postgres tag findings stay (the registry was readable).
	if _, ok := e.open(t)["lab/postgres|postgres|minor"]; !ok {
		t.Error("postgres update resolved without being checked")
	}
	scans, _ := e.m.Scans(ctx)
	if scans["svc_db"].Error == "" || scans["svc_web"].Packages != 2 {
		t.Errorf("scan info = %+v", scans)
	}
}

func TestIgnoreHidesFindingUntilNewerVersion(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_ = e.m.Scan(ctx)
	pg := e.open(t)["lab/postgres|postgres|minor"]
	if err := e.m.Ignore(ctx, Actor{UserID: "usr_1"}, pg.ID, IgnoreVersion, ""); !errors.Is(err, ErrReason) {
		t.Fatalf("ignore without a reason: %v", err)
	}
	if err := e.m.Ignore(ctx, Actor{UserID: "usr_1"}, pg.ID, "forever", "motivo"); !errors.Is(err, ErrIgnoreMode) {
		t.Fatalf("ignore with a bad mode: %v", err)
	}
	if err := e.m.Ignore(ctx, Actor{UserID: "usr_1"}, pg.ID, IgnoreVersion, "esperando a janela de manutenção"); err != nil {
		t.Fatal(err)
	}
	if !e.open(t)["lab/postgres|postgres|minor"].Ignored {
		t.Error("ignored finding not flagged")
	}
	if c, _ := e.m.Count(ctx); c[LevelMinor] != 1 {
		t.Errorf("minor count = %d, want 1 (postgres ignored, caddy open)", c[LevelMinor])
	}

	// A newer tag than the ignored one shows up again.
	e.now = e.now.Add(7 * time.Hour) // past the registry cache
	e.m.o.Registry.cache = map[string]cached[[]string]{}
	srv := fakeRegistry(t, map[string][]string{"library/postgres": {"18.0", "18.3"}, "library/caddy": {"2.11-alpine"}}, nil)
	e.m.o.Registry.http = srv.Client()
	e.m.o.Registry.Endpoint = func(string) string { return srv.URL }
	_ = e.m.Scan(ctx)
	if f := e.open(t)["lab/postgres|postgres|minor"]; f.Ignored || f.Suggested != "18.3" {
		t.Errorf("newer version should show again: %+v", f)
	}

	ign, _ := e.m.Ignores(ctx)
	if len(ign) != 1 || ign[0].UntilVersion != "18.2" || ign[0].Where != "lab/postgres" {
		t.Fatalf("ignores = %+v", ign)
	}
	if err := e.m.Unignore(ctx, Actor{}, ign[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Unignore(ctx, Actor{}, ign[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second unignore: %v", err)
	}
}

func TestOSVCachesAnswers(t *testing.T) {
	f := newFakeOSV()
	srv := httptest.NewServer(f)
	defer srv.Close()
	o := NewOSV(srv.URL, srv.Client())
	pkgs := []Package{{Ecosystem: "PyPI", Name: "django", Version: "5.2.3"}}
	for range 3 {
		advs, err := o.Check(context.Background(), pkgs)
		if err != nil || len(advs[0]) != 1 || advs[0][0].Fixed != "5.2.7" {
			t.Fatalf("check: %+v %v", advs, err)
		}
	}
	if f.batches != 1 {
		t.Errorf("querybatch called %d times, want 1 (6 h cache)", f.batches)
	}
}

// TestFixedVersionPerRelease: OSV lists each distribution release with its
// own fix; a fix that exists only in a newer release is not offered.
func TestFixedVersionPerRelease(t *testing.T) {
	var v osvVuln
	rec := `{"id":"DEBIAN-CVE-X","affected":[
		{"package":{"name":"glibc","ecosystem":"Debian:13"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
		{"package":{"name":"glibc","ecosystem":"Debian:14"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.43-5"}]}]},
		{"package":{"name":"curl","ecosystem":"Alpine:v3.23"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.88.0"},{"fixed":"8.22.0-r0"}]}]},
		{"package":{"name":"curl","ecosystem":"Alpine:v3.24"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.88.0"},{"fixed":"8.21.0-r0"}]}]},
		{"package":{"name":"django","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.1.3"}]}]}]}`
	if err := json.Unmarshal([]byte(rec), &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    Package
		want string
	}{
		{Package{Ecosystem: "Debian:13", Name: "glibc", Version: "2.41-12+deb13u4"}, ""},
		{Package{Ecosystem: "Alpine:v3.23", Name: "curl", Version: "8.17.0-r1"}, "8.22.0-r0"},
		{Package{Ecosystem: "PyPI", Name: "Django", Version: "6.1.2"}, "6.1.3"},
	} {
		if got := fixedVersion(v, c.p); got != c.want {
			t.Errorf("%s %s: fixed = %q, want %q", c.p.Ecosystem, c.p.Name, got, c.want)
		}
	}
}
