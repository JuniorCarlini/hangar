package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/errpages"

	"github.com/JuniorCarlini/hangar/internal/alerts"
	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/lockdown"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/statuspage"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/update"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

const (
	testHost       = "127.0.0.1:7700"
	testStatusHost = "status.hangar.test"
	testEmail      = "junior@hangar.dev"
	testPassword   = "pista-de-pouso-norte-27"
)

type env struct {
	pages  map[string][]byte // the error pages last written for Caddy
	h      http.Handler
	alerts *alerts.Service
	lock   *lockdown.Lock
	tg     *httptest.Server
	node   *fakeNode
	pm     *projects.Manager
	mc     *metrics.Collector
	bm     *backup.Manager
	stats  *fakeStats
	deps   *deps.Monitor
	upd    *fakeUpdates
	status *statuspage.Service
	svc    *auth.Service
	st     *store.Store
	secret string
	now    time.Time
}

func newEnv(t *testing.T, opts ...func(*auth.Options)) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{3}, 32))
	al := audit.New(st.DB)
	e := &env{st: st, now: time.Now()}
	ao := auth.Options{
		Argon: auth.Argon2Params{Memory: 1024, Time: 1, Threads: 1},
		Now:   func() time.Time { return e.now },
	}
	for _, o := range opts {
		o(&ao)
	}
	e.svc, err = auth.NewService(st.DB, box, al, ao)
	if err != nil {
		t.Fatal(err)
	}
	// The tests below were written for the strictest level, where every
	// sensitive action asks again; the lower levels have their own tests.
	if err := e.svc.SetLevel(context.Background(), "", auth.LevelStrict, auth.Client{}); err != nil {
		t.Fatal(err)
	}
	e.node = newFakeNode()
	e.pm = projects.New(st.DB, box, e.node, al, discard)
	e.stats = &fakeStats{}
	e.mc = metrics.New(st.DB, e.stats, dir, discard)
	// Nothing in these tests reaches the network: OSV and the registries
	// point at a closed port unless a test sets its own fakes.
	reg := deps.NewRegistry(nil)
	reg.Endpoint = func(string) string { return "http://127.0.0.1:9" }
	e.deps = deps.New(st.DB, deps.Options{OSV: deps.NewOSV("http://127.0.0.1:9", nil), Registry: reg, Exec: e.node, Audit: al, Log: discard})
	e.status = statuspage.New(st.DB, e.mc, al, discard)
	// Telegram is a local stand-in that accepts every message.
	e.tg = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(e.tg.Close)
	e.alerts = alerts.New(st.DB, box, al, discard, alerts.Options{
		Now: func() time.Time { return e.now }, TelegramAPI: e.tg.URL, HTTPClient: http.DefaultClient, AllowInsecure: true,
		Backoff: []time.Duration{time.Millisecond},
	})
	e.alerts.Observe(al)
	e.lock = lockdown.New(st.DB, al)
	e.bm, err = backup.New(st.DB, box, e.pm, al, discard, backup.Options{StagingDir: filepath.Join(dir, "staging"), DBPath: filepath.Join(dir, "h.db")})
	if err != nil {
		t.Fatal(err)
	}
	e.upd = &fakeUpdates{current: "v1.0.0"}
	e.h, err = New(Deps{
		Hosts: []string{testHost}, Log: discard, Audit: al, Auth: e.svc,
		Updates: e.upd, UpdateDir: filepath.Join(dir, "update"), Projects: e.pm,
		Metrics: e.mc, Deps: e.deps, Status: e.status, StatusHosts: []string{testStatusHost}, Alerts: e.alerts, Lock: e.lock, Backups: e.bm,
		Brand: errpages.NewStore(st.DB), ErrorPages: func(p map[string][]byte) error { e.pages = p; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) createUser(t *testing.T, role auth.Role) {
	t.Helper()
	ctx := context.Background()
	id, err := e.svc.CreateUser(ctx, testEmail, testPassword, role)
	if err != nil {
		t.Fatal(err)
	}
	e.secret, _ = auth.NewTOTPSecret()
	if err := e.svc.EnrollTOTP(ctx, id, e.secret, e.code(t)); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(30 * time.Second)
}

func (e *env) code(t *testing.T) string {
	t.Helper()
	c, err := auth.TOTPCode(e.secret, e.now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type req struct {
	// local makes the request come from the server itself (SSH tunnel).
	local   bool
	method  string
	target  string
	form    url.Values
	cookies []*http.Cookie
	header  map[string]string
	// rawLogin posts /login without fetching the form's token first.
	rawLogin bool
}

func (e *env) do(r req) *httptest.ResponseRecorder {
	// A login form carries the token of the login page, as a browser's
	// would (rawLogin sends it as given).
	if r.method == http.MethodPost && r.target == "/login" && r.form != nil && !r.rawLogin && !r.form.Has("csrf") {
		page := e.do(req{method: http.MethodGet, target: "/login", local: r.local, header: r.header})
		if c := cookie(page, loginCookie); c != nil {
			form := url.Values{}
			for k, v := range r.form {
				form[k] = v
			}
			form.Set("csrf", c.Value)
			r.form = form
			r.cookies = append(append([]*http.Cookie(nil), r.cookies...), c)
		}
	}
	var body io.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	}
	hr := httptest.NewRequest(r.method, r.target, body)
	hr.Host = testHost
	hr.RemoteAddr = "189.10.20.30:51234"
	if r.local {
		hr.RemoteAddr = "127.0.0.1:51234"
		hr = hr.WithContext(context.WithValue(hr.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7700}))
	}
	if r.form != nil {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range r.header {
		hr.Header.Set(k, v)
	}
	for _, c := range r.cookies {
		hr.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, hr)
	return rec
}

func cookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// login runs both steps through the web and returns the session cookie.
func (e *env) login(t *testing.T) *http.Cookie {
	t.Helper()
	rec := e.do(req{method: "POST", target: "/login", form: url.Values{"email": {testEmail}, "password": {testPassword}}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("step 1: status %d, location %q, body %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	pending := cookie(rec, pendingCookie)
	if pending == nil || !pending.Secure || !pending.HttpOnly || pending.SameSite != http.SameSiteStrictMode {
		t.Fatalf("pending-step cookie without the security flags: %+v", pending)
	}

	rec = e.do(req{method: "POST", target: "/login/2fa", form: url.Values{"code": {e.code(t)}}, cookies: []*http.Cookie{pending}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("step 2: status %d, body %s", rec.Code, rec.Body)
	}
	session := cookie(rec, sessionCookie)
	if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" {
		t.Fatalf("session cookie without the security flags: %+v", session)
	}
	return session
}

// TestEveryRouteHasValidPolicy is the CI lock: if someone registers a route
// without a policy, or a write route without auditing, the build fails here.
func TestEveryRouteHasValidPolicy(t *testing.T) {
	rt := newRouter(nil, nil)
	routes(rt, &handlers{})
	if err := rt.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, r := range rt.Routes() {
		if !r.Policy.Public && r.Policy.Role == auth.RoleNone {
			t.Errorf("route %s without a role", r.Pattern)
		}
		if isUnsafe(r.Method) && r.Policy.Audit == "" {
			t.Errorf("route %s changes state without auditing", r.Pattern)
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	ok := func(http.ResponseWriter, *http.Request) {}
	cases := []struct {
		name    string
		pattern string
		policy  Policy
		wantErr string
	}{
		{"no method", "/x", Policy{Public: true}, "method"},
		{"no role", "GET /x", Policy{}, "minimum role"},
		{"write without audit", "POST /x", Policy{Role: auth.RoleAdmin}, "audit name"},
		{"public write without audit", "POST /login", Policy{Public: true}, "audit name"},
		{"public with sudo", "GET /x", Policy{Public: true, Sudo: auth.SudoStrict}, "sudo"},
		{"public with role", "GET /x", Policy{Public: true, Role: auth.RoleViewer}, "role"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt := newRouter(nil, nil)
			rt.HandleFunc(c.pattern, ok, c.policy)
			err := rt.Validate()
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, c.wantErr)
			}
		})
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	for _, target := range []string{"/healthz", "/", "/login", "/nao-existe"} {
		rec := e.do(req{method: "GET", target: target})
		for _, name := range []string{
			"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
			"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
			"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy", "Cache-Control",
		} {
			if rec.Header().Get(name) == "" {
				t.Errorf("%s: header %s missing", target, name)
			}
		}
		if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-") {
			t.Errorf("CSP must not have unsafe-*: %s", csp)
		}
	}
}

func TestPagesHaveNoInlineStyleOrScript(t *testing.T) {
	e := newEnv(t)
	body := e.do(req{method: "GET", target: "/login"}).Body.String()
	for _, bad := range []string{"style=", "onclick", "javascript:"} {
		if strings.Contains(body, bad) {
			t.Errorf("login page contains %q, which the CSP would block", bad)
		}
	}
	// Scripts only from our own files: <script src="/assets/..."></script>.
	for _, m := range regexp.MustCompile(`(?s)<script([^>]*)>(.*?)</script>`).FindAllStringSubmatch(body, -1) {
		if !strings.Contains(m[1], `src="/assets/`) || strings.TrimSpace(m[2]) != "" {
			t.Errorf("inline or foreign script: %s", m[0])
		}
	}
}

func TestUnknownHostIsRejected(t *testing.T) {
	e := newEnv(t)
	hr := httptest.NewRequest("GET", "/healthz", nil)
	hr.Host = "atacante.example"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, hr)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", rec.Code)
	}
}

func TestDenyByDefault(t *testing.T) {
	e := newEnv(t)
	if rec := e.do(req{method: "GET", target: "/"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session (API): status = %d, want 401", rec.Code)
	}
	rec := e.do(req{method: "GET", target: "/", header: map[string]string{"Accept": "text/html"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("no session (browser): status = %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do(req{method: "GET", target: "/healthz"}); rec.Code != http.StatusOK {
		t.Errorf("public route: status = %d", rec.Code)
	}
}

func TestLoginFlowEndToEnd(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	session := e.login(t)

	rec := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Novo projeto") {
		t.Fatalf("home page: status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), session.Value) {
		t.Error("the session token must not appear in the HTML")
	}

	n, err := audit.Verify(context.Background(), e.st.Q)
	if err != nil || n == 0 {
		t.Fatalf("audit: %d records, err %v", n, err)
	}
}

func TestWrongPasswordShowsGenericMessage(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	for _, email := range []string{testEmail, "ninguem@hangar.dev"} {
		rec := e.do(req{method: "POST", target: "/login", form: url.Values{"email": {email}, "password": {"senha-errada-aqui-123"}}})
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), i18n.Tl("pt-BR", "login.error.bad_credentials")) {
			t.Errorf("%s: status %d", email, rec.Code)
		}
	}
}

// A locked account: the right password learns until when; a wrong one still
// gets the generic message, so a guesser learns nothing.
func TestLockedAccountTellsTheRightPasswordUntilWhen(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	until := time.Now().Add(time.Hour).Truncate(time.Second)
	if _, err := e.st.DB.Exec("UPDATE users SET locked_until = ?, lock_count = 1 WHERE email = ?", until.Unix(), testEmail); err != nil {
		t.Fatal(err)
	}
	want := i18n.Tl("pt-BR", "login.error.locked", "time", until.Local().Format("15:04 MST"))
	rec := e.do(req{method: "POST", target: "/login", form: url.Values{"email": {testEmail}, "password": {testPassword}}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), want) {
		t.Errorf("right password: status %d, want the lock message %q", rec.Code, want)
	}
	rec = e.do(req{method: "POST", target: "/login", form: url.Values{"email": {testEmail}, "password": {"senha-errada-aqui-123"}}})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), i18n.Tl("pt-BR", "login.error.bad_credentials")) {
		t.Errorf("wrong password: status %d", rec.Code)
	}
}

func TestLogoutRequiresCSRFToken(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	session := e.login(t)

	rec := e.do(req{method: "POST", target: "/logout", form: url.Values{}, cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF: status %d, want 403", rec.Code)
	}

	p, _ := e.svc.Authenticate(context.Background(), session.Value)
	rec = e.do(req{method: "POST", target: "/logout", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout with CSRF: status %d", rec.Code)
	}
	if p, _ := e.svc.Authenticate(context.Background(), session.Value); p != nil {
		t.Error("session still valid after logout")
	}
}

func TestCrossOriginLoginIsBlocked(t *testing.T) {
	e := newEnv(t)
	rec := e.do(req{
		method: "POST", target: "/login",
		form:   url.Values{"email": {testEmail}, "password": {testPassword}},
		header: map[string]string{"Sec-Fetch-Site": "cross-site"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login from another site: status %d, want 403", rec.Code)
	}
}

func TestSudoGivesAccessAndRedirectIsSafe(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	session := e.login(t)
	p, _ := e.svc.Authenticate(context.Background(), session.Value)

	e.now = e.now.Add(30 * time.Second)
	rec := e.do(req{
		method: "POST", target: "/sudo",
		form:    url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"https://phishing.example/"}},
		cookies: []*http.Cookie{session},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sudo: status %d, body %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("open redirect: went to %q", loc)
	}
	newSession := cookie(rec, sessionCookie)
	np, _ := e.svc.Authenticate(context.Background(), newSession.Value)
	if np == nil || !np.SudoUntil.After(e.now) {
		t.Fatal("new session should be in sudo")
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/projects/x":       "/projects/x",
		"":                  "/",
		"//evil.example":    "/",
		"https://evil":      "/",
		"/\\evil.example":   "/",
		"/ok\r\nSet-Cookie": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAssetsServedWithoutListing(t *testing.T) {
	e := newEnv(t)
	if rec := e.do(req{method: "GET", target: "/assets/app.css"}); rec.Code != http.StatusOK {
		t.Errorf("CSS: status %d", rec.Code)
	}
	if rec := e.do(req{method: "GET", target: "/assets/"}); rec.Code != http.StatusNotFound {
		t.Errorf("/assets/ listing: status %d, want 404", rec.Code)
	}
}

// The fonts are cached for good like the stylesheet: fetched again on each
// page, the text painted in the fallback font and jumped when they arrived.
func TestFontsAreVersionedAndCached(t *testing.T) {
	e := newEnv(t)
	css := e.do(req{method: "GET", target: "/assets/app.css?v=" + views.AssetVersion})
	if css.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Errorf("app.css type %q", css.Header().Get("Content-Type"))
	}
	font := "fonts/space-grotesk-latin.woff2?v=" + views.AssetVersion
	if !strings.Contains(css.Body.String(), "url("+font+")") || strings.Contains(css.Body.String(), "woff2)") {
		t.Fatal("app.css points at unversioned fonts")
	}
	if rec := e.do(req{method: "GET", target: "/assets/" + font}); rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("font: status %d, cache %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}

type fixedAuth struct{ p *auth.Principal }

func (f fixedAuth) Authenticate(context.Context, string) (*auth.Principal, error) { return f.p, nil }

func TestRoleAndSudoEnforcement(t *testing.T) {
	e := newEnv(t)
	al := audit.New(e.st.DB)
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

	post := func(p *auth.Principal) int {
		rt := newRouter(fixedAuth{p}, al)
		rt.HandleFunc("POST /secret/reveal", ok, Policy{Role: auth.RoleAdmin, Sudo: auth.SudoCritical, Audit: "secret.reveal"})
		if err := rt.Validate(); err != nil {
			t.Fatal(err)
		}
		hr := httptest.NewRequest("POST", "/secret/reveal", nil)
		hr.Header.Set("X-CSRF-Token", "tok")
		rec := httptest.NewRecorder()
		rt.mux.ServeHTTP(rec, hr)
		return rec.Code
	}

	future := time.Now().Add(5 * time.Minute)
	cases := []struct {
		name string
		p    *auth.Principal
		want int
	}{
		{"operator", &auth.Principal{UserID: "u1", Role: auth.RoleOperator, SudoUntil: future, CSRFToken: "tok"}, http.StatusForbidden},
		{"admin without sudo", &auth.Principal{UserID: "u2", Role: auth.RoleAdmin, CSRFToken: "tok"}, http.StatusForbidden},
		{"admin with wrong CSRF", &auth.Principal{UserID: "u3", Role: auth.RoleAdmin, SudoUntil: future, CSRFToken: "outro"}, http.StatusForbidden},
		{"admin with sudo", &auth.Principal{UserID: "u4", Role: auth.RoleAdmin, SudoUntil: future, CSRFToken: "tok"}, http.StatusNoContent},
		{"owner with sudo", &auth.Principal{UserID: "u5", Role: auth.RoleOwner, SudoUntil: future, CSRFToken: "tok"}, http.StatusNoContent},
	}
	for _, c := range cases {
		if got := post(c.p); got != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, got, c.want)
		}
	}
	if _, err := audit.Verify(context.Background(), e.st.Q); err != nil {
		t.Fatal(err)
	}
}

type fakeUpdates struct {
	current   string
	available *update.Available
	staged    string
	noApplier bool
}

func (f *fakeUpdates) CanApply() bool { return !f.noApplier }

func (f *fakeUpdates) Current() string                                  { return f.current }
func (f *fakeUpdates) Latest() (*update.Available, error)               { return f.available, nil }
func (f *fakeUpdates) Check(context.Context) (*update.Available, error) { return f.available, nil }
func (f *fakeUpdates) Stage(_ context.Context, version, _ string) error {
	f.staged = version
	return nil
}

func TestUpdatePageRequiresOwnerAndSudo(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	session := e.login(t)
	p, _ := e.svc.Authenticate(context.Background(), session.Value)

	rec := e.do(req{method: "GET", target: "/update", cookies: []*http.Cookie{session}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Tudo em dia") {
		t.Fatalf("update page: status %d", rec.Code)
	}

	// Without sudo, applying the update is refused.
	rec = e.do(req{
		method: "POST", target: "/update", form: url.Values{"csrf": {p.CSRFToken}, "version": {"v1.1.0"}},
		cookies: []*http.Cookie{session},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("update without sudo: status %d, want 403", rec.Code)
	}
}

// The customers' domains modal reopens after its own changes only.
func TestClientsModalReopens(t *testing.T) {
	base := "/p/lab/s/web"
	for _, c := range []struct {
		method, target string
		want           bool
	}{
		{http.MethodGet, base + "?tab=network", false},
		{http.MethodGet, base + "?tab=network&ok=txt-on", true},
		{http.MethodGet, base + "?tab=network&ok=dynamic-on", true},
		{http.MethodGet, base + "?tab=network&ok=domain", false},
		{http.MethodPost, base + "/domains/txt", true},
		{http.MethodPost, base + "/domains/secret/rotate", true},
		{http.MethodPost, base + "/domains/dns-token", false},
	} {
		r := httptest.NewRequest(c.method, c.target, nil)
		if got := clientsOpen(r); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.method, c.target, got, c.want)
		}
	}
}
