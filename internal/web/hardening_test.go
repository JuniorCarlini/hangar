package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// criticalActions are the actions docs/17 § 1.3 marks with 🔒 that cannot
// be undone or show a secret: they ask for the password again from the
// standard level up. Listing them by audit name (not by path) keeps a
// renamed or new route for the same action under the rule.
var criticalActions = []string{
	"secret.reveal",
	"service.delete", "project.delete",
	"service.terminal.open", "service.volume.wipe",
	"service.backup.download", "backup.download_link", "backup.restore.start",
	"project.backup.download", "project.restore.start",
	"backup.key.add", "backup.key.confirm", "backup.key.remove",
	"backup.target.add", "backup.target.remove",
	"user.invite", "user.invite.cancel", "user.update", "user.remove",
}

// guardedActions are the other 🔒 actions: they open a way in or change
// what the panel shows, so the strict level asks again; below it their
// confirmation dialog is the guard.
var guardedActions = []string{
	"service.volume.limit", "service.volume.unlimit",
	"domain.add", "domain.remove", "domain.dynamic", "domain.dynamic.rotate_secret",
	"port.open", "project.link",
	"status_link.create", "status_link.revoke",
	"service.git.webhook",
	"alerts.channel.toggle", "alerts.channel.delete",
	"system.update.request",
}

// TestSensitiveActionsNeedSudo is the "critical action without sudo" lock of
// docs/17 § 1.2: the build fails if one of them is reachable without a
// fresh confirmation at the level its tier promises.
func TestSensitiveActionsNeedSudo(t *testing.T) {
	rt := newRouter(nil, nil)
	routes(rt, &handlers{})
	want := map[string]auth.SudoTier{}
	for _, a := range criticalActions {
		want[a] = auth.SudoCritical
	}
	for _, a := range guardedActions {
		want[a] = auth.SudoStrict
	}
	seen := map[string]bool{}
	for _, r := range rt.Routes() {
		tier, ok := want[r.Policy.Audit]
		if !ok {
			continue
		}
		seen[r.Policy.Audit] = true
		if r.Policy.Sudo < tier {
			t.Errorf("route %s (%s) asks for sudo at tier %d, want at least %d", r.Pattern, r.Policy.Audit, r.Policy.Sudo, tier)
		}
		if r.Policy.Role < auth.RoleAdmin {
			t.Errorf("route %s (%s) is critical and open to %s", r.Pattern, r.Policy.Audit, r.Policy.Role)
		}
	}
	for a := range want {
		if !seen[a] {
			t.Errorf("no route audits %q any more: update the list (and check the replacement needs sudo)", a)
		}
	}
}

// Opening a port, adding a domain or linking projects opens a way in:
// sudo. Closing a port or unlinking only reduces exposure: no sudo, so it
// stays one click away in an emergency.
func TestOpeningNeedsSudoClosingDoesNot(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	ctx := context.Background()
	if _, err := e.pm.CreateProject(ctx, projects.Actor{UserID: "usr_x"}, "outro", ""); err != nil {
		t.Fatal(err)
	}
	c, p := e.session(t, auth.RoleOwner)
	post := func(c *http.Cookie, csrf, target string, form url.Values) int {
		form.Set("csrf", csrf)
		return e.do(req{method: "POST", target: target, form: form, cookies: []*http.Cookie{c}}).Code
	}
	port := url.Values{"host_port": {"15433"}, "container_port": {"80"}, "protocol": {"tcp"}, "access": {"localhost"}, "expires": {"1h"}}
	for target, form := range map[string]url.Values{
		"/p/lab/s/web/ports":   port,
		"/p/lab/s/web/domains": {"hostname": {"loja.example.com"}},
		"/p/lab/links":         {"other": {"outro"}},
	} {
		if code := post(c, p.CSRFToken, target, form); code != http.StatusForbidden {
			t.Errorf("%s without sudo: status %d, want 403", target, code)
		}
	}

	sc, sp := e.sudo(t, c, p)
	if code := post(sc, sp.CSRFToken, "/p/lab/s/web/ports", port); code != http.StatusSeeOther {
		t.Fatalf("open port with sudo: status %d", code)
	}
	if code := post(sc, sp.CSRFToken, "/p/lab/links", url.Values{"other": {"outro"}}); code != http.StatusSeeOther {
		t.Fatalf("link with sudo: status %d", code)
	}

	// A fresh session without sudo can still close and unlink.
	_, s, err := e.pm.GetService(ctx, "lab", "web")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := e.pm.ListPorts(ctx, s.ID)
	if err != nil || len(ports) != 1 {
		t.Fatalf("ports = %+v, %v", ports, err)
	}
	e.now = e.now.Add(30 * time.Second)
	plain := e.login(t)
	pp, _ := e.svc.Authenticate(ctx, plain.Value)
	if code := post(plain, pp.CSRFToken, "/p/lab/s/web/ports/delete", url.Values{"id": {ports[0].ID}}); code != http.StatusSeeOther {
		t.Errorf("close port without sudo: status %d", code)
	}
	if code := post(plain, pp.CSRFToken, "/p/lab/links/delete", url.Values{"other": {"outro"}}); code != http.StatusSeeOther {
		t.Errorf("unlink without sudo: status %d", code)
	}

	// Without sudo the page offers the confirmation, not the form.
	body := e.do(req{method: "GET", target: "/p/lab/s/web?tab=network", cookies: []*http.Cookie{plain}}).Body.String()
	if strings.Contains(body, `id="port-new"`) || !strings.Contains(body, `data-tuc-modal="#sudo-dialog"`) {
		t.Error("ports tab without sudo should show the sudo button instead of the form")
	}
	body = e.do(req{method: "GET", target: "/p/lab/settings", cookies: []*http.Cookie{plain}}).Body.String()
	if strings.Count(body, `id="sudo-code"`) > 1 || strings.Contains(body, `action="/p/lab/links"`) {
		t.Error("project settings without sudo: one sudo form and no link form")
	}
}

// Login CSRF (docs/17 § 3.1): a form posted from another site, or replayed
// without the page's cookie, is refused before the password is checked.
func TestLoginFormNeedsItsToken(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	creds := url.Values{"email": {testEmail}, "password": {testPassword}}

	page := e.do(req{method: "GET", target: "/login"})
	tok := cookie(page, loginCookie)
	if tok == nil || !tok.Secure || !tok.HttpOnly || tok.SameSite != http.SameSiteStrictMode || len(tok.Value) != 43 {
		t.Fatalf("login token cookie: %+v", tok)
	}
	if !strings.Contains(page.Body.String(), `name="csrf" value="`+tok.Value+`"`) {
		t.Fatal("the form does not carry the token")
	}
	for name, r := range map[string]req{
		"no token":    {method: "POST", target: "/login", form: creds, rawLogin: true},
		"no cookie":   {method: "POST", target: "/login", form: withCSRF(creds, tok.Value), rawLogin: true},
		"wrong token": {method: "POST", target: "/login", form: withCSRF(creds, strings.Repeat("A", 43)), cookies: []*http.Cookie{tok}, rawLogin: true},
	} {
		rec := e.do(r)
		if rec.Code != http.StatusForbidden || cookie(rec, pendingCookie) != nil || cookie(rec, sessionCookie) != nil {
			t.Errorf("%s: status %d, want 403 and no session", name, rec.Code)
		}
	}
	rec := e.do(req{method: "POST", target: "/login", form: withCSRF(creds, tok.Value), cookies: []*http.Cookie{tok}, rawLogin: true})
	if rec.Code != http.StatusSeeOther || cookie(rec, pendingCookie) == nil {
		t.Fatalf("with the token: status %d", rec.Code)
	}
}

func withCSRF(v url.Values, tok string) url.Values {
	out := url.Values{"csrf": {tok}}
	for k, vs := range v {
		out[k] = vs
	}
	return out
}

// Someone hammering the webhook URL with bad signatures (or guessing URLs)
// must not fill the audit log or the journal: after hookFailLimit failures
// the address gets 429 before anything is looked up or written.
func TestWebhookFailuresAreCapped(t *testing.T) {
	e := newEnv(t)
	id, _ := e.gitService(t, "")
	hook, err := e.pm.RotateWebhook(context.Background(), projects.Actor{}, id)
	if err != nil {
		t.Fatal(err)
	}
	post := func(ip, token string) int {
		hr := httptest.NewRequest(http.MethodPost, "/hooks/git/"+token, strings.NewReader(`{}`))
		hr.Host = testHost
		hr.RemoteAddr = ip + ":443"
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("X-GitHub-Event", "push")
		hr.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, hr)
		return rec.Code
	}
	auditRows := func() int {
		var n int
		if err := e.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'service.webhook'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i := range hookFailLimit {
		if code := post("203.0.113.9", hook.Token); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, code)
		}
	}
	before := auditRows()
	for range 50 {
		if code := post("203.0.113.9", hook.Token); code != http.StatusTooManyRequests {
			t.Fatalf("after the limit: status %d, want 429", code)
		}
	}
	if after := auditRows(); after != before {
		t.Errorf("blocked attempts still wrote %d audit rows", after-before)
	}
	// Guessing URLs counts too, and other addresses are not affected.
	for range hookFailLimit {
		post("198.51.100.7", strings.Repeat("z", 43))
	}
	if code := post("198.51.100.7", strings.Repeat("y", 43)); code != http.StatusTooManyRequests {
		t.Errorf("URL guessing: status %d, want 429", code)
	}
	if code := post("192.0.2.1", hook.Token); code != http.StatusUnauthorized {
		t.Errorf("another address: status %d, want 401", code)
	}
}
