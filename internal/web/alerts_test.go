package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/alerts"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

const tgToken = "123456789:AAH-web_test_token_for_the_fake_api_0000"

// Every sudo route is a sensitive action, and every sensitive action becomes
// a security alert: adding a sudo route without listing it fails here.
func TestSudoRoutesRaiseSecurityAlerts(t *testing.T) {
	rt := newRouter(nil, nil)
	routes(rt, &handlers{})
	for _, r := range rt.Routes() {
		if r.Policy.Sudo == auth.SudoNone {
			continue
		}
		ok := slices.ContainsFunc(alerts.SensitiveActions, func(a string) bool {
			return a == r.Policy.Audit || strings.HasPrefix(a, r.Policy.Audit+".")
		})
		if !ok {
			t.Errorf("sudo route %s (audit %q) is not in alerts.SensitiveActions", r.Pattern, r.Policy.Audit)
		}
	}
}

func TestAlertsPageByRole(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleViewer)
	page := e.do(req{method: "GET", target: "/alerts", cookies: []*http.Cookie{c}})
	if page.Code != http.StatusOK {
		t.Fatalf("viewer: status %d", page.Code)
	}
	body := page.Body.String()
	if !strings.Contains(body, `id="history"`) || strings.Contains(body, `id="channels"`) || strings.Contains(body, `id="deliveries"`) {
		t.Fatal("a viewer sees the history only")
	}
	rec := e.do(req{method: "POST", target: "/alerts/channels", form: url.Values{
		"csrf": {p.CSRFToken}, "kind": {"telegram"}, "name": {"x"}, "min_severity": {"info"}, "bot_token": {tgToken}, "chat_id": {"1"},
	}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer creating a channel: status %d", rec.Code)
	}
	if rec := e.do(req{method: "POST", target: "/lock", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer locking the panel: status %d", rec.Code)
	}
}

func TestChannelSecretOnlyWithSudo(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	rec := e.do(req{method: "POST", target: "/alerts/channels", form: url.Values{
		"csrf": {p.CSRFToken}, "kind": {"telegram"}, "name": {"Plantão"}, "min_severity": {"warning"},
		"bot_token": {tgToken}, "chat_id": {"-100123"},
	}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: status %d %s", rec.Code, rec.Body)
	}
	chans, _ := e.alerts.Channels(context.Background())
	if len(chans) != 1 {
		t.Fatalf("channels = %d", len(chans))
	}
	id := chans[0].ID

	page := e.do(req{method: "GET", target: "/alerts?tab=config", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(page, tgToken) || !strings.Contains(page, "Plantão") || !strings.Contains(page, "chat -100123") {
		t.Fatal("channel list wrong or token in the HTML")
	}

	// Test send goes through the fake API and shows in the delivery log.
	if rec := e.do(req{method: "POST", target: "/alerts/channels/" + id + "/test", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("test: status %d %s", rec.Code, rec.Body)
	}
	if d, _ := e.alerts.Deliveries(context.Background(), 5); len(d) == 0 || d[0].Status != "sent" || d[0].Kind != "test" {
		t.Fatalf("deliveries = %+v", d)
	}

	for _, action := range []string{"reveal", "toggle", "delete"} {
		rec := e.do(req{method: "POST", target: "/alerts/channels/" + id + "/" + action, form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), tgToken) {
			t.Fatalf("%s without sudo: status %d", action, rec.Code)
		}
	}

	e.now = e.now.Add(30 * time.Second)
	rec = e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/alerts"}}, cookies: []*http.Cookie{c}})
	sc := cookie(rec, sessionCookie)
	sp, _ := e.svc.Authenticate(context.Background(), sc.Value)
	rec = e.do(req{method: "POST", target: "/alerts/channels/" + id + "/reveal", form: url.Values{"csrf": {sp.CSRFToken}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tgToken) {
		t.Fatalf("reveal with sudo: status %d", rec.Code)
	}
	// The reveal itself is a security alert.
	e.alerts.Wait()
	list, _ := e.alerts.Recent(context.Background(), true, 10)
	if !slices.ContainsFunc(list, func(a dbq.Alert) bool { return a.Kind == "sudo_action" }) {
		t.Fatalf("reveal did not raise a security alert: %+v", list)
	}

	rec = e.do(req{method: "POST", target: "/alerts/channels/" + id + "/delete", form: url.Values{"csrf": {sp.CSRFToken}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete with sudo: status %d", rec.Code)
	}
	if chans, _ := e.alerts.Channels(context.Background()); len(chans) != 0 {
		t.Fatal("channel not removed")
	}
}

func TestChannelFormErrorKeepsDialogOpenWithoutSecrets(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	rec := e.do(req{method: "POST", target: "/alerts/channels", form: url.Values{
		"csrf": {p.CSRFToken}, "kind": {"email"}, "name": {"Ops"}, "min_severity": {"info"},
		"host": {"smtp.example.com"}, "security": {"starttls"}, "password": {"senha-que-nao-volta"}, "from": {"nao-e-email"}, "to": {"ops@example.com"},
	}, cookies: []*http.Cookie{c}})
	body := rec.Body.String()
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(body, `id="channel-email"`) || !strings.Contains(body, `data-open="true"`) {
		t.Fatal("the e-mail dialog should reopen")
	}
	if strings.Contains(body, "senha-que-nao-volta") {
		t.Fatal("the password came back in the page")
	}
}

func TestRulesAndMute(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	form := url.Values{"csrf": {p.CSRFToken}, "rule": {"host_disk", "oom"}, "on_host_disk": {"1"}, "v_host_disk": {"70"}}
	if rec := e.do(req{method: "POST", target: "/alerts/rules", form: form, cookies: []*http.Cookie{c}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("rules: %d %s", rec.Code, rec.Body)
	}
	rules, _ := e.alerts.RuleSettings(context.Background())
	for _, r := range rules {
		if r.Kind == "host_disk" && (!r.Enabled || r.Value != 70) {
			t.Errorf("host_disk = %+v", r)
		}
		if r.Kind == "oom" && r.Enabled {
			t.Error("oom should be off")
		}
	}
	form.Set("v_host_disk", "5")
	if rec := e.do(req{method: "POST", target: "/alerts/rules", form: form, cookies: []*http.Cookie{c}}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("out-of-range threshold: %d", rec.Code)
	}
	if rec := e.do(req{method: "POST", target: "/alerts/mute", form: url.Values{"csrf": {p.CSRFToken}, "minutes": {"60"}}, cookies: []*http.Cookie{c}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("mute: %d", rec.Code)
	}
	if e.alerts.MutedUntil(context.Background()).IsZero() {
		t.Fatal("not muted")
	}
}

func TestBellShowsUnreadUntilSeen(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	if _, err := e.alerts.Notify(context.Background(), alerts.Event{
		Kind: "container_down", Severity: alerts.Critical, Category: alerts.Server, Params: map[string]string{"service": "lab_web"},
	}); err != nil {
		t.Fatal(err)
	}
	page := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, "data-unread") || !strings.Contains(page, "lab_web") {
		t.Fatal("bell should show the new alert with the unread dot")
	}
	rec := e.do(req{method: "POST", target: "/alerts/seen", form: url.Values{"csrf": {p.CSRFToken}, "next": {"/ports"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/ports" {
		t.Fatalf("mark seen: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if page := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String(); strings.Contains(page, "data-unread") {
		t.Fatal("dot should be gone after marking as read")
	}
}

func TestLockdownDropsSessionsAndOnlyLocalGetsIn(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleOwner)
	page := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `action="/lock"`) {
		t.Fatal("owner should see the lock action")
	}

	rec := e.do(req{method: "POST", target: "/lock", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("lock: %d %s", rec.Code, rec.Body)
	}
	if ck := cookie(rec, sessionCookie); ck == nil || ck.MaxAge >= 0 {
		t.Error("session cookie should be cleared")
	}
	if pr, _ := e.svc.Authenticate(context.Background(), c.Value); pr != nil {
		t.Fatal("session survived the lockdown")
	}

	// From outside (Caddy, a private address): refused, login included.
	for _, target := range []string{"/", "/login", "/healthz"} {
		if rec := e.do(req{method: "GET", target: target}); rec.Code != http.StatusForbidden {
			t.Errorf("remote %s while locked: status %d", target, rec.Code)
		}
	}
	// From the server itself (SSH tunnel): the login page says why.
	rec = e.do(req{method: "GET", target: "/login", local: true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "hangard lockdown off") {
		t.Fatalf("local login while locked: %d", rec.Code)
	}

	// A lockdown is a security alert.
	e.alerts.Wait()
	list, _ := e.alerts.Recent(context.Background(), true, 10)
	if !slices.ContainsFunc(list, func(a dbq.Alert) bool { return a.Kind == "lockdown" }) {
		t.Fatal("lockdown raised no alert")
	}

	if err := e.lock.Release(context.Background(), "cli"); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(req{method: "GET", target: "/login"}); rec.Code != http.StatusOK {
		t.Fatalf("after release: status %d", rec.Code)
	}
}
