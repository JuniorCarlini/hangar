package alerts

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

const botToken = "123456789:AAH-test_token_for_the_fake_bot_api_000"

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testEnv struct {
	st    *store.Store
	al    *audit.Logger
	svc   *Service
	clock *clock
	tg    *fakeTelegram
}

func newTestEnv(t *testing.T, mod func(*Options)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{7}, 32))
	e := &testEnv{st: st, al: audit.New(st.DB), clock: &clock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}}
	e.tg = newFakeTelegram(t, botToken)
	opt := Options{
		Now: e.clock.now, TelegramAPI: e.tg.srv.URL, HTTPClient: http.DefaultClient,
		AllowInsecure: true, Backoff: []time.Duration{time.Millisecond, time.Millisecond},
	}
	if mod != nil {
		mod(&opt)
	}
	e.svc = New(st.DB, box, e.al, discard, opt)
	return e
}

func (e *testEnv) telegram(t *testing.T, minSeverity string) string {
	t.Helper()
	id, err := e.svc.CreateChannel(context.Background(), Actor{}, NewChannel{
		Kind: KindTelegram, Name: "Telegram", MinSeverity: minSeverity,
		Config: Config{BotToken: botToken, ChatID: "-100123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *testEnv) deliveries(t *testing.T) []dbq.AlertDelivery {
	t.Helper()
	d, err := e.svc.Deliveries(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTelegramDeliveryAndDedup(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "warning")
	ctx := context.Background()
	ev := Event{Kind: "container_down", Severity: Critical, Category: Server, Key: "container_down|svc_1", Params: map[string]string{"service": "lab_web"}}

	id, err := e.svc.Notify(ctx, ev)
	if err != nil || id == 0 {
		t.Fatalf("notify: id=%d err=%v", id, err)
	}
	msgs := e.tg.messages()
	if len(msgs) != 1 || msgs[0].ChatID != "-100123" || !strings.Contains(msgs[0].Text, "lab_web") || !strings.HasPrefix(msgs[0].Text, "🔴") {
		t.Fatalf("telegram got %+v", msgs)
	}

	// Same condition again within the window: counted, not sent.
	e.clock.add(5 * time.Minute)
	if id2, _ := e.svc.Notify(ctx, ev); id2 != 0 {
		t.Fatalf("duplicate should be swallowed, got id %d", id2)
	}
	if len(e.tg.messages()) != 1 {
		t.Fatal("duplicate was sent")
	}
	recent, _ := e.svc.Recent(ctx, true, 10)
	if len(recent) != 1 || recent[0].Repeats != 1 {
		t.Fatalf("recent = %+v", recent)
	}

	// Back to normal is announced once, then a new firing goes out again.
	ev.Resolved = true
	if _, err := e.svc.Notify(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if _, _ = e.svc.Notify(ctx, ev); len(e.tg.messages()) != 2 {
		t.Fatalf("resolved should be sent exactly once, got %d messages", len(e.tg.messages()))
	}
	if m := e.tg.messages()[1]; !strings.HasPrefix(m.Text, "🟢") {
		t.Errorf("resolved message: %q", m.Text)
	}
	ev.Resolved = false
	if id, _ := e.svc.Notify(ctx, ev); id == 0 {
		t.Fatal("a new firing after resolution should be raised")
	}
	if len(e.tg.messages()) != 3 {
		t.Fatalf("messages = %d", len(e.tg.messages()))
	}
}

func TestFlappingIsCapped(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "info")
	ctx := context.Background()
	ev := Event{Kind: "container_down", Severity: Critical, Category: Server, Key: "k"}
	for range 6 {
		_, _ = e.svc.Notify(ctx, ev)
		r := ev
		r.Resolved = true
		_, _ = e.svc.Notify(ctx, r)
		e.clock.add(time.Minute)
	}
	// 3 firings + their 3 resolutions; the rest swallowed.
	if n := len(e.tg.messages()); n != 6 {
		t.Fatalf("flapping sent %d messages, want 6", n)
	}
}

func TestSeverityFilterMuteAndSecurityBypass(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "critical")
	ctx := context.Background()

	_, _ = e.svc.Notify(ctx, Event{Kind: "host_disk", Severity: Warning, Category: Server, Key: "a"})
	if len(e.tg.messages()) != 0 {
		t.Fatal("warning reached a critical-only channel")
	}
	_, _ = e.svc.Notify(ctx, Event{Kind: "login_new_ip", Severity: Warning, Category: Security, Key: "b"})
	if len(e.tg.messages()) != 1 {
		t.Fatal("security alert must reach every channel")
	}

	if err := e.svc.Mute(ctx, Actor{}, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, _ = e.svc.Notify(ctx, Event{Kind: "container_down", Severity: Critical, Category: Server, Key: "c"})
	if len(e.tg.messages()) != 1 {
		t.Fatal("muted server alert was sent")
	}
	_, _ = e.svc.Notify(ctx, Event{Kind: "account_locked", Severity: Critical, Category: Security, Key: "d"})
	if len(e.tg.messages()) != 2 {
		t.Fatal("security alerts cannot be muted")
	}
	if err := e.svc.Mute(ctx, Actor{}, 48*time.Hour); err == nil {
		t.Error("mute longer than MaxMute accepted")
	}
	e.clock.add(2 * time.Hour)
	if !e.svc.MutedUntil(ctx).IsZero() {
		t.Error("mute should have expired")
	}
}

func TestRetriesThenGivesUp(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "info")
	e.tg.failures = 2
	ctx := context.Background()
	_, _ = e.svc.Notify(ctx, Event{Kind: "host_cpu", Severity: Warning, Category: Server, Key: "x"})
	d := e.deliveries(t)
	if len(d) != 1 || d[0].Status != "sent" || d[0].Attempts != 3 {
		t.Fatalf("deliveries = %+v", d)
	}
	e.tg.failures = 5
	_, _ = e.svc.Notify(ctx, Event{Kind: "host_cpu", Severity: Warning, Category: Server, Key: "y"})
	d = e.deliveries(t)
	if d[0].Status != "failed" || d[0].Attempts != 3 || !strings.Contains(d[0].Error, "500") {
		t.Fatalf("deliveries = %+v", d[0])
	}
}

func TestWrongTokenIsPermanentAndNeverLogged(t *testing.T) {
	e := newTestEnv(t, nil)
	other := "987654321:BBB-another_token_that_is_wrong_0000000"
	id, err := e.svc.CreateChannel(context.Background(), Actor{}, NewChannel{
		Kind: KindTelegram, Name: "x", MinSeverity: "info", Config: Config{BotToken: other, ChatID: "42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = e.svc.TestChannel(context.Background(), Actor{}, id)
	if err == nil {
		t.Fatal("test with a wrong token should fail")
	}
	d := e.deliveries(t)
	if len(d) != 1 || d[0].Status != "failed" || d[0].Kind != "test" || d[0].Attempts != 1 {
		t.Fatalf("deliveries = %+v", d)
	}
	if strings.Contains(d[0].Error, other) || strings.Contains(err.Error(), other) {
		t.Fatalf("token leaked: %q / %v", d[0].Error, err)
	}
	// The stored channel never holds the token in clear.
	var blob []byte
	_ = e.st.DB.QueryRow(`SELECT config_enc FROM alert_channels WHERE id = ?`, id).Scan(&blob)
	if bytes.Contains(blob, []byte("another_token")) {
		t.Fatal("bot token stored in clear")
	}
	// Reveal gives it back and is audited.
	got, err := e.svc.RevealSecret(context.Background(), Actor{UserID: "u"}, id)
	if err != nil || got != other {
		t.Fatalf("reveal = %q, %v", got, err)
	}
}

func TestEmailDeliveryStartTLSAndImplicitTLS(t *testing.T) {
	cert, pool := selfSigned(t)
	for _, mode := range []string{SMTPStartTLS, SMTPTLS} {
		t.Run(mode, func(t *testing.T) {
			srv := newFakeSMTP(t, cert, mode == SMTPTLS, false)
			e := newTestEnv(t, func(o *Options) { o.SMTPTLS = &TLSOverride{RootCAs: pool} })
			id, err := e.svc.CreateChannel(context.Background(), Actor{}, NewChannel{
				Kind: KindEmail, Name: "E-mail", MinSeverity: "info",
				Config: Config{
					Host: "127.0.0.1", Port: srv.port(), Security: mode, Username: "hangar", Password: "s3nha-smtp",
					From: "hangar@example.com", To: []string{"ops@example.com", "junior@example.com"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := e.svc.TestChannel(context.Background(), Actor{}, id); err != nil {
				t.Fatal(err)
			}
			_, _ = e.svc.Notify(context.Background(), Event{
				Kind: "container_down", Severity: Critical, Category: Server, Key: "k",
				Params: map[string]string{"service": "lab_web\r\nBcc: evil@example.com"},
			})
			mails := srv.received()
			if len(mails) != 2 {
				t.Fatalf("mails = %d", len(mails))
			}
			m := mails[1]
			if !m.TLS || m.User != "hangar" || m.Pass != "s3nha-smtp" || m.From != "hangar@example.com" || len(m.To) != 2 {
				t.Fatalf("mail = %+v", m)
			}
			if strings.Contains(m.Data, "\nBcc:") {
				t.Fatalf("header injection through a parameter:\n%s", m.Data)
			}
			if !strings.Contains(m.Data, "Subject: =?utf-8?q?") {
				t.Errorf("subject not encoded:\n%s", m.Data)
			}
		})
	}
}

func TestEmailRefusesServerWithoutTLS(t *testing.T) {
	cert, pool := selfSigned(t)
	srv := newFakeSMTP(t, cert, false, true)
	e := newTestEnv(t, func(o *Options) { o.SMTPTLS = &TLSOverride{RootCAs: pool} })
	id, err := e.svc.CreateChannel(context.Background(), Actor{}, NewChannel{
		Kind: KindEmail, Name: "E-mail", MinSeverity: "info",
		Config: Config{Host: "127.0.0.1", Port: srv.port(), Security: SMTPStartTLS, From: "a@example.com", To: []string{"b@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.TestChannel(context.Background(), Actor{}, id); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	if len(srv.received()) != 0 {
		t.Fatal("mail sent in clear text")
	}
}

func TestWebhookSignedPayload(t *testing.T) {
	srv, calls := newHookReceiver(t, http.StatusNoContent)
	e := newTestEnv(t, nil)
	id, err := e.svc.CreateChannel(context.Background(), Actor{}, NewChannel{
		Kind: KindWebhook, Name: "n8n", MinSeverity: "info", Config: Config{URL: srv.URL + "/hook"},
	})
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := e.svc.RevealSecret(context.Background(), Actor{}, id)
	_, secret, _ = strings.Cut(secret, "\n")
	if len(secret) < 32 {
		t.Fatalf("generated secret too short: %q", secret)
	}
	_, _ = e.svc.Notify(context.Background(), Event{Kind: "host_disk", Severity: Warning, Category: Server, Key: "d", Params: map[string]string{"pct": "91", "limit": "85"}})
	got := calls()
	if len(got) != 1 {
		t.Fatalf("calls = %d", len(got))
	}
	c := got[0]
	ts, _ := strconv.ParseInt(c.Header.Get("X-Hangar-Timestamp"), 10, 64)
	if want := SignWebhook(secret, ts, c.Body); c.Header.Get("X-Hangar-Signature") != want {
		t.Fatalf("signature %q, want %q", c.Header.Get("X-Hangar-Signature"), want)
	}
	if c.Payload.Kind != "host_disk" || c.Payload.Severity != Warning || c.Payload.Params["pct"] != "91" || c.Payload.Title == "" {
		t.Fatalf("payload = %+v", c.Payload)
	}
	if c.Header.Get("X-Hangar-Event") != "host_disk" {
		t.Error("event header missing")
	}
}

func TestWebhookRefusesPrivateAddresses(t *testing.T) {
	srv, calls := newHookReceiver(t, http.StatusOK)
	e := newTestEnv(t, func(o *Options) { o.AllowInsecure = false; o.HTTPClient = nil })
	// Plain HTTP and private IP literals are refused up front.
	for _, u := range []string{srv.URL, "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://10.0.0.1/"} {
		_, err := e.svc.CreateChannel(context.Background(), Actor{}, NewChannel{Kind: KindWebhook, Name: "x", MinSeverity: "info", Config: Config{URL: u}})
		if err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	// A name that resolves to loopback is refused when dialing.
	id, err := e.svc.CreateChannel(context.Background(), Actor{}, NewChannel{
		Kind: KindWebhook, Name: "x", MinSeverity: "info",
		Config: Config{URL: "https://localhost:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:] + "/x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.TestChannel(context.Background(), Actor{}, id); err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("err = %v", err)
	}
	if len(calls()) != 0 {
		t.Fatal("request reached a loopback address")
	}
}

func TestChannelValidation(t *testing.T) {
	bad := []NewChannel{
		{Kind: KindTelegram, Name: "x", MinSeverity: "info", Config: Config{BotToken: "nope", ChatID: "1"}},
		{Kind: KindTelegram, Name: "x", MinSeverity: "info", Config: Config{BotToken: botToken, ChatID: "abc"}},
		{Kind: KindTelegram, Name: "", MinSeverity: "info", Config: Config{BotToken: botToken, ChatID: "1"}},
		{Kind: KindTelegram, Name: "x", MinSeverity: "loud", Config: Config{BotToken: botToken, ChatID: "1"}},
		{Kind: KindEmail, Name: "x", MinSeverity: "info", Config: Config{Host: "smtp.example.com", Security: "none", From: "a@b.c", To: []string{"d@e.f"}}},
		{Kind: KindEmail, Name: "x", MinSeverity: "info", Config: Config{Host: "smtp.example.com", Security: SMTPTLS, From: "a@b.c\r\nBcc: x@y.z", To: []string{"d@e.f"}}},
		{Kind: KindEmail, Name: "x", MinSeverity: "info", Config: Config{Host: "smtp.example.com", Security: SMTPTLS, From: "a@b.c"}},
		{Kind: KindEmail, Name: "x", MinSeverity: "info", Config: Config{Host: "bad host", Security: SMTPTLS, From: "a@b.c", To: []string{"d@e.f"}}},
		{Kind: KindWebhook, Name: "x", MinSeverity: "info", Config: Config{URL: "ftp://example.com"}},
		{Kind: KindWebhook, Name: "x", MinSeverity: "info", Config: Config{URL: "https://user:pw@example.com/"}},
		{Kind: KindWebhook, Name: "x", MinSeverity: "info", Config: Config{URL: "https://example.com/", Secret: "short"}},
		{Kind: "sms", Name: "x", MinSeverity: "info"},
	}
	for i, n := range bad {
		if _, err := n.Validate(false); err == nil {
			t.Errorf("case %d accepted: %+v", i, n)
		}
	}
	ok := NewChannel{Kind: KindEmail, Name: " Ops  mail ", MinSeverity: "warning", Config: Config{Host: "SMTP.example.com", Security: SMTPTLS, From: "a@b.co", To: []string{"d@e.co"}}}
	target, err := ok.Validate(false)
	if err != nil || target != "d@e.co" || ok.Config.Port != 465 || ok.Config.Host != "smtp.example.com" || ok.Name != "Ops mail" {
		t.Fatalf("valid e-mail: %q %v %+v", target, err, ok)
	}
}

func TestSecurityAlertsFromAuditLog(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "critical")
	e.svc.Observe(e.al)
	ctx := context.Background()
	if _, err := e.st.DB.Exec(`INSERT INTO users (id, email, password_hash, role, created_at, updated_at) VALUES ('usr_1', 'junior@example.com', 'x', 'owner', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	rec := func(en audit.Entry) {
		t.Helper()
		if err := e.al.Record(ctx, en); err != nil {
			t.Fatal(err)
		}
	}
	rec(audit.Entry{ActorID: "usr_1", IP: "189.10.20.30", Action: "auth.login.ok", Outcome: audit.OK})
	rec(audit.Entry{ActorID: "usr_1", IP: "189.10.20.30", Action: "auth.login.ok", Outcome: audit.OK}) // known now
	rec(audit.Entry{ActorID: "usr_1", IP: "45.1.2.3", Action: "auth.account.locked", Outcome: audit.Denied})
	rec(audit.Entry{ActorID: "usr_1", Action: "auth.totp.disable", Outcome: audit.OK})
	rec(audit.Entry{ActorID: "usr_1", Action: "secret.reveal", Outcome: audit.OK, TargetID: "svc_1", Summary: map[string]any{"key": "SECRET_KEY"}})
	rec(audit.Entry{ActorID: "usr_1", Action: "secret.reveal", Outcome: audit.Denied, Summary: map[string]any{"reason": "sudo_required"}})
	rec(audit.Entry{ActorID: "usr_1", Action: "service.deploy", Outcome: audit.OK}) // not a security event
	rec(audit.Entry{Action: "system.update.rolled_back", Outcome: audit.Error, TargetID: "v0.8.0", Summary: map[string]any{"from": "v0.7.0", "to": "v0.8.0"}})

	msgs := e.tg.messages()
	want := []string{"189.10.20.30", "45.1.2.3", "junior@example.com", "SECRET_KEY", "v0.8.0"}
	if len(msgs) != len(want) {
		for _, m := range msgs {
			t.Log(m.Text)
		}
		t.Fatalf("got %d messages, want %d", len(msgs), len(want))
	}
	for i, w := range want {
		if !strings.Contains(msgs[i].Text, w) {
			t.Errorf("message %d %q should mention %q", i, msgs[i].Text, w)
		}
	}
}

// fakeStates is the list of watched services the monitor reads.
type fakeStates struct {
	mu   sync.Mutex
	list []ServiceState
	err  error
}

func (f *fakeStates) set(list ...ServiceState) { f.mu.Lock(); f.list = list; f.mu.Unlock() }
func (f *fakeStates) get(context.Context) ([]ServiceState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ServiceState(nil), f.list...), f.err
}

func TestMonitorContainerDownWithinAMinute(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "warning")
	ctx := context.Background()
	fs := &fakeStates{}
	up := ServiceState{ID: "svc_1", Name: "lab_web", Exists: true, Running: true, State: "running"}
	fs.set(up)
	m := e.svc.NewMonitor(fs.get, nil)
	m.Check(ctx)

	down := up
	down.Running, down.State = false, "exited"
	fs.set(down)
	elapsed := time.Duration(0)
	for elapsed < time.Minute && len(e.tg.messages()) == 0 {
		e.clock.add(10 * time.Second)
		elapsed += 10 * time.Second
		m.Check(ctx)
	}
	msgs := e.tg.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0].Text, "lab_web") {
		t.Fatalf("after %s: %+v", elapsed, msgs)
	}
	if elapsed < 30*time.Second {
		t.Fatalf("fired after %s, before the 30 s grace", elapsed)
	}

	// A Docker error neither repeats nor resolves.
	fs.mu.Lock()
	fs.err = context.DeadlineExceeded
	fs.mu.Unlock()
	e.clock.add(10 * time.Second)
	m.Check(ctx)
	if len(e.tg.messages()) != 1 {
		t.Fatal("docker error changed the alert state")
	}
	fs.mu.Lock()
	fs.err = nil
	fs.mu.Unlock()

	fs.set(up)
	e.clock.add(10 * time.Second)
	m.Check(ctx)
	msgs = e.tg.messages()
	if len(msgs) != 2 || !strings.HasPrefix(msgs[1].Text, "🟢") {
		t.Fatalf("resolution: %+v", msgs)
	}
}

func TestMonitorRestartLoopAndHostRules(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "info")
	ctx := context.Background()
	fs := &fakeStates{}
	snap := metrics.Snapshot{}
	var smu sync.Mutex
	m := e.svc.NewMonitor(fs.get, func() metrics.Snapshot { smu.Lock(); defer smu.Unlock(); return snap })

	for i := range 6 {
		fs.set(ServiceState{ID: "svc_1", Name: "lab_worker", Exists: true, Running: true, State: "running", RestartCount: i})
		smu.Lock()
		snap = metrics.Snapshot{At: e.clock.now(), Host: metrics.Point{DiskUsed: 90, DiskTotal: 100, Mem: 10, MemLimit: 100}}
		smu.Unlock()
		m.Check(ctx)
		e.clock.add(30 * time.Second)
	}
	m.Check(ctx)
	var kinds []string
	for _, a := range must(e.svc.Recent(ctx, true, 10)) {
		kinds = append(kinds, a.Kind)
	}
	got := strings.Join(kinds, ",")
	if !strings.Contains(got, "restart_loop") || !strings.Contains(got, "host_disk") || strings.Contains(got, "host_memory") {
		t.Fatalf("alerts = %s", got)
	}

	// Turning a rule off forgets it without a "resolved" notice.
	if err := e.svc.SaveRules(ctx, Actor{}, []RuleInput{{Kind: "host_disk", Enabled: false, Value: 85}}); err != nil {
		t.Fatal(err)
	}
	before := len(e.tg.messages())
	m.Check(ctx)
	if len(e.tg.messages()) != before {
		t.Fatal("disabling a rule sent a message")
	}
	if err := e.svc.SaveRules(ctx, Actor{}, []RuleInput{{Kind: "host_disk", Enabled: true, Value: 10}}); err == nil {
		t.Fatal("threshold out of range accepted")
	}
}

// Every alert kind needs its title and text in every language; the i18n
// test only sees the prefixes.
func TestEveryKindHasTexts(t *testing.T) {
	kinds := append(append([]string{"test"}, SecurityKinds...), EventKinds...)
	for _, r := range Rules {
		kinds = append(kinds, r.Kind)
	}
	for _, loc := range i18n.Locales() {
		keys := i18n.Keys(loc)
		for _, k := range kinds {
			for _, key := range []string{"alert.title." + k, "alert.text." + k} {
				if !slices.Contains(keys, key) {
					t.Errorf("%s: missing %s", loc, key)
				}
			}
		}
		for _, a := range SensitiveActions {
			if key := "alert.action." + strings.ReplaceAll(a, ".", "_"); !slices.Contains(keys, key) {
				t.Errorf("%s: missing %s", loc, key)
			}
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// The e-mail host is free text: like webhooks, it may not point the panel
// at its own machine, the private network or the cloud metadata service.
func TestEmailRefusesInternalAddresses(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254"} {
		e := &email{cfg: Config{Host: host, Port: 25, Security: SMTPStartTLS}}
		err := e.send(context.Background(), Message{Title: "x"})
		if err == nil || !strings.Contains(err.Error(), "not public") {
			t.Errorf("%s: %v", host, err)
		}
	}
}
