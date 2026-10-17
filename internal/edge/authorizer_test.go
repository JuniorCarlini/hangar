package edge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

var checkSecret = []byte("segredo-compartilhado-com-a-app-de-teste")

// fakeApp mimics the lab Django app: it verifies the HMAC and answers 200 only
// for stores it knows.
type fakeApp struct {
	stores  map[string]bool
	down    atomic.Bool
	calls   atomic.Int32
	badSigs atomic.Int32
}

func (f *fakeApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if f.down.Load() {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	host := r.URL.Query().Get("domain")
	ts, _ := strconv.ParseInt(r.Header.Get("X-Hangar-Timestamp"), 10, 64)
	want := SignCheck(checkSecret, host, ts)
	if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-Hangar-Signature"))) || time.Since(time.Unix(ts, 0)).Abs() > time.Minute {
		f.badSigs.Add(1)
		http.Error(w, "bad signature", http.StatusForbidden)
		return
	}
	if f.stores[host] {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.NotFound(w, r)
}

type fixedResolver struct{ addr string }

func (f fixedResolver) ServiceAddress(context.Context, string, string, int) (string, error) {
	return f.addr, nil
}

type fixture struct {
	a   *Authorizer
	app *fakeApp
	q   *dbq.Queries
}

func newFixture(t *testing.T, dynamic bool) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.NewBox(bytes.Repeat([]byte{4}, 32))
	app := &fakeApp{stores: map[string]bool{"loja1.com.br": true, "www.loja2.com": true}}
	for i := range 10 {
		app.stores["loja-extra-"+strconv.Itoa(i)+".com"] = true
	}
	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)

	ctx := context.Background()
	q := st.Q
	now := time.Now().Unix()
	if err := q.CreateProject(ctx, dbq.CreateProjectParams{ID: "prj_1", Slug: "lab", Name: "Lab", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateService(ctx, dbq.CreateServiceParams{
		ID: "svc_1", ProjectID: "prj_1", Slug: "web", Image: "lab:dev",
		InternalPort: 8000, MemoryBytes: 256 << 20, NanoCpus: 1e9, PidsLimit: 128, CommandJson: "[]", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.CreateDomain(ctx, dbq.CreateDomainParams{ID: "dom_1", ServiceID: "svc_1", Hostname: "painel.hangar.dev", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if dynamic {
		sealed, _ := box.Seal(checkSecret, CheckSecretAD("svc_1"))
		if err := q.SetDynamicDomains(ctx, dbq.SetDynamicDomainsParams{
			DynamicDomains: 1, DomainCheckPath: "/.well-known/hangar/domain-check",
			DomainCheckSecretEnc: sealed, UpdatedAt: now, ID: "svc_1",
		}); err != nil {
			t.Fatal(err)
		}
	}
	a := NewAuthorizer(st.DB, box, fixedResolver{addr: strings.TrimPrefix(srv.URL, "http://")})
	return &fixture{a: a, app: app, q: q}
}

func TestNormalizeHostname(t *testing.T) {
	ok := map[string]string{"Loja1.COM.br.": "loja1.com.br", "xn--lj-ula.com": "xn--lj-ula.com", "a.b.c.example": "a.b.c.example"}
	for in, want := range ok {
		if got, valid := NormalizeHostname(in); !valid || got != want {
			t.Errorf("NormalizeHostname(%q) = %q, %v", in, got, valid)
		}
	}
	for _, bad := range []string{
		"", "localhost", "1.2.3.4", "::1", "under_score.com", "-lead.com", "trail-.com", "a..b.com",
		"loja.123", strings.Repeat("a", 64) + ".com", strings.Repeat("abc.", 70) + "com", "loja.com/x", "loja.com:443",
	} {
		if _, valid := NormalizeHostname(bad); valid {
			t.Errorf("NormalizeHostname(%q) should be invalid", bad)
		}
	}
}

func TestFixedDomainAllowedWithoutAskingApp(t *testing.T) {
	f := newFixture(t, true)
	if ok, why := f.a.Decide(context.Background(), "painel.hangar.dev"); !ok || why != ReasonFixed {
		t.Fatalf("fixed domain: %v %s", ok, why)
	}
	if f.app.calls.Load() != 0 {
		t.Error("a fixed domain must not call the app")
	}
}

func TestNoDynamicServiceDeniesEverythingElse(t *testing.T) {
	f := newFixture(t, false)
	if ok, why := f.a.Decide(context.Background(), "loja1.com.br"); ok || why != ReasonNoDynamic {
		t.Fatalf("without a dynamic service: %v %s", ok, why)
	}
}

func TestAppDecidesWithSignedRequest(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	if ok, why := f.a.Decide(ctx, "LOJA1.com.br"); !ok || why != ReasonAppAllowed {
		t.Fatalf("store known to the app: %v %s", ok, why)
	}
	if ok, why := f.a.Decide(ctx, "phishing-bank.com"); ok || why != ReasonAppDenied {
		t.Fatalf("unknown hostname: %v %s", ok, why)
	}
	if f.app.badSigs.Load() != 0 {
		t.Error("the app rejected Hangar's signature")
	}
}

func TestFailClosedAndNotCachedWhenAppIsDown(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	f.app.down.Store(true)
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); ok || why != ReasonAppError {
		t.Fatalf("app down must deny: %v %s", ok, why)
	}
	f.app.down.Store(false)
	if ok, _ := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatal("after the app recovers the next handshake must be allowed (errors are not cached)")
	}
}

func TestCacheAvoidsHammeringTheApp(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	for range 20 {
		f.a.Decide(ctx, "www.loja2.com")
		f.a.Decide(ctx, "nao-existe.com")
	}
	if c := f.app.calls.Load(); c != 2 {
		t.Errorf("app called %d times, want 2 (one per hostname, then cache)", c)
	}
}

func TestBlocklistWinsOverApp(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	if err := f.q.BlockHostname(ctx, dbq.BlockHostnameParams{Hostname: "loja1.com.br", Reason: "teste", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); ok || why != ReasonBlocked {
		t.Fatalf("blocked hostname: %v %s", ok, why)
	}
}

func TestHourlyCapOnlyForNewHostnames(t *testing.T) {
	f := newFixture(t, true)
	f.a.MaxNewPerHour = 3
	ctx := context.Background()
	if ok, _ := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatal("first store should pass")
	}
	f.a.Forget()
	allowed := 0
	for i := range 6 {
		if ok, why := f.a.Decide(ctx, "loja-extra-"+strconv.Itoa(i)+".com"); ok {
			allowed++
		} else if why != ReasonRateLimited {
			t.Errorf("unexpected reason %s", why)
		}
	}
	if allowed != 2 {
		t.Errorf("allowed %d new hostnames, want 2 (cap 3 including the first)", allowed)
	}
	f.a.Forget()
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatalf("a store approved before must not be locked out by the cap: %s", why)
	}
}

func TestDNSMustPointHere(t *testing.T) {
	f := newFixture(t, true)
	here := netip.MustParseAddr("203.0.113.10")
	f.a.PublicIPs = []netip.Addr{here}
	answers := map[string][]netip.Addr{
		"loja1.com.br":  {here},
		"www.loja2.com": {netip.MustParseAddr("198.51.100.7")},
	}
	f.a.LookupIP = func(_ context.Context, host string) ([]netip.Addr, error) { return answers[host], nil }
	ctx := context.Background()
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatalf("pointing here: %s", why)
	}
	if ok, why := f.a.Decide(ctx, "www.loja2.com"); ok || why != ReasonDNSMismatch {
		t.Fatalf("pointing elsewhere: %v %s", ok, why)
	}
}

func TestLogIsAggregated(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	for range 100 {
		f.a.Decide(ctx, "1.2.3.4")
	}
	rows, err := f.q.RecentAsks(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Count != 100 || rows[0].Reason != ReasonInvalid {
		t.Fatalf("100 attempts should be one row with count 100: %+v", rows)
	}
}

func TestAskHandlerOnlyServesCaddy(t *testing.T) {
	f := newFixture(t, true)
	caddy := netip.MustParseAddr("172.30.0.2")
	h := AskHandler(f.a, caddy, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ask := func(from, host string) int {
		req := httptest.NewRequest(http.MethodGet, AskPath+"?domain="+host, nil)
		req.RemoteAddr = from
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := ask("172.30.0.2:41000", "loja1.com.br"); c != http.StatusOK {
		t.Errorf("caddy asking for a known store: %d", c)
	}
	if c := ask("172.30.0.2:41000", "phishing.com"); c != http.StatusForbidden {
		t.Errorf("caddy asking for an unknown host: %d", c)
	}
	if c := ask("172.30.0.9:41000", "loja1.com.br"); c != http.StatusForbidden {
		t.Errorf("another container must not query the endpoint: %d", c)
	}
}

func TestRejectedSignatureIsNotADenial(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	// The app has another secret (it was not redeployed after a new one).
	sealed, _ := f.a.box.Seal([]byte("outro-segredo"), CheckSecretAD("svc_1"))
	if err := f.q.SetDynamicDomains(ctx, dbq.SetDynamicDomainsParams{
		DynamicDomains: 1, DomainCheckPath: "/.well-known/hangar/domain-check",
		DomainCheckSecretEnc: sealed, UpdatedAt: 1, ID: "svc_1",
	}); err != nil {
		t.Fatal(err)
	}
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); ok || why != ReasonAppSignature {
		t.Fatalf("bad signature: %v %s", ok, why)
	}
	sealed, _ = f.a.box.Seal(checkSecret, CheckSecretAD("svc_1"))
	_ = f.q.SetDynamicDomains(ctx, dbq.SetDynamicDomainsParams{
		DynamicDomains: 1, DomainCheckPath: "/.well-known/hangar/domain-check",
		DomainCheckSecretEnc: sealed, UpdatedAt: 2, ID: "svc_1",
	})
	if ok, why := f.a.Decide(ctx, "loja1.com.br"); !ok {
		t.Fatalf("once the secrets match the store must pass right away (not cached as denied): %s", why)
	}
}
