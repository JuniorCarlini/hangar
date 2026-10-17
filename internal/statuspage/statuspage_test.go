package statuspage

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/store"
)

type fakeMetrics struct{ snap metrics.Snapshot }

func (f fakeMetrics) Latest() metrics.Snapshot { return f.snap }
func (f fakeMetrics) History(_ context.Context, _ string, p metrics.Period) ([]metrics.Point, error) {
	return make([]metrics.Point, p.Bars), nil
}

func newService(t *testing.T) (*Service, *time.Time) {
	t.Helper()
	if err := i18n.Init(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	s := New(st.DB, fakeMetrics{snap: metrics.Snapshot{CPUs: 2, Host: metrics.Point{CPU: 37.24, Mem: 1 << 30, MemLimit: 4 << 30}}}, nil, log)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestExpiryAndValidation(t *testing.T) {
	s, now := newService(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("189.10.20.30")
	token, _, err := s.Create(ctx, Actor{}, Input{Name: "Casa", Naming: NamingHidden, Expiry: "24h"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 {
		t.Errorf("token length %d, want 43 (32 random bytes)", len(token))
	}
	l, err := s.Resolve(ctx, token, ip)
	if err != nil {
		t.Fatal(err)
	}
	if p := s.Snapshot(ctx, l, "pt-BR"); p.Server.CPUPct != 37.2 || p.Server.MemPct != 25 || len(p.Services) != 0 {
		t.Errorf("snapshot = %+v", p.Server)
	}
	*now = now.Add(25 * time.Hour)
	if _, err := s.Resolve(ctx, token, ip); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired link resolves: %v", err)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 || !list[0].Expired || list[0].AccessCount != 1 || list[0].LastIP != "189.x.x.x" {
		t.Errorf("list = %+v", list)
	}

	for _, in := range []Input{
		{Name: "", Naming: NamingHidden, Expiry: "never"},
		{Name: "x", Naming: "real", Expiry: "never"},
		{Name: "x", Naming: NamingHidden, Expiry: "1y"},
		{Name: "x", Naming: NamingHidden, Expiry: "never", CIDRs: "999.1.1.1"},
		{Name: "x", Naming: NamingGeneric, Expiry: "never", ServiceIDs: []string{"svc_unknown"}},
	} {
		if _, _, err := s.Create(ctx, Actor{}, in, map[string]bool{}); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
}

func TestHelpers(t *testing.T) {
	if err := i18n.Init(); err != nil {
		t.Fatal(err)
	}
	for i, want := range map[int]string{0: "Serviço A", 25: "Serviço Z", 26: "Serviço AA", 27: "Serviço AB"} {
		if got := GenericLabel("pt-BR", i); got != want {
			t.Errorf("GenericLabel(%d) = %q, want %q", i, got, want)
		}
	}
	if got := MaskIP(netip.MustParseAddr("2001:db8:1:2::5")); got != "2001:db8::x" {
		t.Errorf("MaskIP v6 = %q", got)
	}
	var b strings.Builder
	_ = WritePrometheus(&b, Public{Services: []PublicService{{Label: "Loja \"A\"\n", State: StateDegraded}}})
	if !strings.Contains(b.String(), `hangar_service_up{service="Loja \"A\"\n"} 1`) {
		t.Errorf("prometheus label escaping:\n%s", b.String())
	}
	pts := make([]metrics.Point, 10)
	for i := 4; i < 9; i++ {
		pts[i].At = time.Unix(int64(i), 0)
	}
	pts[6].At = time.Time{} // one bar down
	if got := uptimePct(pts); got != 80 {
		t.Errorf("uptime = %v, want 80 (4 of 5 bars since the first reading)", got)
	}
}
