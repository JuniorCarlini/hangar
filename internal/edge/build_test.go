package edge

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A public endpoint with sslip on becomes an exact route in the generated
// config, built from the server's public IP, pointing at the endpoint's own
// port. An endpoint with sslip off is left out.
func TestBuildGeneratesSslipRoutes(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	now := time.Now().Unix()
	if err := f.q.CreateEndpoint(ctx, dbq.CreateEndpointParams{
		ID: "ep_console", ServiceID: "svc_1", Name: "console", Port: 9001,
		Label: "Console", Public: 1, SslipEnabled: 1, CreatedAt: now, HostLabel: "lab-web-console",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.q.CreateEndpoint(ctx, dbq.CreateEndpointParams{
		ID: "ep_cdn", ServiceID: "svc_1", Name: "cdn", Port: 9000,
		Label: "CDN", Public: 1, SslipEnabled: 0, CreatedAt: now, HostLabel: "lab-web-cdn",
	}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(f.q, nil, nil, Options{
		PublicIPs: []netip.Addr{netip.MustParseAddr("203.0.113.10")},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cfg, err := m.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfg)
	if !strings.Contains(s, "lab-web-console.203-0-113-10.sslip.io") {
		t.Error("the public endpoint with sslip on should get its sslip route")
	}
	if !strings.Contains(s, `"dial": "lab_web:9001"`) {
		t.Error("the sslip route should point at the endpoint's own port 9001")
	}
	if strings.Contains(s, "lab-web-cdn.203-0-113-10.sslip.io") {
		t.Error("the endpoint with sslip off must not be routed")
	}
}

// With no base domain and no public IP there is no way to name a link, so
// nothing automatic is generated (and the build still succeeds).
func TestBuildWithoutIPSkipsSslip(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	now := time.Now().Unix()
	if err := f.q.CreateEndpoint(ctx, dbq.CreateEndpointParams{
		ID: "ep_1", ServiceID: "svc_1", Port: 8000, Label: "Web", Public: 1, SslipEnabled: 1, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	m := NewManager(f.q, nil, nil, Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := m.build(ctx); err != nil {
		t.Fatal(err)
	}
}
