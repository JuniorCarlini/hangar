package edge

import (
	"net/netip"
	"testing"
)

func TestAutoHost(t *testing.T) {
	v4 := netip.MustParseAddr("203.0.113.10")
	v6 := netip.MustParseAddr("2001:db8::1")
	cases := []struct {
		base, label string
		ip          netip.Addr
		want        string
	}{
		{"", "loja-rustfs-console", v4, "loja-rustfs-console.203-0-113-10.sslip.io"},
		{"apps.exemplo.com", "loja-rustfs-console", netip.Addr{}, "loja-rustfs-console.apps.exemplo.com"},
		{"apps.exemplo.com", "loja-rustfs-cdn", v4, "loja-rustfs-cdn.apps.exemplo.com"},
		// No base and no IP, IPv6 (not used for sslip), or no label: no link.
		{"", "loja-rustfs", netip.Addr{}, ""},
		{"", "loja-rustfs", v6, ""},
		{"", "", v4, ""},
	}
	for _, c := range cases {
		if got := AutoHost(c.base, c.ip, c.label); got != c.want {
			t.Errorf("AutoHost(%q, %v, %q) = %q, want %q", c.base, c.ip, c.label, got, c.want)
		}
	}
}

func TestPublicAutoIP(t *testing.T) {
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	// Private, CGNAT and IPv6 are skipped; the first public IPv4 wins.
	got := PublicAutoIP([]netip.Addr{addr("192.168.1.10"), addr("100.64.0.5"), addr("2001:db8::1"), addr("203.0.113.9"), addr("8.8.8.8")})
	if got.String() != "203.0.113.9" {
		t.Errorf("PublicAutoIP = %v, want 203.0.113.9", got)
	}
	if ip := PublicAutoIP([]netip.Addr{addr("192.168.1.10"), addr("2001:db8::1")}); ip.IsValid() {
		t.Errorf("no public IPv4 should give no auto link, got %v", ip)
	}
	if ip := PublicAutoIP(nil); ip.IsValid() {
		t.Error("no IPs should give no auto link")
	}
}
