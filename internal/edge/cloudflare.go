package edge

import (
	"net/netip"
	"slices"
)

// cloudflareRanges are Cloudflare's published edge addresses
// (https://www.cloudflare.com/ips-v4 and ips-v6, fetched 2026-10-26). A
// hostname proxied by Cloudflare (orange cloud) resolves to one of them, and
// every request it forwards comes from one of them. The list changes rarely;
// when it does, a missing range only makes those visitors look like
// Cloudflare and their domains wait, it never trusts a stranger.
var cloudflareRanges = mustPrefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// CloudflareRanges returns the published ranges as strings (Caddy's
// trusted_proxies list).
func CloudflareRanges() []string {
	out := make([]string, len(cloudflareRanges))
	for i, p := range cloudflareRanges {
		out[i] = p.String()
	}
	return out
}

// isCloudflare reports whether ip is one of Cloudflare's edge addresses.
func isCloudflare(ip netip.Addr) bool {
	ip = ip.Unmap()
	return slices.ContainsFunc(cloudflareRanges, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// Path says how a hostname reaches this server.
type Path string

const (
	PathDirect     Path = "direct"     // resolves to this server
	PathCloudflare Path = "cloudflare" // proxied by Cloudflare (orange cloud)
	PathElsewhere  Path = "elsewhere"  // neither: it does not reach us
)
