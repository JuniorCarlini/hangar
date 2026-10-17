package edge

import (
	"net/netip"
	"strings"
)

// sslipLabel formats an IPv4 for sslip.io, where the address sits in the
// hostname with dashes in place of dots, so the name resolves back to that IP
// without any DNS of our own. Only IPv4 is used (see PublicAutoIP).
func sslipLabel(ip netip.Addr) string {
	return strings.ReplaceAll(ip.String(), ".", "-")
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// PublicAutoIP returns the first IPv4 usable for a public sslip.io link: a
// global-unicast, non-private, non-CGNAT one. A private or CGNAT address can
// never get a public certificate, and IPv6 is skipped because sslip.io's IPv6
// form can end in a dash (invalid label), so only IPv4 is offered. Zero Addr
// when none. It must match what the panel shows, or Caddy would route a host
// the panel never offered.
func PublicAutoIP(ips []netip.Addr) netip.Addr {
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip) {
			return ip
		}
	}
	return netip.Addr{}
}

// AutoHost builds the automatic hostname of a public endpoint from its unique
// host label (docs/28): with a base domain, "<label>.<base>"; otherwise, with
// a public IPv4, "<label>.<ip>.sslip.io". Returns "" when the label is empty
// or there is neither a base domain nor a public IPv4 (sslip is IPv4 only).
func AutoHost(base string, ip netip.Addr, label string) string {
	if label == "" {
		return ""
	}
	switch {
	case base != "":
		return label + "." + base
	case ip.Is4():
		return label + "." + sslipLabel(ip) + ".sslip.io"
	}
	return ""
}
