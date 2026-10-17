package app

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/config"
)

// serverIP is the address the sidebar shows to copy: the first of
// edge.public_ips when set, else the address the machine goes out to the
// internet from, else the first public IPv4 of its interfaces, else its
// first private one (a test VM behind NAT). Nothing is sent anywhere.
func serverIP(ctx context.Context, cfg config.Config) string {
	if len(cfg.Edge.PublicIPs) > 0 {
		return cfg.Edge.PublicIPs[0]
	}
	if ip := outboundIP(ctx); ip != "" {
		return ip
	}
	return interfaceIP()
}

// autoLinkIP is the public address used to build a service's automatic
// sslip.io link: the first configured edge.public_ips that is globally
// reachable. A private, CGNAT or link-local address can never get a public
// certificate, so it is not offered as a link (the UI then says there is
// none). "" when there is no usable public IP. It must match what the edge
// uses, or the panel would show a link the proxy never serves.
func autoLinkIP(cfg config.Config) string {
	for _, s := range cfg.Edge.PublicIPs {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !isCGNAT(ip) {
			return ip.String()
		}
	}
	return ""
}

// outboundIP asks the kernel which local address a packet to the internet
// would leave from. A UDP "connection" only picks the route: no packet goes
// out. It works where listing interfaces is blocked (systemd's
// RestrictAddressFamilies without AF_NETLINK).
func outboundIP(ctx context.Context) string {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", "192.0.2.1:9") // TEST-NET-1, never contacted
	if err != nil {
		return ""
	}
	defer func() { _ = c.Close() }()
	a, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || a.IP == nil || a.IP.IsLoopback() {
		return ""
	}
	return a.IP.String()
}

func interfaceIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	private := ""
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || dockerIface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap()
			if !ip.Is4() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			if !ip.IsPrivate() && !isCGNAT(ip) {
				return ip.String()
			}
			if private == "" {
				private = ip.String()
			}
		}
	}
	return private
}

func dockerIface(name string) bool {
	return name == "docker0" || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "veth")
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isCGNAT(ip netip.Addr) bool { return cgnat.Contains(ip) }
