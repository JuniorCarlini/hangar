// Package netguard is the anti-SSRF filter (docs/17 § 4, threat 11) for
// URLs the panel calls on a user's behalf: S3 endpoints today, webhooks
// and Git later. The check runs on the address actually dialed, after DNS
// resolution, so a name that resolves to an internal IP (or changes to one
// between check and use: DNS rebinding) is refused at connect time.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrBlocked is returned for addresses inside the server or private
// networks.
var ErrBlocked = errors.New("netguard: address not allowed (private, loopback or link-local)")

// extra ranges that are not public even though netip does not flag them.
var extra = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 internals
	netip.MustParsePrefix("2001:db8::/32"),
}

// Allowed reports whether ip is a public unicast address.
func Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range extra {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// CheckURL validates a URL before use: https only (http is accepted only
// with allowPrivate, for a lab MinIO), a host, no credentials in it.
func CheckURL(raw string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("netguard: invalid URL: %w", err)
	}
	switch {
	case u.Scheme != "https" && (!allowPrivate || u.Scheme != "http"):
		return nil, errors.New("netguard: only https URLs are allowed")
	case u.Host == "" || u.User != nil || u.Opaque != "":
		return nil, errors.New("netguard: URL without a valid host")
	}
	if !allowPrivate {
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !Allowed(ip) {
			return nil, ErrBlocked
		}
	}
	return u, nil
}

// Client returns an HTTP client that refuses to connect to non-public
// addresses (unless allowPrivate) and never follows redirects.
func Client(allowPrivate bool, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !allowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !Allowed(ap.Addr()) {
				return ErrBlocked
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy: nil, // a proxy would dial on our behalf, past the check
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
