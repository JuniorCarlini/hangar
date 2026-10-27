package edge

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// authoritativeTimeout bounds one question to one nameserver.
const authoritativeTimeout = 3 * time.Second

// freshTXT reads TXT records from the zone's own nameservers instead of the
// machine's resolver. A customer typically opens the site, sees it fail,
// and only then creates the ownership TXT: the resolver (and the cloud's,
// upstream of it) has cached that "no such name" for the zone's negative
// TTL, 30 minutes on Cloudflare, and the domain would stay refused that
// long. The nameservers answer the moment the record exists. Anything that
// goes wrong on that path (no NS, a delegated subzone, a timeout) falls back
// to the system resolver, so this never answers worse than before.
type freshTXT struct {
	// system is the fallback: the machine's resolver.
	system func(ctx context.Context, name string) ([]string, error)
	// servers lists "ip:53" addresses of the nameservers of zone.
	servers func(ctx context.Context, zone string) ([]string, error)
	// ask sends one TXT question to one server.
	ask func(ctx context.Context, server, name string) ([]string, error)
}

func newFreshTXT() *freshTXT {
	return &freshTXT{
		system:  net.DefaultResolver.LookupTXT,
		servers: zoneServers,
		ask:     askServer,
	}
}

// Lookup returns the TXT records of name. A "no such name" from a zone's
// nameserver is final; any other failure tries the next one, then the
// system resolver.
func (f *freshTXT) Lookup(ctx context.Context, name string) ([]string, error) {
	zone, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(name, "."))
	if err != nil {
		return f.system(ctx, name)
	}
	servers, err := f.servers(ctx, zone)
	if err != nil {
		return f.system(ctx, name)
	}
	for _, s := range servers {
		recs, err := f.ask(ctx, s, name)
		if err == nil || isNotFound(err) {
			return recs, err
		}
	}
	return f.system(ctx, name)
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// zoneServers resolves the addresses of the zone's nameservers, at most
// two, through the system resolver: NS records change rarely, so its cache
// does no harm. IPv4 comes first: many servers (Oracle's among them) have
// no IPv6 route, and a dead address would only waste the timeout.
func zoneServers(ctx context.Context, zone string) ([]string, error) {
	ns, err := net.DefaultResolver.LookupNS(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range ns {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", n.Host)
		if err != nil || len(ips) == 0 {
			ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", n.Host)
		}
		if err != nil || len(ips) == 0 {
			continue
		}
		out = append(out, net.JoinHostPort(ips[0].Unmap().String(), "53"))
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no reachable nameserver for " + zone)
	}
	return out, nil
}

// askServer sends the TXT question straight to server. A server that is not
// authoritative for name answers with a referral, which the resolver reports
// as an error, so the caller falls back.
func askServer(ctx context.Context, server, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, authoritativeTimeout)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
	// The trailing dot makes the name absolute: no search domains.
	return r.LookupTXT(ctx, strings.TrimSuffix(name, ".")+".")
}
