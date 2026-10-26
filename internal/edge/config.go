package edge

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Route sends a set of hostnames to an upstream ("container:port").
type Route struct {
	Hosts    []string
	Upstream string
	// Key names the service for its state files (its container name): a
	// "<Key>.deploying" file in StateDir makes errors show the updating page.
	Key string
	// Maintenance answers every host with the maintenance page instead of
	// proxying; the service keeps running behind it.
	Maintenance bool
	// Compress encodes the responses (zstd or gzip, as the browser asks).
	// Only the panel uses it: a canvas page is ~165 KB of HTML and ~20 KB
	// compressed; the sites keep whatever their apps do.
	Compress bool
	// OwnCert keeps the hosts on a per-host HTTP-01 certificate even when the
	// DNS-01 wildcard of the base domain would cover them. The panel uses
	// it: a bad or revoked DNS token must never stop its certificate from
	// renewing, or nobody could reach the panel to fix the token.
	OwnCert bool
}

// Where the panel puts the error pages and the deploy markers, as Caddy
// sees them (AdminDir is mounted at /run/caddy).
const (
	PagesDir = "/run/caddy/pages"
	StateDir = "/run/caddy/state"
	// CertsDir is Caddy's own certificate storage (XDG_DATA_HOME=/data,
	// see docker.EnsureEdge): certificates/<issuer>/<host>/<host>.crt.
	CertsDir = "/data/caddy/certificates"
)

// certFile matches the certificate of the requested host, whatever the
// issuer (Let's Encrypt, Pebble in tests). Caddy escapes glob characters
// in placeholders, so a visitor's Host header cannot widen the pattern.
const certFile = "/*/{http.request.host}/{http.request.host}.crt"

// ConfigInput is everything the Caddy config is generated from.
type ConfigInput struct {
	// AdminListen is the admin API address, always a unix socket.
	AdminListen string
	// AskURL is the on-demand TLS permission endpoint (the panel's ask listener).
	AskURL string
	// Email is the ACME account e-mail (expiry warnings).
	Email string
	// ACMECA overrides the ACME directory (tests use Pebble); empty = Let's Encrypt.
	ACMECA string
	// ACMECARoots are PEM files trusted for the ACME directory (Pebble).
	ACMECARoots []string
	// Fixed are the fixed domains.
	Fixed []Route
	// Dynamic, when set, receives every other hostname (certificates on demand).
	Dynamic *Route
	// Hooks, when set, publishes only HooksPath on its hostname, to the
	// panel's hooks listener (GitHub webhooks, docs/07). Everything else on
	// that hostname is 404.
	Hooks *Route
	// BaseDomain, DNSProvider and DNSToken turn on the DNS-01 wildcard
	// (docs/28): when all three are set, "*.<BaseDomain>" gets one managed
	// certificate via the DNS provider, covering every automatic link under
	// it, instead of a certificate per host.
	BaseDomain  string
	DNSProvider string
	DNSToken    string
}

// HooksPath is the only path the hooks hostname serves.
const HooksPath = "/hooks/git/*"

type obj = map[string]any

// internalPath is never served to the internet: the app's domain-check
// endpoint is for the panel only (docs/03).
const internalPath = "/.well-known/hangar/*"

// BuildConfig renders the full Caddy JSON config. The panel is the only
// source of truth: Caddy is reloaded with this document as a whole.
func BuildConfig(in ConfigInput) ([]byte, error) {
	if !strings.HasPrefix(in.AdminListen, "unix/") {
		return nil, fmt.Errorf("admin API must listen on a unix socket, got %q", in.AdminListen)
	}
	issuer := obj{"module": "acme"}
	if in.Email != "" {
		issuer["email"] = in.Email
	}
	if in.ACMECA != "" {
		issuer["ca"] = in.ACMECA
		if len(in.ACMECARoots) > 0 {
			issuer["trusted_roots_pem_files"] = in.ACMECARoots
		}
	}
	issuers := []any{issuer}
	// Certificates issued on demand (customer domains, wildcard subdomains)
	// were approved by the ask endpoint, which saw the name reach this
	// server. Behind Cloudflare's proxy the ACME challenge can fail (the
	// proxy may answer it with an HTTPS redirect); then the internal issuer
	// gives a certificate Cloudflare accepts in "Full" mode, so the site
	// still opens. Directly reached hosts get the public certificate, as
	// the challenge reaches Caddy; renewals try ACME first again.
	onDemandIssuers := []any{issuer, obj{"module": "internal"}}

	routes := []any{
		obj{
			"match":    []any{obj{"path": []string{internalPath}}},
			"handle":   []any{obj{"handler": "static_response", "status_code": 404}},
			"terminal": true,
		},
	}
	var fixedHosts []string
	dnsWildcard := in.BaseDomain != "" && in.DNSProvider != "" && in.DNSToken != ""
	var wildHosts, baseCovered []string
	if h := in.Hooks; h != nil && len(h.Hosts) > 0 {
		hosts := slices.Sorted(slices.Values(h.Hosts))
		for _, hn := range hosts {
			// A hooks host under the base domain is covered by the one DNS-01
			// wildcard too: keep it out of the per-host policy so Caddy does
			// not also obtain a certificate of its own for it.
			if dnsWildcard && coveredByBase(hn, in.BaseDomain) {
				baseCovered = append(baseCovered, hn)
			} else {
				fixedHosts = append(fixedHosts, hn)
			}
		}
		routes = append(routes,
			obj{
				"match":    []any{obj{"host": hosts, "path": []string{HooksPath}}},
				"handle":   []any{proxy(h.Upstream)},
				"terminal": true,
			},
			obj{
				"match":    []any{obj{"host": hosts}},
				"handle":   []any{obj{"handler": "static_response", "status_code": 404}},
				"terminal": true,
			})
	}
	fixed := siteRoutes(in.Fixed)
	for _, r := range fixed {
		if IsWildcard(r.Hosts[0]) {
			for _, h := range r.Hosts {
				// A custom "*.<base>" must not get its own on-demand HTTP-01
				// policy: it would match before the managed DNS-01 wildcard
				// below and push every new subdomain onto per-host issuance,
				// burning ACME rate limits. The DNS-01 policy serves its cert.
				if dnsWildcard && h == "*."+in.BaseDomain {
					continue
				}
				wildHosts = append(wildHosts, h)
			}
		} else {
			for _, h := range r.Hosts {
				// A host under the base domain is served by the one DNS-01
				// wildcard certificate: it is left out of the per-host policy
				// and skipped by automatic HTTPS, so Caddy never asks for a
				// certificate of its own (no ACME rate-limit burn).
				if dnsWildcard && !r.OwnCert && coveredByBase(h, in.BaseDomain) {
					baseCovered = append(baseCovered, h)
					continue
				}
				fixedHosts = append(fixedHosts, h)
			}
		}
		routes = append(routes, obj{
			"match":    []any{obj{"host": r.Hosts}},
			"handle":   siteHandlers(r),
			"terminal": true,
		})
	}
	if in.Dynamic != nil {
		routes = append(routes, obj{"handle": []any{siteHandler(*in.Dynamic)}, "terminal": true})
	} else {
		// An error (not a plain response) so the "unknown domain" page shows.
		routes = append(routes, obj{"handle": []any{obj{"handler": "error", "status_code": 404}}})
	}

	policies := []any{}
	if len(fixedHosts) > 0 {
		slices.Sort(fixedHosts)
		policies = append(policies, obj{"subjects": fixedHosts, "issuers": issuers})
	}
	// A wildcard certificate needs the DNS-01 challenge, which needs the
	// DNS provider's credentials; the edge only answers HTTP-01. So a
	// wildcard is served with one certificate per subdomain, issued on
	// demand the first time it is visited, after the ask endpoint approves.
	if len(wildHosts) > 0 {
		slices.Sort(wildHosts)
		policies = append(policies, obj{"subjects": wildHosts, "on_demand": true, "issuers": onDemandIssuers})
	}
	// One managed wildcard certificate for the base domain, via DNS-01. It
	// covers every automatic link under the base, so those hosts never need
	// a certificate of their own.
	if dnsWildcard {
		policies = append(policies, obj{"subjects": []string{"*." + in.BaseDomain}, "issuers": []any{dnsIssuer(in)}})
	}
	tlsApp := obj{}
	if in.Dynamic != nil || len(wildHosts) > 0 {
		if in.AskURL == "" {
			return nil, fmt.Errorf("on-demand certificates need the ask endpoint")
		}
		if in.Dynamic != nil {
			policies = append(policies, obj{"on_demand": true, "issuers": onDemandIssuers})
		}
		tlsApp["automation"] = obj{
			"policies":  policies,
			"on_demand": obj{"permission": obj{"module": "http", "endpoint": in.AskURL}},
		}
	} else if len(policies) > 0 {
		tlsApp["automation"] = obj{"policies": policies}
	}

	// The :443 server redirects HTTP by itself (the :80 server does it, with
	// the "activating HTTPS" page); automatic HTTPS only manages certificates.
	autoHTTPS := obj{"disable_redirects": true}
	if dnsWildcard {
		// Proactively obtain the one "*.<base>" certificate (via the DNS-01
		// policy above), and skip automatic HTTPS for the hosts it covers so
		// Caddy does not also obtain one per host.
		tlsApp["certificates"] = obj{"automate": []string{"*." + in.BaseDomain}}
		if len(baseCovered) > 0 {
			slices.Sort(baseCovered)
			autoHTTPS["skip"] = baseCovered
		}
	}

	cfg := obj{
		"admin": obj{
			"listen": in.AdminListen,
			// The panel re-sends the whole config on start; nothing to keep.
			"config": obj{"persist": false},
		},
		"logging": obj{"logs": obj{"default": obj{"level": "INFO", "encoder": obj{"format": "json"}}}},
		"apps": obj{
			"http": obj{
				"servers": obj{
					"edge": obj{
						"listen": []string{":443"},
						// Behind Cloudflare's proxy every request comes from
						// its edge; the visitor's address is in
						// CF-Connecting-IP. It is believed only from
						// Cloudflare's published ranges (strict), so a direct
						// visitor cannot forge it.
						"trusted_proxies":        obj{"source": "static", "ranges": CloudflareRanges()},
						"trusted_proxies_strict": 1,
						"client_ip_headers":      []string{"CF-Connecting-IP"},
						"routes":                 routes,
						"errors":                 obj{"routes": errorRoutes(fixed, in.Dynamic)},
						// The :80 server below redirects every host,
						// including customer domains Caddy cannot list.
						"automatic_https": autoHTTPS,
					},
					// HTTP-01 challenges are answered here before any
					// route runs (Caddy's server checks them ahead of the
					// routes); everything else goes to HTTPS, or waits on
					// the "activating HTTPS" page while the host has no
					// certificate yet.
					"redirect": obj{
						"listen": []string{":80"},
						"routes": redirectRoutes(exactHosts(fixed), in.BaseDomain, baseCovered),
					},
				},
			},
			"tls": tlsApp,
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// exactHosts are the exact service hostnames: Caddy obtains their
// certificates as soon as the config loads. Wildcards and customer domains
// are left out: their certificates are issued on demand, at the first HTTPS
// handshake, so making them wait on http:// would wait forever.
func exactHosts(fixed []Route) []string {
	var hosts []string
	for _, r := range fixed {
		if !IsWildcard(r.Hosts[0]) {
			hosts = append(hosts, r.Hosts...)
		}
	}
	slices.Sort(hosts)
	return hosts
}

// redirectRoutes are the :80 routes: a fixed host whose certificate is not
// in Caddy's storage yet gets the "activating HTTPS" page (it reloads
// itself, and lands on HTTPS once the certificate exists); every other
// request is redirected to HTTPS. The check reads Caddy's storage on each
// request, so no reload is needed when the certificate arrives. covered are
// the hosts served by the DNS-01 wildcard certificate.
func redirectRoutes(pending []string, baseDomain string, covered []string) []any {
	redirect := obj{"handle": []any{obj{
		"handler":     "static_response",
		"status_code": 308,
		"headers":     obj{"Location": []string{"https://{http.request.host}{http.request.uri}"}},
	}}}
	// Hosts covered by the DNS-01 wildcard wait on the wildcard certificate
	// file, not a per-host one (which never appears); the rest wait on their
	// own file.
	var exact, wild []string
	for _, h := range pending {
		if slices.Contains(covered, h) {
			wild = append(wild, h)
		} else {
			exact = append(exact, h)
		}
	}
	var routes []any
	if len(exact) > 0 {
		routes = append(routes, waitRoute(exact, certFile))
	}
	if len(wild) > 0 {
		routes = append(routes, waitRoute(wild, wildcardCertFile(baseDomain)))
	}
	return append(routes, redirect)
}

// waitRoute shows the "activating HTTPS" page while none of hosts has its
// certificate file yet; it never gets in the way of an ACME challenge.
func waitRoute(hosts []string, file string) obj {
	return obj{
		"match": []any{obj{
			"host": hosts,
			"not": []any{
				obj{"file": obj{"root": CertsDir, "try_files": []string{file}}},
				obj{"path": []string{"/.well-known/acme-challenge/*"}},
			},
		}},
		"handle":   []any{page("https", "503", "5")},
		"terminal": true,
	}
}

// coveredByBase reports whether host is one label below baseDomain
// ("loja-web.apps.x.com" under "apps.x.com"), which the "*.<base>" wildcard
// certificate covers (one level only).
func coveredByBase(host, baseDomain string) bool {
	prefix, ok := strings.CutSuffix(host, "."+baseDomain)
	return ok && prefix != "" && !strings.Contains(prefix, ".")
}

// wildcardCertFile is Caddy's storage path of the "*.<base>" certificate,
// where the leading "*" becomes "wildcard_".
func wildcardCertFile(baseDomain string) string {
	name := "wildcard_." + baseDomain
	return "/*/" + name + "/" + name + ".crt"
}

// dnsIssuer is the ACME issuer that proves the base-domain wildcard over
// DNS-01, using the operator's DNS provider credentials.
func dnsIssuer(in ConfigInput) obj {
	iss := obj{
		"module":     "acme",
		"challenges": obj{"dns": obj{"provider": obj{"name": in.DNSProvider, "api_token": in.DNSToken}}},
	}
	if in.Email != "" {
		iss["email"] = in.Email
	}
	if in.ACMECA != "" {
		iss["ca"] = in.ACMECA
		if len(in.ACMECARoots) > 0 {
			iss["trusted_roots_pem_files"] = in.ACMECARoots
		}
	}
	return iss
}

// siteRoutes splits each service's hosts into exact names and wildcards,
// sorted, exact routes first: a name listed on its own (a.loja.com.br on
// one service) wins over a wildcard covering it (*.loja.com.br on another).
func siteRoutes(in []Route) []Route {
	var exact, wild []Route
	for _, r := range in {
		var e, w []string
		for _, h := range r.Hosts {
			if IsWildcard(h) {
				w = append(w, h)
			} else {
				e = append(e, h)
			}
		}
		if len(e) > 0 {
			exact = append(exact, Route{Hosts: slices.Sorted(slices.Values(e)), Upstream: r.Upstream, Key: r.Key, Maintenance: r.Maintenance, Compress: r.Compress, OwnCert: r.OwnCert})
		}
		if len(w) > 0 {
			wild = append(wild, Route{Hosts: slices.Sorted(slices.Values(w)), Upstream: r.Upstream, Key: r.Key, Maintenance: r.Maintenance, Compress: r.Compress, OwnCert: r.OwnCert})
		}
	}
	byUpstream := func(a, b Route) int { return strings.Compare(a.Upstream, b.Upstream) }
	slices.SortFunc(exact, byUpstream)
	slices.SortFunc(wild, byUpstream)
	return append(exact, wild...)
}

// errorRoutes pick the page a visitor sees when a site cannot answer:
// unknown domain (404), too slow (504), and for each site "updating" while
// its deploy marker exists, else "down". The pages are files the panel
// renders; Caddy serves them alone, so they work with the panel down.
func errorRoutes(fixed []Route, dynamic *Route) []any {
	status := func(codes string) obj { return obj{"expression": "{http.error.status_code} in [" + codes + "]"} }
	var routes []any
	routes = append(routes,
		obj{"match": []any{status("404")}, "handle": []any{page("unknown", "404", "")}, "terminal": true},
		obj{"match": []any{status("504")}, "handle": []any{page("timeout", "504", "")}, "terminal": true},
	)
	site := func(r Route) []any {
		return []any{obj{"handler": "subroute", "routes": []any{
			obj{
				"match":    []any{obj{"file": obj{"root": StateDir, "try_files": []string{"/" + r.Key + ".deploying"}}}},
				"handle":   []any{page("deploy", "503", "6")},
				"terminal": true,
			},
			obj{"handle": []any{page("down", "502", "10")}},
		}}}
	}
	for _, r := range fixed {
		if len(r.Hosts) == 0 || r.Key == "" {
			continue
		}
		routes = append(routes, obj{"match": []any{obj{"host": slices.Sorted(slices.Values(r.Hosts))}}, "handle": site(r), "terminal": true})
	}
	if dynamic != nil && dynamic.Key != "" {
		routes = append(routes, obj{"handle": site(*dynamic), "terminal": true})
	}
	return append(routes, obj{"handle": []any{page("down", "502", "10")}})
}

// page serves one of the panel's pages with its status, through Caddy's
// templates (request id and time) with [[ ]] delimiters.
func page(kind, code, retryAfter string) obj {
	headers := obj{"Cache-Control": []string{"no-store"}}
	if retryAfter != "" {
		headers["Retry-After"] = []string{retryAfter}
	}
	return obj{"handler": "subroute", "routes": []any{obj{"handle": []any{
		obj{"handler": "rewrite", "uri": "/" + kind + ".html"},
		obj{"handler": "headers", "response": obj{"set": headers}},
		obj{"handler": "templates", "delimiters": []string{"[[", "]]"}},
		obj{"handler": "file_server", "root": PagesDir, "status_code": code},
	}}}}
}

// siteHandler proxies to the service, or serves the maintenance page while
// its maintenance mode is on (same status and retry as the other pages).
// siteHandlers is the handler chain of a site: compression first when the
// route asks for it, then the site itself.
func siteHandlers(r Route) []any {
	if r.Compress {
		return []any{
			obj{"handler": "encode", "encodings": obj{"zstd": obj{}, "gzip": obj{}}, "prefer": []string{"zstd", "gzip"}, "minimum_length": 1024},
			siteHandler(r),
		}
	}
	return []any{siteHandler(r)}
}

func siteHandler(r Route) obj {
	if r.Maintenance {
		return page("maint", "503", "30")
	}
	return proxy(r.Upstream)
}

func proxy(upstream string) obj {
	return obj{
		"handler":   "reverse_proxy",
		"upstreams": []any{obj{"dial": upstream}},
		// A site that takes longer than this to start answering gets the
		// "too slow" page (504) instead of an endless spinner.
		"transport": obj{"protocol": "http", "response_header_timeout": "100s"},
		// The app (and the panel) read the visitor from X-Forwarded-For:
		// one address, the one Caddy determined (the Cloudflare visitor or
		// the direct peer), never a chain a client could prefix.
		"headers": obj{"request": obj{"set": obj{
			"X-Forwarded-For": []string{"{http.vars.client_ip}"},
			"X-Real-Ip":       []string{"{http.vars.client_ip}"},
		}}},
		// During a zero-downtime deploy the old container stops accepting
		// connections; Caddy dials again (the name now resolves to the new
		// one) instead of answering 502. Only requests that never reached
		// the app are retried.
		"load_balancing": obj{"try_duration": "10s", "try_interval": "100ms"},
	}
}
