// Package edge manages the Caddy edge proxy: its configuration, its container
// and the on-demand TLS authorization endpoint (docs/03).
package edge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Decision reasons, stored in tls_ask_log and shown in the UI.
const (
	ReasonFixed        = "fixed_domain"
	ReasonWildcard     = "wildcard_domain"
	ReasonAppAllowed   = "app_authorized"
	ReasonInvalid      = "invalid_hostname"
	ReasonBlocked      = "blocked"
	ReasonNoDynamic    = "no_dynamic_service"
	ReasonRateLimited  = "rate_limited"
	ReasonAppDenied    = "app_denied"
	ReasonAppError     = "app_error"
	ReasonAppSignature = "app_bad_signature"
	ReasonDNSMismatch  = "dns_mismatch"
	ReasonInternalFail = "internal_error"
)

const (
	cacheAllowTTL = time.Hour
	cacheDenyTTL  = 5 * time.Minute
	appTimeout    = 2 * time.Second
	// maxAskRows caps tls_ask_log; above it, only the counters of rows that
	// already exist keep growing (docs/20).
	maxAskRows = 50_000
)

// AppResolver finds where to reach the dynamic-domain service: "ip:port" on a
// network the panel can reach.
type AppResolver interface {
	ServiceAddress(ctx context.Context, project, service string, port int) (string, error)
}

// Authorizer decides, for each TLS handshake with an unknown hostname,
// whether Caddy may obtain a certificate. Anything other than a clear "yes"
// is a "no" (fail closed).
type Authorizer struct {
	q        *dbq.Queries
	box      *secrets.Box
	resolver AppResolver
	http     *http.Client
	now      func() time.Time

	// MaxNewPerHour caps new hostnames approved per hour, so pointing
	// thousands of names at the server cannot burn the ACME rate limits.
	MaxNewPerHour int
	// PublicIPs, when set, requires the hostname to resolve to one of them.
	PublicIPs []netip.Addr
	// LookupIP resolves a hostname (replaceable in tests).
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	allow   bool
	reason  string
	expires time.Time
}

// NewAuthorizer creates the authorizer.
func NewAuthorizer(db *sql.DB, box *secrets.Box, resolver AppResolver) *Authorizer {
	return &Authorizer{
		q: dbq.New(db), box: box, resolver: resolver,
		http:          &http.Client{Timeout: appTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now:           time.Now,
		MaxNewPerHour: 30,
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		cache: map[string]cached{},
	}
}

// Forget drops cached decisions (after a domain or the blocklist changes).
func (a *Authorizer) Forget() {
	a.mu.Lock()
	a.cache = map[string]cached{}
	a.mu.Unlock()
}

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeHostname lowercases and validates a DNS name. It rejects IPs,
// single labels, underscores and anything that is not a plain hostname.
func NormalizeHostname(h string) (string, bool) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return "", false
		}
	}
	if !labelRE.MatchString(labels[len(labels)-1]) || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", false // all-numeric TLD
	}
	return h, true
}

// WildcardPrefix marks a domain that covers every subdomain one level below
// it ("*.loja.com.br" covers "a.loja.com.br", not "loja.com.br" itself nor
// "a.b.loja.com.br": the same rule as Caddy's host matcher and TLS).
const WildcardPrefix = "*."

// NormalizeDomain validates a domain as an admin types it: a hostname, or a
// wildcard "*.<hostname>". A wildcard over a public suffix ("*.com.br")
// would claim every site under it and is refused.
func NormalizeDomain(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSpace(h))
	rest, wild := strings.CutPrefix(h, WildcardPrefix)
	if !wild {
		return NormalizeHostname(h)
	}
	base, ok := NormalizeHostname(rest)
	if !ok || len(base)+len(WildcardPrefix) > 253 {
		return "", false
	}
	if suffix, _ := publicsuffix.PublicSuffix(base); suffix == base {
		return "", false
	}
	return WildcardPrefix + base, true
}

// IsWildcard reports whether a stored domain is a wildcard.
func IsWildcard(host string) bool { return strings.HasPrefix(host, WildcardPrefix) }

// wildcardFor is the wildcard that would cover host ("a.loja.com.br" →
// "*.loja.com.br"), or "" when host has too few labels to be covered.
func wildcardFor(host string) string {
	_, parent, ok := strings.Cut(host, ".")
	if !ok || !strings.Contains(parent, ".") {
		return ""
	}
	return WildcardPrefix + parent
}

// Decide answers whether a certificate may be issued for hostname, and why.
// Every decision is logged (aggregated per hour).
func (a *Authorizer) Decide(ctx context.Context, hostname string) (bool, string) {
	host, ok := NormalizeHostname(hostname)
	if !ok {
		a.log(ctx, truncate(strings.ToLower(hostname), 253), false, ReasonInvalid)
		return false, ReasonInvalid
	}
	allow, reason, cache := a.decide(ctx, host)
	if cache {
		ttl := cacheDenyTTL
		if allow {
			ttl = cacheAllowTTL
		}
		a.mu.Lock()
		a.cache[host] = cached{allow: allow, reason: reason, expires: a.now().Add(ttl)}
		a.mu.Unlock()
	}
	a.log(ctx, host, allow, reason)
	return allow, reason
}

// decide returns the decision and whether it may be cached. Transient
// failures (app or DNS errors) are not cached, so a recovered app answers on
// the next handshake.
func (a *Authorizer) decide(ctx context.Context, host string) (bool, string, bool) {
	if n, err := a.q.IsBlocked(ctx, host); err != nil {
		return false, ReasonInternalFail, false
	} else if n > 0 {
		return false, ReasonBlocked, true
	}

	a.mu.Lock()
	c, hit := a.cache[host]
	a.mu.Unlock()
	if hit && a.now().Before(c.expires) {
		return c.allow, c.reason, false
	}

	if _, err := a.q.GetDomainByHostname(ctx, host); err == nil {
		return true, ReasonFixed, true
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, ReasonInternalFail, false
	}

	// A subdomain of a wildcard the admin added: no app to ask, but the
	// name is still made up by whoever connects, so the hourly cap and the
	// DNS check apply (random names must not burn the ACME limits).
	if w := wildcardFor(host); w != "" {
		if _, err := a.q.GetDomainByHostname(ctx, w); err == nil {
			if why := a.limitNew(ctx, host); why != "" {
				return false, why, false
			}
			if !a.pointsHere(ctx, host) {
				return false, ReasonDNSMismatch, false
			}
			return true, ReasonWildcard, true
		} else if !errors.Is(err, sql.ErrNoRows) {
			return false, ReasonInternalFail, false
		}
	}

	svc, err := a.q.DynamicService(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ReasonNoDynamic, true
	}
	if err != nil {
		return false, ReasonInternalFail, false
	}

	if why := a.limitNew(ctx, host); why != "" {
		return false, why, false
	}

	allowed, err := a.askApp(ctx, svc, host)
	if errors.Is(err, errBadSignature) {
		return false, ReasonAppSignature, false
	}
	if err != nil {
		return false, ReasonAppError, false
	}
	if !allowed {
		return false, ReasonAppDenied, true
	}

	if !a.pointsHere(ctx, host) {
		return false, ReasonDNSMismatch, false
	}
	return true, ReasonAppAllowed, true
}

// limitNew applies the hourly cap on new hostnames: it returns the denial
// reason, or "" to go on. Only hostnames never approved before count, so a
// flood of fake names cannot lock out real stores renewing.
func (a *Authorizer) limitNew(ctx context.Context, host string) string {
	seen, err := a.q.WasAllowed(ctx, host)
	if err != nil {
		return ReasonInternalFail
	}
	if seen > 0 {
		return ""
	}
	n, err := a.q.CountNewAllowsSince(ctx, a.now().Unix()/3600)
	if err != nil {
		return ReasonInternalFail
	}
	if int(n) >= a.MaxNewPerHour {
		return ReasonRateLimited
	}
	return ""
}

// pointsHere reports whether host resolves to this server (always true when
// the server's public IPs are not known).
func (a *Authorizer) pointsHere(ctx context.Context, host string) bool {
	if len(a.PublicIPs) == 0 {
		return true
	}
	ips, err := a.LookupIP(ctx, host)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(ips, func(ip netip.Addr) bool { return slices.Contains(a.PublicIPs, ip.Unmap()) })
}

var errBadSignature = errors.New("the app rejected the domain-check signature")

// SignCheck builds the HMAC the app verifies: hex(HMAC-SHA256(secret,
// "<hostname>|<unix timestamp>")).
func SignCheck(secret []byte, hostname string, ts int64) string {
	m := hmac.New(sha256.New, secret)
	fmt.Fprintf(m, "%s|%d", hostname, ts)
	return hex.EncodeToString(m.Sum(nil))
}

// CheckSecretAD is the associated data of the encrypted HMAC secret.
func CheckSecretAD(serviceID string) string { return "services|" + serviceID + "|domain_check_secret" }

// askApp calls the app's domain-check endpoint. 200 = this hostname belongs to
// an active store; anything else = no.
func (a *Authorizer) askApp(ctx context.Context, svc dbq.DynamicServiceRow, host string) (bool, error) {
	if len(svc.DomainCheckSecretEnc) == 0 || svc.InternalPort == 0 {
		return false, errors.New("dynamic service has no check secret or port")
	}
	secret, err := a.box.Open(svc.DomainCheckSecretEnc, CheckSecretAD(svc.ID))
	if err != nil {
		return false, err
	}
	addr, err := a.resolver.ServiceAddress(ctx, svc.ProjectSlug, svc.Slug, int(svc.InternalPort))
	if err != nil {
		return false, err
	}
	ts := a.now().Unix()
	u := url.URL{Scheme: "http", Host: addr, Path: svc.DomainCheckPath, RawQuery: url.Values{"domain": {host}}.Encode()}
	ctx, cancel := context.WithTimeout(ctx, appTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Hangar-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Hangar-Signature", SignCheck(secret, host, ts))
	req.Header.Set("User-Agent", "hangard-domain-check")
	resp, err := a.http.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusForbidden:
		// The app refused the signature: the secret it has is not this one
		// (not redeployed yet?). A configuration problem, not a "no".
		return false, errBadSignature
	}
	return false, fmt.Errorf("domain check answered %d", resp.StatusCode)
}

func (a *Authorizer) log(ctx context.Context, host string, allow bool, reason string) {
	if n, err := a.q.CountAskRows(ctx); err == nil && n >= maxAskRows {
		return
	}
	decision := "deny"
	if allow {
		decision = "allow"
	}
	now := a.now().Unix()
	_ = a.q.LogAsk(context.WithoutCancel(ctx), dbq.LogAskParams{
		Hostname: host, Decision: decision, Reason: reason, Hour: now / 3600, LastAt: now,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
