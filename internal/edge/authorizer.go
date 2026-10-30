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
	ReasonTXTMissing   = "txt_missing"
	ReasonInternalFail = "internal_error"
)

const (
	cacheAllowTTL = time.Hour
	cacheDenyTTL  = 5 * time.Minute
	appTimeout    = 2 * time.Second
	// maxAskRows caps tls_ask_log; above it, only the counters of rows that
	// already exist keep growing (docs/20). The cap on new certificates
	// does not read this log (it reads tls_approvals), so a full log never
	// switches it off.
	maxAskRows = 50_000
	// askRowsRecheck is how long the "log is full" answer is reused, so a
	// flood of handshakes does not run count(*) on every one.
	askRowsRecheck = 30 * time.Second
	// maxCached bounds the decision cache: random names cannot grow it
	// past this, the least recently used entry goes first.
	maxCached = 10_000
)

// InvalidHostLabel is the hostname every syntactically invalid name is
// logged under: one aggregated row per hour, so made-up SNIs cannot add
// rows to the log.
const InvalidHostLabel = ""

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
	// LookupTXT reads TXT records from the zone's nameservers, past any
	// cached "no such name" (replaceable in tests).
	LookupTXT func(ctx context.Context, name string) ([]string, error)

	cache *decisionCache

	// capMu serializes the hourly cap check with the approval it allows;
	// inflight counts new hosts that passed the cap and are still being
	// decided (the app call), so concurrent handshakes cannot all slip
	// under the same count.
	capMu    sync.Mutex
	inflight int

	rowsMu      sync.Mutex
	rowsFull    bool
	rowsChecked time.Time
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
		LookupTXT: newFreshTXT().Lookup,
		cache:     newDecisionCache(maxCached),
	}
}

// Forget drops cached decisions (after a domain or the blocklist changes).
func (a *Authorizer) Forget() { a.cache.clear() }

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
		// Never logged under the name it came with: anyone can send any
		// SNI, and one row per made-up name would fill the log.
		a.log(ctx, InvalidHostLabel, false, ReasonInvalid)
		return false, ReasonInvalid
	}
	allow, reason, cache, via := a.decide(ctx, host)
	if allow {
		// Keeps the approval fresh (renewals) for every path, fixed domains
		// and cache hits included; the capped paths already recorded it.
		_ = a.recordApproval(ctx, host)
	}
	if cache {
		ttl := cacheDenyTTL
		if allow {
			ttl = cacheAllowTTL
		}
		a.cache.put(host, cached{allow: allow, reason: reason, via: via, expires: a.now().Add(ttl)})
	}
	a.logVia(ctx, host, allow, reason, via)
	return allow, reason
}

// decide returns the decision, whether it may be cached, and how the host
// reaches this server. Transient failures (app or DNS errors, a missing TXT,
// the hourly cap) are not cached, so a fixed DNS or a recovered app answers
// on the next handshake. The cheap checks run first: the DNS before the
// ownership TXT, both before the hourly cap and the call to the app.
func (a *Authorizer) decide(ctx context.Context, host string) (bool, string, bool, Path) {
	if n, err := a.q.IsBlocked(ctx, host); err != nil {
		return false, ReasonInternalFail, false, ""
	} else if n > 0 {
		return false, ReasonBlocked, true, ""
	}

	if c, hit := a.cache.get(host, a.now()); hit {
		return c.allow, c.reason, false, c.via
	}

	if _, err := a.q.GetDomainByHostname(ctx, host); err == nil {
		return true, ReasonFixed, true, ""
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, ReasonInternalFail, false, ""
	}

	// A subdomain of a wildcard the admin added: no app to ask, but the
	// name is still made up by whoever connects, so the DNS check and the
	// hourly cap apply (random names must not burn the ACME limits).
	if w := wildcardFor(host); w != "" {
		if _, err := a.q.GetDomainByHostname(ctx, w); err == nil {
			via := a.pathOf(ctx, host)
			if via == PathElsewhere {
				return false, ReasonDNSMismatch, false, via
			}
			why, done := a.limitNew(ctx, host)
			defer done()
			if why != "" {
				return false, why, false, via
			}
			if err := a.recordApproval(ctx, host); err != nil {
				return false, ReasonInternalFail, false, via
			}
			return true, ReasonWildcard, true, via
		} else if !errors.Is(err, sql.ErrNoRows) {
			return false, ReasonInternalFail, false, ""
		}
	}

	svc, err := a.q.DynamicService(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ReasonNoDynamic, true, ""
	}
	if err != nil {
		return false, ReasonInternalFail, false, ""
	}

	via := a.pathOf(ctx, host)
	if via == PathElsewhere {
		return false, ReasonDNSMismatch, false, via
	}
	// The ownership TXT is asked of new names only: turning it on must not
	// break the renewals of customers already served.
	if svc.DomainRequireTxt == 1 {
		ok, err := a.ownsNew(ctx, svc, host)
		if err != nil {
			return false, ReasonInternalFail, false, via
		}
		if !ok {
			return false, ReasonTXTMissing, false, via
		}
	}
	why, done := a.limitNew(ctx, host)
	defer done()
	if why != "" {
		return false, why, false, via
	}

	allowed, err := a.askApp(ctx, svc, host)
	if errors.Is(err, errBadSignature) {
		return false, ReasonAppSignature, false, via
	}
	if err != nil {
		return false, ReasonAppError, false, via
	}
	if !allowed {
		return false, ReasonAppDenied, true, via
	}
	if err := a.recordApproval(ctx, host); err != nil {
		return false, ReasonInternalFail, false, via
	}
	return true, ReasonAppAllowed, true, via
}

// MaxNewSetting is the panel setting that overrides MaxNewPerHour.
const MaxNewSetting = "edge.max_new_per_hour"

// maxNew is the hourly cap: the panel's setting when there is one, else the
// configured default.
func (a *Authorizer) maxNew(ctx context.Context) int {
	if v, err := a.q.GetSetting(ctx, MaxNewSetting); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return a.MaxNewPerHour
}

// limitNew caps hostnames approved for the first time in the current hour.
// A host approved before never counts: renewals and returning visitors pass.
// The count comes from tls_approvals, which only approvals write, so no
// amount of denied or invalid handshakes can switch the cap off. A host
// that passes holds a slot until done is called; the caller records the
// approval before that, so the slot turns into a row without a gap where
// another handshake could take it.
func (a *Authorizer) limitNew(ctx context.Context, host string) (string, func()) {
	seen, err := a.q.WasApproved(ctx, host)
	if err != nil {
		return ReasonInternalFail, func() {}
	}
	if seen > 0 {
		return "", func() {}
	}
	limit := a.maxNew(ctx)
	a.capMu.Lock()
	defer a.capMu.Unlock()
	n, err := a.q.CountNewApprovalsSince(ctx, a.now().Unix()/3600)
	if err != nil {
		return ReasonInternalFail, func() {}
	}
	if int(n)+a.inflight >= limit {
		return ReasonRateLimited, func() {}
	}
	a.inflight++
	var once sync.Once
	return "", func() {
		once.Do(func() {
			a.capMu.Lock()
			a.inflight--
			a.capMu.Unlock()
		})
	}
}

// recordApproval stores that host was approved this hour: the first time
// it counts against the hourly cap, later ones keep it exempt (renewals).
func (a *Authorizer) recordApproval(ctx context.Context, host string) error {
	return a.q.RecordApproval(context.WithoutCancel(ctx), dbq.RecordApprovalParams{Hostname: host, Hour: a.now().Unix() / 3600})
}

// pathOf reports how host reaches this server: directly (it resolves to
// one of the server's public IPs), through Cloudflare (every address is a
// Cloudflare edge: the orange cloud), or not at all. When the server's
// public IPs are not known, every host counts as direct.
func (a *Authorizer) pathOf(ctx context.Context, host string) Path {
	if len(a.PublicIPs) == 0 {
		return PathDirect
	}
	ips, err := a.LookupIP(ctx, host)
	if err != nil {
		return PathElsewhere
	}
	return ClassifyPath(a.PublicIPs, ips)
}

// ClassifyPath says how a name whose addresses are resolved reaches a
// server at public: one of them is the server (direct), all of them are
// Cloudflare's edge (the orange cloud), or neither.
func ClassifyPath(public, resolved []netip.Addr) Path {
	if len(resolved) == 0 {
		return PathElsewhere
	}
	if slices.ContainsFunc(resolved, func(ip netip.Addr) bool { return slices.Contains(public, ip.Unmap()) }) {
		return PathDirect
	}
	if !slices.ContainsFunc(resolved, func(ip netip.Addr) bool { return !isCloudflare(ip) }) {
		return PathCloudflare
	}
	return PathElsewhere
}

// Path reports how host reaches this server, for the panel's checks.
func (a *Authorizer) Path(ctx context.Context, host string) Path { return a.pathOf(ctx, host) }

// OwnershipCode is the value of the _hangar.<host> TXT record that proves a
// customer controls host: derived from the service's check secret, so the
// app computes the same code without storing anything ("hg-" + 12 hex).
func OwnershipCode(secret []byte, host string) string {
	m := hmac.New(sha256.New, secret)
	fmt.Fprintf(m, "txt|%s", host)
	return "hg-" + hex.EncodeToString(m.Sum(nil))[:12]
}

// OwnershipRecord is the TXT record name the customer creates.
func OwnershipRecord(host string) string { return "_hangar." + host }

// ownsTXT reports whether _hangar.<host> holds the service's code for host.
// A lookup failure other than "no such record" is an error, not a "no".
func (a *Authorizer) ownsTXT(ctx context.Context, svc dbq.DynamicServiceRow, host string) (bool, error) {
	if len(svc.DomainCheckSecretEnc) == 0 {
		return false, errors.New("dynamic service has no check secret")
	}
	secret, err := a.box.Open(svc.DomainCheckSecretEnc, CheckSecretAD(svc.ID))
	if err != nil {
		return false, err
	}
	return a.HasTXT(ctx, host, OwnershipCode(secret, host))
}

// ownsNew is ownsTXT for a host never approved before; one approved before
// passes.
func (a *Authorizer) ownsNew(ctx context.Context, svc dbq.DynamicServiceRow, host string) (bool, error) {
	seen, err := a.q.WasApproved(ctx, host)
	if err != nil {
		return false, err
	}
	if seen > 0 {
		return true, nil
	}
	return a.ownsTXT(ctx, svc, host)
}

// HasTXT reports whether _hangar.<host> holds want.
func (a *Authorizer) HasTXT(ctx context.Context, host, want string) (bool, error) {
	recs, err := a.LookupTXT(ctx, OwnershipRecord(host))
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	for _, r := range recs {
		if strings.TrimSpace(r) == want {
			return true, nil
		}
	}
	return false, nil
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
	a.logVia(ctx, host, allow, reason, "")
}

// logVia aggregates a decision into tls_ask_log. At the row ceiling only
// rows that already exist keep counting; the log is for the operator to
// read, nothing that decides a certificate depends on it.
func (a *Authorizer) logVia(ctx context.Context, host string, allow bool, reason string, via Path) {
	ctx = context.WithoutCancel(ctx)
	decision := "deny"
	if allow {
		decision = "allow"
	}
	now := a.now().Unix()
	if a.logFull(ctx) {
		_ = a.q.BumpAsk(ctx, dbq.BumpAskParams{
			Reason: reason, LastAt: now, Via: string(via), Hostname: host, Decision: decision, Hour: now / 3600,
		})
		return
	}
	_ = a.q.LogAsk(ctx, dbq.LogAskParams{
		Hostname: host, Decision: decision, Reason: reason, Hour: now / 3600, LastAt: now, Via: string(via),
	})
}

// logFull reports whether tls_ask_log reached maxAskRows, counting at most
// once every askRowsRecheck.
func (a *Authorizer) logFull(ctx context.Context) bool {
	a.rowsMu.Lock()
	defer a.rowsMu.Unlock()
	if now := a.now(); a.rowsChecked.IsZero() || now.Sub(a.rowsChecked) >= askRowsRecheck || now.Before(a.rowsChecked) {
		n, err := a.q.CountAskRows(ctx)
		a.rowsFull = err != nil || n >= maxAskRows
		a.rowsChecked = now
	}
	return a.rowsFull
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
