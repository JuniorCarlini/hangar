package edge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// AskPath is the on-demand TLS permission endpoint Caddy calls.
const AskPath = "/internal/tls/ask"

// AskPort is where the ask endpoint listens, on the edge gateway address.
const AskPort = 7701

// PanelPort is where the panel listens on the edge gateway address when it
// is public: Caddy terminates HTTPS on its public hostname and proxies here.
const PanelPort = 7702

const (
	adminSocket   = "admin.sock"
	bootstrapFile = "bootstrap.json"
	caRootFile    = "acme-ca-root.pem"
	// caddyRunDir is where AdminDir is mounted inside the Caddy container.
	caddyRunDir = "/run/caddy"
)

// Options configures the Manager.
type Options struct {
	Spec       node.EdgeSpec
	Email      string
	ACMECA     string
	ACMECARoot string // host path of a PEM file, copied into AdminDir
	// HooksHost and Hooks publish GitHub webhooks: Caddy sends
	// https://HooksHost/hooks/git/* to the ask listener, which hands them
	// to Hooks. Both empty = no public webhooks.
	HooksHost string
	Hooks     http.Handler
	// PanelHost publishes the panel on the internet: Caddy serves it with
	// HTTPS at this hostname and proxies to the panel's listener on the
	// gateway (PanelPort). Empty = the panel stays private.
	PanelHost string
	// PublicIPs are the server's public addresses; the first builds the
	// automatic sslip.io link of a public endpoint (docs/28).
	PublicIPs []netip.Addr
	// BaseDomain is the operator's own domain for automatic links instead of
	// sslip.io ("" = use sslip.io).
	BaseDomain string
	// DNSProvider and DNSToken, with BaseDomain, turn on the DNS-01 wildcard
	// certificate for the base domain (docs/28); empty = per-host HTTP-01.
	DNSProvider string
	DNSToken    string
	// Pages renders the error pages (file name → HTML) written to
	// AdminDir/pages on start; nil leaves whatever is there.
	Pages func(ctx context.Context) (map[string][]byte, error)
}

// Manager keeps Caddy running with the configuration derived from the
// database. The panel is the only source of truth: every change re-sends the
// whole config.
type Manager struct {
	q    *dbq.Queries
	node node.Node
	auth *Authorizer
	opts Options
	log  *slog.Logger
	http *http.Client

	mu sync.Mutex
	// dns is the panel's DNS settings source (SetDNSSource); dnsBase and
	// dnsWild cache the last resolved base domain and whether the DNS-01
	// wildcard is on, so HasCertificate needs no database read. All under mu.
	dns     DNSSource
	dnsBase string
	dnsWild bool
	// dnsToken caches the resolved token (panel database or config file) so a
	// Caddy config-reject error can be redacted against the token actually in
	// the config, not only the config-file one.
	dnsToken string
	// degraded says why Caddy is not running the full config ("" = it is):
	// the last good one, or the minimal one, serves in the meantime. Under mu.
	degraded string

	// applyMu serializes build, load and saving the boot config, so an older
	// config never overwrites a newer one on disk.
	applyMu sync.Mutex
	// loadWait bounds how long Start waits for Caddy to answer (0 = 30s;
	// tests shorten it).
	loadWait time.Duration
}

// errRejected marks a config Caddy answered and refused, as opposed to a
// Caddy that did not answer at all.
var errRejected = errors.New("caddy rejected the config")

// SetDNSSource wires the panel's DNS settings (base domain, provider, token)
// into the edge so the operator can configure the wildcard from the panel
// instead of the config file. It is set after construction because the source
// (the projects manager) is built with the edge, not before it.
func (m *Manager) SetDNSSource(s DNSSource) {
	m.mu.Lock()
	m.dns = s
	m.mu.Unlock()
}

// resolveDNS returns the base domain, provider and token in effect: the panel's
// database when a base domain is set there, otherwise the config file (the
// bootstrap values). A source error falls back to the file rather than dropping
// TLS, and the token is never logged.
func (m *Manager) resolveDNS(ctx context.Context) (base, provider, token string) {
	base, provider, token = m.opts.BaseDomain, m.opts.DNSProvider, m.opts.DNSToken
	m.mu.Lock()
	src := m.dns
	m.mu.Unlock()
	if src == nil {
		return
	}
	s, err := src.EdgeDNS(ctx)
	if err != nil {
		m.log.Warn("read edge DNS settings; using the config file", "error", err)
		return
	}
	if s.BaseDomain != "" {
		base, provider, token = s.BaseDomain, s.Provider, string(s.Token)
	}
	return
}

// NewManager creates the manager; Start brings Caddy up.
func NewManager(q *dbq.Queries, n node.Node, auth *Authorizer, opts Options, log *slog.Logger) *Manager {
	sock := filepath.Join(opts.Spec.AdminDir, adminSocket)
	return &Manager{
		q: q, node: n, auth: auth, opts: opts, log: log,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			}},
		},
	}
}

// Start ensures the network and the Caddy container, starts the ask listener
// and loads the current config. It returns once Caddy has a config (bounded
// by ctx); the listener runs until life ends.
//
// bootstrap.json, the file Caddy boots from (the container restarts by
// itself), only ever holds a config Caddy accepted: a rejected one there would
// crash-loop Caddy on the next reboot and take every site and the panel down.
// When the full config is rejected, Start still succeeds with the last good
// config, or a minimal one that serves the panel and the error pages, and
// Degraded says why.
func (m *Manager) Start(ctx, life context.Context) error {
	for _, d := range []string{m.opts.Spec.AdminDir, m.opts.Spec.DataDir, m.pagesDir(), m.stateDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("edge dir: %w", err)
		}
	}
	// Deploy markers left by a crash would show "updating" forever.
	if entries, err := os.ReadDir(m.stateDir()); err == nil {
		for _, e := range entries {
			_ = os.Remove(filepath.Join(m.stateDir(), e.Name()))
		}
	}
	if m.opts.Pages != nil {
		pages, err := m.opts.Pages(ctx)
		if err != nil {
			return fmt.Errorf("error pages: %w", err)
		}
		if err := m.WritePages(pages); err != nil {
			return err
		}
	}
	if m.opts.ACMECARoot != "" {
		pem, err := os.ReadFile(m.opts.ACMECARoot)
		if err != nil {
			return fmt.Errorf("acme_ca_root: %w", err)
		}
		if err := writeFile(filepath.Join(m.opts.Spec.AdminDir, caRootFile), pem); err != nil {
			return err
		}
	}
	// A first start has no boot config yet: Caddy boots from the minimal one
	// and gets the full one through the admin API below.
	if err := m.ensureBootFile(); err != nil {
		return err
	}
	if err := m.node.EnsureEdge(ctx, m.opts.Spec); err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(life, "tcp",
		net.JoinHostPort(m.opts.Spec.Gateway.String(), strconv.Itoa(AskPort)))
	if err != nil {
		return fmt.Errorf("ask listener: %w", err)
	}
	srv := &http.Server{
		Handler:           listenerHandler(AskHandler(m.auth, m.opts.Spec.CaddyIP, m.log), m.opts.Hooks, m.opts.Spec.CaddyIP),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      15 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() { _ = srv.Serve(ln) }()
	stop := context.AfterFunc(life, func() { _ = srv.Close() })
	// Caddy may still be starting (or already running an older config): load
	// the current one through the admin API.
	if err := m.bringUp(ctx); err != nil {
		// Free the ask port: the caller retries Start from scratch.
		stop()
		_ = srv.Close()
		return err
	}
	return nil
}

// bringUp loads the full config, falling back to the last good one and then
// to the minimal one when Caddy rejects it. It fails only when Caddy does not
// answer or rejects even the minimal config.
func (m *Manager) bringUp(ctx context.Context) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	full, err := m.build(ctx)
	if err != nil {
		return err
	}
	err = m.waitAndLoad(ctx, full)
	if err == nil {
		m.setDegraded("")
		return m.saveBoot(full)
	}
	if !errors.Is(err, errRejected) {
		// Caddy never answered. A boot config it cannot run (one written by
		// an older Hangar before it was validated) crash-loops it: replace it
		// with the minimal one, which the next restart picks up.
		if merr := m.saveMinimalBoot(); merr != nil {
			m.log.Error("write the minimal caddy boot config", "error", merr)
		}
		return err
	}
	reason := err.Error()
	m.log.Error("caddy rejected the full config; serving the last good one", "error", err)
	if last, rerr := os.ReadFile(m.bootPath()); rerr == nil {
		lerr := m.load(ctx, last)
		if lerr == nil {
			m.setDegraded(reason)
			return nil
		}
		m.log.Error("caddy rejected the last good config; serving the minimal one", "error", lerr)
	}
	minimal, err := m.minimal()
	if err != nil {
		return err
	}
	if err := m.load(ctx, minimal); err != nil {
		return fmt.Errorf("minimal config: %w", err)
	}
	m.setDegraded(reason)
	return m.saveBoot(minimal)
}

// Apply rebuilds the config from the database and loads it into Caddy. Only
// a config Caddy accepted becomes its boot config; a rejected one leaves
// Caddy (and the boot file) on the previous one.
func (m *Manager) Apply(ctx context.Context) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	cfg, err := m.build(ctx)
	if err != nil {
		return err
	}
	m.auth.Forget()
	if err := m.load(ctx, cfg); err != nil {
		return err
	}
	m.setDegraded("")
	return m.saveBoot(cfg)
}

// Check reports whether Caddy's admin API answers, which also means its
// container is running.
func (m *Manager) Check(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://caddy/config/", nil)
	if err != nil {
		return err
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("caddy admin: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caddy admin answered %d", resp.StatusCode)
	}
	return nil
}

// Heal brings back a Caddy that stopped answering: the container is
// recreated or started as needed, then the config is loaded again.
func (m *Manager) Heal(ctx context.Context) error {
	if err := m.node.EnsureEdge(ctx, m.opts.Spec); err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}
	return m.bringUp(ctx)
}

// Degraded says why Caddy is not serving the full config, "" when it is.
func (m *Manager) Degraded() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.degraded
}

func (m *Manager) setDegraded(reason string) {
	m.mu.Lock()
	m.degraded = reason
	m.mu.Unlock()
}

func (m *Manager) bootPath() string { return filepath.Join(m.opts.Spec.AdminDir, bootstrapFile) }

// saveBoot makes cfg, which Caddy just accepted, its boot config (atomic
// replace: a crash never leaves half a file).
func (m *Manager) saveBoot(cfg []byte) error {
	if err := writeFile(m.bootPath(), cfg); err != nil {
		return fmt.Errorf("caddy boot config: %w", err)
	}
	return nil
}

// ensureBootFile writes the minimal boot config when there is none yet.
func (m *Manager) ensureBootFile() error {
	if _, err := os.Stat(m.bootPath()); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("caddy boot config: %w", err)
	}
	return m.saveMinimalBoot()
}

func (m *Manager) saveMinimalBoot() error {
	cfg, err := m.minimal()
	if err != nil {
		return err
	}
	return m.saveBoot(cfg)
}

func (m *Manager) pagesDir() string { return filepath.Join(m.opts.Spec.AdminDir, "pages") }
func (m *Manager) stateDir() string { return filepath.Join(m.opts.Spec.AdminDir, "state") }

// WritePages replaces the error pages Caddy serves (file name → HTML).
// Caddy reads them per request, so no reload is needed.
func (m *Manager) WritePages(pages map[string][]byte) error {
	for name, html := range pages {
		if name != filepath.Base(name) || !strings.HasSuffix(name, ".html") {
			return fmt.Errorf("error page name %q", name)
		}
		if err := writeFile(filepath.Join(m.pagesDir(), name), html); err != nil {
			return fmt.Errorf("error page %s: %w", name, err)
		}
	}
	return nil
}

// SetDeploying marks a service (by container name) as being deployed or
// restarted: while marked, its errors show the "updating" page instead of
// "down".
func (m *Manager) SetDeploying(container string, on bool) {
	if container == "" || container != filepath.Base(container) {
		return
	}
	p := filepath.Join(m.stateDir(), container+".deploying")
	if !on {
		_ = os.Remove(p)
		return
	}
	if err := writeFile(p, nil); err != nil {
		m.log.Warn("deploy marker", "service", container, "error", err)
	}
}

// HasCertificate reports whether Caddy's storage holds a certificate for an
// exact hostname, from any issuer: the same file the :80 server checks
// before redirecting (CertsDir, here on the host side of the mount). It
// says nothing about why one is missing; that is only in Caddy's log.
func (m *Manager) HasCertificate(host string) bool {
	if host == "" || strings.ContainsAny(host, `*?[]\/`) || strings.Contains(host, "..") {
		return false
	}
	certs := filepath.Join(m.opts.Spec.DataDir, "caddy", "certificates")
	if matches, _ := filepath.Glob(filepath.Join(certs, "*", host, host+".crt")); len(matches) > 0 {
		return true
	}
	// With DNS-01 on, a host under the base domain is served by the
	// "*.<base>" wildcard certificate (stored as wildcard_.<base>), not a
	// per-host one. Only when DNS-01 is on: otherwise an old wildcard left on
	// disk would wrongly report hosts as ready while Caddy issues per-host.
	m.mu.Lock()
	base, wild := m.dnsBase, m.dnsWild
	m.mu.Unlock()
	// The panel always has a certificate of its own (Route.OwnCert).
	if wild && host != m.opts.PanelHost && coveredByBase(host, base) {
		name := "wildcard_." + base
		if matches, _ := filepath.Glob(filepath.Join(certs, "*", name, name+".crt")); len(matches) > 0 {
			return true
		}
	}
	return false
}

// baseInput is what every config has: the admin socket, the ACME account
// and the public panel. On its own it is the minimal config, which needs
// nothing from the database or the DNS provider and so always loads.
func (m *Manager) baseInput() ConfigInput {
	in := ConfigInput{
		AdminListen: "unix/" + caddyRunDir + "/" + adminSocket + "|0660",
		AskURL:      "http://" + net.JoinHostPort(m.opts.Spec.Gateway.String(), strconv.Itoa(AskPort)) + AskPath,
		Email:       m.opts.Email,
		ACMECA:      m.opts.ACMECA,
	}
	if m.opts.ACMECARoot != "" {
		in.ACMECARoots = []string{caddyRunDir + "/" + caRootFile}
	}
	if m.opts.PanelHost != "" {
		in.Fixed = append(in.Fixed, Route{
			Hosts:    []string{m.opts.PanelHost},
			Upstream: net.JoinHostPort(m.opts.Spec.Gateway.String(), strconv.Itoa(PanelPort)),
			Key:      "hangar_panel",
			Compress: true,
			OwnCert:  true,
		})
	}
	return in
}

// minimal is the fallback config: the panel and the error pages only.
func (m *Manager) minimal() ([]byte, error) { return BuildConfig(m.baseInput()) }

func (m *Manager) build(ctx context.Context) ([]byte, error) {
	base, provider, token := m.resolveDNS(ctx)
	m.mu.Lock()
	m.dnsBase = base
	m.dnsWild = base != "" && provider != "" && token != ""
	m.dnsToken = token
	m.mu.Unlock()
	in := m.baseInput()
	in.BaseDomain, in.DNSProvider, in.DNSToken = base, provider, token
	if m.opts.HooksHost != "" && m.opts.Hooks != nil {
		in.Hooks = &Route{Hosts: []string{m.opts.HooksHost}, Upstream: net.JoinHostPort(m.opts.Spec.Gateway.String(), strconv.Itoa(AskPort))}
	}
	rows, err := m.q.ListAllDomains(ctx)
	if err != nil {
		return nil, err
	}
	byUpstream := map[string]*Route{}
	for _, r := range rows {
		port := r.InternalPort
		if r.EndpointPort.Valid {
			port = r.EndpointPort.Int64
		}
		up := Upstream(r.ProjectSlug, r.ServiceSlug, port)
		if byUpstream[up] == nil {
			byUpstream[up] = &Route{Upstream: up, Key: node.ContainerName(r.ProjectSlug, r.ServiceSlug), Maintenance: r.Maintenance == 1}
		}
		byUpstream[up].Hosts = append(byUpstream[up].Hosts, r.Hostname)
	}
	// Automatic links: every public endpoint with sslip on gets an exact
	// host (its sslip.io name, or a subdomain of the base domain) routed to
	// the endpoint's own port, served like any fixed domain. Generated only
	// when there is a base domain or a known public IP to build the name.
	autoIP := PublicAutoIP(m.opts.PublicIPs)
	if m.opts.BaseDomain != "" || autoIP.IsValid() {
		eps, err := m.q.ListPublicEndpoints(ctx)
		if err != nil {
			return nil, err
		}
		for _, e := range eps {
			if e.SslipEnabled != 1 {
				continue
			}
			host := AutoHost(m.opts.BaseDomain, autoIP, e.HostLabel)
			if host == "" {
				continue
			}
			up := Upstream(e.ProjectSlug, e.ServiceSlug, e.Port)
			if byUpstream[up] == nil {
				byUpstream[up] = &Route{Upstream: up, Key: node.ContainerName(e.ProjectSlug, e.ServiceSlug), Maintenance: e.Maintenance == 1}
			}
			byUpstream[up].Hosts = append(byUpstream[up].Hosts, host)
		}
	}
	for _, r := range byUpstream {
		in.Fixed = append(in.Fixed, *r)
	}
	svc, err := m.q.DynamicService(ctx)
	switch {
	case err == nil:
		in.Dynamic = &Route{Upstream: Upstream(svc.ProjectSlug, svc.Slug, svc.InternalPort), Key: node.ContainerName(svc.ProjectSlug, svc.Slug), Maintenance: svc.Maintenance == 1}
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	return BuildConfig(in)
}

// Upstream is how Caddy reaches a service: its container name on the edge
// network.
func Upstream(project, service string, port int64) string {
	return net.JoinHostPort(node.ContainerName(project, service), strconv.FormatInt(port, 10))
}

func (m *Manager) waitAndLoad(ctx context.Context, cfg []byte) error {
	wait := m.loadWait
	if wait == 0 {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		err := m.load(ctx, cfg)
		// A rejection will not change by asking again.
		if err == nil || errors.Is(err, errRejected) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (m *Manager) load(ctx context.Context, cfg []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://caddy/load", bytes.NewReader(cfg))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("caddy admin: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		// Redact the token that is actually in the config (panel database or
		// config file), held in m.dnsToken under the lock load() already holds,
		// not only the config-file token (empty in the normal panel setup).
		msg := redactConfigError(body, m.dnsToken, 8<<10)
		return fmt.Errorf("%w (%d): %s", errRejected, resp.StatusCode, msg)
	}
	return nil
}

// redactConfigError strips the DNS token from a Caddy error body (which can
// quote the rejected config), raw and JSON-escaped, and only then caps it —
// so a token split by the cap cannot leak a prefix.
func redactConfigError(body []byte, token string, max int) []byte {
	msg := body
	if token != "" {
		msg = bytes.ReplaceAll(msg, []byte(token), []byte("[redacted]"))
		if esc, err := json.Marshal(token); err == nil {
			msg = bytes.ReplaceAll(msg, bytes.Trim(esc, `"`), []byte("[redacted]"))
		}
	}
	if msg = bytes.TrimSpace(msg); len(msg) > max {
		msg = msg[:max]
	}
	return msg
}

// hooksPrefix is HooksPath without the wildcard.
const hooksPrefix = "/hooks/git/"

// listenerHandler serves the edge listener: GitHub webhooks Caddy forwards
// (when hooks is set) and the certificate ask endpoint. Only Caddy may
// talk to it either way.
func listenerHandler(ask, hooks http.Handler, caddy netip.Addr) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hooks != nil && strings.HasPrefix(r.URL.Path, hooksPrefix) {
			ap, err := netip.ParseAddrPort(r.RemoteAddr)
			if err != nil || ap.Addr().Unmap() != caddy {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			hooks.ServeHTTP(w, r)
			return
		}
		ask.ServeHTTP(w, r)
	})
}

// ForwardedIP is the client address Caddy reports for a request it
// forwarded (Caddy replaces any X-Forwarded-For sent by the client, since
// it trusts no proxy in front of it).
func ForwardedIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		if i := strings.LastIndex(v, ","); i >= 0 {
			v = v[i+1:]
		}
		if ip, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			return ip.String()
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// AskHandler answers Caddy's "may I get a certificate for ?domain=" with 200
// or 403. Only Caddy's address is served: another container reaching the
// gateway cannot probe which domains are authorized.
func AskHandler(a *Authorizer, caddy netip.Addr, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || ap.Addr().Unmap() != caddy {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != AskPath {
			http.NotFound(w, r)
			return
		}
		ok, reason := a.Decide(r.Context(), r.URL.Query().Get("domain"))
		if !ok {
			log.Info("certificate denied", "domain", truncate(r.URL.Query().Get("domain"), 253), "reason", reason)
			http.Error(w, reason, http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// writeFile replaces path atomically, readable only by the panel user (Caddy
// runs as the same user).
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
