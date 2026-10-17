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

// Start writes the bootstrap config, ensures the network and the Caddy
// container, and starts the ask listener. It returns once Caddy has the
// current config (bounded by ctx); the listener runs until life ends.
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
	cfg, err := m.build(ctx)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(m.opts.Spec.AdminDir, bootstrapFile), cfg); err != nil {
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
	go func() {
		<-life.Done()
		_ = srv.Close()
	}()
	// Caddy may still be starting (or already running an older config): load
	// the current one through the admin API.
	return m.waitAndLoad(ctx, cfg)
}

// Apply rebuilds the config from the database and loads it into Caddy.
func (m *Manager) Apply(ctx context.Context) error {
	cfg, err := m.build(ctx)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(m.opts.Spec.AdminDir, bootstrapFile), cfg); err != nil {
		return err
	}
	m.auth.Forget()
	return m.load(ctx, cfg)
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
	if o := m.opts; o.BaseDomain != "" && o.DNSProvider != "" && o.DNSToken != "" && coveredByBase(host, o.BaseDomain) {
		name := "wildcard_." + o.BaseDomain
		if matches, _ := filepath.Glob(filepath.Join(certs, "*", name, name+".crt")); len(matches) > 0 {
			return true
		}
	}
	return false
}

func (m *Manager) build(ctx context.Context) ([]byte, error) {
	in := ConfigInput{
		AdminListen: "unix/" + caddyRunDir + "/" + adminSocket + "|0660",
		AskURL:      "http://" + net.JoinHostPort(m.opts.Spec.Gateway.String(), strconv.Itoa(AskPort)) + AskPath,
		Email:       m.opts.Email,
		ACMECA:      m.opts.ACMECA,
		BaseDomain:  m.opts.BaseDomain,
		DNSProvider: m.opts.DNSProvider,
		DNSToken:    m.opts.DNSToken,
	}
	if m.opts.ACMECARoot != "" {
		in.ACMECARoots = []string{caddyRunDir + "/" + caRootFile}
	}
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
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := m.load(ctx, cfg)
		if err == nil || time.Now().After(deadline) {
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
		msg := redactConfigError(body, m.opts.DNSToken, 8<<10)
		return fmt.Errorf("caddy rejected the config (%d): %s", resp.StatusCode, msg)
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
