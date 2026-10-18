// Package config reads and validates hangar.toml.
//
// Validation is deliberately strict: an unknown field is an error (a typo must
// not silently switch a protection off) and the panel never agrees to listen
// on a public IP.
package config

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// Config is hangard's full configuration.
type Config struct {
	// DataDir holds the database, deploy logs and backup staging.
	DataDir string `toml:"data_dir"`
	// MasterKeyFile is the key that encrypts the database secrets. It lives
	// outside data_dir so a database leak does not take the key along.
	MasterKeyFile string    `toml:"master_key_file"`
	Panel         Panel     `toml:"panel"`
	Update        Update    `toml:"update"`
	Docker        Docker    `toml:"docker"`
	Edge          Edge      `toml:"edge"`
	Auth          Auth      `toml:"auth"`
	Scan          Scan      `toml:"scan"`
	Status        Status    `toml:"status"`
	Alerts        Alerts    `toml:"alerts"`
	Backup        Backup    `toml:"backup"`
	Templates     Templates `toml:"templates"`
	// Path is the file this configuration was read from (it goes into the
	// panel backup).
	Path string `toml:"-"`
}

// Scan configures the dependency and vulnerability monitor (docs/14).
type Scan struct {
	// Enabled runs the daily scan. Off, the page still works and "scan
	// now" still scans.
	Enabled bool `toml:"enabled"`
	// Hour (0–23, server time) of the daily scan.
	Hour int `toml:"hour"`
	// OSVAPI is the OSV.dev API; only package names and versions are sent.
	OSVAPI string `toml:"osv_api"`
}

// Templates configures the service catalog (docs/08).
type Templates struct {
	// Sync fetches the signed community catalog once a day, on top of the
	// templates embedded in this binary. Off, only the embedded ones are
	// offered (and the server never calls out for them).
	Sync bool `toml:"sync"`
	// CatalogURL is the signed catalog (catalog.tar.gz; the signature is
	// the same URL with .sig).
	CatalogURL string `toml:"catalog_url"`
}

// Status configures the public status links (docs/15).
type Status struct {
	// Hosts are extra hostnames (status.example.com) that only reach the
	// public status pages, never the panel. Caddy must route them here.
	Hosts []string `toml:"hosts"`
}

// Alerts configures how alerts leave the server.
type Alerts struct {
	// TelegramAPI replaces https://api.telegram.org (a self-hosted Bot API
	// server, or a dead address in tests). The anti-SSRF filter still
	// applies: it must be a public address.
	TelegramAPI string `toml:"telegram_api"`
	// AllowedPorts are host ports that may listen to the internet besides
	// the panel's own (80/443 with the edge, ports opened in the panel):
	// SSH, by default. Any other raises a security alert (docs/17, hole 33).
	AllowedPorts []int `toml:"allowed_ports"`
}

// Backup configures backups (docs/09). Destinations and keys are set in
// the panel; only what must not be changed from the web lives here.
type Backup struct {
	// AllowPrivateEndpoints accepts an S3 endpoint on a private or loopback
	// address (a MinIO in the lab). Off in production: the anti-SSRF filter
	// (docs/17) refuses internal addresses.
	AllowPrivateEndpoints bool `toml:"allow_private_endpoints"`
}

// Auth configures login.
type Auth struct {
	// Require2FA refuses login to accounts without 2FA. Off, 2FA is optional
	// per account (like Easypanel) and accounts without it see a banner
	// asking to turn it on. Turn it on in production.
	Require2FA bool `toml:"require_2fa"`
}

// DefaultEdgeImage is the stock Caddy image. It cannot do DNS-01: using a
// DNS provider needs a custom image (deploy/caddy/Dockerfile).
const DefaultEdgeImage = "caddy:2.11-alpine"

// isStockCaddyImage reports whether image is the official Caddy image, under
// any tag or registry prefix ("caddy", "caddy:2.11", "library/caddy:latest",
// "docker.io/library/caddy@sha256:…"). None of them ship a DNS provider
// module, so DNS-01 needs a custom image instead.
func isStockCaddyImage(image string) bool {
	s := strings.TrimPrefix(image, "index.docker.io/")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "docker.io/"), "library/")
	return s == "caddy" || strings.HasPrefix(s, "caddy:") || strings.HasPrefix(s, "caddy@")
}

// Edge configures the Caddy edge proxy: public HTTPS for services with
// domains, including customer domains with on-demand certificates (docs/03).
type Edge struct {
	// Enabled starts Caddy on ports 80 and 443. Off by default so the panel
	// never takes those ports from another proxy without being asked.
	Enabled bool `toml:"enabled"`
	// Subnet of the hangar_edge network. The first address is the host
	// (where the TLS ask endpoint listens), the second is Caddy.
	Subnet string `toml:"subnet"`
	Image  string `toml:"image"`
	// ACMEEmail receives expiry warnings from the certificate authority.
	ACMEEmail string `toml:"acme_email"`
	// ACMECA overrides the ACME directory (staging, or Pebble in tests);
	// empty = Let's Encrypt production.
	ACMECA string `toml:"acme_ca"`
	// ACMECARoot is a PEM file that signs the ACMECA's HTTPS (Pebble only).
	ACMECARoot string `toml:"acme_ca_root"`
	// PublicIPs, when set, makes a customer domain need DNS pointing here
	// before a certificate is requested. The first one is also used to build
	// the automatic sslip.io link of a public endpoint (docs/28).
	PublicIPs []string `toml:"public_ips"`
	// BaseDomain, when set, is the operator's own domain for automatic links
	// ("<project>-<service>.<base_domain>") instead of sslip.io. A wildcard
	// "*.<base_domain>" must point here (docs/28).
	BaseDomain string `toml:"base_domain"`
	// DNSProvider and DNSToken, with BaseDomain, turn on the DNS-01 wildcard
	// certificate "*.<base_domain>" (docs/28): one certificate for every
	// automatic link, so a busy sign-up flow never hits the per-domain ACME
	// limit. Needs a Caddy image built with the provider's caddy-dns module.
	// Empty = per-host HTTP-01 (fine until ~50 new subdomains a week).
	DNSProvider string `toml:"dns_provider"`
	DNSToken    string `toml:"dns_token"`
	// MaxNewCertsPerHour caps new customer domains approved per hour.
	MaxNewCertsPerHour int `toml:"max_new_certs_per_hour"`
	// HooksHostname is a public domain (pointing to this server) where
	// Caddy serves only /hooks/git/* to the panel, so GitHub can deliver
	// webhooks while the panel itself stays private (docs/07). Empty = off.
	HooksHostname string `toml:"hooks_hostname"`
}

// EdgeAddrs returns the edge subnet, the host (gateway) address and Caddy's
// address. Only valid after Validate.
func (e Edge) EdgeAddrs() (netip.Prefix, netip.Addr, netip.Addr) {
	p := netip.MustParsePrefix(e.Subnet).Masked()
	gw := p.Addr().Next()
	return p, gw, gw.Next()
}

// Docker says how to reach the Docker Engine.
type Docker struct {
	// An empty Host uses DOCKER_HOST or the default socket (/var/run/docker.sock).
	Host string `toml:"host"`
}

// Update configures one-click panel updates (docs/21).
type Update struct {
	Repo    string `toml:"repo"`
	APIBase string `toml:"api_base"`
	// TokenFile holds a read-only GitHub token, needed while the repository
	// is private. Mode 0600, outside data_dir.
	TokenFile  string `toml:"token_file"`
	BinaryPath string `toml:"binary_path"`
	Service    string `toml:"service"`
}

// Panel configures the web UI listeners.
type Panel struct {
	// Listen are the host:port addresses the panel listens on. Loopback or a
	// private IP only (e.g. the hangar-edge gateway); never 0.0.0.0.
	Listen []string `toml:"listen"`
	// Hosts are the values accepted in the Host header. Anything else gets
	// 421, which closes the door on DNS rebinding attacks.
	Hosts []string `toml:"hosts"`
	// Public also serves the panel on the internet, through Caddy with
	// HTTPS (needs the edge): at PublicHost, or by default at
	// "hangar.<ip>.sslip.io" (or "hangar.<base_domain>").
	Public bool `toml:"public"`
	// PublicHost is the panel's own public hostname (e.g.
	// "painel.example.com", DNS pointing here); empty = automatic.
	PublicHost string `toml:"public_host"`
}

// Default returns the configuration of a fresh install in bunker mode.
func Default() Config {
	return Config{
		DataDir:       "/var/lib/hangar",
		MasterKeyFile: "/etc/hangar/master.key",
		Panel: Panel{
			Listen: []string{"127.0.0.1:7700"},
			Hosts:  []string{"127.0.0.1:7700", "localhost:7700"},
		},
		Update: Update{
			Repo:       "JuniorCarlini/hangar",
			APIBase:    "https://api.github.com",
			BinaryPath: "/usr/local/bin/hangard",
			Service:    "hangard",
		},
		Scan: Scan{Enabled: true, Hour: 6, OSVAPI: "https://api.osv.dev"},
		Templates: Templates{
			Sync:       true,
			CatalogURL: "https://github.com/JuniorCarlini/hangar-templates/releases/latest/download/catalog.tar.gz",
		},
		Alerts: Alerts{AllowedPorts: []int{22}},
		Edge: Edge{
			Subnet:             "172.30.0.0/24",
			Image:              DefaultEdgeImage,
			MaxNewCertsPerHour: 30,
		},
	}
}

// Load reads the file at path over the defaults and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()

	raw, err := os.ReadFile(path) //nolint:gosec // the path comes from the operator, on the command line
	if err != nil {
		return Config{}, i18n.E("config.error.read", "error", err)
	}

	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return Config{}, i18n.E("config.error.unknown_field", "file", path, "detail", strict.String())
		}
		return Config{}, i18n.E("config.error.parse", "file", path, "error", err)
	}

	// Relative paths are resolved from the config file, so the result does
	// not depend on the directory the binary runs from.
	cfg.Path, _ = filepath.Abs(path)
	cfg.DataDir = resolve(path, cfg.DataDir)
	cfg.MasterKeyFile = resolve(path, cfg.MasterKeyFile)
	if cfg.Update.TokenFile != "" {
		cfg.Update.TokenFile = resolve(path, cfg.Update.TokenFile)
	}
	if cfg.Edge.ACMECARoot != "" {
		cfg.Edge.ACMECARoot = resolve(path, cfg.Edge.ACMECARoot)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func resolve(configPath, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(filepath.Dir(configPath), p)
}

// Validate checks the rules the configuration must follow.
func (c Config) Validate() error {
	var errs []error

	if c.DataDir == "" {
		errs = append(errs, i18n.E("config.error.required", "field", "data_dir"))
	}
	if c.MasterKeyFile == "" || c.MasterKeyFile == "." {
		errs = append(errs, i18n.E("config.error.required", "field", "master_key_file"))
	}

	if len(c.Panel.Listen) == 0 {
		errs = append(errs, i18n.E("config.error.listen_empty"))
	}
	for _, addr := range c.Panel.Listen {
		if err := validateListen(addr); err != nil {
			errs = append(errs, i18n.E("config.error.listen", "addr", addr, "error", err))
		}
	}

	if c.Panel.PublicHost != "" && (!hostnameRE.MatchString(c.Panel.PublicHost) || len(c.Panel.PublicHost) > 253) {
		errs = append(errs, i18n.E("config.error.panel_public_host", "value", c.Panel.PublicHost))
	}
	if c.Panel.Public && !c.Edge.Enabled {
		errs = append(errs, i18n.E("config.error.panel_public_edge"))
	}
	if len(c.Panel.Hosts) == 0 {
		errs = append(errs, i18n.E("config.error.hosts_empty"))
	}
	for _, h := range c.Panel.Hosts {
		if h == "" {
			errs = append(errs, i18n.E("config.error.host_blank"))
		}
	}

	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(c.Update.Repo) {
		errs = append(errs, i18n.E("config.error.repo", "value", c.Update.Repo))
	}
	if u, err := url.Parse(c.Update.APIBase); err != nil || (u.Scheme != "https" && !isLocalHTTP(u)) {
		errs = append(errs, i18n.E("config.error.api_base", "value", c.Update.APIBase))
	}
	if !filepath.IsAbs(c.Update.BinaryPath) {
		errs = append(errs, i18n.E("config.error.binary_path"))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`).MatchString(c.Update.Service) {
		errs = append(errs, i18n.E("config.error.service", "value", c.Update.Service))
	}

	errs = append(errs, c.Edge.validate()...)
	if c.Alerts.TelegramAPI != "" {
		if u, err := url.Parse(c.Alerts.TelegramAPI); err != nil || u.Host == "" || (u.Scheme != "https" && !isLocalHTTP(u)) {
			errs = append(errs, i18n.E("config.error.telegram_api", "value", c.Alerts.TelegramAPI))
		}
	}

	for _, p := range c.Alerts.AllowedPorts {
		if p < 1 || p > 65535 {
			errs = append(errs, i18n.E("config.error.allowed_port", "value", p))
		}
	}

	if c.Scan.Hour < 0 || c.Scan.Hour > 23 {
		errs = append(errs, i18n.E("config.error.scan_hour", "value", c.Scan.Hour))
	}
	if u, err := url.Parse(c.Scan.OSVAPI); err != nil || (u.Scheme != "https" && !isLocalHTTP(u)) {
		errs = append(errs, i18n.E("config.error.osv_api", "value", c.Scan.OSVAPI))
	}
	if u, err := url.Parse(c.Templates.CatalogURL); err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, i18n.E("config.error.catalog_url", "value", c.Templates.CatalogURL))
	}
	for _, h := range c.Status.Hosts {
		if h == "" || strings.ContainsAny(h, "/ ") {
			errs = append(errs, i18n.E("config.error.status_host", "value", h))
		}
		for _, ph := range c.Panel.Hosts {
			if strings.EqualFold(h, ph) {
				errs = append(errs, i18n.E("config.error.status_host", "value", h))
			}
		}
	}

	return errors.Join(errs...)
}

// hostnameRE is a lowercase DNS name with at least one dot.
var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (e Edge) validate() []error {
	var errs []error
	p, err := netip.ParsePrefix(e.Subnet)
	if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() > 29 {
		errs = append(errs, i18n.E("config.error.edge_subnet", "value", e.Subnet))
	}
	if !regexp.MustCompile(`^[a-z0-9]+([._/:@-][a-z0-9]+)*$`).MatchString(e.Image) {
		errs = append(errs, i18n.E("config.error.edge_image", "value", e.Image))
	}
	if e.ACMECA != "" {
		if u, err := url.Parse(e.ACMECA); err != nil || u.Scheme != "https" {
			errs = append(errs, i18n.E("config.error.edge_acme_ca", "value", e.ACMECA))
		}
	}
	if e.ACMECARoot != "" && e.ACMECA == "" {
		errs = append(errs, i18n.E("config.error.edge_acme_root"))
	}
	for _, ip := range e.PublicIPs {
		if a, err := netip.ParseAddr(ip); err != nil || !a.IsGlobalUnicast() {
			errs = append(errs, i18n.E("config.error.edge_public_ip", "value", ip))
		}
	}
	if e.MaxNewCertsPerHour < 1 || e.MaxNewCertsPerHour > 1000 {
		errs = append(errs, i18n.E("config.error.edge_rate", "value", e.MaxNewCertsPerHour))
	}
	if e.HooksHostname != "" {
		if !hostnameRE.MatchString(e.HooksHostname) || len(e.HooksHostname) > 253 {
			errs = append(errs, i18n.E("config.error.edge_hooks_host", "value", e.HooksHostname))
		} else if !e.Enabled {
			errs = append(errs, i18n.E("config.error.edge_hooks_disabled"))
		}
	}
	if e.BaseDomain != "" && (!hostnameRE.MatchString(e.BaseDomain) || len(e.BaseDomain) > 253) {
		errs = append(errs, i18n.E("config.error.edge_base_domain", "value", e.BaseDomain))
	}
	// DNS-01 needs a supported provider plus the base domain and its token.
	if e.DNSProvider != "" && (e.DNSProvider != "cloudflare" || e.BaseDomain == "" || e.DNSToken == "") {
		errs = append(errs, i18n.E("config.error.edge_dns", "value", e.DNSProvider))
	}
	// DNS-01 needs a Caddy image built with the provider's module; the stock
	// image rejects the config and takes the edge down. Refuse to boot with
	// the default image when a provider is set (build deploy/caddy).
	if e.DNSProvider != "" && isStockCaddyImage(e.Image) {
		errs = append(errs, i18n.E("config.error.edge_dns_image", "image", e.Image))
	}
	// A token with no provider does nothing; say so instead of ignoring it.
	if e.DNSToken != "" && e.DNSProvider == "" {
		errs = append(errs, i18n.E("config.error.edge_dns_token"))
	}
	return errs
}

// isLocalHTTP allows http only for a test release server on this machine or
// a private network; releases are signed either way.
func isLocalHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && (ip.IsLoopback() || ip.IsPrivate())
}

func validateListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if port == "" || port == "0" {
		return i18n.E("config.error.listen_port")
	}
	if host == "" {
		return i18n.E("config.error.listen_all")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return i18n.E("config.error.listen_name")
	}
	if !ip.IsLoopback() && !ip.IsPrivate() {
		return i18n.E("config.error.listen_public")
	}
	return nil
}
