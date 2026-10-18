package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hangar.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsAndRelativeDataDir(t *testing.T) {
	path := writeConfig(t, `data_dir = ".data"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(filepath.Dir(path), ".data"); cfg.DataDir != want {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, want)
	}
	if len(cfg.Panel.Listen) != 1 || cfg.Panel.Listen[0] != "127.0.0.1:7700" {
		t.Errorf("unexpected default Listen: %v", cfg.Panel.Listen)
	}
}

func TestScanAndStatusValidation(t *testing.T) {
	cfg := Default()
	if !cfg.Scan.Enabled || cfg.Scan.Hour != 6 || cfg.Scan.OSVAPI != "https://api.osv.dev" {
		t.Errorf("scan defaults = %+v", cfg.Scan)
	}
	for name, mutate := range map[string]func(*Config){
		"hour":           func(c *Config) { c.Scan.Hour = 24 },
		"plain osv":      func(c *Config) { c.Scan.OSVAPI = "http://osv.example.com" },
		"status = panel": func(c *Config) { c.Status.Hosts = []string{"localhost:7700"} },
		"status path":    func(c *Config) { c.Status.Hosts = []string{"status.example.com/x"} },
	} {
		c := Default()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := Default()
	c.Status.Hosts = []string{"status.example.com"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid status host refused: %v", err)
	}
}

func TestTelegramAPIMustBeHTTPS(t *testing.T) {
	for body, ok := range map[string]bool{
		"[alerts]\ntelegram_api = \"https://bot.example.com\"\n": true,
		"[alerts]\ntelegram_api = \"http://127.0.0.1:9\"\n":      true,
		"[alerts]\ntelegram_api = \"http://bot.example.com\"\n":  false,
		"[alerts]\ntelegram_api = \"nada\"\n":                    false,
	} {
		_, err := Load(writeConfig(t, "data_dir = \"/tmp/x\"\n"+body))
		if (err == nil) != ok {
			t.Errorf("%q: err = %v", body, err)
		}
	}
}

func TestHooksHostname(t *testing.T) {
	for body, want := range map[string]string{
		"[edge]\nhooks_hostname = \"hooks.hangar.dev\"\n":                     "config.error.edge_hooks_disabled",
		"[edge]\nenabled = true\nhooks_hostname = \"Hooks Hangar\"\n":         "config.error.edge_hooks_host",
		"[edge]\nenabled = true\nhooks_hostname = \"https://x.hangar.dev\"\n": "config.error.edge_hooks_host",
	} {
		err := loadErr(t, "data_dir = \"/tmp/x\"\n"+body)
		if !hasKey(err, want) {
			t.Errorf("%q: expected %s, got %v", body, want, err)
		}
	}
	cfg, err := Load(writeConfig(t, "data_dir = \"/tmp/x\"\n[edge]\nenabled = true\nhooks_hostname = \"hooks.hangar.dev\"\n"))
	if err != nil || cfg.Edge.HooksHostname != "hooks.hangar.dev" {
		t.Fatalf("valid hooks hostname: %v", err)
	}
}

// loadErr loads body and returns the error.
func loadErr(t *testing.T, body string) error {
	t.Helper()
	_, err := Load(writeConfig(t, body))
	return err
}

func hasKey(err error, key string) bool {
	var ie *i18n.Error
	if errors.As(err, &ie) && ie.Key == key {
		return true
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			if hasKey(e, key) {
				return true
			}
		}
	}
	return false
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, "data_dir = \"/tmp/x\"\n[panel]\nlsten = [\"127.0.0.1:7700\"]\n")

	_, err := Load(path)
	var ie *i18n.Error
	if !errors.As(err, &ie) || ie.Key != "config.error.unknown_field" {
		t.Fatalf("expected an unknown-field error, got %v", err)
	}
}

func TestValidateListen(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:7700", true},
		{"[::1]:7700", true},
		{"172.30.0.1:7700", true},
		{"10.0.0.5:7700", true},
		{"0.0.0.0:7700", false},
		{":7700", false},
		{"[::]:7700", false},
		{"8.8.8.8:7700", false},
		{"localhost:7700", false},
		{"127.0.0.1", false},
		{"127.0.0.1:0", false},
	}
	for _, c := range cases {
		err := validateListen(c.addr)
		if (err == nil) != c.ok {
			t.Errorf("validateListen(%q) err = %v, want ok = %v", c.addr, err, c.ok)
		}
	}
}

func TestEdgeDNS(t *testing.T) {
	cases := []struct{ body, want string }{
		{"[edge]\ndns_provider = \"cloudflare\"\nbase_domain = \"apps.x.com\"\ndns_token = \"t\"\n", "config.error.edge_dns_image"},
		{"[edge]\ndns_provider = \"cloudflare\"\nbase_domain = \"apps.x.com\"\ndns_token = \"t\"\nimage = \"caddy:2.11.7-alpine\"\n", "config.error.edge_dns_image"},
		{"[edge]\ndns_provider = \"cloudflare\"\n", "config.error.edge_dns"},
		{"[edge]\ndns_token = \"t\"\n", "config.error.edge_dns_token"},
		{"[edge]\ndns_provider = \"route53\"\nbase_domain = \"apps.x.com\"\ndns_token = \"t\"\nimage = \"hangar-caddy:2.11\"\n", "config.error.edge_dns"},
	}
	for _, c := range cases {
		err := loadErr(t, "data_dir = \"/tmp/x\"\n"+c.body)
		if !hasKey(err, c.want) {
			t.Errorf("%q: expected %s, got %v", c.body, c.want, err)
		}
	}
	cfg, err := Load(writeConfig(t, "data_dir = \"/tmp/x\"\n[edge]\ndns_provider = \"cloudflare\"\nbase_domain = \"apps.x.com\"\ndns_token = \"t\"\nimage = \"hangar-caddy:2.11\"\n"))
	if err != nil || cfg.Edge.DNSProvider != "cloudflare" {
		t.Fatalf("valid DNS-01 config should load: %v", err)
	}
}

func TestIsStockCaddyImage(t *testing.T) {
	stock := []string{
		"caddy", "caddy:2.11", "caddy:latest", "caddy:2.11.7-alpine",
		"library/caddy:2.11-alpine", "docker.io/library/caddy:2.11-alpine", "caddy@sha256:abc",
		"index.docker.io/library/caddy:2.11-alpine",
	}
	for _, s := range stock {
		if !isStockCaddyImage(s) {
			t.Errorf("%q should be the stock caddy image", s)
		}
	}
	custom := []string{"hangar-caddy:2.11", "ghcr.io/me/caddy-dns:1", "mycaddy:1", "caddyserver/caddy:2.11"}
	for _, s := range custom {
		if isStockCaddyImage(s) {
			t.Errorf("%q should not be treated as the stock caddy image", s)
		}
	}
}
