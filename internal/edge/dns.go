package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DNSSettings is the operator's wildcard-DNS configuration, read from the
// panel's database: the base domain, the provider, and the decrypted API
// token. An empty BaseDomain means none is set, and the edge falls back to the
// config file (the bootstrap values).
type DNSSettings struct {
	BaseDomain string
	Provider   string
	Token      []byte
}

// DNSSource supplies the current DNSSettings. The panel's store implements it
// and decrypts the token; the edge reads it on every rebuild, so a change made
// in the panel takes effect on the next Apply with no restart. Keeping the
// interface here lets the edge read the settings without importing the store.
type DNSSource interface {
	EdgeDNS(ctx context.Context) (DNSSettings, error)
}

// DNSProviders lists the DNS providers the edge image can answer the DNS-01
// challenge with. Adding one means compiling its caddy-dns module into the
// edge image (deploy/caddy) and listing it here; the panel's provider picker
// reads this list, so the two never drift apart.
var DNSProviders = []string{"cloudflare"}

// ErrDNSTokenRejected is returned when the provider refuses the token.
var ErrDNSTokenRejected = errors.New("the DNS provider rejected the token")

// cloudflareAPI is the provider's API base; a var so tests can point it at a
// local server. It is never built from user input.
var cloudflareAPI = "https://api.cloudflare.com/client/v4"

// dnsCheckClient talks to the provider's public API (not the Caddy admin
// socket), with a short timeout.
var dnsCheckClient = &http.Client{Timeout: 10 * time.Second}

// CheckDNSToken verifies, before the operator commits to DNS-01 for a base
// domain, that the token actually controls the zone covering it — so a wrong
// or mis-scoped token is refused in the panel instead of silently failing to
// obtain certificates later. The token is never logged or echoed.
func CheckDNSToken(ctx context.Context, provider, baseDomain string, token []byte) error {
	if len(token) == 0 {
		return ErrDNSTokenRejected
	}
	switch provider {
	case "cloudflare":
		return checkCloudflareToken(ctx, baseDomain, token)
	default:
		return fmt.Errorf("unsupported DNS provider %q", provider)
	}
}

// checkCloudflareToken lists the zones the token can reach and accepts it only
// when one of them is baseDomain or a parent of it (the Cloudflare zone of
// "loja.apps.x.com" is "x.com"). A zone-scoped "Edit zone DNS" token can both
// read its zone and edit DNS, which is exactly what DNS-01 needs.
func checkCloudflareToken(ctx context.Context, baseDomain string, token []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareAPI+"/zones?per_page=50&status=active", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/json")
	resp, err := dnsCheckClient.Do(req)
	if err != nil {
		return fmt.Errorf("reaching the DNS provider: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrDNSTokenRejected
	}
	var out struct {
		Success bool `json:"success"`
		Result  []struct {
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("reading the DNS provider response: %w", err)
	}
	if !out.Success {
		return ErrDNSTokenRejected
	}
	for _, z := range out.Result {
		if baseDomain == z.Name || strings.HasSuffix(baseDomain, "."+z.Name) {
			return nil
		}
	}
	return fmt.Errorf("the token does not control the DNS zone for %q", baseDomain)
}
