package edge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckDNSToken(t *testing.T) {
	var gotAuth string
	// A fake Cloudflare: it reports one accessible zone, "checksafe.com.br",
	// but only when the bearer token is "good".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth != "Bearer good" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":[{"name":"checksafe.com.br"}]}`))
	}))
	defer srv.Close()
	old := cloudflareAPI
	cloudflareAPI = srv.URL
	defer func() { cloudflareAPI = old }()

	ctx := context.Background()
	// The token controls the exact zone, and a subdomain used as the base is
	// covered by the parent zone.
	for _, base := range []string{"checksafe.com.br", "apps.checksafe.com.br"} {
		if err := CheckDNSToken(ctx, "cloudflare", base, []byte("good")); err != nil {
			t.Errorf("base %q with a valid token: %v", base, err)
		}
	}
	if gotAuth != "Bearer good" {
		t.Errorf("the token was not sent as a bearer: %q", gotAuth)
	}
	// A zone the token cannot see is refused, not accepted.
	if err := CheckDNSToken(ctx, "cloudflare", "outro.com", []byte("good")); err == nil {
		t.Error("a zone the token does not control must be refused")
	}
	// A rejected token (403) comes back as ErrDNSTokenRejected.
	if err := CheckDNSToken(ctx, "cloudflare", "checksafe.com.br", []byte("wrong")); !errors.Is(err, ErrDNSTokenRejected) {
		t.Errorf("a rejected token should be ErrDNSTokenRejected, got %v", err)
	}
	// Guards that never reach the network.
	if err := CheckDNSToken(ctx, "cloudflare", "checksafe.com.br", nil); !errors.Is(err, ErrDNSTokenRejected) {
		t.Errorf("an empty token should be ErrDNSTokenRejected, got %v", err)
	}
	if err := CheckDNSToken(ctx, "route53", "checksafe.com.br", []byte("good")); err == nil {
		t.Error("an unsupported provider must be refused")
	}
}
