package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.17.0.1": false, "192.168.0.10": false,
		"169.254.169.254": false, "100.64.1.1": false, "0.0.0.0": false, "::1": false,
		"fd00::1": false, "fe80::1": false, "::ffff:127.0.0.1": false, "224.0.0.1": false,
	} {
		if got := Allowed(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Allowed(%s) = %v", ip, got)
		}
	}
}

func TestCheckURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://s3.us-west-004.backblazeb2.com": true,
		"http://s3.amazonaws.com":                false,
		"https://169.254.169.254/latest":         false,
		"https://user:pw@example.com":            false,
		"ftp://example.com":                      false,
		"https://":                               false,
	} {
		if _, err := CheckURL(raw, false); (err == nil) != ok {
			t.Errorf("CheckURL(%q) err = %v", raw, err)
		}
	}
	if _, err := CheckURL("http://127.0.0.1:9000", true); err != nil {
		t.Errorf("lab mode should accept a local MinIO: %v", err)
	}
}

// The check happens on the dialed address: a server on loopback is refused
// even when reached by name.
func TestClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	blocked, err := Client(false, time.Second).Do(req)
	if err == nil {
		_ = blocked.Body.Close()
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback must be blocked: %v", err)
	}
	resp, err := Client(true, time.Second).Do(req)
	if err != nil {
		t.Fatalf("lab mode: %v", err)
	}
	_ = resp.Body.Close()
}
