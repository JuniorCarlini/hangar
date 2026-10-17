package lockdown

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store"
)

func TestLocalOnly(t *testing.T) {
	cases := []struct {
		remote, local string
		want          bool
	}{
		{"127.0.0.1:5000", "127.0.0.1:7700", true},
		{"[::1]:5000", "[::1]:7700", true},
		{"172.30.0.3:5000", "172.30.0.1:7700", false}, // through Caddy
		{"127.0.0.1:5000", "172.30.0.1:7700", false},
		{"189.10.20.30:5000", "127.0.0.1:7700", false},
		{"127.0.0.1:5000", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.local != "" {
			la, _ := net.ResolveTCPAddr("tcp", c.local)
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, la))
		}
		if got := LocalOnly(r); got != c.want {
			t.Errorf("%s → %s: %v, want %v", c.remote, c.local, got, c.want)
		}
	}
}

func TestEngageEndsEverySessionAndReleaseUnlocks(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role, created_at, updated_at) VALUES ('u1', 'a@b.c', 'x', 'owner', 0, 0), ('u2', 'd@e.f', 'x', 'viewer', 0, 0)`,
		`INSERT INTO sessions (id_hash, user_id, stage, csrf_token, created_at, last_seen_at, expires_at) VALUES (x'01', 'u1', 'active', 'c', 0, 0, 9999999999), (x'02', 'u2', 'active', 'c', 0, 0, 9999999999)`,
	} {
		if _, err := st.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	l := New(st.DB, nil)
	n, err := l.Engage(ctx, "u1", "127.0.0.1", "panel")
	if err != nil || n != 2 {
		t.Fatalf("engage: n=%d err=%v", n, err)
	}
	if !l.Locked(ctx) {
		t.Fatal("not locked")
	}
	// Another process (the CLI) releases: this one notices after the cache.
	other := New(st.DB, nil)
	if err := other.Release(ctx, "cli"); err != nil {
		t.Fatal(err)
	}
	if !l.Locked(ctx) {
		t.Fatal("the cache should still say locked for a moment")
	}
	l.now = func() time.Time { return time.Now().Add(cacheTTL) }
	if l.Locked(ctx) {
		t.Fatal("release not seen after the cache expired")
	}
}
