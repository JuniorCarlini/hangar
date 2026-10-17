package web

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/lockdown"
)

// maxBodyBytes caps the body of any panel request. Large uploads (recovery
// kit, .env) will have their own route with their own limit.
const maxBodyBytes = 1 << 20

// panelCSP is the panel's Content-Security-Policy.
const panelCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; " +
	"base-uri 'none'; form-action 'self'"

// securityHeaders applies the headers from [17 § 1.5] to every response,
// error responses included.
func securityHeaders(next http.Handler) http.Handler {
	const csp = panelCSP
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// Everything the pages load is the panel's own: nothing cross-origin
		// may be embedded, which also isolates the page process (Spectre).
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// hostCheck rejects any Host outside the configured list (421). Without it,
// an attacker's domain pointed at 127.0.0.1 (DNS rebinding) could talk to
// the panel through the victim's browser. Status hosts (a separate public
// domain for the status links, docs/15) only reach /s/ and the assets.
func hostCheck(allowed, statusOnly []string, next http.Handler) http.Handler {
	set := make(map[string]struct{}, len(allowed))
	for _, h := range allowed {
		set[strings.ToLower(h)] = struct{}{}
	}
	status := make(map[string]struct{}, len(statusOnly))
	for _, h := range statusOnly {
		status[strings.ToLower(h)] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if _, ok := set[host]; ok {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := status[host]; ok {
			if strings.HasPrefix(r.URL.Path, "/s/") || strings.HasPrefix(r.URL.Path, "/assets/") {
				next.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
	})
}

// lockGate refuses everything that does not come from the server itself
// while the panel is locked (docs/17 § 1.6): through Caddy or a private
// address the panel answers 403; through an SSH tunnel it works, so the
// operator can still log in and look around.
func lockGate(l *lockdown.Lock, next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !lockdown.LocalOnly(r) && l.Locked(r.Context()) {
			http.Error(w, i18n.T(r.Context(), "lock.refused"), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

type loggerKey struct{}

func withLogger(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), loggerKey{}, log)))
	})
}

func loggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// withLocale picks the request language before any session is known: the
// language cookie chosen on the login page, else Accept-Language. A logged-in
// user's own preference overrides it later, in the route policy.
func withLocale(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loc := ""
		if c, err := r.Cookie(langCookie); err == nil && i18n.Supported(c.Value) {
			loc = c.Value
		} else {
			loc = i18n.Match(r.Header.Get("Accept-Language"))
		}
		next.ServeHTTP(w, r.WithContext(i18n.WithLocale(r.Context(), loc)))
	})
}

// clientIP uses the connection address. Once the panel sits behind Caddy,
// the real IP will come from X-Forwarded-For, accepted only from Caddy's
// fixed IP.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// BehindEdge serves the public panel on the edge gateway: only Caddy may
// connect there, and the visitor's address (for rate limits, sessions and
// the audit log) is taken from the X-Forwarded-For Caddy sets. Requests that
// arrive this way are never "local", so a locked panel refuses them.
func BehindEdge(next http.Handler, caddy netip.Addr) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || ap.Addr().Unmap() != caddy {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ip := ""
		if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
			if i := strings.LastIndex(v, ","); i >= 0 {
				v = v[i+1:]
			}
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				ip = a.Unmap().String()
			}
		}
		if ip == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r2 := r.Clone(r.Context())
		r2.RemoteAddr = net.JoinHostPort(ip, "0")
		next.ServeHTTP(w, r2)
	})
}
