package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// Policy is what every route declares when registered. There is no route
// without a policy: that is what closes the "forgot to protect the new
// route" hole.
type Policy struct {
	// Public allows the route without a session. It must be explicit.
	Public bool
	// Role is the minimum role (required when not public).
	Role auth.Role
	// Sudo is which security levels require recent re-authentication
	// (password or 2FA within the last minutes) for this route.
	Sudo auth.SudoTier
	// Audit is the action name in the audit log. Required on every route
	// that changes state.
	Audit string
	// AuditByHandler means the handler itself writes a more detailed audit
	// record (e.g. login), so the router does not write a duplicate.
	AuditByHandler bool
}

// authenticator finds the Principal from the cookie token.
type authenticator interface {
	Authenticate(ctx context.Context, token string) (*auth.Principal, error)
}

// denyAll is used when there is no authentication service: nobody gets in.
type denyAll struct{}

func (denyAll) Authenticate(context.Context, string) (*auth.Principal, error) { return nil, nil }

type principalKey struct{}

// PrincipalFrom returns the Principal the policy already validated.
func PrincipalFrom(ctx context.Context) *auth.Principal {
	p, _ := ctx.Value(principalKey{}).(*auth.Principal)
	return p
}

// Router registers routes and requires a policy for each one.
type Router struct {
	mux    *http.ServeMux
	auth   authenticator
	audit  *audit.Logger
	now    func() time.Time
	routes []RouteInfo
	errs   []error
	// nav builds the sidebar data for authenticated pages.
	nav func(r *http.Request, p *auth.Principal) views.Nav
}

// RouteInfo describes a registered route, for inspection and tests.
type RouteInfo struct {
	Pattern string
	Method  string
	Policy  Policy
}

func newRouter(a authenticator, al *audit.Logger) *Router {
	if a == nil {
		a = denyAll{}
	}
	return &Router{mux: http.NewServeMux(), auth: a, audit: al, now: time.Now}
}

// Handle registers h at pattern ("METHOD /path") under policy p. An invalid
// policy does not stop registration on the spot: it is kept and Validate
// refuses to start the server.
func (rt *Router) Handle(pattern string, h http.Handler, p Policy) {
	method, _, ok := strings.Cut(pattern, " ")
	if !ok || method == "" || strings.HasPrefix(method, "/") {
		rt.errs = append(rt.errs, fmt.Errorf("route %q: the pattern must start with the method", pattern))
		return
	}
	if err := checkPolicy(method, p); err != nil {
		rt.errs = append(rt.errs, fmt.Errorf("route %q: %w", pattern, err))
		return
	}
	rt.routes = append(rt.routes, RouteInfo{Pattern: pattern, Method: method, Policy: p})
	rt.mux.Handle(pattern, rt.enforce(method, pattern, p, h))
}

// HandleFunc is Handle for functions.
func (rt *Router) HandleFunc(pattern string, h http.HandlerFunc, p Policy) {
	rt.Handle(pattern, h, p)
}

// Validate returns every policy error found during registration.
func (rt *Router) Validate() error { return errors.Join(rt.errs...) }

// Routes lists the registered routes.
func (rt *Router) Routes() []RouteInfo { return append([]RouteInfo(nil), rt.routes...) }

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

func checkPolicy(method string, p Policy) error {
	if p.Public {
		if p.Role != auth.RoleNone {
			return errors.New("public route cannot require a role")
		}
		if p.Sudo != auth.SudoNone {
			return errors.New("public route cannot require sudo")
		}
	} else if p.Role < auth.RoleViewer || p.Role > auth.RoleOwner {
		return errors.New("non-public route needs a minimum role")
	}
	if isUnsafe(method) && p.Audit == "" {
		return errors.New("state-changing route needs an audit name")
	}
	return nil
}

// limitedRoutes are the routes outside any project that a user limited to
// some projects may still use: their own account and the overview (which
// shows only their projects). Everything else server-wide is out of reach.
var limitedRoutes = map[string]bool{
	"GET /{$}":                           true,
	"GET /overview":                      true,
	"GET /palette.json":                  true,
	"POST /logout":                       true,
	"POST /sudo":                         true,
	"GET /account":                       true,
	"POST /account/sessions/end":         true,
	"POST /account/totp/enable":          true,
	"POST /account/totp/disable":         true,
	"POST /account/preferences":          true,
	"GET /templates/{template}/logo.svg": true,
	"GET /_pista":                        true,
}

// limitedAllows reports whether a user limited to some projects may use the
// route: a project route only for one of their projects, else the list above.
func limitedAllows(pattern string, r *http.Request, who *auth.Principal) bool {
	if strings.Contains(pattern, "{project}") {
		return who.CanSeeProject(r.PathValue("project"))
	}
	return limitedRoutes[pattern] || strings.HasPrefix(pattern, "GET "+views.ComposeSampleURL)
}

func (rt *Router) enforce(method, pattern string, p Policy, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var principal *auth.Principal
		if !p.Public {
			var err error
			principal, err = rt.auth.Authenticate(r.Context(), sessionToken(r))
			switch {
			case err != nil:
				loggerFrom(r.Context()).Error("authentication failed", "error", err)
				http.Error(w, i18n.T(r.Context(), "error.internal"), http.StatusInternalServerError)
				return
			case principal == nil:
				// No session: do not audit (otherwise any bot would flood the log,
				// docs/20). Browsers go to the login page; everything else gets 401.
				if method == http.MethodGet && wantsHTML(r) {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
				http.Error(w, i18n.T(r.Context(), "error.unauthenticated"), http.StatusUnauthorized)
				return
			case principal.Role < p.Role:
				rt.record(r, p, principal, audit.Denied, map[string]any{"reason": "insufficient_role"})
				http.Error(w, i18n.T(r.Context(), "error.forbidden"), http.StatusForbidden)
				return
			case principal.Limited() && !limitedAllows(pattern, r, principal):
				// Not found rather than forbidden: a limited user does not learn
				// which other projects exist.
				rt.record(r, p, principal, audit.Denied, map[string]any{"reason": "project_access"})
				http.NotFound(w, r)
				return
			case !principal.SudoFor(p.Sudo, rt.now()):
				rt.record(r, p, principal, audit.Denied, map[string]any{"reason": "sudo_required"})
				http.Error(w, i18n.T(r.Context(), "error.sudo_required"), http.StatusForbidden)
				return
			}
			// Besides cross-origin blocking (CrossOriginProtection), every
			// authenticated write carries the session's CSRF token.
			if isUnsafe(method) && !auth.EqualCSRF(csrfFromRequest(r), principal.CSRFToken) {
				rt.record(r, p, principal, audit.Denied, map[string]any{"reason": "invalid_csrf"})
				http.Error(w, i18n.T(r.Context(), "error.csrf"), http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), principalKey{}, principal)
			if principal.Locale != "" {
				ctx = i18n.WithLocale(ctx, principal.Locale)
			}
			ctx = views.WithTheme(ctx, principal.Theme)
			if !principal.HasTOTP {
				ctx = views.WithoutTOTP(ctx)
			}
			if rt.nav != nil {
				ctx = views.WithNav(ctx, rt.nav(r.WithContext(ctx), principal))
			}
			r = r.WithContext(ctx)
		}

		if p.Audit == "" || p.AuditByHandler {
			h.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		var outcome audit.Outcome
		switch {
		case sw.status == http.StatusTooManyRequests:
			return // already counted by the limiter; not one row per attempt
		case sw.status == http.StatusUnauthorized || sw.status == http.StatusForbidden:
			outcome = audit.Denied
		case sw.status >= 400:
			outcome = audit.Error
		default:
			outcome = audit.OK
		}
		rt.record(r, p, principal, outcome, map[string]any{"status": sw.status})
	})
}

func (rt *Router) record(r *http.Request, p Policy, who *auth.Principal, outcome audit.Outcome, summary map[string]any) {
	if rt.audit == nil {
		return
	}
	action := p.Audit
	if action == "" {
		action = "route." + r.Method
	}
	e := audit.Entry{
		IP:        clientIP(r),
		UserAgent: truncate(r.UserAgent(), 256),
		Action:    action,
		Outcome:   outcome,
		Summary:   summary,
	}
	if who != nil {
		e.ActorID = who.UserID
	}
	// Auditing must not depend on the client staying connected.
	if err := rt.audit.Record(context.WithoutCancel(r.Context()), e); err != nil {
		loggerFrom(r.Context()).Error("failed to write audit record", "action", action, "error", err)
	}
}

func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func csrfFromRequest(r *http.Request) string {
	if v := r.Header.Get("X-CSRF-Token"); v != "" {
		return v
	}
	return r.PostFormValue("csrf")
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wroteHeader = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
