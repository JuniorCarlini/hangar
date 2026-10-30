package web

import (
	"context"
	"net/http"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup"
)

// weakensBackups reports whether in turns off the routine or the WAL of a
// service that has them on. A service it cannot load counts as weakening:
// the request then fails closed on the sudo check.
func (h *handlers) weakensBackups(r *http.Request, in backup.PolicyInput) bool {
	_, s, err := h.projects.GetService(r.Context(), r.PathValue("project"), r.PathValue("service"))
	if err != nil {
		return true
	}
	old, existed := h.backups.ServicePolicy(r.Context(), s.ID)
	if !existed {
		return false
	}
	return (old.Enabled && !in.Enabled) || (old.WAL && !in.WAL)
}

// recordDenied audits a refusal decided inside a handler (AuditByHandler
// routes, where the router does not record the outcome).
func (h *handlers) recordDenied(r *http.Request, action, reason string) {
	if h.audit == nil {
		return
	}
	e := audit.Entry{
		IP: clientIP(r), UserAgent: truncate(r.UserAgent(), 256), Action: action,
		Outcome: audit.Denied, Summary: map[string]any{"reason": reason},
	}
	if pr := PrincipalFrom(r.Context()); pr != nil {
		e.ActorID = pr.UserID
	}
	if err := h.audit.Record(context.WithoutCancel(r.Context()), e); err != nil {
		loggerFrom(r.Context()).Error("failed to write audit record", "action", action, "error", err)
	}
}
