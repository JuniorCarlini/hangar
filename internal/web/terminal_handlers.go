package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// The service terminal: xterm.js in the page talks to a shell in the
// container over a WebSocket. Binary frames carry the keystrokes (in) and
// the screen (out); a text frame {"cols":N,"rows":N} resizes the TTY.

const (
	// terminalMaxAge ends a session however active it is: sudo lasts less,
	// and a forgotten tab should not keep a root shell open.
	terminalMaxAge = time.Hour
	// terminalIdle ends a session nobody typed in.
	terminalIdle = 20 * time.Minute
)

func clampSize(s string, lo, hi, def int) uint {
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		n = def
	}
	return uint(n) //nolint:gosec // clamped above
}

// terminalCSP is the panel's CSP for the terminal page only: xterm.js
// writes its theme into a <style> element (inline styles; scripts stay
// 'self'), and the page is shown in a frame of the panel itself, the
// drawer's terminal modal.
var terminalCSP = strings.NewReplacer(
	"style-src 'self'", "style-src 'self' 'unsafe-inline'",
	"frame-ancestors 'none'", "frame-ancestors 'self'",
).Replace(panelCSP)

// terminalPage is the terminal itself: shell picker, saved commands and
// the xterm screen, loaded in the drawer's terminal modal.
func (h *handlers) terminalPage(w http.ResponseWriter, r *http.Request) {
	h.renderTerminal(w, r, http.StatusOK, "")
}

func (h *handlers) renderTerminal(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	w.Header().Set("Content-Security-Policy", terminalCSP)
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	pr := PrincipalFrom(r.Context())
	p, s, err := h.projects.GetService(r.Context(), r.PathValue("project"), r.PathValue("service"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := views.TerminalData{
		CSRF: pr.CSRFToken, Project: p.Slug, Slug: s.Slug, Error: errMsg,
		SudoActive: pr.SudoFor(auth.SudoCritical, time.Now()),
		Running:    h.serviceState(r.Context(), p.Slug, s) == "running",
	}
	if d.SudoActive && d.Running {
		for _, c := range h.projects.SuggestCommands(r.Context(), p.Slug, s.Slug) {
			d.Suggested = append(d.Suggested, views.SavedCommand{Name: c.Name, Command: c.Command})
		}
	}
	if cmds, err := h.projects.ListCommands(r.Context(), s.ID); err == nil {
		for _, c := range cmds {
			d.Commands = append(d.Commands, views.SavedCommand{ID: c.ID, Name: c.Name, Command: c.Command})
		}
	}
	render(w, r, status, views.TerminalPage(d))
}

func (h *handlers) saveCommand(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	if err := h.projects.SaveCommand(r.Context(), actor(r), s.ID, r.PostFormValue("name"), r.PostFormValue("command")); err != nil {
		code, msg := userError(r, err)
		h.renderTerminal(w, r, code, msg)
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"/terminal")
}

func (h *handlers) deleteCommand(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	if err := h.projects.DeleteCommand(r.Context(), actor(r), s.ID, r.PostFormValue("id")); err != nil {
		code, msg := userError(r, err)
		h.renderTerminal(w, r, code, msg)
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"/terminal")
}

// terminalWS upgrades to a WebSocket and pipes it to a shell in the
// container. The WebSocket library refuses another site's Origin, and the
// route needs an admin in sudo mode.
func (h *handlers) terminalWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept already answered
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(64 << 10)

	ctx, cancel := context.WithTimeout(r.Context(), terminalMaxAge)
	defer cancel()
	q := r.URL.Query()
	sh, err := h.projects.OpenShell(ctx, actor(r), r.PathValue("project"), r.PathValue("service"), q.Get("shell"), q.Get("cmd"),
		clampSize(q.Get("cols"), 10, 500, 120), clampSize(q.Get("rows"), 4, 200, 32))
	if err != nil {
		_, msg := userError(r, err)
		_ = conn.Close(websocket.StatusPolicyViolation, truncate(msg, 120))
		return
	}
	defer func() { _ = sh.Close() }()

	// Screen → browser.
	go func() {
		defer cancel()
		buf := make([]byte, 32<<10)
		for {
			n, err := sh.Read(buf)
			if n > 0 {
				if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Browser → shell, with an idle limit.
	for {
		rctx, rcancel := context.WithTimeout(ctx, terminalIdle)
		typ, data, err := conn.Read(rctx)
		rcancel()
		if err != nil {
			code := websocket.StatusNormalClosure
			if errors.Is(err, context.DeadlineExceeded) {
				code = websocket.StatusGoingAway
			}
			_ = conn.Close(code, "")
			return
		}
		if typ == websocket.MessageText {
			var size struct{ Cols, Rows int }
			if json.Unmarshal(data, &size) == nil && size.Cols > 0 && size.Rows > 0 {
				_ = sh.Resize(ctx, clampSize(strconv.Itoa(size.Cols), 10, 500, 120), clampSize(strconv.Itoa(size.Rows), 4, 200, 32))
			}
			continue
		}
		if _, err := sh.Write(data); err != nil {
			return
		}
	}
}
