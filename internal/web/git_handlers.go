package web

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// --- creating a service from a repository ---------------------------------------

func (h *handlers) createGitService(w http.ResponseWriter, r *http.Request) {
	form := views.ServiceForm{
		Name: r.PostFormValue("name"), Slug: r.PostFormValue("slug"), Port: r.PostFormValue("port"),
		MemoryMB: r.PostFormValue("memory_mb"), CPUs: r.PostFormValue("cpus"),
		Repo: r.PostFormValue("repo"), Branch: r.PostFormValue("branch"),
		Subdir: r.PostFormValue("subdir"), Dockerfile: r.PostFormValue("dockerfile"),
		Credential: r.PostFormValue("credential"),
	}
	in := projects.GitServiceInput{
		ServiceInput:   projects.ServiceInput{Name: form.Name, Slug: form.Slug},
		GitSourceInput: projects.GitSourceInput{URL: form.Repo, Branch: form.Branch, Subdir: form.Subdir, Dockerfile: form.Dockerfile},
		DetectPort:     strings.TrimSpace(form.Port) == "",
	}
	var err error
	if in.Port, err = optInt(form.Port); err == nil {
		if in.MemoryMB, err = optInt(form.MemoryMB); err == nil {
			in.CPUs, err = optFloat(form.CPUs)
		}
	}
	if err != nil {
		h.renderNew(w, r, http.StatusUnprocessableEntity, nsState{tab: "git", form: form, err: i18n.T(r.Context(), "project.form.number_invalid")})
		return
	}
	if in.CredentialID, err = h.pickedCredential(r, r.PathValue("project")); err != nil {
		code, msg := userError(r, err)
		h.renderNew(w, r, code, nsState{tab: "git", form: form, err: msg})
		return
	}
	if form.Credential == "new" {
		form.Credential = in.CredentialID // saved even if the service fails: pick it next time
	}
	s, err := h.projects.CreateGitService(r.Context(), actor(r), r.PathValue("project"), in)
	if err != nil && s.ID == "" {
		code, msg := userError(r, err)
		h.renderNew(w, r, code, nsState{tab: "git", form: form, err: msg})
		return
	}
	h.placeNew(r, s.Slug)
	redirectLocal(w, r, servicePath(r.PathValue("project"), s.Slug))
}

// --- the repository of an existing service ------------------------------------

func (h *handlers) saveGitSource(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	in := projects.GitSourceInput{
		URL: r.PostFormValue("repo"), Branch: r.PostFormValue("branch"),
		Subdir: r.PostFormValue("subdir"), Dockerfile: r.PostFormValue("dockerfile"),
	}
	if err := h.projects.SetGitSource(r.Context(), actor(r), s.ID, in, r.PostFormValue("token")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=git")
}

func (h *handlers) saveGitToken(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	token := r.PostFormValue("token")
	if r.PostFormValue("action") == "clear" {
		token = ""
	} else if strings.TrimSpace(token) == "" {
		h.renderService(w, r, serviceView{status: http.StatusUnprocessableEntity, errMsg: i18n.T(r.Context(), "git.error.token")})
		return
	}
	if err := h.projects.SetGitToken(r.Context(), actor(r), s.ID, token); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=git-token")
}

// revealGitToken shows the token once, in this response (sudo route).
func (h *handlers) revealGitToken(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	t, err := h.projects.RevealGitToken(r.Context(), actor(r), s.ID)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	h.renderService(w, r, serviceView{status: http.StatusOK, gitToken: t, flash: i18n.T(r.Context(), "service.env.revealed")})
}

// gitWebhook turns automatic deploys on (a new URL and secret, shown once
// here) or off.
func (h *handlers) gitWebhook(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	switch r.PostFormValue("action") {
	case "rotate":
		hook, err := h.projects.RotateWebhook(r.Context(), actor(r), s.ID)
		if err != nil {
			code, msg := userError(r, err)
			h.renderService(w, r, serviceView{status: code, errMsg: msg})
			return
		}
		h.renderService(w, r, serviceView{status: http.StatusOK, hook: &hook, flash: i18n.T(r.Context(), "git.webhook.created")})
	case "disable":
		if err := h.projects.DisableWebhook(r.Context(), actor(r), s.ID); err != nil {
			code, msg := userError(r, err)
			h.renderService(w, r, serviceView{status: code, errMsg: msg})
			return
		}
		redirectLocal(w, r, h.serviceBase(r)+"?ok=webhook-off")
	default:
		http.Error(w, i18n.T(r.Context(), "error.bad_request"), http.StatusBadRequest)
	}
}

func (h *handlers) revealWebhook(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	hook, err := h.projects.RevealWebhook(r.Context(), actor(r), s.ID)
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	h.renderService(w, r, serviceView{status: http.StatusOK, hook: &hook, flash: i18n.T(r.Context(), "service.env.revealed")})
}

// gitView fills the repository card of a service built from Git.
func (h *handlers) gitView(r *http.Request, serviceID, projectID string, v serviceView) *views.GitView {
	src, ok, err := h.projects.GetGitSource(r.Context(), serviceID)
	if err != nil || !ok {
		return nil
	}
	g := &views.GitView{
		URL: src.URL, Display: src.Display, Branch: src.Branch, Subdir: src.Subdir, Dockerfile: src.Dockerfile,
		HasToken: src.HasToken, Webhook: src.Webhook, Token: v.gitToken,
		HooksPublic:  h.hooksBase != "",
		CredentialID: src.CredentialID, CredentialName: src.CredentialName, CredentialHost: src.CredentialHost,
		CredentialMine: src.CredentialMine,
	}
	g.CredOptions = h.gitCredOptions(r.Context(), projectID)
	if v.hook != nil {
		g.HookURL, g.HookSecret = h.hookURL(r, v.hook.Token), v.hook.Secret
	}
	return g
}

// hookURL is the address to paste into GitHub: on the public hooks host
// when one is configured (edge.hooks_hostname), else on this panel.
func (h *handlers) hookURL(r *http.Request, token string) string {
	base := h.hooksBase
	if base == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		base = scheme + "://" + r.Host
	}
	return strings.TrimRight(base, "/") + projects.HookPath + token
}

// --- the webhook itself ---------------------------------------------------------

// hookBodyMax: GitHub caps payloads at 25 MB, but a push is a few KB; 1 MB
// covers hundreds of commits.
const hookBodyMax = 1 << 20

func (h *handlers) gitHook(w http.ResponseWriter, r *http.Request) {
	serveHook(h.projects, h.hookFails, loggerFrom(r.Context()), clientIP(r), w, r)
}

// Failed deliveries (unknown URL, bad signature, replay, malformed) an
// address may send per window. A misconfigured GitHub hook still shows up
// in the log and the audit; someone guessing URLs or replaying a captured
// delivery gets 429 before any database lookup, audit row or log line.
const (
	hookFailLimit  = 20
	hookFailWindow = 10 * time.Minute
)

func newHookFails() *ipRate { return newIPRate(hookFailLimit, hookFailWindow, time.Now) }

// HookHandler answers GitHub's deliveries outside the panel (the edge's
// hooks listener, docs/07): Caddy forwards only /hooks/git/* of the public
// hooks hostname to it. ipFrom says where the request came from.
func HookHandler(pm *projects.Manager, log *slog.Logger, ipFrom func(*http.Request) string) http.Handler {
	mux := http.NewServeMux()
	fails := newHookFails()
	mux.HandleFunc("POST "+projects.HookPath+"{token}", func(w http.ResponseWriter, r *http.Request) {
		serveHook(pm, fails, log, ipFrom(r), w, r)
	})
	return mux
}

// serveHook reads a delivery and answers with a short plain-text status:
// 202 deploying/queued, 200 pong or ignored, 401 bad signature, 404 unknown
// URL, 409 replay or stale, 400 malformed. No session, no CSRF: the HMAC is
// the authentication.
func serveHook(pm *projects.Manager, fails *ipRate, log *slog.Logger, ip string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if fails.exceeded(ip) {
		w.Header().Set("Retry-After", strconv.Itoa(int(hookFailWindow.Seconds())))
		http.Error(w, "too many failed deliveries", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, hookBodyMax))
	if err != nil {
		fails.allow(ip)
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	out, err := pm.GitHubHook(r.Context(), projects.HookDelivery{
		Token: r.PathValue("token"), Event: r.Header.Get("X-GitHub-Event"), ID: r.Header.Get("X-GitHub-Delivery"),
		Signature: r.Header.Get("X-Hub-Signature-256"), Body: body, IP: ip, ContentType: r.Header.Get("Content-Type"),
	})
	if err != nil {
		fails.allow(ip) // counts one failure
	}
	switch {
	case errors.Is(err, projects.ErrHookUnknown):
		http.NotFound(w, r)
	case errors.Is(err, projects.ErrHookSignature):
		log.Warn("webhook refused: bad signature", "ip", ip)
		http.Error(w, err.Error(), http.StatusUnauthorized)
	case errors.Is(err, projects.ErrHookReplay), errors.Is(err, projects.ErrHookStale):
		log.Warn("webhook refused", "reason", err.Error(), "ip", ip)
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, projects.ErrHookMalformed):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case err != nil:
		log.Error("webhook", "error", err)
		http.Error(w, "deploy could not start", http.StatusInternalServerError)
	case out == projects.HookDeployed || out == projects.HookQueued:
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, string(out)+"\n")
	default:
		_, _ = io.WriteString(w, string(out)+"\n")
	}
}
