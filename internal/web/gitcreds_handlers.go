package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// Git credentials: the server page, and the create/replace/delete forms the
// project settings post here too ("back" says where to return).

func (h *handlers) gitCredsPage(w http.ResponseWriter, r *http.Request) {
	h.renderGitCreds(w, r, http.StatusOK, "", credFlash(r), false)
}

// credFlash maps the ?ok= of the credential forms to their message.
func credFlash(r *http.Request) string {
	switch r.URL.Query().Get("ok") {
	case "git-cred-created":
		return i18n.T(r.Context(), "gitcred.flash.created")
	case "git-cred-replaced":
		return i18n.T(r.Context(), "gitcred.flash.replaced")
	case "git-cred-deleted":
		return i18n.T(r.Context(), "gitcred.flash.deleted")
	}
	return ""
}

func (h *handlers) renderGitCreds(w http.ResponseWriter, r *http.Request, status int, errMsg, flash string, open bool) {
	ctx := r.Context()
	d := views.GitCredsData{CSRF: PrincipalFrom(ctx).CSRFToken, Error: errMsg, Flash: flash, Open: open}
	list, err := h.projects.ListGitCredentials(ctx)
	if err != nil {
		status, d.Error = userError(r, err)
	}
	d.Creds = gitCredRows(ctx, list)
	render(w, r, status, views.GitCreds(d))
}

func gitCredRows(ctx context.Context, list []projects.GitCredential) []views.GitCredRow {
	now := time.Now()
	out := make([]views.GitCredRow, 0, len(list))
	for _, c := range list {
		row := views.GitCredRow{
			ID: c.ID, Name: c.Name, Host: c.Host, Hint: c.Hint, Project: c.ProjectSlug, Uses: c.Uses,
			Updated: ago(ctx, c.UpdatedAt.Format(time.RFC3339Nano), now),
		}
		if !c.LastUsed.IsZero() {
			row.LastUsed = ago(ctx, c.LastUsed.Format(time.RFC3339Nano), now)
		}
		out = append(out, row)
	}
	return out
}

// gitCredOptions is what a project's services can pick.
func (h *handlers) gitCredOptions(ctx context.Context, projectID string) []views.GitCredOption {
	list, err := h.projects.GitCredentialsFor(ctx, projectID)
	if err != nil {
		loggerFrom(ctx).Error("git credentials", "error", err)
		return nil
	}
	out := make([]views.GitCredOption, 0, len(list))
	for _, c := range list {
		out = append(out, views.GitCredOption{ID: c.ID, Name: c.Name, Host: c.Host, Project: !c.Server()})
	}
	return out
}

// credBack is where a credential form returns: the server page, a project's
// settings, or the project's "new service" dialog on the Git tab (so adding a
// credential from there comes back with it selected). Nothing else, so the
// field cannot redirect away. It returns the clean back path and the project
// slug ("" = server-wide).
func credBack(r *http.Request) (string, string) {
	rest, ok := strings.CutPrefix(r.PostFormValue("back"), "/p/")
	if !ok {
		return "/git-credentials", ""
	}
	path, query, _ := strings.Cut(rest, "?")
	slug, tail, ok := strings.Cut(path, "/")
	if !ok || !node.SlugRE.MatchString(slug) {
		return "/git-credentials", ""
	}
	switch {
	case tail == "settings":
		return "/p/" + slug + "/settings", slug
	case tail == "new" && query == "tab=git":
		return "/p/" + slug + "/new?tab=git", slug
	case tail == "new":
		return "/p/" + slug + "/new", slug
	}
	return "/git-credentials", ""
}

// backWithQuery adds query parameters to a back path, keeping any it already
// has (the new-service back arrives as "…?tab=git").
func backWithQuery(base string, kv ...string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// checkGitCred validates a GitHub token the operator is typing in the "new
// credential" dialog and answers with the profile it belongs to, so the
// dialog can show "profile found" before saving. It stores nothing.
func (h *handlers) checkGitCred(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	acc, err := h.projects.CheckGitHubAccount(r.Context(), r.PostFormValue("token"))
	if err != nil {
		_, msg := userError(r, err)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "login": acc.Login, "name": acc.Name})
}

// credFail shows the error where the form was: the server page, or the
// project settings with the dialog open again.
func (h *handlers) credFail(w http.ResponseWriter, r *http.Request, err error, open bool) {
	code, msg := userError(r, err)
	if _, slug := credBack(r); slug != "" {
		r.SetPathValue("project", slug)
		h.renderProjectCreds(w, r, code, msg, open)
		return
	}
	h.renderGitCreds(w, r, code, msg, "", open)
}

func (h *handlers) createGitCred(w http.ResponseWriter, r *http.Request) {
	back, slug := credBack(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	host := strings.TrimSpace(r.PostFormValue("host"))
	token := r.PostFormValue("token")
	// For GitHub, the read token identifies the account: check it before
	// saving and, when no name was typed, use the account's login.
	if host == "" || host == gitsrc.GitHubHost {
		acc, err := h.projects.CheckGitHubAccount(r.Context(), token)
		if err != nil {
			h.credFail(w, r, err, true)
			return
		}
		if name == "" {
			name = acc.Login
		}
	}
	c, err := h.projects.CreateGitCredential(r.Context(), actor(r), projects.GitCredentialInput{
		ProjectSlug: slug, Name: name, Host: host, Token: token,
	})
	if err != nil {
		h.credFail(w, r, err, true)
		return
	}
	// Back to where it was asked, with the new credential selected (the
	// new-service dialog reads ?credential=<id>).
	redirectLocal(w, r, backWithQuery(back, "ok", "git-cred-created", "credential", c.ID))
}

func (h *handlers) replaceGitCred(w http.ResponseWriter, r *http.Request) {
	back, _ := credBack(r)
	if err := h.projects.ReplaceGitCredentialToken(r.Context(), actor(r), r.PathValue("id"), r.PostFormValue("token")); err != nil {
		h.credFail(w, r, err, false)
		return
	}
	redirectLocal(w, r, back+"?ok=git-cred-replaced")
}

func (h *handlers) deleteGitCred(w http.ResponseWriter, r *http.Request) {
	back, _ := credBack(r)
	if err := h.projects.DeleteGitCredential(r.Context(), actor(r), r.PathValue("id")); err != nil {
		h.credFail(w, r, err, false)
		return
	}
	redirectLocal(w, r, back+"?ok=git-cred-deleted")
}

// pickedCredential reads the credential picker of a service form: a saved
// one, none, or "new" (the token typed there is saved as a credential
// first, for the server or this project).
func (h *handlers) pickedCredential(r *http.Request, projectSlug string) (string, error) {
	id := r.PostFormValue("credential")
	// "public" is the Tucano-safe value for "no credential" (an empty value
	// would be swallowed as the select's placeholder and vanish from the list).
	if id == "public" {
		return "", nil
	}
	if id != "new" {
		return id, nil
	}
	scope := ""
	if r.PostFormValue("cred_scope") == "project" {
		scope = projectSlug
	}
	c, err := h.projects.CreateGitCredential(r.Context(), actor(r), projects.GitCredentialInput{
		ProjectSlug: scope, Name: r.PostFormValue("cred_name"), Token: r.PostFormValue("token"),
		Host: hostOfRepo(r.PostFormValue("repo")),
	})
	return c.ID, err
}

// hostOfRepo is the host of a repository URL typed in the form ("" when it
// is not one: the credential then defaults to github.com and the repository
// check reports the URL).
func hostOfRepo(u string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(u), "https://")
	if !ok {
		return ""
	}
	h, _, _ := strings.Cut(rest, "/")
	return h
}

// saveGitCredential points a service at another credential (or none).
func (h *handlers) saveGitCredential(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	id, err := h.pickedCredential(r, r.PathValue("project"))
	if err == nil {
		err = h.projects.SetGitCredential(r.Context(), actor(r), s.ID, id)
	}
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=git-token")
}
