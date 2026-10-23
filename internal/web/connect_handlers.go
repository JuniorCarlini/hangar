package web

import (
	"errors"
	"net/http"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// connectForm is the body of the connect dialog (canvas.js and the
// Variables tab load it): what the target offers, each with the variable
// of this service that would receive it.
func (h *handlers) connectForm(w http.ResponseWriter, r *http.Request) {
	pr := PrincipalFrom(r.Context())
	project, from, target := r.PathValue("project"), r.PathValue("service"), r.URL.Query().Get("to")
	d := views.ConnectFormData{CSRF: pr.CSRFToken, Project: project, From: from, Target: target}
	plan, err := h.projects.PlanConnect(r.Context(), project, from, target)
	switch {
	case errors.Is(err, projects.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		_, d.Error = userError(r, err)
	default:
		d.Vars = plan.Vars
		for _, row := range plan.Rows {
			d.Rows = append(d.Rows, views.ConnectRow{
				Key: row.Key, Secret: row.Secret, Var: row.Var, Known: row.Known,
				Current: row.Current, Linked: row.Linked, Checked: row.Checked,
			})
		}
	}
	render(w, r, http.StatusOK, views.ConnectForm(d))
}

// connect saves the chosen connections: each ticked value goes into the
// variable written next to it, as a reference.
func (h *handlers) connect(w http.ResponseWriter, r *http.Request) {
	project, from, target := r.PathValue("project"), r.PathValue("service"), r.PostFormValue("to")
	var maps []projects.Mapping
	for _, key := range r.PostForm["key"] {
		maps = append(maps, projects.Mapping{Key: key, Var: r.PostFormValue("var_" + key)})
	}
	if _, err := h.projects.Connect(r.Context(), actor(r), project, from, target, maps, true); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=variables&ok=connected")
}

// setOffered offers one of the service's variables to the others, or stops.
func (h *handlers) setOffered(w http.ResponseWriter, r *http.Request) {
	s, ok := h.withService(w, r)
	if !ok {
		return
	}
	on := r.PostFormValue("on") == "1"
	if err := h.projects.SetOffered(r.Context(), actor(r), s.ID, r.PostFormValue("key"), on); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	flash := "offered"
	if !on {
		flash = "unoffered"
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=variables&ok="+flash)
}

// connectTargets are the services of the project this one could connect
// to: the others that offer something.
func (h *handlers) connectTargets(r *http.Request, projectID, self string) []string {
	svcs, err := h.projects.ListServices(r.Context(), projectID)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range svcs {
		if s.Slug == self {
			continue
		}
		if offers, err := h.projects.Offers(r.Context(), s.ID); err == nil && len(offers) > 0 {
			out = append(out, s.Slug)
		}
	}
	return out
}

// dependentsLabel is "app (DATABASE_URL), outro/worker (DB_HOST)".
func dependentsLabel(r *http.Request, deps []projects.Dependent) []string {
	out := make([]string, 0, len(deps))
	for _, d := range deps {
		name := d.Service
		if d.Project != "" {
			name = d.Project + "/" + d.Service
		}
		out = append(out, i18n.T(r.Context(), "connect.used_by_item", "service", name, "var", d.Var, "key", d.Key))
	}
	return out
}
