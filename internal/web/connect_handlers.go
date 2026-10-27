package web

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// connectForm is the body of the connect dialog (canvas.js and the
// Variables tab load it): what each service offers, with the variable of
// this one that would receive it. ?to= limits it to one service (a drag on
// the canvas); without it, every service that offers something, by name.
func (h *handlers) connectForm(w http.ResponseWriter, r *http.Request) {
	pr := PrincipalFrom(r.Context())
	project, from, target := r.PathValue("project"), r.PathValue("service"), r.URL.Query().Get("to")
	d := views.ConnectFormData{CSRF: pr.CSRFToken, Project: project, From: from}
	targets := []string{target}
	if target == "" {
		p, s, err := h.projects.GetService(r.Context(), project, from)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		targets = h.connectTargets(r, p.ID, s.Slug)
		slices.Sort(targets)
	}
	for _, to := range targets {
		plan, err := h.projects.PlanConnect(r.Context(), project, from, to)
		switch {
		case errors.Is(err, projects.ErrNotFound):
			http.NotFound(w, r)
			return
		case err != nil:
			_, d.Error = userError(r, err)
		default:
			d.Vars = plan.Vars
			g := views.ConnectGroup{Target: to}
			for _, row := range plan.Rows {
				g.Rows = append(g.Rows, views.ConnectRow{
					Key: row.Key, Secret: row.Secret, Var: row.Var, Known: row.Known,
					Current: row.Current, Linked: row.Linked, Checked: row.Checked,
				})
			}
			d.Groups = append(d.Groups, g)
		}
		if d.Error != "" {
			break
		}
	}
	if d.Error == "" && len(d.Groups) == 0 {
		d.Error = i18n.T(r.Context(), "connect.no_targets")
	}
	render(w, r, http.StatusOK, views.ConnectForm(d))
}

// connect saves the chosen connections: each ticked value ("db|HOST") goes
// into the variable written next to it, as a reference, service by
// service. Forms from before the list name one service in "to".
func (h *handlers) connect(w http.ResponseWriter, r *http.Request) {
	project, from := r.PathValue("project"), r.PathValue("service")
	var order []string
	maps := map[string][]projects.Mapping{}
	seen := map[string]bool{}
	type pair struct{ field, v string }
	var pairs []pair
	for _, field := range r.PostForm["key"] {
		pairs = append(pairs, pair{field, r.PostFormValue("var_" + field)})
	}
	for _, p := range pairs {
		field, v := p.field, p.v
		target, key, ok := strings.Cut(field, "|")
		if !ok {
			target, key = r.PostFormValue("to"), field
		}
		// One variable cannot take two values, even from two services.
		if seen[v] {
			h.renderService(w, r, serviceView{status: http.StatusBadRequest, errMsg: i18n.T(r.Context(), "connect.error.duplicate", "var", v)})
			return
		}
		seen[v] = true
		if _, ok := maps[target]; !ok {
			order = append(order, target)
		}
		maps[target] = append(maps[target], projects.Mapping{Key: key, Var: v})
	}
	if len(order) == 0 {
		order = []string{r.PostFormValue("to")}
	}
	for _, target := range order {
		if _, err := h.projects.Connect(r.Context(), actor(r), project, from, target, maps[target], true); err != nil {
			code, msg := userError(r, err)
			h.renderService(w, r, serviceView{status: code, errMsg: msg})
			return
		}
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

// connectOffers are the values the project's other services offer, by
// service name, each with the variable name the connector would write.
func (h *handlers) connectOffers(r *http.Request, p dbq.Project, self string) []views.ConnectOffer {
	targets := h.connectTargets(r, p.ID, self)
	slices.Sort(targets)
	var out []views.ConnectOffer
	for _, to := range targets {
		plan, err := h.projects.PlanConnect(r.Context(), p.Slug, self, to)
		if err != nil {
			continue
		}
		for _, row := range plan.Rows {
			out = append(out, views.ConnectOffer{Service: to, Key: row.Key, Secret: row.Secret, Var: row.Var, Known: row.Known})
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
