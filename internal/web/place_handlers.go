package web

import (
	"net/http"
	"strconv"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// placeFrom reads where a new service should appear on the canvas and which
// service the line was dragged from (the canvas sends them when a line is
// dropped on empty space). Anything malformed is ignored.
func placeFrom(r *http.Request) views.Place {
	get := func(k string) string {
		if v := r.PostFormValue(k); v != "" {
			return v
		}
		return r.URL.Query().Get(k)
	}
	p := views.Place{}
	if f := get("from"); node.SlugRE.MatchString(f) {
		p.From = f
	}
	if x, err := strconv.Atoi(get("x")); err == nil {
		if y, err := strconv.Atoi(get("y")); err == nil {
			p.X, p.Y, p.Set = x, y, true
		}
	}
	return p
}

// placeNew puts a just-created service where the line was dropped and
// connects the service it came from. Failing here never fails the creation:
// the service exists, the user can move or connect it by hand.
func (h *handlers) placeNew(r *http.Request, slug string) {
	p := placeFrom(r)
	project := r.PathValue("project")
	if p.Set {
		if err := h.projects.SetCanvasPosition(r.Context(), project, slug, p.X, p.Y); err != nil {
			loggerFrom(r.Context()).Warn("place new service", "error", err)
		}
	}
	if p.From != "" {
		if _, err := h.projects.ConnectNew(r.Context(), actor(r), project, p.From, slug); err != nil {
			loggerFrom(r.Context()).Warn("connect new service", "from", p.From, "error", err)
		}
	}
}
