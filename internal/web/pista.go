package web

import (
	"net/http"

	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// pistaPage is the /_pista catalog: the design system as the panel uses it
// (docs/18). Read-only, so any logged-in user may open it.
func (h *handlers) pistaPage(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusOK, views.Pista())
}
