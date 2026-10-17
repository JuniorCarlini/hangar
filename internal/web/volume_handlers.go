package web

import (
	"net/http"
)

// Disks of a service (settings tab): add, detach, and detach deleting the
// data (sudo: the files are gone for good).

func (h *handlers) addVolume(w http.ResponseWriter, r *http.Request) {
	if err := h.projects.AddServiceVolume(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"),
		r.PostFormValue("name"), r.PostFormValue("path")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=settings&ok=volume")
}

func (h *handlers) removeVolume(w http.ResponseWriter, r *http.Request) {
	h.detachVolume(w, r, false)
}

func (h *handlers) wipeVolume(w http.ResponseWriter, r *http.Request) {
	h.detachVolume(w, r, true)
}

func (h *handlers) detachVolume(w http.ResponseWriter, r *http.Request, wipe bool) {
	if err := h.projects.RemoveServiceVolume(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"),
		r.PostFormValue("name"), wipe); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=settings&ok=volume-removed")
}
