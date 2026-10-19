package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/volumes"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// Disks of a service (settings tab): add, detach, and detach deleting the
// data (sudo: the files are gone for good); limit a disk's size, increase
// the limit or take it away (sudo: the services stop while the data moves).

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

// sizeGB reads the size field (whole GB).
func sizeGB(raw string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n < volumes.MinSize/volumes.GiB || n > volumes.MaxSize/volumes.GiB {
		return 0, false
	}
	return n * volumes.GiB, true
}

func (h *handlers) limitVolume(w http.ResponseWriter, r *http.Request) {
	size, ok := sizeGB(r.PostFormValue("size_gb"))
	var err error
	if !ok {
		err = i18n.E("volume.limit.error.size", "max", volumes.MaxSize>>40)
	} else {
		err = h.projects.SetVolumeLimit(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("name"), size)
	}
	if err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=settings&ok=volume-limit")
}

func (h *handlers) unlimitVolume(w http.ResponseWriter, r *http.Request) {
	if err := h.projects.RemoveVolumeLimit(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), r.PostFormValue("name")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?tab=settings&ok=volume-unlimit")
}

func ceilGB(b int64) int { return int((max(b, 0) + volumes.GiB - 1) / volumes.GiB) }

// volumeRow is a disk as the disks card shows it, with what its limit
// dialog suggests: twice what it holds (at least 10 GB) for a new limit,
// half again for an increase, never more than the server has free.
func volumeRow(ctx context.Context, v projects.ServiceVolume, freeGB int) views.VolumeRow {
	row := views.VolumeRow{
		Name: v.Name, Path: v.Path, Docker: v.Docker, Fixed: v.Fixed, ReadOnly: v.ReadOnly,
		Owner: v.Owner, SharedWith: strings.Join(v.SharedWith, ", "),
	}
	used := max(v.Used, 0)
	if v.Used >= 0 {
		row.Used = fmtBytes(ctx, uint64(used))
	}
	row.MinGB = max(1, ceilGB(used+used/10+256<<20))
	row.SuggestGB = max(row.MinGB, min(max(10, 2*ceilGB(used)), max(row.MinGB, freeGB)))
	if l := v.Limit; l != nil {
		lr := &views.VolumeLimitRow{
			Size: fmtBytes(ctx, uint64(max(l.Size, 0))), SizeGB: ceilGB(l.Size), State: l.State, Pending: l.Pending,
			Error: l.Error, Dismiss: l.Failed() && !l.Busy() && l.Cleaned,
		}
		if l.Total > 0 {
			lr.Used = fmtBytes(ctx, l.Used)
			lr.Pct = int(min(100, (l.Used*100+l.Total/2)/l.Total)) //nolint:gosec // 0–100
		}
		if l.Active() {
			row.SuggestGB = lr.SizeGB + max(1, min(max(5, lr.SizeGB/2), freeGB))
		}
		row.Limit = lr
	}
	return row
}
