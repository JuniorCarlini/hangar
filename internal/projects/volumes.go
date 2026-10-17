package projects

import (
	"context"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Disks (named Docker volumes) on any service: what the app writes there —
// uploads, a SQLite file — survives deploys. A disk is attached at the next
// deploy, and a service with one is deployed by stopping the old container
// first (two containers must not write the same disk).

// MaxVolumes is how many disks a service may have.
const MaxVolumes = 8

var volumeNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,29}$`)

// ServiceVolume is a disk as the panel shows it.
type ServiceVolume struct {
	Name   string
	Path   string
	Docker string // the Docker volume's name
	Fixed  bool   // part of the service's template (the database files)
}

// ErrVolumeRemover means the node cannot delete volumes.
var ErrVolumeRemover = errors.New("node cannot remove volumes")

// volumeRemover is the node's ability to delete a volume's data.
type volumeRemover interface {
	RemoveVolume(ctx context.Context, project, service, name string) error
}

// ListServiceVolumes lists a service's disks.
func (m *Manager) ListServiceVolumes(ctx context.Context, projectSlug string, s dbq.Service) ([]ServiceVolume, error) {
	rows, err := m.q.ListVolumes(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceVolume, 0, len(rows))
	for _, v := range rows {
		out = append(out, ServiceVolume{
			Name: v.Name, Path: v.Path, Docker: node.VolumeName(projectSlug, s.Slug, v.Name), Fixed: s.Template != "",
		})
	}
	return out, nil
}

func cleanMount(p string) (string, error) {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") || len(p) > 200 || strings.ContainsAny(p, "\x00\n\r:") || strings.Contains(p, "..") {
		return "", i18n.E("volume.error.path")
	}
	p = path.Clean(p)
	if p == "/" {
		return "", i18n.E("volume.error.path")
	}
	if r := node.ReservedMount(p); r != "" {
		return "", i18n.E("volume.error.reserved", "path", r)
	}
	return p, nil
}

// AddServiceVolume attaches a new disk at a path, from the next deploy.
func (m *Manager) AddServiceVolume(ctx context.Context, a Actor, projectSlug, serviceSlug, name, mountPath string) error {
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if !volumeNameRE.MatchString(name) {
		return i18n.E("volume.error.name")
	}
	if mountPath, err = cleanMount(mountPath); err != nil {
		return err
	}
	rows, err := m.q.ListVolumes(ctx, s.ID)
	if err != nil {
		return err
	}
	if len(rows) >= MaxVolumes {
		return i18n.E("volume.error.too_many", "n", MaxVolumes)
	}
	for _, v := range rows {
		switch {
		case v.Name == name:
			return i18n.E("volume.error.name_taken", "name", name)
		case v.Path == mountPath || strings.HasPrefix(mountPath, v.Path+"/") || strings.HasPrefix(v.Path, mountPath+"/"):
			return i18n.E("volume.error.overlap", "path", v.Path)
		}
	}
	if err := m.q.AddVolume(ctx, dbq.AddVolumeParams{ServiceID: s.ID, Name: name, Path: mountPath}); err != nil {
		return err
	}
	m.record(ctx, a, "service.volume.add", "service", s.ID, audit.OK, map[string]any{"name": name, "path": mountPath})
	return nil
}

// RemoveServiceVolume detaches a disk from the next deploy. With wipe, its
// data is deleted too (the container must not be using it: deploy first).
// A template's disk (the database files) cannot be removed here.
func (m *Manager) RemoveServiceVolume(ctx context.Context, a Actor, projectSlug, serviceSlug, name string, wipe bool) error {
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if s.Template != "" {
		return i18n.E("volume.error.template")
	}
	if wipe {
		vr, ok := m.node.(volumeRemover)
		if !ok {
			return ErrVolumeRemover
		}
		if err := vr.RemoveVolume(ctx, p.Slug, s.Slug, name); err != nil {
			return i18n.E("volume.error.in_use")
		}
	}
	n, err := m.q.DeleteVolume(ctx, dbq.DeleteVolumeParams{ServiceID: s.ID, Name: name})
	if err != nil {
		return err
	}
	if n == 0 && !wipe {
		return ErrNotFound
	}
	action := "service.volume.remove"
	if wipe {
		action = "service.volume.wipe"
	}
	m.record(ctx, a, action, "service", s.ID, audit.OK, map[string]any{"name": name})
	return nil
}
