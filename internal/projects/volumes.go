package projects

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
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

// Shared volumes: the services of one template or compose import may mount
// the same named volume (a server and the tool that reads its files). The
// volume belongs to one of them, the owner: the Docker volume carries the
// owner's name and labels, backups read it there, and the owner cannot be
// deleted while another service still mounts it. Deleting one of the
// others only drops its mount.

// ServiceVolume is a disk as the panel shows it.
type ServiceVolume struct {
	Name     string
	Path     string
	Docker   string // the Docker volume's name
	Fixed    bool   // part of the service's template (the database files)
	ReadOnly bool   // mounted read-only
	// Owner is the service whose volume this is, when it is another one.
	Owner string
	// SharedWith are the other services that mount this service's volume.
	SharedWith []string
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
	sharers, err := m.volumeSharers(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceVolume, 0, len(rows))
	for _, v := range rows {
		owner := s.Slug
		if v.OwnerSlug != "" {
			owner = v.OwnerSlug
		}
		out = append(out, ServiceVolume{
			Name: v.Name, Path: v.Path, Docker: node.VolumeName(projectSlug, owner, v.Name), Fixed: s.Template != "",
			ReadOnly: v.ReadOnly == 1, Owner: v.OwnerSlug, SharedWith: sharers[v.Name],
		})
	}
	return out, nil
}

// volumeSharers maps each volume of the service to the other services
// that mount it.
func (m *Manager) volumeSharers(ctx context.Context, serviceID string) (map[string][]string, error) {
	rows, err := m.q.ListVolumeSharers(ctx, sql.NullString{String: serviceID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, r := range rows {
		out[r.Name] = append(out[r.Name], r.ServiceSlug)
	}
	return out, nil
}

// ownerID is the id of the service that owns a shared volume v (from the
// services already written, by slug), or NULL for a volume of its own.
func ownerID(idBySlug map[string]string, v node.Volume) (sql.NullString, error) {
	if v.Service == "" {
		return sql.NullString{}, nil
	}
	id, ok := idBySlug[v.Service]
	if !ok {
		return sql.NullString{}, fmt.Errorf("volume %s: its owner %s is not created before it", v.Name, v.Service)
	}
	return sql.NullString{String: id, Valid: true}, nil
}

// ensureSharedVolumes creates the shared volumes of services just created,
// before their deploys start (they run at the same time): each one with
// its owner's name and labels. A failure is only logged: the first deploy
// that mounts the volume creates it as well.
func (m *Manager) ensureSharedVolumes(ctx context.Context, p dbq.Project, created []dbq.Service) {
	ve, ok := m.node.(node.VolumeEnsurer)
	if !ok {
		return
	}
	for _, s := range created {
		sharers, err := m.volumeSharers(ctx, s.ID)
		if err != nil || len(sharers) == 0 {
			continue
		}
		vols, err := m.q.ListVolumes(ctx, s.ID)
		if err != nil {
			continue
		}
		spec := node.ServiceSpec{
			ProjectID: p.ID, Project: p.Slug, ServiceID: s.ID, Service: s.Slug, Image: s.Image,
			MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCpus, PidsLimit: s.PidsLimit,
		}
		for _, v := range vols {
			if _, shared := sharers[v.Name]; shared && !v.OwnerServiceID.Valid {
				spec.Volumes = append(spec.Volumes, node.Volume{Name: v.Name, Path: v.Path})
			}
		}
		if err := ve.EnsureVolumes(ctx, spec); err != nil {
			m.log.Warn("create shared volumes", "service", p.Slug+"/"+s.Slug, "error", err)
		}
	}
}

// sharedVolumeError says which services still mount the volumes of the
// service being deleted, or nil when none does.
func (m *Manager) sharedVolumeError(ctx context.Context, s dbq.Service) error {
	sharers, err := m.volumeSharers(ctx, s.ID)
	if err != nil || len(sharers) == 0 {
		return err
	}
	var vols, svcs []string
	for name, list := range sharers {
		vols = append(vols, name)
		for _, x := range list {
			if !slices.Contains(svcs, x) {
				svcs = append(svcs, x)
			}
		}
	}
	slices.Sort(vols)
	slices.Sort(svcs)
	return i18n.E("service.error.volume_shared", "volumes", strings.Join(vols, ", "), "services", strings.Join(svcs, ", "))
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
	rows, err := m.q.ListVolumes(ctx, s.ID)
	if err != nil {
		return err
	}
	for _, v := range rows {
		if v.Name != name {
			continue
		}
		// Another service's volume: this one only drops its mount.
		if v.OwnerSlug != "" && wipe {
			return i18n.E("volume.error.shared_wipe", "service", v.OwnerSlug)
		}
	}
	if sharers, err := m.volumeSharers(ctx, s.ID); err != nil {
		return err
	} else if list := sharers[name]; len(list) > 0 {
		return i18n.E("volume.error.shared_owner", "services", strings.Join(list, ", "))
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
