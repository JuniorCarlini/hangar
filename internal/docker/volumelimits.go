package docker

import (
	"context"
	"fmt"
	"sync"

	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/volumes"
)

// A limited volume (internal/volumes) is a local volume bound to a folder
// inside its disk image: driver options type=none, o=bind, device=<folder>.
// Docker mounts the folder when a container uses the volume, and removing
// the volume never touches the image's files.

var (
	_ node.VolumeBinder = (*Local)(nil)
	_ volumes.Docker    = (*Local)(nil)
)

func bindOptions(device string) map[string]string {
	if device == "" {
		return nil
	}
	return map[string]string{"type": "none", "o": "bind", "device": device}
}

// VolumeDevice reports whether the volume exists and the folder it binds
// to ("" for a plain volume).
func (l *Local) VolumeDevice(ctx context.Context, name string) (exists bool, device string, err error) {
	res, err := l.c.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if isNotFound(err) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if res.Volume.Labels[node.LabelManaged] != "true" {
		return true, "", fmt.Errorf("volume %s was not created by Hangar", name)
	}
	if err := l.checkOwner(ctx, name, res.Volume.Labels); err != nil {
		return true, "", err
	}
	return true, res.Volume.Options["device"], nil
}

// SwitchVolume recreates the volume with the same labels, bound to device
// (or plain when device is ""). No container may use it, not even a
// stopped one: Docker refuses to remove it otherwise. Removing a plain
// volume deletes its files: the panel only switches one whose data the
// root unit copied into the image and checked. A volume that does not
// exist is created with the labels the panel would give it.
func (l *Local) SwitchVolume(ctx context.Context, spec node.ServiceSpec, v node.Volume, device string) error {
	owner, ownerID := spec.VolumeOwner(v)
	name := node.VolumeName(spec.Project, owner, v.Name)
	mu, _ := l.volumeLocks.LoadOrStore(name, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	labels := l.managedLabels(spec.ProjectID, spec.Project)
	labels[node.LabelServiceID] = ownerID
	labels[node.LabelService] = owner
	res, err := l.c.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	switch {
	case err == nil:
		if res.Volume.Labels[node.LabelManaged] != "true" {
			return fmt.Errorf("volume %s was not created by Hangar", name)
		}
		if err := l.checkOwner(ctx, name, res.Volume.Labels); err != nil {
			return err
		}
		if res.Volume.Options["device"] == device && (device != "" || len(res.Volume.Options) == 0) {
			return nil
		}
		used, err := l.c.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: make(client.Filters).Add("volume", name)})
		if err != nil {
			return err
		}
		if len(used.Items) > 0 {
			return fmt.Errorf("volume %s is still used by %d container(s)", name, len(used.Items))
		}
		labels = res.Volume.Labels
		if _, err := l.c.VolumeRemove(ctx, name, client.VolumeRemoveOptions{}); err != nil {
			return fmt.Errorf("remove volume %s: %w", name, err)
		}
	case !isNotFound(err):
		return err
	}
	if _, err := l.c.VolumeCreate(ctx, client.VolumeCreateOptions{Name: name, Driver: "local", DriverOpts: bindOptions(device), Labels: labels}); err != nil {
		return fmt.Errorf("create volume %s: %w", name, err)
	}
	return nil
}

// ProbeVolume tells the root unit what it needs about a volume
// (volumes.Docker): whose it is, where its files are, and whether a
// running container uses it.
func (l *Local) ProbeVolume(ctx context.Context, name string) (volumes.DockerVolume, error) {
	res, err := l.c.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if isNotFound(err) {
		return volumes.DockerVolume{}, nil
	}
	if err != nil {
		return volumes.DockerVolume{}, err
	}
	v := res.Volume
	out := volumes.DockerVolume{
		Exists: true, Managed: v.Labels[node.LabelManaged] == "true", Driver: v.Driver,
		Options: v.Options, Mountpoint: v.Mountpoint,
	}
	running, err := l.c.ContainerList(ctx, client.ContainerListOptions{Filters: make(client.Filters).Add("volume", name)})
	if err != nil {
		return out, err
	}
	out.InUse = len(running.Items) > 0
	return out, nil
}
