package docker

import (
	"context"
	"fmt"
	"io"

	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// ContainerImage returns the ID and size of the image the Hangar container
// runs: the image it was created from, not whatever its tag points to now.
func (l *Local) ContainerImage(ctx context.Context, name string) (string, int64, error) {
	res, err := l.c.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if isNotFound(err) {
		return "", 0, errNoContainer
	}
	if err != nil {
		return "", 0, err
	}
	c := res.Container
	if c.Config == nil || c.Config.Labels[node.LabelManaged] != "true" {
		return "", 0, ErrNotManaged
	}
	img, err := l.c.ImageInspect(ctx, c.Image)
	if err != nil {
		return "", 0, fmt.Errorf("inspect image %s: %w", c.Image, err)
	}
	return img.ID, img.Size, nil
}

// SaveImage writes the image as a `docker save` tarball, only for its own
// platform (a multi-platform image in the containerd store would otherwise
// fail on the platforms that were never pulled).
func (l *Local) SaveImage(ctx context.Context, id string, w io.Writer) error {
	img, err := l.c.ImageInspect(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect image %s: %w", id, err)
	}
	var opts []client.ImageSaveOption
	if img.Os != "" && img.Architecture != "" {
		opts = append(opts, client.ImageSaveWithPlatforms(ocispec.Platform{OS: img.Os, Architecture: img.Architecture, Variant: img.Variant}))
	}
	rc, err := l.c.ImageSave(ctx, []string{id}, opts...)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	_, err = io.Copy(w, rc)
	return err
}
