package projects

import (
	"context"
	"regexp"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Errors of an image change.
var (
	ErrImageGit  = &i18n.Error{Key: "image_tag.error.git"}
	ErrImageTag  = &i18n.Error{Key: "image_tag.error.tag"}
	ErrImageSame = &i18n.Error{Key: "image_tag.error.same"}
	// ErrImageChanged: someone changed the service's image meanwhile.
	ErrImageChanged = &i18n.Error{Key: "image_tag.error.changed"}
)

// tagRE is a Docker tag: what goes after the last ":" of an image.
var tagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// SplitImage cuts an image reference into its repository and tag
// ("nginx:1.29-alpine" → "nginx", "1.29-alpine"; a registry port is not a
// tag). A reference pinned by digest has no tag to change and is refused by
// the callers.
func SplitImage(image string) (repo, tag string) {
	image = strings.TrimSpace(image)
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[:i], image[i+1:]
	}
	return image, ""
}

// ChangeImageTag points a service run from an image at another tag of the
// same repository and deploys it: only the tag can change, so this never
// swaps what the service is (another image would need the same trust as
// creating a service). The deploy keeps the previous version serving when
// the new one does not become healthy (rolling), or starts it again
// (recreate, under the same rules as any deploy); either way the service
// goes back to the previous tag, so the next deploy does not retry the
// broken one.
func (m *Manager) ChangeImageTag(ctx context.Context, a Actor, projectSlug, serviceSlug, tag string) (string, error) {
	if err := m.requireNode(); err != nil {
		return "", err
	}
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return "", err
	}
	if _, isGit, err := m.gitRow(ctx, s.ID); err != nil {
		return "", err
	} else if isGit {
		return "", ErrImageGit
	}
	tag = strings.TrimSpace(tag)
	repo, cur := SplitImage(s.Image)
	if strings.Contains(s.Image, "@") || !tagRE.MatchString(tag) {
		return "", ErrImageTag
	}
	if tag == cur {
		return "", ErrImageSame
	}
	image := repo + ":" + tag
	if !node.ImageRE.MatchString(image) {
		return "", ErrImageTag
	}
	n, err := m.q.SetServiceImage(ctx, dbq.SetServiceImageParams{Image: image, UpdatedAt: m.now().Unix(), ID: s.ID, OldImage: s.Image})
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", ErrImageChanged
	}
	m.record(ctx, a, "service.image.change", "service", s.ID, audit.OK, map[string]any{"from": s.Image, "to": image})
	id, err := m.deploy(ctx, a, projectSlug, serviceSlug, deployRequest{trigger: "image", revertImage: s.Image})
	if err != nil {
		// Nothing was deployed (another deploy runs, Docker is gone): the
		// service keeps the image it runs.
		m.revertImage(ctx, a, s.ID, image, s.Image, "")
		return "", err
	}
	return id, nil
}

// revertImage puts the previous image back after a failed image change,
// unless the service was changed again meanwhile.
func (m *Manager) revertImage(ctx context.Context, a Actor, serviceID, failed, previous, deployID string) {
	n, err := m.q.SetServiceImage(ctx, dbq.SetServiceImageParams{Image: previous, UpdatedAt: m.now().Unix(), ID: serviceID, OldImage: failed})
	if err != nil {
		m.log.Error("revert service image", "service", serviceID, "error", err)
		return
	}
	if n > 0 {
		m.record(ctx, a, "service.image.revert", "service", serviceID, audit.OK, map[string]any{"from": failed, "to": previous, "deploy": deployID})
	}
}
