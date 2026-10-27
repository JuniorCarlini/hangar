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
	ErrImage     = &i18n.Error{Key: "image_tag.error.image"}
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
// same repository and deploys it (the updates page: a newer tag that fixes
// a vulnerability). See ChangeImage.
func (m *Manager) ChangeImageTag(ctx context.Context, a Actor, projectSlug, serviceSlug, tag string) (string, error) {
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return "", err
	}
	tag = strings.TrimSpace(tag)
	repo, _ := SplitImage(s.Image)
	if strings.Contains(s.Image, "@") || !tagRE.MatchString(tag) || !node.ImageRE.MatchString(repo+":"+tag) {
		return "", ErrImageTag
	}
	return m.ChangeImage(ctx, a, projectSlug, serviceSlug, repo+":"+tag)
}

// ChangeImage points a service run from an image at another image
// reference (usually another tag, but the repository may change too) and
// deploys it. Swapping what a service runs takes the same trust as
// creating one, which the route asks for (admin and sudo). The deploy
// keeps the previous version serving when the new one does not become
// healthy (rolling), or starts it again (recreate, under the same rules as
// any deploy); either way the service goes back to the previous image, so
// the next deploy does not retry the broken one.
func (m *Manager) ChangeImage(ctx context.Context, a Actor, projectSlug, serviceSlug, image string) (string, error) {
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
	image = strings.TrimSpace(image)
	if !node.ImageRE.MatchString(image) {
		return "", ErrImage
	}
	if image == s.Image {
		return "", ErrImageSame
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
