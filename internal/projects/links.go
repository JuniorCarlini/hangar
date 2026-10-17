package projects

import (
	"context"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// LinkedProjects lists the projects connected to this one.
func (m *Manager) LinkedProjects(ctx context.Context, projectID string) ([]dbq.Project, error) {
	return m.q.LinkedProjects(ctx, projectID)
}

// LinkProjects connects two projects: their services see each other by
// container name (<project>_<service>), like Easypanel. Running containers
// join right away.
func (m *Manager) LinkProjects(ctx context.Context, a Actor, slugA, slugB string) error {
	return m.setLink(ctx, a, slugA, slugB, true)
}

// UnlinkProjects disconnects two projects.
func (m *Manager) UnlinkProjects(ctx context.Context, a Actor, slugA, slugB string) error {
	return m.setLink(ctx, a, slugA, slugB, false)
}

func (m *Manager) setLink(ctx context.Context, a Actor, slugA, slugB string, link bool) error {
	if err := m.requireNode(); err != nil {
		return err
	}
	pa, err := m.GetProject(ctx, slugA)
	if err != nil {
		return err
	}
	pb, err := m.GetProject(ctx, slugB)
	if err != nil {
		return err
	}
	if pa.ID == pb.ID {
		return i18n.E("project.error.link_self")
	}
	x, y := pa.ID, pb.ID
	if x > y {
		x, y = y, x
	}
	action := "project.link"
	if link {
		if err := m.q.LinkProjects(ctx, dbq.LinkProjectsParams{ProjectA: x, ProjectB: y, CreatedAt: m.now().Unix()}); err != nil {
			return err
		}
	} else {
		action = "project.unlink"
		n, err := m.q.UnlinkProjects(ctx, dbq.UnlinkProjectsParams{ProjectA: x, ProjectB: y})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
	}
	m.record(ctx, a, action, "project", pa.ID, audit.OK, map[string]any{"projects": []string{pa.Slug, pb.Slug}})
	if err := m.applyLinks(ctx, pa); err != nil {
		return err
	}
	return m.applyLinks(ctx, pb)
}

// applyLinks makes every running container of the project match its links.
func (m *Manager) applyLinks(ctx context.Context, p dbq.Project) error {
	linked, err := m.q.LinkedProjects(ctx, p.ID)
	if err != nil {
		return err
	}
	slugs := make([]string, 0, len(linked))
	for _, l := range linked {
		slugs = append(slugs, l.Slug)
	}
	svcs, err := m.q.ListServices(ctx, p.ID)
	if err != nil {
		return err
	}
	for _, s := range svcs {
		if err := m.node.SetLinked(ctx, p.Slug, s.Slug, slugs); err != nil {
			return err
		}
	}
	return nil
}
