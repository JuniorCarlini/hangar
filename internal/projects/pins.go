package projects

import (
	"context"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// PinProject pins a project to the top of the person's sidebar, or unpins
// it. Pinning is personal and changes nothing in the project.
func (m *Manager) PinProject(ctx context.Context, userID, projectSlug string, on bool) error {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return err
	}
	if on {
		return m.q.PinProject(ctx, dbq.PinProjectParams{UserID: userID, ProjectID: p.ID, PinnedAt: m.now().UnixNano()})
	}
	return m.q.UnpinProject(ctx, dbq.UnpinProjectParams{UserID: userID, ProjectID: p.ID})
}

// PinnedProjects returns the person's pinned projects: their position in
// the order they were pinned, by project id.
func (m *Manager) PinnedProjects(ctx context.Context, userID string) (map[string]int, error) {
	ids, err := m.q.ListPinnedProjects(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(ids))
	for i, id := range ids {
		out[id] = i
	}
	return out, nil
}
