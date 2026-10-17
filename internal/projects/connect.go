package projects

import (
	"context"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
)

// preferredExports are the connection strings a new service hands to the
// one it was dragged from, best first.
var preferredExports = []string{"DATABASE_URL", "REDIS_URL"}

// ConnectNew wires a service just created by dragging a line out of another
// one: the origin gets a variable that references the new service's
// connection string (DATABASE_URL=${{db.DATABASE_URL}}), applied at its next
// deploy. A service without one (an app from an image) is left unconnected;
// a variable the origin already has is never overwritten. It returns the
// variable it set ("" = none).
func (m *Manager) ConnectNew(ctx context.Context, a Actor, projectSlug, fromSlug, toSlug string) (string, error) {
	if fromSlug == "" || fromSlug == toSlug {
		return "", nil
	}
	_, from, err := m.GetService(ctx, projectSlug, fromSlug)
	if err != nil {
		return "", err
	}
	_, to, err := m.GetService(ctx, projectSlug, toSlug)
	if err != nil {
		return "", err
	}
	exps, err := m.q.ListExports(ctx, to.ID)
	if err != nil {
		return "", err
	}
	key := ""
	for _, want := range preferredExports {
		for _, e := range exps {
			if e.Key == want {
				key = want
			}
		}
		if key != "" {
			break
		}
	}
	if key == "" {
		for _, e := range exps {
			if strings.HasSuffix(e.Key, "_URL") {
				key = e.Key
				break
			}
		}
	}
	if key == "" {
		return "", nil
	}
	env, err := m.q.ListEnv(ctx, from.ID)
	if err != nil {
		return "", err
	}
	for _, e := range env {
		if e.Key == key {
			return "", nil
		}
	}
	if err := m.SetEnv(ctx, a, from.ID, key, "${{"+to.Slug+"."+key+"}}", false); err != nil {
		return "", err
	}
	m.record(ctx, a, "service.connect", "service", from.ID, audit.OK, map[string]any{"to": to.Slug, "key": key})
	return key, nil
}
