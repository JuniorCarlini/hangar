package docker

import (
	"context"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
)

// Several panels may share one Docker daemon (a development panel next to
// another, two installs on one lab machine). Names alone do not tell their
// objects apart: two panels with a project "shop" and a service "web" both
// call the container shop_web. Every container, network and volume a panel
// creates therefore carries its instance id (node.LabelInstance), and a
// panel only acts on objects with its own id.
//
// Objects created before the label existed have no id. They are adopted
// when their project and service ids (random, see internal/ids) exist in
// this panel's database, so an upgrade keeps every running service. Shared
// Hangar infrastructure without a project (the edge proxy and its network)
// is adopted as it is: only one panel can hold ports 80 and 443 anyway.

// AdoptFunc reports whether this panel's database knows the project (and,
// when serviceID is not empty, the service in it).
type AdoptFunc func(ctx context.Context, projectID, serviceID string) bool

// SetInstance makes the node act only on objects labeled with id, adopting
// unlabeled ones that adopt recognizes. Call it once, right after New and
// before anything else uses the node. Without it (tests, tools that only
// read) every Hangar object is treated as this panel's, as before.
func (l *Local) SetInstance(id string, adopt AdoptFunc) {
	l.instance, l.adopt = id, adopt
}

// Instance is the id set by SetInstance.
func (l *Local) Instance() string { return l.instance }

// otherInstance names an object that belongs to another panel.
func otherInstance(name string) error {
	return &i18n.Error{Key: "docker.error.other_instance", Args: []any{"name", name}}
}

// checkOwner says whether the object called name with these labels is this
// panel's: nil when it is, ErrNotManaged when Hangar did not create it, and
// a clear error naming it when another panel did.
func (l *Local) checkOwner(ctx context.Context, name string, labels map[string]string) error {
	if labels[node.LabelManaged] != "true" {
		return ErrNotManaged
	}
	if l.instance == "" {
		return nil
	}
	switch id := labels[node.LabelInstance]; {
	case id == l.instance:
		return nil
	case id != "":
		return otherInstance(name)
	}
	// Created before instance ids: adopt it when this panel knows it.
	projectID := labels[node.LabelProjectID]
	if projectID == "" || l.adopt == nil {
		return nil // Hangar's own infrastructure, or no database to ask
	}
	key := projectID + "|" + labels[node.LabelServiceID]
	if _, ok := l.adopted.Load(key); ok {
		return nil
	}
	if l.adopt(ctx, projectID, labels[node.LabelServiceID]) {
		// Ids are never reused: once known, always known (listings ask
		// for every container every few seconds).
		l.adopted.Store(key, struct{}{})
		return nil
	}
	return otherInstance(name)
}

// owns is checkOwner as a yes or no, for listings.
func (l *Local) owns(ctx context.Context, labels map[string]string) bool {
	return l.checkOwner(ctx, "", labels) == nil
}

// withInstance adds this panel's id to labels (when one is set).
func (l *Local) withInstance(labels map[string]string) map[string]string {
	if l.instance != "" {
		labels[node.LabelInstance] = l.instance
	}
	return labels
}
