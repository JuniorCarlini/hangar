package projects

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

type specExtras struct {
	volumes []node.Volume
	health  *node.Health
	capAdd  []string
	ports   []node.Port
	linked  []string
}

// specExtras reads what a deploy needs beyond the service row: volumes,
// healthcheck, capabilities, published ports and linked projects.
func (m *Manager) specExtras(ctx context.Context, p dbq.Project, s dbq.Service) (specExtras, error) {
	var x specExtras
	vols, err := m.q.ListVolumes(ctx, s.ID)
	if err != nil {
		return x, err
	}
	for _, v := range vols {
		x.volumes = append(x.volumes, node.Volume{
			Name: v.Name, Path: v.Path, ReadOnly: v.ReadOnly == 1,
			Service: v.OwnerSlug, ServiceID: v.OwnerServiceID.String,
		})
	}
	if s.HealthJson != "" {
		x.health = &node.Health{}
		if err := json.Unmarshal([]byte(s.HealthJson), x.health); err != nil {
			return x, fmt.Errorf("healthcheck: %w", err)
		}
	}
	if s.CapAddJson != "" {
		if err := json.Unmarshal([]byte(s.CapAddJson), &x.capAdd); err != nil {
			return x, fmt.Errorf("capabilities: %w", err)
		}
	}
	ports, err := m.q.ListPorts(ctx, s.ID)
	if err != nil {
		return x, err
	}
	for _, pt := range ports {
		np := node.Port{HostPort: int(pt.HostPort), ContainerPort: int(pt.ContainerPort), Protocol: pt.Protocol}
		if pt.Access == AccessLocalhost {
			np.HostIP = netip.MustParseAddr("127.0.0.1")
		}
		x.ports = append(x.ports, np)
	}
	linked, err := m.q.LinkedProjects(ctx, p.ID)
	if err != nil {
		return x, err
	}
	for _, l := range linked {
		x.linked = append(x.linked, l.Slug)
	}
	return x, nil
}
