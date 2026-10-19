//go:build integration

package docker

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// After a reboot Docker restarts every container at once and a service on
// the edge network can take Caddy's fixed address; Caddy must still start,
// and the service must stay reachable on the network by its alias.
func TestStartOnAddressFreesTakenAddress(t *testing.T) {
	l, ctx := setup(t)
	name := uniq("hgedge")
	subnet := netip.MustParsePrefix("10.213.7.0/24")
	gw := netip.MustParseAddr("10.213.7.1")
	fixed := netip.MustParseAddr("10.213.7.2")
	if _, err := l.c.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
		IPAM:   &network.IPAM{Config: []network.IPAMConfig{{Subnet: subnet, Gateway: gw}}},
		Labels: map[string]string{node.LabelManaged: "true"},
	}); err != nil {
		t.Fatal(err)
	}
	var ids []string
	t.Cleanup(func() {
		bg := context.Background()
		for _, id := range ids {
			_, _ = l.c.ContainerRemove(bg, id, client.ContainerRemoveOptions{Force: true})
		}
		_, _ = l.c.NetworkRemove(bg, name, client.NetworkRemoveOptions{})
	})
	create := func(cname string, ep *network.EndpointSettings) string {
		t.Helper()
		res, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{
			Name: cname,
			Config: &container.Config{
				Image: "busybox:1.37", Cmd: []string{"sleep", "3600"},
				Labels: map[string]string{node.LabelManaged: "true"},
			},
			HostConfig:       &container.HostConfig{NetworkMode: container.NetworkMode(name)},
			NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{name: ep}},
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, res.ID)
		return res.ID
	}
	if err := l.pull(ctx, "busybox:1.37"); err != nil {
		t.Fatal(err)
	}
	caddy := create(name+"_caddy", &network.EndpointSettings{IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: fixed}})
	svc := create(name+"_web", &network.EndpointSettings{Aliases: []string{name + "_web"}})
	// Caddy is stopped, so the service gets the first free address: Caddy's.
	if _, err := l.c.ContainerStart(ctx, svc, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := addrOn(t, l, ctx, svc, name); got != fixed {
		t.Fatalf("setup: service got %s, want it to take %s", got, fixed)
	}

	if err := l.startOnAddress(ctx, caddy, name, fixed); err != nil {
		t.Fatal(err)
	}
	if got := addrOn(t, l, ctx, caddy, name); got != fixed {
		t.Fatalf("caddy on %s, want %s", got, fixed)
	}
	got := addrOn(t, l, ctx, svc, name)
	if !got.IsValid() || got == fixed {
		t.Fatalf("service on %v after the move, want another address", got)
	}
	info, err := l.c.ContainerInspect(ctx, svc, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ep := info.Container.NetworkSettings.Networks[name]; ep == nil || !slices.Contains(ep.Aliases, name+"_web") {
		t.Fatalf("service lost its alias: %+v", ep)
	}
}

func addrOn(t *testing.T, l *Local, ctx context.Context, id, networkName string) netip.Addr {
	t.Helper()
	info, err := l.c.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Container.NetworkSettings == nil || info.Container.NetworkSettings.Networks[networkName] == nil {
		return netip.Addr{}
	}
	return info.Container.NetworkSettings.Networks[networkName].IPAddress
}
