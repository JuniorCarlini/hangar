//go:build integration

package docker

import (
	"context"
	"io"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
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

// Services with a domain must not share a network across projects: Caddy
// joins each project network instead, reaches both services, and neither
// project reaches the other. A service an older version left on the edge
// network leaves it once Caddy is on its project network.
func TestEdgeKeepsProjectsApart(t *testing.T) {
	l, ctx := setup(t)
	if _, err := l.c.ContainerInspect(ctx, node.EdgeContainer, client.ContainerInspectOptions{}); err == nil {
		t.Skipf("%s already exists on this Docker; not touching it", node.EdgeContainer)
	}
	if _, err := l.c.NetworkInspect(ctx, node.EdgeNetwork, client.NetworkInspectOptions{}); err == nil {
		t.Skipf("%s already exists on this Docker; not touching it", node.EdgeNetwork)
	}
	if err := l.pull(ctx, "busybox:1.37"); err != nil {
		t.Fatal(err)
	}
	a, b := uniq("hga"), uniq("hgb")
	cleanup(t, l, a, "web")
	cleanup(t, l, b, "web")
	for _, p := range []string{a, b} {
		if err := l.EnsureProjectNetwork(ctx, "prj_"+p, p); err != nil {
			t.Fatal(err)
		}
	}
	// Stand-ins for Caddy and the edge network: the real Caddy would publish
	// 80/443 on this machine.
	if _, err := l.c.NetworkCreate(ctx, node.EdgeNetwork, client.NetworkCreateOptions{
		Driver: "bridge",
		IPAM:   &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix("10.213.8.0/24"), Gateway: netip.MustParseAddr("10.213.8.1")}}},
		Labels: map[string]string{node.LabelManaged: "true", "hangar.role": "edge"},
	}); err != nil {
		t.Fatal(err)
	}
	caddy, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: node.EdgeContainer,
		Config: &container.Config{
			Image: "busybox:1.37", Cmd: []string{"sleep", "3600"},
			Labels: map[string]string{node.LabelManaged: "true", "hangar.role": "edge"},
		},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(node.EdgeNetwork)},
	})
	if err != nil {
		_, _ = l.c.NetworkRemove(context.Background(), node.EdgeNetwork, client.NetworkRemoveOptions{})
		t.Fatal(err)
	}
	// Registered after the project cleanups, so it runs before them: the
	// project networks go once Caddy left them (RemoveProjectNetwork).
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = l.c.ContainerRemove(bg, caddy.ID, client.ContainerRemoveOptions{Force: true})
		_, _ = l.c.NetworkRemove(bg, node.EdgeNetwork, client.NetworkRemoveOptions{})
	})
	if _, err := l.c.ContainerStart(ctx, caddy.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{a, b} {
		s := spec(p, "web", "nginx:1.31-alpine")
		s.Edge = true
		if _, err := l.Deploy(ctx, s, node.DeployOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// An older version put b's service on the edge network too.
	webA, webB := node.ContainerName(a, "web"), node.ContainerName(b, "web")
	if _, err := l.c.NetworkConnect(ctx, node.EdgeNetwork, client.NetworkConnectOptions{
		Container: webB, EndpointConfig: &network.EndpointSettings{Aliases: []string{webB}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.moveServicesOffEdge(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{webA, webB} {
		info, err := l.c.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if info.Container.NetworkSettings.Networks[node.EdgeNetwork] != nil {
			t.Errorf("%s is on %s", name, node.EdgeNetwork)
		}
	}
	time.Sleep(2 * time.Second)

	reaches := func(from, target string) bool {
		t.Helper()
		var out strings.Builder
		ex, err := l.c.ExecCreate(ctx, from, client.ExecCreateOptions{
			Cmd:          []string{"sh", "-c", "wget -q -T 3 -O - http://" + target + "/ >/dev/null && echo REACHED || echo NOT_REACHED"},
			AttachStdout: true, AttachStderr: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		att, err := l.c.ExecAttach(ctx, ex.ID, client.ExecAttachOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer att.Close()
		_, _ = stdcopy.StdCopy(&out, io.Discard, att.Reader)
		return strings.Contains(out.String(), "REACHED") && !strings.Contains(out.String(), "NOT_REACHED")
	}
	for _, name := range []string{webA, webB} {
		if !reaches(caddy.ID, name) {
			t.Errorf("caddy should reach %s", name)
		}
	}
	// The services with a domain themselves, which used to share the edge
	// network.
	if reaches(webB, webA) || reaches(webA, webB) {
		t.Error("a service with a domain reaches another project's service by name")
	}
	// By address, what keeps two bridges apart is Docker's own isolation
	// (iptables on Linux); Docker Desktop and OrbStack route between bridges,
	// with or without Hangar, so it is only checked on Linux.
	if runtime.GOOS == "linux" {
		addrA, err := l.ServiceAddress(ctx, a, "web", 80)
		if err != nil {
			t.Fatal(err)
		}
		if reaches(webB, addrA) {
			t.Errorf("%s reaches %s at %s", webB, webA, addrA)
		}
	}
}
