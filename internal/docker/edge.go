package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

const labelEdgeSpec = "hangar.edge.spec"

// EnsureEdge creates the edge network and the Caddy container, recreating
// Caddy only when its spec changed. Caddy is Hangar's own infrastructure, so
// it is the one container allowed bind mounts (its admin socket and its
// certificates) and published ports (80/443); it still runs without
// capabilities, read-only and as the panel user.
//
// The edge network holds Caddy alone: Caddy reaches services by joining their
// project networks (ConnectEdge). Services that older versions put on the
// edge network leave it here, once Caddy reaches them through their own.
func (l *Local) EnsureEdge(ctx context.Context, spec node.EdgeSpec) error {
	if err := l.ensureCaddy(ctx, spec); err != nil {
		return err
	}
	return l.moveServicesOffEdge(ctx)
}

func (l *Local) ensureCaddy(ctx context.Context, spec node.EdgeSpec) error {
	if err := l.ensureEdgeNetwork(ctx, spec); err != nil {
		return err
	}
	// The base image is pulled only when missing: Caddy changes version when
	// edge.image changes, never by surprise.
	if _, err := l.c.ImageInspect(ctx, spec.Image); err != nil {
		if err := l.pull(ctx, spec.Image); err != nil {
			return err
		}
	}
	image, err := l.edgeImage(ctx, spec.Image)
	if err != nil {
		return err
	}
	hash := edgeHash(spec, image)
	// The project networks a replaced Caddy had joined: the new one joins
	// them again, or every site would lose its upstream.
	var projectNets []string
	res, err := l.c.ContainerInspect(ctx, node.EdgeContainer, client.ContainerInspectOptions{})
	switch {
	case err == nil:
		c := res.Container
		if c.Config == nil {
			return ErrNotManaged
		}
		if err := l.checkOwner(ctx, node.EdgeContainer, c.Config.Labels); err != nil {
			return err
		}
		if c.Config.Labels[labelEdgeSpec] == hash {
			if c.State != nil && c.State.Running {
				return nil
			}
			return l.startOnAddress(ctx, c.ID, node.EdgeNetwork, spec.CaddyIP)
		}
		projectNets = caddyProjectNetworks(c)
		if _, err := l.c.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
			return fmt.Errorf("replace caddy: %w", err)
		}
	case !isNotFound(err):
		return err
	}

	pids := int64(256)
	initProc := true
	ports := network.PortMap{}
	exposed := network.PortSet{}
	for _, p := range []string{"80/tcp", "443/tcp", "443/udp"} {
		port := network.MustParsePort(p)
		exposed[port] = struct{}{}
		ports[port] = []network.PortBinding{{HostPort: strconv.Itoa(int(port.Num()))}}
	}
	created, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: node.EdgeContainer,
		Config: &container.Config{
			Image:        image,
			User:         fmt.Sprintf("%d:%d", spec.UID, spec.GID),
			Cmd:          []string{"caddy", "run", "--config", "/run/caddy/bootstrap.json"},
			Env:          []string{"XDG_DATA_HOME=/data", "XDG_CONFIG_HOME=/config", "HOME=/tmp"},
			ExposedPorts: exposed,
			Labels: l.withInstance(map[string]string{
				node.LabelManaged: "true", "hangar.role": "edge", labelEdgeSpec: hash,
			}),
		},
		HostConfig: &container.HostConfig{
			PortBindings:   ports,
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			ReadonlyRootfs: true,
			Init:           &initProc,
			Tmpfs:          map[string]string{"/tmp": "rw,noexec,nosuid,size=16m", "/config": "rw,noexec,nosuid,size=4m"},
			Mounts: []mount.Mount{
				{Type: mount.TypeBind, Source: spec.AdminDir, Target: "/run/caddy"},
				{Type: mount.TypeBind, Source: spec.DataDir, Target: "/data"},
			},
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			LogConfig:     container.LogConfig{Type: "local", Config: map[string]string{"max-size": "50m", "max-file": "3"}},
			Resources:     container.Resources{Memory: 256 << 20, MemorySwap: 256 << 20, NanoCPUs: 1e9, PidsLimit: &pids},
			NetworkMode:   container.NetworkMode(node.EdgeNetwork),
			// Caddy sits on every project network with a domain; a network
			// namespace inherits the host's forwarding, and with it a
			// service able to craft packets could route through Caddy into
			// another project.
			Sysctls: map[string]string{"net.ipv4.ip_forward": "0"},
		},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
			node.EdgeNetwork: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: spec.CaddyIP}},
		}},
	})
	if err != nil {
		return fmt.Errorf("create caddy: %w", err)
	}
	if err := l.startOnAddress(ctx, created.ID, node.EdgeNetwork, spec.CaddyIP); err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}
	for _, n := range projectNets {
		if err := l.connectCaddy(ctx, n); err != nil && !isNotFound(err) {
			return fmt.Errorf("caddy: join %s: %w", n, err)
		}
	}
	return nil
}

// caddyProjectNetworks lists the project networks Caddy has joined.
func caddyProjectNetworks(c container.InspectResponse) []string {
	if c.NetworkSettings == nil {
		return nil
	}
	var out []string
	for name := range c.NetworkSettings.Networks {
		if name != node.EdgeNetwork && strings.HasPrefix(name, node.NetworkPrefix) {
			out = append(out, name)
		}
	}
	return out
}

// moveServicesOffEdge takes the service containers older versions joined to
// the edge network off it: on a network shared by every project with a
// domain, any of them could reach the others' ports. Caddy joins each
// service's project network first, so no site stops answering in between.
// Only this panel's containers are touched.
func (l *Local) moveServicesOffEdge(ctx context.Context) error {
	res, err := l.c.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("network", node.EdgeNetwork).Add("label", node.LabelManaged+"=true"),
	})
	if err != nil {
		return fmt.Errorf("list containers on %s: %w", node.EdgeNetwork, err)
	}
	for _, c := range res.Items {
		project := c.Labels[node.LabelProject]
		if project == "" || !l.owns(ctx, c.Labels) {
			continue // Caddy itself, or another panel's container
		}
		if err := l.connectCaddy(ctx, node.NetworkName(project)); err != nil {
			return fmt.Errorf("caddy: join the network of %s: %w", project, err)
		}
		_, err := l.c.NetworkDisconnect(ctx, node.EdgeNetwork, client.NetworkDisconnectOptions{Container: c.ID, Force: true})
		if err != nil && !isNotFound(err) {
			return fmt.Errorf("take %s off %s: %w", c.ID, node.EdgeNetwork, err)
		}
	}
	return nil
}

// startOnAddress starts a container that has the fixed address ip on
// network. Docker hands the other containers of the network addresses from
// the whole subnet and does not keep a stopped container's fixed address
// for it, so while Caddy is down a service can take Caddy's address: at boot
// Docker restarts every container at once, and Caddy's start then fails with
// "Address already in use" for as long as that service runs, which leaves
// every site down. A Hangar container holding the address leaves the
// network, the container starts, and the other one joins again with a new
// address and the same aliases.
func (l *Local) startOnAddress(ctx context.Context, id, networkName string, ip netip.Addr) error {
	moved, err := l.freeAddress(ctx, id, networkName, ip)
	if err == nil {
		_, err = l.c.ContainerStart(ctx, id, client.ContainerStartOptions{})
	}
	for _, m := range moved {
		_, cerr := l.c.NetworkConnect(context.WithoutCancel(ctx), networkName, client.NetworkConnectOptions{
			Container: m.id, EndpointConfig: &network.EndpointSettings{Aliases: m.aliases},
		})
		if cerr != nil && err == nil {
			err = fmt.Errorf("reconnect %s to %s: %w", m.name, networkName, cerr)
		}
	}
	return err
}

type movedEndpoint struct {
	id, name string
	aliases  []string
}

// freeAddress disconnects from network the container other than id that
// holds ip, returning it so the caller connects it again.
func (l *Local) freeAddress(ctx context.Context, id, networkName string, ip netip.Addr) ([]movedEndpoint, error) {
	res, err := l.c.NetworkInspect(ctx, networkName, client.NetworkInspectOptions{})
	if err != nil {
		return nil, err
	}
	var moved []movedEndpoint
	for cid, ep := range res.Network.Containers {
		if cid == id || ep.IPv4Address.Addr() != ip {
			continue
		}
		info, err := l.c.ContainerInspect(ctx, cid, client.ContainerInspectOptions{})
		if err != nil {
			return moved, err
		}
		c := info.Container
		if c.Config == nil {
			return moved, fmt.Errorf("%s holds %s on %s: %w", ep.Name, ip, networkName, ErrNotManaged)
		}
		if err := l.checkOwner(ctx, ep.Name, c.Config.Labels); err != nil {
			return moved, fmt.Errorf("%s holds %s on %s: %w", ep.Name, ip, networkName, err)
		}
		m := movedEndpoint{id: cid, name: ep.Name}
		if c.NetworkSettings != nil {
			if e := c.NetworkSettings.Networks[networkName]; e != nil {
				m.aliases = e.Aliases
			}
		}
		if _, err := l.c.NetworkDisconnect(ctx, networkName, client.NetworkDisconnectOptions{Container: cid, Force: true}); err != nil {
			return moved, fmt.Errorf("free %s on %s: %w", ip, networkName, err)
		}
		moved = append(moved, m)
	}
	return moved, nil
}

// edgeImage derives, once per base image, a copy of the Caddy image without
// the file capability on /usr/bin/caddy. The official image marks the binary
// with cap_net_bind_service; with no-new-privileges the kernel refuses to exec
// a binary whose file capabilities it cannot grant. Caddy does not need it:
// Docker already lets unprivileged processes bind low ports inside the
// container (net.ipv4.ip_unprivileged_port_start=0).
func (l *Local) edgeImage(ctx context.Context, base string) (string, error) {
	img, err := l.c.ImageInspect(ctx, base)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", base, err)
	}
	id := strings.TrimPrefix(img.ID, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}
	target := "hangar-edge-caddy:" + id
	if _, err := l.c.ImageInspect(ctx, target); err == nil {
		return target, nil
	}
	helper, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:      base,
			User:       "0:0",
			Entrypoint: []string{"setcap", "-r", "/usr/bin/caddy"},
			Labels:     l.withInstance(map[string]string{node.LabelManaged: "true", "hangar.role": "edge-build"}),
		},
		HostConfig: &container.HostConfig{
			NetworkMode: "none",
			CapDrop:     []string{"ALL"},
			CapAdd:      []string{"SETFCAP"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("prepare caddy image: %w", err)
	}
	defer func() {
		_, _ = l.c.ContainerRemove(context.WithoutCancel(ctx), helper.ID, client.ContainerRemoveOptions{Force: true})
	}()
	wait := l.c.ContainerWait(ctx, helper.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	if _, err := l.c.ContainerStart(ctx, helper.ID, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("prepare caddy image: %w", err)
	}
	select {
	case res := <-wait.Result:
		if res.StatusCode != 0 {
			return "", fmt.Errorf("prepare caddy image: setcap exited with %d", res.StatusCode)
		}
	case err := <-wait.Error:
		return "", fmt.Errorf("prepare caddy image: %w", err)
	}
	if _, err := l.c.ContainerCommit(ctx, helper.ID, client.ContainerCommitOptions{
		Reference: target,
		Comment:   "Hangar: " + base + " without file capabilities",
		Config: &container.Config{
			Entrypoint: []string{},
			Cmd:        []string{"caddy", "version"},
			Labels:     map[string]string{node.LabelManaged: "true", "hangar.role": "edge"},
		},
	}); err != nil {
		return "", fmt.Errorf("prepare caddy image: %w", err)
	}
	return target, nil
}

func (l *Local) ensureEdgeNetwork(ctx context.Context, spec node.EdgeSpec) error {
	res, err := l.c.NetworkInspect(ctx, node.EdgeNetwork, client.NetworkInspectOptions{})
	if err == nil {
		if res.Network.Labels[node.LabelManaged] != "true" {
			return fmt.Errorf("network %s exists and was not created by Hangar", node.EdgeNetwork)
		}
		return l.checkOwner(ctx, node.EdgeNetwork, res.Network.Labels)
	}
	if !isNotFound(err) {
		return err
	}
	_, err = l.c.NetworkCreate(ctx, node.EdgeNetwork, client.NetworkCreateOptions{
		Driver: "bridge",
		IPAM:   &network.IPAM{Config: []network.IPAMConfig{{Subnet: spec.Subnet, Gateway: spec.Gateway}}},
		Labels: l.withInstance(map[string]string{node.LabelManaged: "true", "hangar.role": "edge"}),
	})
	if err != nil {
		return fmt.Errorf("create edge network: %w", err)
	}
	return nil
}

func edgeHash(spec node.EdgeSpec, image string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|v2",
		image, spec.Subnet, spec.Gateway, spec.CaddyIP, spec.AdminDir, spec.DataDir, spec.UID, spec.GID)))
	return hex.EncodeToString(h[:8])
}

// ServiceAddress returns ip:port of the service container on its project
// network (reachable from the host and from Caddy).
func (l *Local) ServiceAddress(ctx context.Context, project, service string, port int) (string, error) {
	res, err := l.c.ContainerInspect(ctx, node.ContainerName(project, service), client.ContainerInspectOptions{})
	if err != nil {
		return "", err
	}
	c := res.Container
	if c.Config == nil {
		return "", ErrNotManaged
	}
	if err := l.checkOwner(ctx, node.ContainerName(project, service), c.Config.Labels); err != nil {
		return "", err
	}
	if c.NetworkSettings == nil {
		return "", errors.New("container has no network")
	}
	if ep := c.NetworkSettings.Networks[node.NetworkName(project)]; ep != nil && ep.IPAddress.IsValid() {
		return net.JoinHostPort(ep.IPAddress.String(), strconv.Itoa(port)), nil
	}
	return "", errors.New("container has no address on the project network")
}

// ConnectEdge joins Caddy to the project's network, so it reaches the
// project's services by their full name. Services never join the edge
// network themselves: there every project with a domain could reach the
// others (docs/05). Without Caddy (no edge on this server, or not created
// yet) there is nothing to join; the edge joins it when it starts.
func (l *Local) ConnectEdge(ctx context.Context, project string) error {
	err := l.connectCaddy(ctx, node.NetworkName(project))
	if errors.Is(err, errNoCaddy) {
		return nil
	}
	return err
}

var errNoCaddy = errors.New("caddy container not found")

// connectCaddy joins Caddy to a project network of this panel, if it is not
// there yet. That endpoint never provides the default gateway: Caddy keeps
// leaving through the edge network, where the panel and the firewall expect
// its fixed address.
func (l *Local) connectCaddy(ctx context.Context, networkName string) error {
	c, err := l.caddy(ctx)
	if err != nil {
		return err
	}
	if onNetwork(c, networkName) {
		return nil
	}
	res, err := l.c.NetworkInspect(ctx, networkName, client.NetworkInspectOptions{})
	if err != nil {
		return err
	}
	if res.Network.Labels[node.LabelManaged] != "true" || res.Network.Labels[node.LabelProject] == "" {
		return fmt.Errorf("network %s is not a Hangar project network", networkName)
	}
	if err := l.checkOwner(ctx, networkName, res.Network.Labels); err != nil {
		return err
	}
	_, err = l.c.NetworkConnect(ctx, networkName, client.NetworkConnectOptions{
		Container: c.ID, EndpointConfig: &network.EndpointSettings{GwPriority: -1},
	})
	if err != nil {
		// A concurrent deploy of the same project may have joined it first.
		if now, ierr := l.caddy(ctx); ierr == nil && onNetwork(now, networkName) {
			return nil
		}
	}
	return err
}

// disconnectCaddy takes Caddy off a project network that is going away.
// Docker removes a network a stopped Caddy still lists, and that Caddy would
// then fail to start, taking every site down.
func (l *Local) disconnectCaddy(ctx context.Context, networkName string) error {
	c, err := l.caddy(ctx)
	if errors.Is(err, errNoCaddy) {
		return nil
	}
	if err != nil {
		return err
	}
	if !onNetwork(c, networkName) {
		return nil
	}
	_, err = l.c.NetworkDisconnect(ctx, networkName, client.NetworkDisconnectOptions{Container: c.ID, Force: true})
	if isNotFound(err) {
		return nil
	}
	return err
}

// caddy inspects Caddy's container, refusing one Hangar did not create.
func (l *Local) caddy(ctx context.Context) (container.InspectResponse, error) {
	res, err := l.c.ContainerInspect(ctx, node.EdgeContainer, client.ContainerInspectOptions{})
	if isNotFound(err) {
		return container.InspectResponse{}, errNoCaddy
	}
	if err != nil {
		return container.InspectResponse{}, err
	}
	c := res.Container
	if c.Config == nil {
		return c, ErrNotManaged
	}
	if err := l.checkOwner(ctx, node.EdgeContainer, c.Config.Labels); err != nil {
		return c, err
	}
	return c, nil
}

func onNetwork(c container.InspectResponse, networkName string) bool {
	return c.NetworkSettings != nil && c.NetworkSettings.Networks[networkName] != nil
}
