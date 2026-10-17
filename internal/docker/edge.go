package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
func (l *Local) EnsureEdge(ctx context.Context, spec node.EdgeSpec) error {
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
	res, err := l.c.ContainerInspect(ctx, node.EdgeContainer, client.ContainerInspectOptions{})
	switch {
	case err == nil:
		c := res.Container
		if c.Config == nil || c.Config.Labels[node.LabelManaged] != "true" {
			return ErrNotManaged
		}
		if c.Config.Labels[labelEdgeSpec] == hash {
			if c.State != nil && c.State.Running {
				return nil
			}
			_, err := l.c.ContainerStart(ctx, c.ID, client.ContainerStartOptions{})
			return err
		}
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
			Labels: map[string]string{
				node.LabelManaged: "true", "hangar.role": "edge", labelEdgeSpec: hash,
			},
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
		},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
			node.EdgeNetwork: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: spec.CaddyIP}},
		}},
	})
	if err != nil {
		return fmt.Errorf("create caddy: %w", err)
	}
	if _, err := l.c.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}
	return nil
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
			Labels:     map[string]string{node.LabelManaged: "true", "hangar.role": "edge-build"},
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
		return nil
	}
	if !isNotFound(err) {
		return err
	}
	_, err = l.c.NetworkCreate(ctx, node.EdgeNetwork, client.NetworkCreateOptions{
		Driver: "bridge",
		IPAM:   &network.IPAM{Config: []network.IPAMConfig{{Subnet: spec.Subnet, Gateway: spec.Gateway}}},
		Labels: map[string]string{node.LabelManaged: "true", "hangar.role": "edge"},
	})
	if err != nil {
		return fmt.Errorf("create edge network: %w", err)
	}
	return nil
}

func edgeHash(spec node.EdgeSpec, image string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|v1",
		image, spec.Subnet, spec.Gateway, spec.CaddyIP, spec.AdminDir, spec.DataDir, spec.UID, spec.GID)))
	return hex.EncodeToString(h[:8])
}

// ServiceAddress returns ip:port of the service container, preferring the
// edge network (reachable from the host and from Caddy).
func (l *Local) ServiceAddress(ctx context.Context, project, service string, port int) (string, error) {
	res, err := l.c.ContainerInspect(ctx, node.ContainerName(project, service), client.ContainerInspectOptions{})
	if err != nil {
		return "", err
	}
	c := res.Container
	if c.Config == nil || c.Config.Labels[node.LabelManaged] != "true" {
		return "", ErrNotManaged
	}
	if c.NetworkSettings == nil {
		return "", errors.New("container has no network")
	}
	for _, name := range []string{node.EdgeNetwork, node.NetworkName(project)} {
		if ep := c.NetworkSettings.Networks[name]; ep != nil && ep.IPAddress.IsValid() {
			return net.JoinHostPort(ep.IPAddress.String(), strconv.Itoa(port)), nil
		}
	}
	return "", errors.New("container has no address on the project or edge network")
}

// ConnectEdge joins the service container to the edge network, if it is not
// there yet.
func (l *Local) ConnectEdge(ctx context.Context, project, service string) error {
	res, err := l.c.ContainerInspect(ctx, node.ContainerName(project, service), client.ContainerInspectOptions{})
	if isNotFound(err) {
		return nil // not deployed yet: the deploy joins it
	}
	if err != nil {
		return err
	}
	c := res.Container
	if c.Config == nil || c.Config.Labels[node.LabelManaged] != "true" {
		return ErrNotManaged
	}
	if c.NetworkSettings != nil && c.NetworkSettings.Networks[node.EdgeNetwork] != nil {
		return nil
	}
	_, err = l.c.NetworkConnect(ctx, node.EdgeNetwork, client.NetworkConnectOptions{Container: c.ID})
	return err
}
