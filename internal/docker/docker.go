// Package docker implements node.Node on top of the local Docker Engine. It is
// the only package that imports the Docker SDK and the only place where the
// container hardening (docs/05) is applied, so no service starts without it.
package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
)

// ErrNotManaged protects containers Hangar did not create: a container with
// the requested name exists but lacks Hangar's label.
var ErrNotManaged = &i18n.Error{Key: "docker.error.not_managed"}

// Local implements node.Node on this machine's Docker.
type Local struct {
	c *client.Client
	// instance and adopt decide which Hangar objects are this panel's
	// (owner.go); adopted caches the positive answers.
	instance string
	adopt    AdoptFunc
	adopted  sync.Map
	// volumeLocks holds one mutex per volume name: the services sharing a
	// volume may deploy at the same time, and only one may create it.
	volumeLocks sync.Map
}

// New connects to Docker (DOCKER_HOST or the default socket).
func New(ctx context.Context, host string) (*Local, error) {
	opts := []client.Opt{client.FromEnv}
	if host != "" {
		opts = append(opts, client.WithHost(host))
	}
	c, err := client.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("docker: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := c.Ping(pingCtx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("docker is not responding: %w", err)
	}
	return &Local{c: c}, nil
}

// Close closes the connection.
func (l *Local) Close() error { return l.c.Close() }

var (
	_ node.Node          = (*Local)(nil)
	_ node.VolumeEnsurer = (*Local)(nil)
)

func (l *Local) managedLabels(projectID, project string) map[string]string {
	return l.withInstance(map[string]string{node.LabelManaged: "true", node.LabelProjectID: projectID, node.LabelProject: project})
}

// EnsureProjectNetwork creates the project's network if it does not exist.
// Different projects live on different networks and cannot reach each other;
// only Caddy joins the networks of projects with a domain (ConnectEdge).
func (l *Local) EnsureProjectNetwork(ctx context.Context, projectID, project string) error {
	name := node.NetworkName(project)
	res, err := l.c.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if err == nil {
		if res.Network.Labels[node.LabelManaged] != "true" {
			return fmt.Errorf("network %s exists and was not created by Hangar", name)
		}
		return l.checkOwner(ctx, name, res.Network.Labels)
	}
	if !isNotFound(err) {
		return fmt.Errorf("inspect network %s: %w", name, err)
	}
	_, err = l.c.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: l.managedLabels(projectID, project),
	})
	if err != nil {
		return fmt.Errorf("create network %s: %w", name, err)
	}
	return nil
}

// RemoveProjectNetwork removes the project's network (only if Hangar owns it).
func (l *Local) RemoveProjectNetwork(ctx context.Context, project string) error {
	name := node.NetworkName(project)
	res, err := l.c.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if res.Network.Labels[node.LabelManaged] != "true" {
		return fmt.Errorf("network %s was not created by Hangar", name)
	}
	if err := l.checkOwner(ctx, name, res.Network.Labels); err != nil {
		return err
	}
	if err := l.disconnectCaddy(ctx, name); err != nil {
		return fmt.Errorf("caddy: leave %s: %w", name, err)
	}
	_, err = l.c.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	return err
}

// createContainer creates (without starting) a service container named name
// running image, with the hardening from docs/05.
func (l *Local) createContainer(ctx context.Context, spec node.ServiceSpec, name, image string) (string, error) {
	labels := l.managedLabels(spec.ProjectID, spec.Project)
	labels[node.LabelServiceID] = spec.ServiceID
	labels[node.LabelService] = spec.Service
	labels[node.LabelDeployment] = spec.Deployment

	cfg := &container.Config{
		Image:  image,
		Env:    envList(spec.Env),
		Labels: labels,
	}
	if len(spec.Command) > 0 {
		cfg.Cmd = spec.Command
	}
	// Kept on the container: every stop of it (a deploy, the stop button,
	// a delete, Docker shutting down) waits the same.
	grace := int(node.DefaultStopGrace / time.Second)
	if spec.StopGrace > 0 {
		grace = int(spec.StopGrace / time.Second)
	}
	cfg.StopTimeout = &grace
	if h := spec.Health; h != nil {
		cfg.Healthcheck = &container.HealthConfig{
			Test: h.Test, Interval: h.Interval, Timeout: h.Timeout, StartPeriod: h.StartPeriod, Retries: h.Retries,
		}
	}
	if len(spec.Ports) > 0 {
		cfg.ExposedPorts = network.PortSet{}
	}
	for _, p := range spec.Ports {
		cfg.ExposedPorts[containerPort(p)] = struct{}{}
	}
	hc := hostConfig(spec)
	for _, v := range spec.Volumes {
		name, err := l.ensureVolume(ctx, spec, v)
		if err != nil {
			return "", err
		}
		hc.Mounts = append(hc.Mounts, mount.Mount{Type: mount.TypeVolume, Source: name, Target: v.Path, ReadOnly: v.ReadOnly})
	}
	// The full name is also an alias on every network: during a zero-downtime
	// deploy the old and the new container answer for it together.
	full := node.ContainerName(spec.Project, spec.Service)
	endpoints := map[string]*network.EndpointSettings{
		node.NetworkName(spec.Project): {Aliases: []string{spec.Service, full}},
	}
	// No endpoint on the edge network even with a domain: Caddy joins the
	// project network instead (ConnectEdge), so a shared network never lets
	// one project reach another.
	// Linked projects see this container by its full name (<project>_<service>),
	// never by the short alias, so names do not clash across projects.
	for _, linked := range spec.Linked {
		endpoints[node.NetworkName(linked)] = &network.EndpointSettings{Aliases: []string{full}}
	}
	res, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:             name,
		Config:           cfg,
		HostConfig:       hc,
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: endpoints},
	})
	if err != nil {
		return "", fmt.Errorf("create container: %w", err)
	}
	return res.ID, nil
}

// hostConfig holds the protections from docs/05. Nothing here is optional in
// the UI: privileged, docker.sock and bind mounts simply do not exist.
// withKill adds KILL to the capabilities: the container's init (docker-init,
// PID 1, root) forwards the stop signal to the app, and most images drop to
// an unprivileged user (postgres, redis, mariadb…). Without KILL that
// forward fails, init exits and the app is killed without its chance to
// shut down cleanly. KILL only reaches processes of the same container (its
// own PID namespace).
func withKill(caps []string) []string {
	for _, c := range caps {
		if strings.EqualFold(strings.TrimPrefix(strings.ToUpper(c), "CAP_"), "KILL") {
			return caps
		}
	}
	return append(slices.Clone(caps), "KILL")
}

func hostConfig(spec node.ServiceSpec) *container.HostConfig {
	initProc := true
	pids := spec.PidsLimit
	caps := spec.CapAdd
	if caps == nil {
		caps = node.DefaultCaps
	}
	caps = withKill(caps)
	hc := &container.HostConfig{
		Privileged:    false,
		CapDrop:       []string{"ALL"},
		CapAdd:        caps,
		SecurityOpt:   []string{"no-new-privileges:true"},
		Init:          &initProc,
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		LogConfig: container.LogConfig{Type: "local", Config: map[string]string{
			"max-size": "50m", "max-file": "3",
		}},
		Resources: container.Resources{
			Memory:     spec.MemoryBytes,
			MemorySwap: spec.MemoryBytes, // no swap: hitting the limit is a visible OOM, not slowness
			NanoCPUs:   spec.NanoCPUs,
			PidsLimit:  &pids,
		},
		ReadonlyRootfs: spec.ReadOnly,
		NetworkMode:    container.NetworkMode(node.NetworkName(spec.Project)),
	}
	if spec.ReadOnly {
		hc.Tmpfs = map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"}
	}
	if len(spec.Ports) > 0 {
		hc.PortBindings = network.PortMap{}
	}
	for _, p := range spec.Ports {
		b := network.PortBinding{HostPort: strconv.Itoa(p.HostPort)}
		if p.HostIP.IsValid() {
			b.HostIP = p.HostIP
		}
		cp := containerPort(p)
		hc.PortBindings[cp] = append(hc.PortBindings[cp], b)
	}
	return hc
}

func containerPort(p node.Port) network.Port {
	return network.MustParsePort(strconv.Itoa(p.ContainerPort) + "/" + p.Protocol)
}

// labelChownPending marks a volume created before its owner's image was
// here (by a service that shares it, or ahead of the deploys): the owner's
// deploy gives it to the image's user (ownVolume) instead.
const labelChownPending = "hangar.volume.chown-pending"

// ensureVolume creates the named volume, or checks that an existing one
// with that name is this panel's. A volume shared with another service of
// the project carries the owner's name and labels, whichever service
// creates it.
func (l *Local) ensureVolume(ctx context.Context, spec node.ServiceSpec, v node.Volume) (string, error) {
	owner, ownerID := spec.VolumeOwner(v)
	name := node.VolumeName(spec.Project, owner, v.Name)
	mu, _ := l.volumeLocks.LoadOrStore(name, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	res, err := l.c.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if err == nil {
		if res.Volume.Labels[node.LabelManaged] != "true" {
			return "", fmt.Errorf("volume %s exists and was not created by Hangar", name)
		}
		if err := l.checkOwner(ctx, name, res.Volume.Labels); err != nil {
			return "", err
		}
		// A volume with a size limit must already be on its disk image:
		// a plain one here means its data was not moved yet, and the app
		// must not start on it.
		if v.Device != "" && res.Volume.Options["device"] != v.Device {
			return "", fmt.Errorf("volume %s is not on its size-limited disk yet", name)
		}
		// Labels cannot change, so the mark stays: chown only touches the
		// volume's top folder, and doing it again gives the same result.
		if res.Volume.Labels[labelChownPending] == "true" && v.Service == "" && l.imageHere(ctx, spec.Image) {
			l.ownVolume(ctx, spec.Image, name)
		}
		return name, nil
	}
	if !isNotFound(err) {
		return "", err
	}
	labels := l.managedLabels(spec.ProjectID, spec.Project)
	labels[node.LabelServiceID] = ownerID
	labels[node.LabelService] = owner
	// Only the owner's image says who the files belong to.
	chownNow := v.Service == "" && l.imageHere(ctx, spec.Image)
	if !chownNow {
		labels[labelChownPending] = "true"
	}
	if _, err := l.c.VolumeCreate(ctx, client.VolumeCreateOptions{Name: name, Driver: "local", DriverOpts: bindOptions(v.Device), Labels: labels}); err != nil {
		return "", fmt.Errorf("create volume %s: %w", name, err)
	}
	if chownNow {
		l.ownVolume(ctx, spec.Image, name)
	}
	return name, nil
}

// imageHere reports whether the image is in the local store.
func (l *Local) imageHere(ctx context.Context, image string) bool {
	_, err := l.c.ImageInspect(ctx, image)
	return err == nil
}

// EnsureVolumes creates the volumes spec owns before any service deploys
// (node.VolumeEnsurer): the services of a template that share a volume
// deploy at the same time, and the volume must carry the owner's labels.
func (l *Local) EnsureVolumes(ctx context.Context, spec node.ServiceSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	for _, v := range spec.Volumes {
		if v.Service != "" {
			continue
		}
		if _, err := l.ensureVolume(ctx, spec, v); err != nil {
			return err
		}
	}
	return nil
}

// ownVolume gives a new, empty volume to the user the image runs as: Docker
// creates it owned by root, and an app running as www-data could not write
// its uploads there. Done once, by a helper with no network and only the
// CHOWN capability. A failure (an image without chown, say) is only logged:
// the app may still manage, and the deploy should not stop for it.
func (l *Local) ownVolume(ctx context.Context, image, volume string) {
	img, err := l.c.ImageInspect(ctx, image)
	if err != nil || img.Config == nil {
		return
	}
	user := strings.TrimSpace(img.Config.User)
	if user == "" || user == "root" || user == "0" || strings.HasPrefix(user, "0:") {
		return
	}
	owner := user
	if _, err := strconv.Atoi(owner); err != nil && !strings.Contains(owner, ":") {
		owner += ":" // a user name: also its login group (chown refuses "1000:")
	}
	cfg := &container.Config{
		Image: image, User: "0:0", Entrypoint: []string{"chown", owner, "/mnt/volume"},
		Labels: l.withInstance(map[string]string{node.LabelManaged: "true", LabelTask: "true"}),
	}
	hc := &container.HostConfig{
		NetworkMode: "none", CapDrop: []string{"ALL"}, CapAdd: []string{"CHOWN"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Mounts:      []mount.Mount{{Type: mount.TypeVolume, Source: volume, Target: "/mnt/volume"}},
	}
	res, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{Config: cfg, HostConfig: hc})
	if err != nil {
		slog.Warn("give the volume to the app's user", "volume", volume, "error", err)
		return
	}
	defer func() {
		_, _ = l.c.ContainerRemove(context.WithoutCancel(ctx), res.ID, client.ContainerRemoveOptions{Force: true})
	}()
	wait := l.c.ContainerWait(ctx, res.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	if _, err := l.c.ContainerStart(ctx, res.ID, client.ContainerStartOptions{}); err != nil {
		slog.Warn("give the volume to the app's user", "volume", volume, "error", err)
		return
	}
	select {
	case r := <-wait.Result:
		if r.StatusCode != 0 {
			slog.Warn("give the volume to the app's user", "volume", volume, "user", user, "exit", r.StatusCode)
		}
	case err := <-wait.Error:
		slog.Warn("give the volume to the app's user", "volume", volume, "error", err)
	case <-ctx.Done():
	}
}

func envList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// pull fetches the image. An image that exists only locally (built on this
// server) is used as is when the registry does not have it.
func (l *Local) pull(ctx context.Context, image string) error {
	err := l.pullRemote(ctx, image)
	if err == nil {
		return nil
	}
	if _, ierr := l.c.ImageInspect(ctx, image); ierr == nil {
		return nil
	}
	return err
}

func (l *Local) pullRemote(ctx context.Context, image string) error {
	resp, err := l.c.ImagePull(ctx, image, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull image %s: %w", image, err)
	}
	defer func() { _ = resp.Close() }()
	if err := resp.Wait(ctx); err != nil {
		return fmt.Errorf("pull image %s: %w", image, err)
	}
	return nil
}

var errNoContainer = errors.New("container does not exist")

// inspectManaged returns the ID of the Hangar container with this name.
func (l *Local) inspectManaged(ctx context.Context, name string) (string, error) {
	res, err := l.c.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if isNotFound(err) {
		return "", errNoContainer
	}
	if err != nil {
		return "", err
	}
	if res.Container.Config == nil {
		return "", ErrNotManaged
	}
	if err := l.checkOwner(ctx, strings.TrimPrefix(res.Container.Name, "/"), res.Container.Config.Labels); err != nil {
		return "", err
	}
	return res.Container.ID, nil
}

func (l *Local) managedID(ctx context.Context, project, service string) (string, error) {
	return l.inspectManaged(ctx, node.ContainerName(project, service))
}

// Start starts the stopped container.
func (l *Local) Start(ctx context.Context, project, service string) error {
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return err
	}
	_, err = l.c.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}

// Stop stops the container: SIGTERM, then its grace period (stopTimeout)
// before it is killed.
func (l *Local) Stop(ctx context.Context, project, service string) error {
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return err
	}
	_, err = l.c.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: l.stopTimeout(ctx, id)})
	return err
}

// stopTimeout is the grace period kept on the container when it was
// created (the service's stop_grace_period), or the default for containers
// from before it was kept there.
func (l *Local) stopTimeout(ctx context.Context, id string) *int {
	secs := int(node.DefaultStopGrace / time.Second)
	res, err := l.c.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err == nil && res.Container.Config != nil && res.Container.Config.StopTimeout != nil {
		if v := *res.Container.Config.StopTimeout; v >= 0 && v <= int(node.MaxStopGrace/time.Second) {
			secs = v
		}
	}
	return &secs
}

var _ node.Pauser = (*Local)(nil)

// Pause freezes the container's processes (node.Pauser).
func (l *Local) Pause(ctx context.Context, project, service string) error {
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return err
	}
	_, err = l.c.ContainerPause(ctx, id, client.ContainerPauseOptions{})
	return err
}

// Unpause lets a paused container's processes run again.
func (l *Local) Unpause(ctx context.Context, project, service string) error {
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return err
	}
	_, err = l.c.ContainerUnpause(ctx, id, client.ContainerUnpauseOptions{})
	return err
}

// Restart restarts the container.
func (l *Local) Restart(ctx context.Context, project, service string) error {
	if err := l.Stop(ctx, project, service); err != nil {
		return err
	}
	return l.Start(ctx, project, service)
}

// Remove deletes the container (volumes stay: deleting a volume is a
// separate action). A running one is stopped first with its grace period,
// so a server that saves its state on SIGTERM gets to do it.
func (l *Local) Remove(ctx context.Context, project, service string) error {
	id, err := l.managedID(ctx, project, service)
	if errors.Is(err, errNoContainer) {
		return nil
	}
	if err != nil {
		return err
	}
	if l.running(ctx, id) {
		if _, err := l.c.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: l.stopTimeout(ctx, id)}); err != nil && !isNotFound(err) {
			slog.Warn("stop before removing", "container", node.ContainerName(project, service), "error", err)
		}
	}
	_, err = l.c.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true})
	return err
}

// RemoveVolume deletes a service volume and its data. Docker refuses while
// a container still mounts it; a volume that does not exist is fine.
func (l *Local) RemoveVolume(ctx context.Context, project, service, name string) error {
	_, err := l.c.VolumeRemove(ctx, node.VolumeName(project, service, name), client.VolumeRemoveOptions{})
	if isNotFound(err) {
		return nil
	}
	return err
}

// Status reads the container state.
func (l *Local) Status(ctx context.Context, project, service string) (node.Status, error) {
	res, err := l.c.ContainerInspect(ctx, node.ContainerName(project, service), client.ContainerInspectOptions{})
	if isNotFound(err) {
		return node.Status{}, nil
	}
	if err != nil {
		return node.Status{}, err
	}
	c := res.Container
	if c.Config == nil {
		return node.Status{}, ErrNotManaged
	}
	if err := l.checkOwner(ctx, node.ContainerName(project, service), c.Config.Labels); err != nil {
		return node.Status{}, err
	}
	st := node.Status{Exists: true, RestartCount: c.RestartCount, Image: c.Config.Image, Deployment: c.Config.Labels[node.LabelDeployment]}
	if c.State != nil {
		st.State = string(c.State.Status)
		st.Running = c.State.Running
		st.OOMKilled = c.State.OOMKilled
		st.ExitCode = c.State.ExitCode
		st.StartedAt, _ = time.Parse(time.RFC3339Nano, c.State.StartedAt)
		if c.State.Health != nil {
			st.Health = string(c.State.Health.Status)
		}
	}
	return st, nil
}

// Logs reads the container logs and calls fn for each line. With Follow, it
// only returns when ctx ends or the container stops.
func (l *Local) Logs(ctx context.Context, project, service string, opt node.LogOptions, fn func(node.LogLine) error) error {
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return err
	}
	o := client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Timestamps: true, Follow: opt.Follow}
	if opt.Tail > 0 {
		o.Tail = strconv.Itoa(opt.Tail)
	}
	if !opt.Since.IsZero() {
		o.Since = strconv.FormatInt(opt.Since.Unix(), 10)
	}
	rc, err := l.c.ContainerLogs(ctx, id, o)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	return demux(rc, fn)
}

// demux splits Docker's multiplexed stream (8-byte header: [stream, 0, 0, 0,
// big-endian size]) into lines per stream.
func demux(r io.Reader, fn func(node.LogLine) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var hdr [8]byte
	partial := map[byte]*strings.Builder{1: {}, 2: {}}
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		stream := hdr[0]
		size := binary.BigEndian.Uint32(hdr[4:])
		if size > 1<<20 {
			return fmt.Errorf("log frame too large (%d bytes)", size)
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil
		}
		b, ok := partial[stream]
		if !ok {
			continue // stdin or unknown
		}
		b.Write(buf)
		text := b.String()
		for {
			i := strings.IndexByte(text, '\n')
			if i < 0 {
				break
			}
			if err := fn(parseLine(stream, text[:i])); err != nil {
				return err
			}
			text = text[i+1:]
		}
		b.Reset()
		b.WriteString(text)
	}
}

func parseLine(stream byte, s string) node.LogLine {
	ln := node.LogLine{Stream: "stdout", Text: s}
	if stream == 2 {
		ln.Stream = "stderr"
	}
	if ts, rest, ok := strings.Cut(s, " "); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ln.Time, ln.Text = t, rest
		}
	}
	return ln
}

// ListManaged lists Hangar's containers.
func (l *Local) ListManaged(ctx context.Context) ([]node.Managed, error) {
	res, err := l.c.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", node.LabelManaged+"=true"),
	})
	if err != nil {
		return nil, err
	}
	out := make([]node.Managed, 0, len(res.Items))
	for _, c := range res.Items {
		if !l.owns(ctx, c.Labels) {
			continue // another panel's container on the same Docker
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		out = append(out, node.Managed{
			ID: c.ID, Name: name, State: string(c.State),
			ProjectID: c.Labels[node.LabelProjectID], ServiceID: c.Labels[node.LabelServiceID],
			Project: c.Labels[node.LabelProject], Service: c.Labels[node.LabelService],
		})
	}
	return out, nil
}

func isNotFound(err error) bool {
	return err != nil && cerrdefs.IsNotFound(err)
}
