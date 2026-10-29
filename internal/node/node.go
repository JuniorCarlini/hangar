// Package node defines the container operations the panel uses. Today only
// the local implementation exists (internal/docker); later, an agent on
// another server implements the same interface.
package node

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"time"
)

// Labels written on everything Hangar creates. Hangar never touches a
// container or network without hangar.managed=true.
const (
	LabelManaged    = "hangar.managed"
	LabelProjectID  = "hangar.project.id"
	LabelProject    = "hangar.project"
	LabelServiceID  = "hangar.service.id"
	LabelService    = "hangar.service"
	LabelDeployment = "hangar.deployment"
	// LabelInstance is the id of the panel that created the object: several
	// panels may share one Docker daemon (internal/docker/owner.go).
	LabelInstance    = "hangar.instance"
	NetworkPrefix    = "hangar_"
	ContainerNameSep = "_"
)

// SlugRE validates project and service names: they become container and
// network names, so only lowercase letters, digits and hyphens.
var SlugRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// ImageRE accepts common image references (registry/name:tag@digest), with
// no spaces or shell characters.
var ImageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:@-]{0,254}$`)

// ServiceSpec is everything needed to run a service.
type ServiceSpec struct {
	ProjectID   string
	Project     string // slug
	ServiceID   string
	Service     string // slug
	Deployment  string
	Image       string
	Env         map[string]string
	Command     []string
	MemoryBytes int64
	NanoCPUs    int64
	PidsLimit   int64
	ReadOnly    bool
	CapAdd      []string
	// Edge joins Caddy to the project network, so it can proxy to the
	// container (services with domains). The container itself never joins
	// the edge network, which would let it reach other projects.
	Edge bool
	// Volumes are named Docker volumes (never host paths).
	Volumes []Volume
	Health  *Health
	// Ports are published on the host (the "Ports" tab).
	Ports []Port
	// Linked are other projects whose networks the container also joins, so
	// both sides see each other by container name.
	Linked []string
	// StopGrace is how long a stop waits after SIGTERM before killing the
	// container (0 = DefaultStopGrace, at most MaxStopGrace). It is kept on
	// the container, so every stop of it — a deploy replacing it, the stop
	// button, a delete, Docker shutting down — gives it the same time.
	StopGrace time.Duration
}

// Stop grace periods.
const (
	DefaultStopGrace = 30 * time.Second
	// MaxStopGrace bounds how long one container can hold up a deploy, a
	// stop or the server's shutdown.
	MaxStopGrace = 120 * time.Second
)

// Deploy strategies (docs/07).
const (
	// StrategyRolling starts the new container next to the old one and only
	// stops the old after the new is healthy: no downtime.
	StrategyRolling = "rolling"
	// StrategyRecreate stops, then starts: for databases (two processes on
	// one volume corrupt data) and services with published ports.
	StrategyRecreate = "recreate"
)

// Deploy phases, in order, as shown in the deploy timeline.
const (
	PhaseClone     = "clone" // services built from Git: fetch the source
	PhaseBuild     = "build" // services built from Git: build the image
	PhasePull      = "pull"
	PhasePreDeploy = "predeploy"
	PhaseStart     = "start"
	PhaseHealth    = "health"
	// PhaseValidate runs the service's validation command inside the new
	// container, once it is healthy and before it takes over.
	PhaseValidate = "validate"
	PhaseSwitch   = "switch"
	// PhaseRestore starts the previous version again after the new one
	// failed in a recreate deploy (the old one had already been stopped).
	PhaseRestore = "restore"
)

// What to do with the previous version when the new container of a
// recreate deploy fails after the old one was stopped (DeployOptions.Restore).
const (
	// RestoreAlways starts the previous container again. The zero value
	// means the same.
	RestoreAlways = "always"
	// RestoreSameImage starts it again only when the new container runs the
	// very same image (a configuration change). For databases: a new image
	// may already have converted the data on the volume (a major upgrade),
	// and the old one would then read files it no longer understands.
	RestoreSameImage = "same-image"
	// RestoreNever leaves the service down for the operator to decide.
	RestoreNever = "never"
)

// What became of the previous version when a deploy failed
// (DeployResult.Previous).
const (
	// PreviousNone: there was no previous container.
	PreviousNone = "none"
	// PreviousLive: it was never stopped and keeps serving.
	PreviousLive = "live"
	// PreviousRestored: it was stopped and came back after the new one failed.
	PreviousRestored = "restored"
	// PreviousDown: it was stopped and is not back; the service is down.
	PreviousDown = "down"
)

// DeployOptions controls how a deploy happens.
type DeployOptions struct {
	Strategy string
	// PreDeploy runs once in a temporary container with the new image
	// (e.g. "python manage.py migrate") before anything switches.
	PreDeploy []string
	// Port and HealthPath tell how to know the new container is ready when
	// the image has no Docker healthcheck: HTTP GET on the path, or a TCP
	// connect on the port when the path is empty.
	Port       int
	HealthPath string
	// HealthTimeout is how long the new container may take to become
	// ready (see HealthWait). A container that stops meanwhile fails the
	// deploy at once; one still running is waited for up to this long.
	HealthTimeout time.Duration
	// Progress receives each phase change and log line (may be nil).
	Progress func(phase, line string)
	// LocalImage says the image was built on this server: it is never
	// pulled (a registry could serve something else under the same name).
	LocalImage bool
	// Validate runs inside the new container once it is healthy, before it
	// takes over (e.g. "python manage.py check --deploy"). A non-zero exit
	// fails the deploy: rolling keeps the old version, recreate restores it.
	Validate        []string
	ValidateTimeout time.Duration
	// Restore is what a failed recreate does with the stopped previous
	// version (RestoreAlways when empty).
	Restore string
	// Fresh refuses to fall back on a local copy when the pull fails: a
	// deploy "from scratch" must run what the registry has now.
	Fresh bool
}

// BuildSpec is an image build from a checked-out repository (docs/07).
type BuildSpec struct {
	ProjectID  string
	Project    string // slug
	ServiceID  string
	Service    string // slug
	Deployment string
	// ContextDir is the build context on this machine (the workspace or a
	// subdirectory of it).
	ContextDir string
	// Dockerfile is relative to ContextDir.
	Dockerfile string
	// Tag names the result, e.g. hangar/<project>/<service>:<deploy>.
	Tag string
	// Fresh builds without the layer cache and pulls the base images again
	// (a dependency that changed upstream without a new tag).
	Fresh bool
}

// BuildRepo is the local image repository of a service built from Git.
func BuildRepo(project, service string) string { return "hangar/" + project + "/" + service }

// Builder is implemented by nodes that can build images. It is separate
// from Node so a node without it still runs services from images.
type Builder interface {
	// Build builds spec and returns the image ID. Each output line goes to
	// log as it arrives.
	Build(ctx context.Context, spec BuildSpec, log func(line string)) (string, error)
	// PruneBuilds removes the service's built images except keep (image
	// IDs): old builds would otherwise fill the disk.
	PruneBuilds(ctx context.Context, serviceID string, keep []string) error
}

// Recoverer tidies what an interrupted deploy left in Docker (the panel
// was killed half-way): the temporary pre-deploy container and the "-next"
// container of a rolling deploy. Optional: a node without it leaves the
// leftovers to the next deploy.
type Recoverer interface {
	// RecoverDeploy returns what it did ("" when there was nothing to do):
	// "removed-next" when the old container is still there (the new one was
	// never confirmed healthy), "promoted-next" when only the new one is
	// left (it had passed the health check and already serves the site).
	// For a recreate: "removed-prev" when the new container exists (the
	// stopped previous one goes away, as a finished deploy would remove it),
	// "restored-prev" when the panel died between stopping the old one and
	// creating the new one (the old one is started again).
	RecoverDeploy(ctx context.Context, project, service string) (string, error)
}

// DeployResult says what went live.
type DeployResult struct {
	ContainerID string
	// ImageRef pins the exact image (digest or ID) for a later rollback.
	ImageRef string
	// Previous says, when the deploy failed, whether the previous version
	// is serving (PreviousLive, PreviousRestored), gone (PreviousDown) or
	// never existed (PreviousNone). Empty on success.
	Previous string
}

// Volume is a named volume mounted in the container.
type Volume struct {
	Name string // short name inside the service, e.g. "data"
	Path string // mount point in the container
	// ReadOnly mounts it read-only: the app reads the files and cannot
	// change them.
	ReadOnly bool
	// Service and ServiceID name the service of the same project that owns
	// the volume when it is another one: services of one template or
	// compose import may share a volume, which then keeps the owner's name
	// (VolumeName(project, Service, Name)) and labels. Empty: the volume
	// is this service's own.
	Service   string
	ServiceID string
	// Device, when set, is the folder inside the volume's disk image that
	// the Docker volume binds to: a volume with a size limit
	// (internal/volumes). Always <data>/volume-mounts/<Docker name>/data.
	Device string
}

// ValidDevice reports whether device is where the disk image of the
// Docker volume name is mounted: never any other host path.
func ValidDevice(device, name string) bool {
	return path.IsAbs(device) && path.Clean(device) == device && path.Base(device) == "data" &&
		path.Base(path.Dir(device)) == name && path.Base(path.Dir(path.Dir(device))) == "volume-mounts" &&
		!strings.ContainsAny(device, "\x00\n\r:,")
}

// VolumeOwner is the service whose Docker volume v is, in spec.
func (s ServiceSpec) VolumeOwner(v Volume) (slug, id string) {
	if v.Service != "" {
		return v.Service, v.ServiceID
	}
	return s.Service, s.ServiceID
}

// VolumeName is the Docker name of a service volume.
func VolumeName(project, service, name string) string {
	return NetworkPrefix + project + "_" + service + "_" + name
}

// Health is the container healthcheck.
type Health struct {
	Test        []string // e.g. ["CMD-SHELL", "pg_isready"]
	Interval    time.Duration
	Timeout     time.Duration
	StartPeriod time.Duration
	Retries     int
}

// DefaultHealthTimeout is how long a deploy waits for the new container to
// be ready when nothing says otherwise: enough for an app that runs its
// migrations or uploads its static files before it listens (a Django or
// Rails boot), the grace period other platforms give by default.
const DefaultHealthTimeout = 5 * time.Minute

// Docker's own defaults for a healthcheck field left at zero.
const (
	dockerHealthInterval = 30 * time.Second
	dockerHealthTimeout  = 30 * time.Second
	dockerHealthRetries  = 3
)

// HealthWait is how long a deploy should wait for a container with this
// healthcheck to report healthy: the service's startup grace (zero =
// DefaultHealthTimeout), or longer when Docker itself may take more to
// decide (start period, then every retry at its interval, plus the last
// probe's timeout), and never more than limit. A server that loads a large
// world or database for minutes before it answers is not a failed deploy,
// and in a recreate deploy giving up early would remove a container that
// was about to become healthy.
func HealthWait(h *Health, grace, limit time.Duration) time.Duration {
	wait := grace
	if wait <= 0 {
		wait = DefaultHealthTimeout
	}
	if h != nil {
		interval, timeout, retries := h.Interval, h.Timeout, h.Retries
		if interval <= 0 {
			interval = dockerHealthInterval
		}
		if timeout <= 0 {
			timeout = dockerHealthTimeout
		}
		if retries <= 0 {
			retries = dockerHealthRetries
		}
		wait = max(wait, h.StartPeriod+interval*time.Duration(retries)+timeout)
	}
	if limit > 0 {
		wait = min(wait, limit)
	}
	return wait
}

// Port is a port published on the host.
type Port struct {
	HostPort      int
	ContainerPort int
	Protocol      string     // tcp or udp
	HostIP        netip.Addr // invalid = every address; 127.0.0.1 = local only
}

// VolumeNameRE validates a volume's short name.
var VolumeNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// ReservedHostPorts are taken by Hangar itself or SSH: the edge (80/443), the
// panel (7700), the certificate ask listener (7701) and the public panel's
// listener behind Caddy (7702). ReserveHostPorts adds the configured panel
// ports.
var ReservedHostPorts = map[int]bool{22: true, 80: true, 443: true, 7700: true, 7701: true, 7702: true}

// ReserveHostPorts adds ports to ReservedHostPorts. Call it at startup only,
// before anything reads the map.
func ReserveHostPorts(ports ...int) {
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			ReservedHostPorts[p] = true
		}
	}
}

func validMountPath(p string) bool {
	if !strings.HasPrefix(p, "/") || p == "/" || strings.Contains(p, "..") || strings.ContainsAny(p, ":,\x00") {
		return false
	}
	return ReservedMount(p) == ""
}

// reservedMounts are system paths a disk would hide or that make no sense
// to persist.
var reservedMounts = []string{"/proc", "/sys", "/dev", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/run", "/var/run", "/boot"}

// usrDataDirs are the places under /usr where images keep their data, not
// their programs: nginx serves /usr/share/nginx/html, Apache
// /usr/local/apache2/htdocs. A disk is allowed one level below them
// (/usr/share/nginx/html), never on them or on the program folders.
var (
	usrDataDirs   = []string{"/usr/share/", "/usr/local/"}
	usrProgramDir = map[string]bool{"bin": true, "sbin": true, "lib": true, "lib64": true, "libexec": true, "include": true}
)

// ReservedMount returns the system folder that makes p unusable as a mount
// point, or "" when p is allowed. The node, the disks and the templates all
// ask here, so a path is never accepted by one and refused by another.
func ReservedMount(p string) string {
	for _, d := range usrDataDirs {
		if rest, ok := strings.CutPrefix(p, d); ok {
			first, _, _ := strings.Cut(rest, "/")
			if first != "" && !usrProgramDir[first] {
				return ""
			}
		}
	}
	for _, bad := range reservedMounts {
		if p == bad || strings.HasPrefix(p, bad+"/") {
			return bad
		}
	}
	return ""
}

// ContainerName follows the Easypanel convention: <project>_<service>.
func ContainerName(project, service string) string { return project + ContainerNameSep + service }

// NetworkName is the project's network.
func NetworkName(project string) string { return NetworkPrefix + project }

// Validate checks everything that becomes a Docker argument.
func (s ServiceSpec) Validate() error {
	switch {
	case !SlugRE.MatchString(s.Project):
		return fmt.Errorf("invalid project name: %q", s.Project)
	case !SlugRE.MatchString(s.Service):
		return fmt.Errorf("invalid service name: %q", s.Service)
	case !ImageRE.MatchString(s.Image):
		return fmt.Errorf("invalid image: %q", s.Image)
	case s.MemoryBytes < 6<<20:
		return fmt.Errorf("memory limit too low: %d bytes", s.MemoryBytes)
	case s.NanoCPUs <= 0:
		return fmt.Errorf("CPU limit required")
	case s.PidsLimit <= 0:
		return fmt.Errorf("process limit required")
	}
	seenVol := map[string]bool{}
	for _, v := range s.Volumes {
		if !VolumeNameRE.MatchString(v.Name) || seenVol[v.Name] {
			return fmt.Errorf("invalid volume name: %q", v.Name)
		}
		if !validMountPath(v.Path) {
			return fmt.Errorf("invalid volume path: %q", v.Path)
		}
		// Another service's volume is always one of this project's: the
		// name never leaves hangar_<project>_.
		if v.Service != "" && (!SlugRE.MatchString(v.Service) || v.Service == s.Service || v.ServiceID == "") {
			return fmt.Errorf("invalid owner of volume %q: %q", v.Name, v.Service)
		}
		if owner, _ := s.VolumeOwner(v); v.Device != "" && !ValidDevice(v.Device, VolumeName(s.Project, owner, v.Name)) {
			return fmt.Errorf("invalid disk image folder of volume %q: %q", v.Name, v.Device)
		}
		seenVol[v.Name] = true
	}
	for _, p := range s.Ports {
		switch {
		case p.HostPort < 1 || p.HostPort > 65535 || ReservedHostPorts[p.HostPort]:
			return fmt.Errorf("host port %d is not allowed", p.HostPort)
		case p.ContainerPort < 1 || p.ContainerPort > 65535:
			return fmt.Errorf("invalid container port: %d", p.ContainerPort)
		case p.Protocol != "tcp" && p.Protocol != "udp":
			return fmt.Errorf("invalid protocol: %q", p.Protocol)
		}
	}
	for _, l := range s.Linked {
		if !SlugRE.MatchString(l) || l == s.Project {
			return fmt.Errorf("invalid linked project: %q", l)
		}
	}
	if s.StopGrace < 0 || s.StopGrace > MaxStopGrace {
		return fmt.Errorf("stop grace period %s is outside 0 to %s", s.StopGrace, MaxStopGrace)
	}
	if s.Health != nil && len(s.Health.Test) == 0 {
		return fmt.Errorf("healthcheck without a test")
	}
	for _, c := range s.CapAdd {
		if _, ok := AllowedCaps[c]; !ok {
			return fmt.Errorf("capability %q is not allowed", c)
		}
	}
	return nil
}

// DefaultCaps is the minimum common images (nginx, apps that switch users on
// startup) need after cap_drop ALL.
var DefaultCaps = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "NET_BIND_SERVICE", "KILL"}

// VolumeBinder is implemented by nodes that can move a volume onto a disk
// image with a size limit (internal/volumes) and back.
type VolumeBinder interface {
	// VolumeDevice says whether the Docker volume exists and the folder it
	// binds to ("" for a plain volume).
	VolumeDevice(ctx context.Context, name string) (exists bool, device string, err error)
	// SwitchVolume recreates v, which no container may use, bound to
	// device, or plain when device is "". A plain volume's files are
	// deleted with it.
	SwitchVolume(ctx context.Context, spec ServiceSpec, v Volume, device string) error
}

// VolumeEnsurer is implemented by nodes that can create a service's
// volumes ahead of its deploy (shared volumes of a template). Optional: a
// node without it creates them at the first deploy that mounts them.
type VolumeEnsurer interface {
	EnsureVolumes(ctx context.Context, spec ServiceSpec) error
}

// Pauser is implemented by nodes that can freeze a service's processes
// (docker pause, the cgroup freezer) and let them go on: a copy of its
// volumes taken meanwhile sees no file half written. Optional: backups of
// volumes say so when it is missing.
type Pauser interface {
	Pause(ctx context.Context, project, service string) error
	Unpause(ctx context.Context, project, service string) error
}

// Shell is an interactive terminal inside a service container: what is
// written goes to the shell's input, what is read is its screen.
type Shell interface {
	io.ReadWriteCloser
	Resize(ctx context.Context, cols, rows uint) error
}

// Terminal is implemented by nodes that can open a shell in a container.
type Terminal interface {
	// OpenShell runs cmd (a shell, or one command) on a TTY in the
	// service container, as the container's own user.
	OpenShell(ctx context.Context, project, service string, cmd []string, cols, rows uint) (Shell, error)
}

// AllowedCaps are the only capabilities a service may receive. SYS_ADMIN,
// NET_ADMIN, SYS_PTRACE and the like are deliberately absent.
var AllowedCaps = map[string]struct{}{
	"CHOWN": {}, "DAC_OVERRIDE": {}, "FOWNER": {}, "FSETID": {}, "SETGID": {}, "SETUID": {},
	"NET_BIND_SERVICE": {}, "KILL": {}, "SETPCAP": {}, "AUDIT_WRITE": {},
}

// Status is a container's state.
type Status struct {
	Exists       bool
	State        string // created, running, restarting, exited, dead…
	Running      bool
	Health       string // starting, healthy, unhealthy or empty
	RestartCount int
	OOMKilled    bool
	ExitCode     int
	StartedAt    time.Time
	Image        string
	Deployment   string
}

// LogLine is one container log line.
type LogLine struct {
	Stream string // stdout or stderr
	Time   time.Time
	Text   string
}

// LogOptions controls how logs are read.
type LogOptions struct {
	Tail   int
	Follow bool
	Since  time.Time
}

// Managed describes a container created by Hangar.
type Managed struct {
	ID        string
	Name      string
	ProjectID string
	ServiceID string
	Project   string // project slug (label), "" for the edge proxy
	Service   string // service slug (label)
	State     string
}

// ContainerStats is one reading of a container's cumulative counters. CPU
// percentages come from the difference between two readings.
type ContainerStats struct {
	CPUTotal   uint64 // CPU time used by the container, ns
	SystemCPU  uint64 // CPU time of the whole host, ns
	OnlineCPUs int
	MemUsed    uint64 // without the reclaimable page cache, as docker stats shows
	MemLimit   uint64
	NetRx      uint64 // bytes, all interfaces
	NetTx      uint64
}

// DiskUsage is what Docker keeps on disk, in bytes.
type DiskUsage struct {
	Images     int64
	Volumes    int64
	Containers int64 // writable layers
	BuildCache int64
	// ByService is each service's volume bytes (by service id), summed from
	// the same "docker system df" so no extra call is made.
	ByService map[string]int64
	// ByVolume is each service volume's bytes, by Docker name.
	ByVolume map[string]int64
}

// Reclaimed is disk space freed by a cleanup, in bytes.
type Reclaimed struct {
	BuildCache int64
	Images     int64
}

// StatsReader is implemented by nodes that can report resource usage. It is
// separate from Node so a node without it still runs services.
type StatsReader interface {
	// ContainerStats takes a single reading (no stream) of a managed container.
	ContainerStats(ctx context.Context, id string) (ContainerStats, error)
	// DiskUsage is "docker system df": expensive, call it rarely.
	DiskUsage(ctx context.Context) (DiskUsage, error)
	// ReclaimDisk removes old, unused build cache and dangling images. It
	// only removes what is old, so a running build (which uses recent cache
	// and images) is never affected.
	ReclaimDisk(ctx context.Context) (Reclaimed, error)
}

// EdgeNetwork is Caddy's own network, where the panel's listeners on its
// gateway expect Caddy's fixed address. No service joins it: Caddy joins the
// project networks instead.
const EdgeNetwork = "hangar_edge"

// EdgeContainer is Caddy's container name.
const EdgeContainer = "hangar_caddy"

// EdgeSpec describes the edge proxy on a server.
type EdgeSpec struct {
	Image    string
	Subnet   netip.Prefix
	Gateway  netip.Addr
	CaddyIP  netip.Addr
	AdminDir string // host dir with bootstrap.json and the admin socket
	DataDir  string // host dir for certificates
	UID, GID int    // Caddy runs as the panel user, never as root
}

// Node is what the panel can do with containers on a server.
type Node interface {
	EnsureEdge(ctx context.Context, spec EdgeSpec) error
	// ConnectEdge joins Caddy to the project's network so it reaches the
	// project's services (a domain was added; no redeploy needed).
	ConnectEdge(ctx context.Context, project string) error
	ServiceAddress(ctx context.Context, project, service string, port int) (string, error)
	EnsureProjectNetwork(ctx context.Context, projectID, project string) error
	RemoveProjectNetwork(ctx context.Context, project string) error
	Deploy(ctx context.Context, spec ServiceSpec, opt DeployOptions) (DeployResult, error)
	Start(ctx context.Context, project, service string) error
	Stop(ctx context.Context, project, service string) error
	Restart(ctx context.Context, project, service string) error
	Remove(ctx context.Context, project, service string) error
	Status(ctx context.Context, project, service string) (Status, error)
	Logs(ctx context.Context, project, service string, opt LogOptions, fn func(LogLine) error) error
	ListManaged(ctx context.Context) ([]Managed, error)
	// Exec runs a fixed command in the service container, streaming stdout.
	Exec(ctx context.Context, project, service string, cmd []string, w io.Writer) error
	// SetLinked joins the running container to the linked projects' networks.
	SetLinked(ctx context.Context, project, service string, linked []string) error
}
