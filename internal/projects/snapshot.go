package projects

import (
	"context"
	"encoding/json"
)

// ServiceSnapshot is a service's configuration as a downloaded backup
// carries it (service.json, docs/09): what it takes to recreate the
// service elsewhere next to its data. Values of variables are included:
// the file travels encrypted with the backup (the recovery kit), or
// decrypted with the data in the simple mode, which already holds every
// byte of the database.
type ServiceSnapshot struct {
	Format   int    `json:"format"`
	Project  string `json:"project"`
	Service  string `json:"service"`
	Template string `json:"template,omitempty"`
	// Image is what runs (for a Git service, the image Hangar builds).
	Image string           `json:"image"`
	Git   *SnapshotGit     `json:"git,omitempty"`
	Port  int64            `json:"internal_port,omitempty"`
	Cmd   []string         `json:"command,omitempty"`
	Check json.RawMessage  `json:"healthcheck,omitempty"`
	Res   SnapshotLimits   `json:"resources"`
	Vols  []SnapshotVolume `json:"volumes,omitempty"`
	// Endpoints are its HTTP ports; Domains, the fixed domains.
	Endpoints []SnapshotEndpoint `json:"endpoints,omitempty"`
	Domains   []string           `json:"domains,omitempty"`
	Env       []SnapshotVar      `json:"env,omitempty"`
	Commands  []SnapshotCommand  `json:"saved_commands,omitempty"`
}

// SnapshotGit is a Git service's source (never its token).
type SnapshotGit struct {
	URL        string `json:"url"`
	Branch     string `json:"branch"`
	Subdir     string `json:"subdir,omitempty"`
	Dockerfile string `json:"dockerfile,omitempty"`
}

// SnapshotLimits are the service's resources.
type SnapshotLimits struct {
	MemoryBytes int64    `json:"memory_bytes"`
	NanoCPUs    int64    `json:"nano_cpus"`
	Pids        int64    `json:"pids_limit"`
	ReadOnly    bool     `json:"read_only"`
	CapAdd      []string `json:"cap_add,omitempty"`
	StopGraceS  int64    `json:"stop_grace_s,omitempty"`
}

// SnapshotVolume is a volume and its disk size.
type SnapshotVolume struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only,omitempty"`
	// From is the service whose volume this is, when it mounts another's.
	From       string `json:"from,omitempty"`
	LimitBytes int64  `json:"limit_bytes,omitempty"`
}

// SnapshotEndpoint is an HTTP port of the service.
type SnapshotEndpoint struct {
	Name   string `json:"name,omitempty"`
	Port   int    `json:"port"`
	Public bool   `json:"public"`
}

// SnapshotVar is a variable.
type SnapshotVar struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret bool   `json:"secret,omitempty"`
}

// SnapshotCommand is a command saved on the service.
type SnapshotCommand struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// Snapshot reads the configuration of a service (ServiceSnapshot).
func (m *Manager) Snapshot(ctx context.Context, projectSlug, serviceSlug string) (ServiceSnapshot, error) {
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return ServiceSnapshot{}, err
	}
	out := ServiceSnapshot{
		Format: 1, Project: p.Slug, Service: s.Slug, Template: s.Template, Image: s.Image, Port: s.InternalPort,
		Res: SnapshotLimits{MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCpus, Pids: s.PidsLimit, ReadOnly: s.ReadOnly == 1, StopGraceS: s.StopGraceS},
	}
	_ = json.Unmarshal([]byte(s.CommandJson), &out.Cmd)
	_ = json.Unmarshal([]byte(s.CapAddJson), &out.Res.CapAdd)
	if s.HealthJson != "" && json.Valid([]byte(s.HealthJson)) && s.HealthJson != "null" {
		out.Check = json.RawMessage(s.HealthJson)
	}
	if g, ok, err := m.GetGitSource(ctx, s.ID); err != nil {
		return out, err
	} else if ok {
		out.Git = &SnapshotGit{URL: g.URL, Branch: g.Branch, Subdir: g.Subdir, Dockerfile: g.Dockerfile}
	}
	vols, err := m.ListServiceVolumes(ctx, p.Slug, s)
	if err != nil {
		return out, err
	}
	for _, v := range vols {
		sv := SnapshotVolume{Name: v.Name, Path: v.Path, ReadOnly: v.ReadOnly, From: v.Owner}
		if v.Limit != nil && v.Owner == "" {
			sv.LimitBytes = v.Limit.Size
		}
		out.Vols = append(out.Vols, sv)
	}
	eps, err := m.ListEndpoints(ctx, s.ID)
	if err != nil {
		return out, err
	}
	for _, e := range eps {
		out.Endpoints = append(out.Endpoints, SnapshotEndpoint{Name: e.Name, Port: e.Port, Public: e.Public})
	}
	doms, err := m.ListDomains(ctx, s.ID)
	if err != nil {
		return out, err
	}
	for _, d := range doms {
		out.Domains = append(out.Domains, d.Hostname)
	}
	env, err := m.ListEnvValues(ctx, s.ID)
	if err != nil {
		return out, err
	}
	for _, e := range env {
		out.Env = append(out.Env, SnapshotVar(e))
	}
	cmds, err := m.ListCommands(ctx, s.ID)
	if err != nil {
		return out, err
	}
	for _, c := range cmds {
		out.Commands = append(out.Commands, SnapshotCommand{Name: c.Name, Command: c.Command})
	}
	return out, nil
}
