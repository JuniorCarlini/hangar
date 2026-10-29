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
	// Stateful marks a service made to keep data (a template's database).
	Stateful bool `json:"stateful,omitempty"`
	// Exports are the connection values other services reference
	// (${{service.KEY}}); Offers, the variables it offers them.
	Exports []SnapshotVar   `json:"exports,omitempty"`
	Offers  []string        `json:"offers,omitempty"`
	Deploy  *SnapshotDeploy `json:"deploy,omitempty"`
	Canvas  *SnapshotCanvas `json:"canvas,omitempty"`
}

// SnapshotGit is a Git service's source (never its token).
type SnapshotGit struct {
	URL        string `json:"url"`
	Branch     string `json:"branch"`
	Subdir     string `json:"subdir,omitempty"`
	Dockerfile string `json:"dockerfile,omitempty"`
	// Credential is the id of the server-wide Git credential it used: on
	// the same server the copy uses it too.
	Credential string `json:"credential,omitempty"`
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
	// Label is the stored label (every language it has); Sslip, whether
	// its automatic link is on.
	Label string `json:"label,omitempty"`
	Sslip bool   `json:"sslip,omitempty"`
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

// SnapshotDeploy are the service's deploy settings, as stored.
type SnapshotDeploy struct {
	Predeploy        json.RawMessage `json:"predeploy,omitempty"`
	HealthPath       string          `json:"health_path,omitempty"`
	Validate         json.RawMessage `json:"validate,omitempty"`
	ValidateTimeoutS int64           `json:"validate_timeout_s,omitempty"`
}

// SnapshotCanvas is where the service's card sits on the canvas.
type SnapshotCanvas struct {
	X int64 `json:"x"`
	Y int64 `json:"y"`
}

// Snapshot reads the configuration of a service (ServiceSnapshot).
func (m *Manager) Snapshot(ctx context.Context, projectSlug, serviceSlug string) (ServiceSnapshot, error) {
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return ServiceSnapshot{}, err
	}
	out := ServiceSnapshot{
		Format: 1, Project: p.Slug, Service: s.Slug, Template: s.Template, Image: s.Image, Port: s.InternalPort,
		Res:      SnapshotLimits{MemoryBytes: s.MemoryBytes, NanoCPUs: s.NanoCpus, Pids: s.PidsLimit, ReadOnly: s.ReadOnly == 1, StopGraceS: s.StopGraceS},
		Stateful: s.Stateful == 1,
	}
	_ = json.Unmarshal([]byte(s.CommandJson), &out.Cmd)
	_ = json.Unmarshal([]byte(s.CapAddJson), &out.Res.CapAdd)
	if rawSet(s.HealthJson) {
		out.Check = json.RawMessage(s.HealthJson)
	}
	d := SnapshotDeploy{HealthPath: s.HealthPath, ValidateTimeoutS: s.ValidateTimeoutS}
	if rawSet(s.PredeployJson) {
		d.Predeploy = json.RawMessage(s.PredeployJson)
	}
	if rawSet(s.ValidateJson) {
		d.Validate = json.RawMessage(s.ValidateJson)
	}
	if d.Predeploy != nil || d.Validate != nil || d.HealthPath != "" || d.ValidateTimeoutS != 0 {
		out.Deploy = &d
	}
	if s.CanvasX.Valid && s.CanvasY.Valid {
		out.Canvas = &SnapshotCanvas{X: s.CanvasX.Int64, Y: s.CanvasY.Int64}
	}
	if g, ok, err := m.GetGitSource(ctx, s.ID); err != nil {
		return out, err
	} else if ok {
		out.Git = &SnapshotGit{URL: g.URL, Branch: g.Branch, Subdir: g.Subdir, Dockerfile: g.Dockerfile}
		if !g.CredentialMine {
			out.Git.Credential = g.CredentialID
		}
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
	eps, err := m.q.ListEndpoints(ctx, s.ID)
	if err != nil {
		return out, err
	}
	for _, e := range eps {
		out.Endpoints = append(out.Endpoints, SnapshotEndpoint{
			Name: e.Name, Port: int(e.Port), Public: e.Public == 1, Label: e.Label, Sslip: e.SslipEnabled == 1,
		})
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
	exps, err := m.q.ListExports(ctx, s.ID)
	if err != nil {
		return out, err
	}
	for _, e := range exps {
		plain, err := m.box.Open(e.ValueEnc, exportAD(s.ID, e.Key))
		if err != nil {
			return out, err
		}
		out.Exports = append(out.Exports, SnapshotVar{Key: e.Key, Value: string(plain), Secret: e.Secret == 1})
	}
	offers, err := m.q.ListOffers(ctx, s.ID)
	if err != nil {
		return out, err
	}
	if len(offers) > 0 {
		out.Offers = offers
	}
	return out, nil
}

// rawSet reports whether a stored JSON column holds a value.
func rawSet(s string) bool {
	return s != "" && s != "null" && s != "[]" && s != "{}" && json.Valid([]byte(s))
}
