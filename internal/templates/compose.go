package templates

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// A template's compose.yaml is plain Docker Compose, but only a strict
// subset of it: what a Hangar service can be. Anything else is an error
// naming the key — never silently ignored, so a template can never look
// like it asks for something it does not get. The parser is the same
// go.yaml.in/yaml/v3 the compose importer uses (internal/projects).

// composeNameRE limits a compose service name: it becomes the suffix of the
// other services ("-db") and the ${service_<name>} placeholder.
var composeNameRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,11}$`)

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// refusals explains the keys people reach for most, instead of a bare
// "not allowed".
var refusals = map[string]string{
	"ports":          "published ports are not allowed; the user opens one in the panel (Network tab) if needed",
	"privileged":     "privileged mode is never allowed",
	"network_mode":   "services always run on the project's own network",
	"networks":       "services always run on the project's own network",
	"pid":            "sharing the host's process namespace is not allowed",
	"ipc":            "sharing IPC namespaces is not allowed",
	"devices":        "host devices are not allowed",
	"build":          "templates run published images; build: is not allowed",
	"cap_drop":       "every capability is already dropped; add back only what is needed with cap_add",
	"security_opt":   "the panel sets the security options itself (no-new-privileges)",
	"entrypoint":     "not supported: put the program and its arguments in command",
	"user":           "not supported: the image's own user is used",
	"env_file":       "files from the host are not allowed; use environment",
	"container_name": "the panel names containers (<project>_<service>)",
	"restart":        "the panel sets the restart policy itself",
	"extra_hosts":    "not allowed",
	"sysctls":        "not allowed",
	"ulimits":        "not allowed",
	"volumes_from":   "not allowed; give each service its own named volume",
	"secrets":        "use generated variables (generate = \"secret\" in template.toml)",
	"configs":        "files from the host are not allowed",
	"labels":         "the panel sets the labels itself",
	"mem_limit":      "use deploy.resources.limits.memory",
	"cpus":           "use deploy.resources.limits.cpus",
}

// keyErr is an error at a key path inside compose.yaml.
func keyErr(path, format string, args ...any) error {
	return fmt.Errorf("compose.yaml: %s: %s", path, fmt.Sprintf(format, args...))
}

// parseCompose converts compose.yaml into services, the one named main
// first. Every problem found is returned, joined.
func parseCompose(data []byte, main string) ([]Service, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("compose.yaml: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("compose.yaml: expected a mapping with a services key")
	}
	var errs []error
	top := root.Content[0]
	var servicesNode *yaml.Node
	declared := map[string]bool{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		key, val := top.Content[i].Value, top.Content[i+1]
		switch key {
		case "services":
			servicesNode = val
		case "volumes":
			if val.Kind != yaml.MappingNode {
				errs = append(errs, keyErr("volumes", "expected a mapping of volume names"))
				continue
			}
			for j := 0; j+1 < len(val.Content); j += 2 {
				name, cfg := val.Content[j].Value, val.Content[j+1]
				if !node.VolumeNameRE.MatchString(name) {
					errs = append(errs, keyErr("volumes."+name, "invalid volume name"))
				}
				// Only plain named volumes: a driver or driver_opts could
				// bind a host directory.
				plain := (cfg.Kind == yaml.ScalarNode && cfg.Tag == "!!null") || (cfg.Kind == yaml.MappingNode && len(cfg.Content) == 0)
				if !plain {
					errs = append(errs, keyErr("volumes."+name, "only plain named volumes are allowed (no driver, driver_opts or external)"))
				}
				declared[name] = true
			}
		default:
			if r, ok := refusals[key]; ok {
				errs = append(errs, keyErr(key, "%s", r))
			} else {
				errs = append(errs, keyErr(key, "not allowed at the top level (only services and volumes)"))
			}
		}
	}
	if servicesNode == nil || servicesNode.Kind != yaml.MappingNode || len(servicesNode.Content) == 0 {
		return nil, errors.Join(append(errs, errors.New("compose.yaml: services: at least one service is required"))...)
	}
	if n := len(servicesNode.Content) / 2; n > 8 {
		errs = append(errs, keyErr("services", "at most 8 services (got %d)", n))
	}

	var list []Service
	usedVolume := map[string]string{}
	for i := 0; i+1 < len(servicesNode.Content); i += 2 {
		name, body := servicesNode.Content[i].Value, servicesNode.Content[i+1]
		at := "services." + name
		if !composeNameRE.MatchString(name) {
			errs = append(errs, keyErr(at, "service names are lowercase letters and digits, at most 12 (they become the suffix -%s)", name))
			continue
		}
		s, serr := parseComposeService(at, name, body, declared)
		errs = append(errs, serr...)
		for _, v := range s.Volumes {
			if other, ok := usedVolume[v.Name]; ok {
				errs = append(errs, keyErr(at+".volumes", "volume %s is already used by %s; services never share a volume", v.Name, other))
			}
			usedVolume[v.Name] = name
		}
		list = append(list, s)
	}
	for v := range declared {
		if _, ok := usedVolume[v]; !ok {
			errs = append(errs, keyErr("volumes."+v, "declared but not used"))
		}
	}

	// The main service first; the rest in file order, suffixed by name.
	idx := slices.IndexFunc(list, func(s Service) bool { return s.Name == main })
	if idx < 0 {
		errs = append(errs, fmt.Errorf("template.toml: main: %q is not a service in compose.yaml", main))
	} else {
		m := list[idx]
		list = append([]Service{m}, slices.Delete(list, idx, idx+1)...)
		for j := 1; j < len(list); j++ {
			list[j].Suffix = "-" + list[j].Name
		}
	}
	if cyc := dependencyCycle(list); cyc != "" {
		errs = append(errs, keyErr("services."+cyc+".depends_on", "dependency cycle"))
	}
	return list, errors.Join(errs...)
}

func parseComposeService(at, name string, body *yaml.Node, declared map[string]bool) (Service, []error) {
	s := Service{Name: name, Env: map[string]string{}}
	var errs []error
	fail := func(path, format string, args ...any) { errs = append(errs, keyErr(path, format, args...)) }
	if body.Kind != yaml.MappingNode {
		fail(at, "expected a mapping")
		return s, errs
	}
	for i := 0; i+1 < len(body.Content); i += 2 {
		key, val := body.Content[i].Value, body.Content[i+1]
		path := at + "." + key
		switch key {
		case "image":
			s.Image = scalar(val)
			if err := checkImage(s.Image); err != nil {
				fail(path, "%v", err)
			}
		case "command":
			list, ok := stringList(val)
			if !ok || len(list) == 0 {
				fail(path, "use the list form ([\"prog\", \"arg\"]); a string would depend on how it is split")
			}
			s.Command = list
		case "environment":
			parseEnvironment(path, val, s.Env, fail)
		case "volumes":
			parseServiceVolumes(path, val, declared, &s, fail)
		case "expose":
			list, ok := stringList(val)
			if !ok || len(list) != 1 {
				fail(path, "list exactly one port: the one the service listens on inside the network")
				continue
			}
			p, proto, _ := strings.Cut(list[0], "/")
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 || (proto != "" && proto != "tcp") {
				fail(path, "invalid port %q", list[0])
				continue
			}
			s.Port = n
		case "healthcheck":
			h, err := parseHealthcheck(path, val)
			if err != nil {
				errs = append(errs, err)
			}
			s.Health = h
		case "cap_add":
			list, ok := stringList(val)
			if !ok {
				fail(path, "expected a list")
				continue
			}
			s.CapAdd = make([]string, 0, len(list))
			for _, c := range list {
				c = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
				if _, ok := node.AllowedCaps[c]; !ok {
					fail(path, "capability %s is not allowed", c)
				}
				s.CapAdd = append(s.CapAdd, c)
			}
		case "read_only":
			b, ok := boolean(val)
			if !ok {
				fail(path, "expected true or false")
			}
			s.ReadOnly = b
		case "stop_grace_period":
			secs, clamped, ok := StopGrace(scalar(val))
			if !ok {
				fail(path, "%q: use a duration like 30s or 1m30s", scalar(val))
				continue
			}
			if clamped {
				s.warnings = append(s.warnings, fmt.Sprintf("compose.yaml: %s: %s is more than the panel allows; %s is used", path, scalar(val), node.MaxStopGrace))
			}
			s.StopGraceS = secs
		case "deploy":
			parseDeploy(path, val, &s, fail)
		case "depends_on":
			switch val.Kind {
			case yaml.SequenceNode:
				list, _ := stringList(val)
				s.DependsOn = list
			case yaml.MappingNode:
				for j := 0; j+1 < len(val.Content); j += 2 {
					s.DependsOn = append(s.DependsOn, val.Content[j].Value)
				}
			default:
				fail(path, "expected a list of service names")
			}
		default:
			if r, ok := refusals[key]; ok {
				fail(path, "%s", r)
			} else {
				fail(path, "not supported in templates (allowed: image, command, environment, volumes, expose, healthcheck, cap_add, read_only, stop_grace_period, deploy, depends_on)")
			}
		}
	}
	if s.Image == "" {
		fail(at+".image", "required")
	}
	if s.MemoryMB == 0 || s.CPUs == 0 {
		fail(at+".deploy.resources.limits", "memory and cpus are required")
	}
	s.Stateful = len(s.Volumes) > 0
	return s, errs
}

// StopGrace reads a Compose stop_grace_period ("45s", "1m30s") as whole
// seconds, rounded up. A value above node.MaxStopGrace becomes the cap and
// clamped is true: one container must not hold a deploy, a stop or the
// server's shutdown for longer. ok is false for anything that is not a
// positive duration.
func StopGrace(v string) (secs int, clamped, ok bool) {
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return 0, false, false
	}
	if d > node.MaxStopGrace {
		d, clamped = node.MaxStopGrace, true
	}
	return int((d + time.Second - 1) / time.Second), clamped, true
}

func parseEnvironment(path string, val *yaml.Node, env map[string]string, fail func(string, string, ...any)) {
	set := func(k, v string) {
		switch {
		case !envNameRE.MatchString(k):
			fail(path, "invalid variable name %q", k)
		case strings.ContainsRune(v, 0) || len(v) > 8192:
			fail(path+"."+k, "invalid value")
		default:
			if _, dup := env[k]; dup {
				fail(path+"."+k, "repeated")
			}
			env[k] = v
		}
	}
	switch val.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(val.Content); i += 2 {
			v := val.Content[i+1]
			if v.Kind != yaml.ScalarNode {
				fail(path+"."+val.Content[i].Value, "expected a plain value")
				continue
			}
			if v.Tag == "!!null" {
				fail(path+"."+val.Content[i].Value, "a value is required (nothing comes from the host's environment)")
				continue
			}
			set(val.Content[i].Value, v.Value)
		}
	case yaml.SequenceNode:
		for _, item := range val.Content {
			k, v, ok := strings.Cut(item.Value, "=")
			if !ok || item.Kind != yaml.ScalarNode {
				fail(path, "%q: use KEY=value (nothing comes from the host's environment)", item.Value)
				continue
			}
			set(k, v)
		}
	default:
		fail(path, "expected a mapping or a list of KEY=value")
	}
}

func parseServiceVolumes(path string, val *yaml.Node, declared map[string]bool, s *Service, fail func(string, string, ...any)) {
	if val.Kind != yaml.SequenceNode {
		fail(path, "expected a list")
		return
	}
	for _, item := range val.Content {
		var src, target string
		switch item.Kind {
		case yaml.ScalarNode:
			parts := strings.Split(item.Value, ":")
			if len(parts) != 2 {
				fail(path, "%q: use name:/path (no options, no anonymous volumes)", item.Value)
				continue
			}
			src, target = parts[0], parts[1]
		case yaml.MappingNode:
			var m map[string]any
			if err := item.Decode(&m); err != nil {
				fail(path, "invalid entry")
				continue
			}
			for k := range m {
				if k != "type" && k != "source" && k != "target" {
					fail(path, "%s: only type, source and target are allowed", k)
				}
			}
			if t := fmt.Sprint(m["type"]); t != "volume" {
				fail(path, "type %q is not allowed: only named volumes (type: volume)", t)
				continue
			}
			src, target = fmt.Sprint(m["source"]), fmt.Sprint(m["target"])
		default:
			fail(path, "invalid entry")
			continue
		}
		switch {
		case strings.Contains(src, "docker.sock"):
			fail(path, "%s: the Docker socket is never allowed", src)
		case strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") || strings.HasPrefix(src, "$"):
			fail(path, "%s: host paths (bind mounts) are not allowed; use a named volume", src)
		case !node.VolumeNameRE.MatchString(src):
			fail(path, "%s: invalid volume name", src)
		case !mountPathOK(target):
			fail(path, "%s: invalid mount path (absolute, outside system directories)", target)
		case !declared[src]:
			fail(path, "%s: declare it under the top-level volumes:", src)
		default:
			s.Volumes = append(s.Volumes, Volume{Name: src, Path: target})
		}
	}
}

// mountPathOK mirrors the node's check, so a template fails here instead of
// at its first deploy.
func mountPathOK(p string) bool {
	if !strings.HasPrefix(p, "/") || p == "/" || strings.Contains(p, "..") || strings.ContainsAny(p, ":,$\x00") {
		return false
	}
	return node.ReservedMount(p) == ""
}

func parseHealthcheck(path string, val *yaml.Node) (*Health, error) {
	if val.Kind != yaml.MappingNode {
		return nil, keyErr(path, "expected a mapping")
	}
	h := &Health{}
	for i := 0; i+1 < len(val.Content); i += 2 {
		key, v := val.Content[i].Value, val.Content[i+1]
		switch key {
		case "test":
			if v.Kind == yaml.ScalarNode {
				h.Test = []string{"CMD-SHELL", v.Value}
				continue
			}
			list, ok := stringList(v)
			if !ok {
				return nil, keyErr(path+".test", "expected a list or a string")
			}
			h.Test = list
		case "interval":
			h.Interval = scalar(v)
		case "timeout":
			h.Timeout = scalar(v)
		case "start_period":
			h.StartPeriod = scalar(v)
		case "retries":
			n, err := strconv.Atoi(scalar(v))
			if err != nil || n < 0 || n > 100 {
				return nil, keyErr(path+".retries", "expected a number from 0 to 100")
			}
			h.Retries = n
		default:
			return nil, keyErr(path+"."+key, "not supported (allowed: test, interval, timeout, start_period, retries)")
		}
	}
	if _, err := h.toNode(); err != nil {
		return nil, keyErr(path, "%v", err)
	}
	return h, nil
}

func parseDeploy(path string, val *yaml.Node, s *Service, fail func(string, string, ...any)) {
	var d map[string]any
	if err := val.Decode(&d); err != nil {
		fail(path, "expected a mapping")
		return
	}
	for k := range d {
		if k != "resources" {
			fail(path+"."+k, "not supported (only resources.limits)")
		}
	}
	res, _ := d["resources"].(map[string]any)
	for k := range res {
		if k != "limits" {
			fail(path+".resources."+k, "not supported (only limits)")
		}
	}
	limits, _ := res["limits"].(map[string]any)
	for k, v := range limits {
		p := path + ".resources.limits." + k
		switch k {
		case "memory":
			mb, ok := memoryMB(fmt.Sprint(v))
			if !ok || mb < 16 {
				fail(p, "%v: use a size like 256M or 1G (16M or more)", v)
			}
			s.MemoryMB = mb
		case "cpus":
			c, err := strconv.ParseFloat(fmt.Sprint(v), 64)
			if err != nil || c <= 0 || c > 64 || math.IsNaN(c) {
				fail(p, "%v: use a number like 0.5", v)
			}
			s.CPUs = c
		default:
			fail(p, "not supported (only memory and cpus)")
		}
	}
}

var memRE = regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*([kmg]?)(i?b)?$`)

// memoryMB reads a Compose size (512m, 1G, 256MiB, bytes) in whole MiB.
func memoryMB(v string) (int, bool) {
	m := memRE.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	switch strings.ToLower(m[2]) {
	case "":
		n /= 1 << 20
	case "k":
		n /= 1 << 10
	case "g":
		n *= 1 << 10
	}
	if n > 1<<20 {
		return 0, false
	}
	return int(n), true
}

func scalar(n *yaml.Node) string {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

func boolean(n *yaml.Node) (bool, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		return false, false
	}
	b, err := strconv.ParseBool(n.Value)
	return b, err == nil
}

// stringList reads a sequence of scalars (numbers become strings).
func stringList(n *yaml.Node) ([]string, bool) {
	if n.Kind != yaml.SequenceNode {
		return nil, false
	}
	out := make([]string, 0, len(n.Content))
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode || c.Tag == "!!null" {
			return nil, false
		}
		out = append(out, c.Value)
	}
	return out, true
}

// dependencyCycle returns a service that is part of a depends_on cycle, or
// "" when there is none.
func dependencyCycle(list []Service) string {
	deps := map[string][]string{}
	for _, s := range list {
		deps[s.Name] = s.DependsOn
	}
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(string) bool
	visit = func(n string) bool {
		switch state[n] {
		case 1:
			return true
		case 2:
			return false
		}
		state[n] = 1
		for _, d := range deps[n] {
			if visit(d) {
				return true
			}
		}
		state[n] = 2
		return false
	}
	for _, s := range list {
		if visit(s.Name) {
			return s.Name
		}
	}
	return ""
}
