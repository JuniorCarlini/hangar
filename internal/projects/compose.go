package projects

import (
	_ "embed"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// Importing a docker-compose file (docs/27): the file is read, never run.
// Each service becomes a Hangar service — a catalog template for the
// databases (generated passwords, backups, exports), an image service or a
// build from the same repository — and whatever the Hangar does not do, or
// refuses for safety (bind mounts, privileged mode, the host network,
// published ports), is listed in the preview with the reason. Nothing is
// created until the user confirms, and the confirmation parses the file
// again: the preview is never trusted.
//
// The parser is go.yaml.in/yaml/v3 (the YAML organization's maintained
// continuation of gopkg.in/yaml.v3, no dependencies of its own, and it
// refuses alias bombs) rather than compose-spec/compose-go: that one pulls
// in dozens of modules to support what this importer deliberately ignores
// (profiles, extends, includes, interpolation from the host environment,
// env files on disk).

// ComposeSample is the model file the panel offers (Django, PostgreSQL,
// Redis and a Celery worker): everything in it maps without loss.
//
//go:embed compose_sample.yaml
var ComposeSample string

// Limits of an imported file.
const (
	MaxComposeBytes    = 256 << 10
	MaxComposeServices = 20
	maxComposeEnv      = 200
)

// Note levels, from good to bad.
const (
	NoteOK   = "ok"   // recognized and mapped
	NoteInfo = "info" // ignored on purpose, nothing to do
	NoteWarn = "warn" // changed or needs the user's attention
	NoteSkip = "skip" // refused or impossible
)

// Kinds of imported service.
const (
	ComposeTemplate = "template"
	ComposeImage    = "image"
	ComposeGit      = "git"
	ComposeSkip     = "skip"
)

// ComposeNote is one line of the preview.
type ComposeNote struct {
	Level string
	Msg   *i18n.Error
}

// ComposeEnv is a variable of an imported service.
type ComposeEnv struct {
	Key    string
	Value  string
	Secret bool
	Ref    bool // the value references another service (${{db.DATABASE_URL}})
}

// ComposeService is what one compose service becomes.
type ComposeService struct {
	Name       string // as written in the file
	Slug       string
	Kind       string
	Template   string            // catalog id (Kind template)
	Inputs     map[string]string // template inputs taken from the file
	Image      string            // Kind image, or the file's image for a template
	Subdir     string            // Kind git: the build context
	Dockerfile string
	Port       int
	MemoryMB   int
	CPUs       float64
	Command    []string
	Env        []ComposeEnv
	Volumes    []node.Volume
	DependsOn  []string
	// StopGrace is stop_grace_period in seconds (0 = the default).
	StopGrace int
	Notes     []ComposeNote
	// Problem blocks the import (a name already taken, a missing
	// Dockerfile); the user fixes the file or the project and tries again.
	Problem *i18n.Error
	// X, Y is where the card goes on the canvas (Placed).
	X, Y   int
	Placed bool

	// The database's credentials as written in the file: an app variable
	// holding one of them becomes a reference to the template's export.
	creds map[string]string
}

// ComposePlan is the parsed file.
type ComposePlan struct {
	Services []ComposeService
	Notes    []ComposeNote
	FromRepo bool
	File     string // the file read from the repository
}

// Creatable reports whether the plan creates at least one service and
// nothing blocks it.
func (p ComposePlan) Creatable() bool {
	n := 0
	for _, s := range p.Services {
		if s.Problem != nil {
			return false
		}
		if s.Kind != ComposeSkip {
			n++
		}
	}
	return n > 0
}

// note wraps a message built with i18n.E (always an *i18n.Error).
func note(level string, msg error) ComposeNote {
	var ie *i18n.Error
	errors.As(msg, &ie)
	return ComposeNote{Level: level, Msg: ie}
}

func (s *ComposeService) add(level string, msg error) {
	s.Notes = append(s.Notes, note(level, msg))
}

// skip marks the service as not created, with the reason.
func (s *ComposeService) skip(msg error) {
	s.Kind = ComposeSkip
	s.add(NoteSkip, msg)
}

// ParseCompose reads a compose file. fromRepo says the file came from a
// repository, so build: sections can become builds of that repository.
// Errors are about the file as a whole (too big, not YAML, no services);
// everything about one service is in its notes.
func ParseCompose(data []byte, fromRepo bool) (ComposePlan, error) {
	plan := ComposePlan{FromRepo: fromRepo}
	if len(data) > MaxComposeBytes {
		return plan, i18n.E("compose.error.too_large", "max", MaxComposeBytes>>10)
	}
	if strings.TrimSpace(string(data)) == "" {
		return plan, i18n.E("compose.error.empty")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return plan, i18n.E("compose.error.yaml", "error", yamlMessage(err))
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return plan, i18n.E("compose.error.no_services")
	}
	top := root.Content[0]
	var servicesNode *yaml.Node
	volumes := map[string]any{}
	var ignored []string
	for i := 0; i+1 < len(top.Content); i += 2 {
		key, val := top.Content[i].Value, top.Content[i+1]
		switch {
		case key == "services":
			servicesNode = val
		case key == "volumes":
			_ = val.Decode(&volumes)
		case key == "version" || strings.HasPrefix(key, "x-"):
			// The version is obsolete; extension fields only feed anchors.
		case key == "secrets" || key == "configs":
			plan.Notes = append(plan.Notes, note(NoteWarn, i18n.E("compose.note.top_secrets", "key", key)))
		default:
			ignored = append(ignored, key)
		}
	}
	if len(ignored) > 0 {
		plan.Notes = append(plan.Notes, note(NoteInfo, i18n.E("compose.note.top_ignored", "keys", strings.Join(ignored, ", "))))
	}
	if servicesNode == nil || servicesNode.Kind != yaml.MappingNode || len(servicesNode.Content) == 0 {
		return plan, i18n.E("compose.error.no_services")
	}
	if n := len(servicesNode.Content) / 2; n > MaxComposeServices {
		return plan, i18n.E("compose.error.too_many", "n", n, "max", MaxComposeServices)
	}
	bindVolumes := map[string]bool{}
	for name, v := range volumes {
		if cfg, ok := v.(map[string]any); ok {
			if opts, ok := cfg["driver_opts"].(map[string]any); ok {
				if o := fmt.Sprint(opts["o"]); strings.Contains(o, "bind") || opts["device"] != nil {
					bindVolumes[name] = true
				}
			}
		}
	}

	slugs := map[string]string{}
	for i := 0; i+1 < len(servicesNode.Content); i += 2 {
		name := servicesNode.Content[i].Value
		var raw map[string]any
		if err := servicesNode.Content[i+1].Decode(&raw); err != nil || raw == nil {
			raw = map[string]any{}
		}
		s := parseService(name, raw, fromRepo, bindVolumes)
		if s.Slug == "" {
			s.Problem = &i18n.Error{Key: "compose.problem.name", Args: []any{"name", name}}
		} else if other, ok := slugs[s.Slug]; ok {
			s.Problem = &i18n.Error{Key: "compose.problem.same_slug", Args: []any{"a", other, "b", name, "slug", s.Slug}}
		} else {
			slugs[s.Slug] = name
			if s.Slug != name {
				s.add(NoteWarn, i18n.E("compose.note.renamed", "name", name, "slug", s.Slug))
			}
		}
		plan.Services = append(plan.Services, s)
	}
	linkReferences(&plan)
	return plan, nil
}

// yamlMessage keeps the parser's line information, without its prefix.
func yamlMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), "yaml: ")
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// refusedKeys are options the Hangar never applies: each one would weaken
// the isolation between the container and the server (docs/04).
var refusedKeys = []string{
	"privileged", "cap_add", "devices", "pid", "ipc", "security_opt", "userns_mode", "sysctls",
	"cgroup_parent", "cgroup", "volumes_from", "runtime", "isolation", "device_cgroup_rules", "group_add",
}

// silentKeys need no note: the Hangar does the equivalent or they only
// matter to docker compose itself.
var silentKeys = map[string]bool{
	"image": true, "build": true, "environment": true, "volumes": true, "ports": true, "expose": true,
	"command": true, "depends_on": true, "deploy": true, "mem_limit": true, "cpus": true,
	"stdin_open": true, "tty": true, "network_mode": true,
}

// infoKeys are ignored on purpose, with nothing for the user to do.
var infoKeys = map[string]bool{
	"container_name": true, "hostname": true, "restart": true, "labels": true, "logging": true,
	"networks": true, "links": true, "init": true, "stop_signal": true,
	"pull_policy": true, "platform": true, "cap_drop": true, "ulimits": true, "shm_size": true,
	"tmpfs": true, "dns": true, "dns_search": true, "extra_hosts": true, "domainname": true,
	"read_only": true, "mem_reservation": true, "memswap_limit": true, "oom_score_adj": true,
}

func parseService(name string, raw map[string]any, fromRepo bool, bindVolumes map[string]bool) ComposeService {
	s := ComposeService{Name: name, Slug: Slugify(name), Inputs: map[string]string{}}
	image, imageOK := interpolate(str(raw["image"]))
	if !imageOK {
		s.add(NoteWarn, i18n.E("compose.note.image_variable", "image", str(raw["image"])))
	}
	base, tag := imageBase(image)

	// What it becomes.
	build, hasBuild := raw["build"]
	switch {
	case hasBuild && fromRepo:
		s.Kind = ComposeGit
		parseBuild(&s, build)
	case base == "postgres":
		s.Kind, s.Template, s.Image = ComposeTemplate, "postgres", image
	case base == "redis":
		s.Kind, s.Template, s.Image = ComposeTemplate, "redis-cache", image
		if redisPersists(raw) {
			s.Template = "redis-queue"
		}
	case image != "":
		s.Kind, s.Image = ComposeImage, image
		if hasBuild {
			s.add(NoteWarn, i18n.E("compose.note.build_needs_repo_image"))
		}
	case hasBuild:
		s.skip(i18n.E("compose.note.build_needs_repo"))
	default:
		s.skip(i18n.E("compose.note.no_image"))
	}
	if s.Kind == ComposeImage && !node.ImageRE.MatchString(s.Image) {
		s.skip(i18n.E("compose.note.bad_image", "image", s.Image))
	}

	switch s.Kind {
	case ComposeTemplate:
		tpl, _ := templates.Builtin().Get(s.Template)
		want := ""
		if len(tpl.Services) > 0 {
			want = tpl.Services[0].Image
		}
		switch s.Template {
		case "postgres":
			s.add(NoteOK, i18n.E("compose.note.template_postgres"))
		case "redis-queue":
			s.add(NoteOK, i18n.E("compose.note.template_redis_queue"))
		default:
			s.add(NoteOK, i18n.E("compose.note.template_redis_cache"))
		}
		if _, wantTag := imageBase(want); tag != "" && !strings.HasPrefix(wantTag, strings.Split(tag, "-")[0]) {
			s.add(NoteWarn, i18n.E("compose.note.template_version", "from", image, "to", want))
		}
	case ComposeImage:
		s.add(NoteOK, i18n.E("compose.note.image", "image", s.Image))
		if tag == "" || tag == "latest" {
			s.add(NoteWarn, i18n.E("compose.note.image_latest"))
		}
	}

	if s.Kind == ComposeTemplate {
		// The database's variables only feed its inputs: no notes about them.
		var scratch ComposeService
		parseEnv(&scratch, raw["environment"])
		s.Env = scratch.Env
	} else {
		parseEnv(&s, raw["environment"])
	}
	parsePorts(&s, raw)
	if s.Kind != ComposeTemplate {
		parseCommand(&s, raw["command"])
		parseVolumes(&s, raw["volumes"], bindVolumes)
		parseLimits(&s, raw)
		parseStopGrace(&s, raw["stop_grace_period"])
	} else {
		templateFromEnv(&s)
		var dropped []string
		for _, k := range []string{"command", "volumes", "healthcheck", "deploy", "mem_limit", "cpus", "stop_grace_period"} {
			if _, ok := raw[k]; ok {
				dropped = append(dropped, k)
			}
		}
		if len(dropped) > 0 {
			s.add(NoteInfo, i18n.E("compose.note.template_keeps", "keys", strings.Join(dropped, ", ")))
		}
	}
	if s.Kind == ComposeImage && s.Port == 0 {
		if p := KnownImagePort(s.Image); p > 0 {
			s.Port = p
			s.add(NoteInfo, i18n.E("compose.note.port_known", "port", p))
		}
	}
	s.DependsOn = dependsOn(raw["depends_on"])
	if len(s.DependsOn) > 0 {
		s.add(NoteInfo, i18n.E("compose.note.depends_on", "services", strings.Join(s.DependsOn, ", ")))
	}

	// What it asks for that the Hangar refuses or ignores.
	for _, k := range refusedKeys {
		if v, ok := raw[k]; ok && v != false && v != nil {
			s.add(NoteSkip, i18n.E("compose.note.refused", "key", k))
		}
	}
	if nm := str(raw["network_mode"]); nm != "" {
		if nm == "host" || strings.HasPrefix(nm, "container:") || strings.HasPrefix(nm, "service:") {
			s.add(NoteSkip, i18n.E("compose.note.refused", "key", "network_mode: "+nm))
		} else {
			s.add(NoteInfo, i18n.E("compose.note.ignored", "keys", "network_mode"))
		}
	}
	for _, k := range []string{"entrypoint", "user", "working_dir"} {
		if _, ok := raw[k]; ok {
			s.add(NoteWarn, i18n.E("compose.note.unsupported", "key", k))
		}
	}
	if _, ok := raw["env_file"]; ok {
		s.add(NoteWarn, i18n.E("compose.note.env_file"))
	}
	if _, ok := raw["healthcheck"]; ok && s.Kind != ComposeTemplate {
		s.add(NoteInfo, i18n.E("compose.note.healthcheck"))
	}
	for _, k := range []string{"extends", "profiles", "scale"} {
		if _, ok := raw[k]; ok {
			s.add(NoteWarn, i18n.E("compose.note.unsupported", "key", k))
		}
	}
	var ignored []string
	for k := range raw {
		if silentKeys[k] || slices.Contains(refusedKeys, k) || infoKeys[k] {
			if infoKeys[k] {
				ignored = append(ignored, k)
			}
			continue
		}
		switch k {
		case "entrypoint", "user", "working_dir", "env_file", "healthcheck", "extends", "profiles", "scale", "stop_grace_period":
			continue
		}
		ignored = append(ignored, k)
	}
	if len(ignored) > 0 {
		sort.Strings(ignored)
		s.add(NoteInfo, i18n.E("compose.note.ignored", "keys", strings.Join(ignored, ", ")))
	}
	return s
}

// str is a scalar as text ("" for anything else).
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int, int64, float64, bool:
		return fmt.Sprint(x)
	}
	return ""
}

// interpolate resolves the compose syntax for host variables. The Hangar
// does not read the server's environment: ${VAR:-default} takes the
// default, anything else becomes empty and ok is false. $$ is a literal $.
func interpolate(v string) (string, bool) {
	if !strings.Contains(v, "$") {
		return v, true
	}
	ok := true
	out := varRE.ReplaceAllStringFunc(v, func(m string) string {
		if m == "$$" {
			return "$"
		}
		g := varRE.FindStringSubmatch(m)
		if g[2] == ":-" || g[2] == "-" {
			return g[3]
		}
		ok = false
		return ""
	})
	return out, ok
}

var varRE = regexp.MustCompile(`\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// imageBase is an image's repository without the default registry and
// library prefix ("postgres", "bitnami/redis") and its tag.
func imageBase(image string) (string, string) {
	name, _, _ := strings.Cut(image, "@")
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	name = strings.TrimPrefix(name, "docker.io/")
	name = strings.TrimPrefix(name, "library/")
	return name, tag
}

// redisPersists: a Redis that keeps its data (a volume, AOF or snapshots)
// is a queue or a session store, not a cache.
func redisPersists(raw map[string]any) bool {
	if v, ok := raw["volumes"].([]any); ok && len(v) > 0 {
		return true
	}
	cmd := strings.Join(commandOf(raw["command"]), " ")
	return strings.Contains(cmd, "appendonly yes") || (strings.Contains(cmd, "--save") && !strings.Contains(cmd, `--save ""`) && !strings.Contains(cmd, "--save ''"))
}

func parseBuild(s *ComposeService, build any) {
	ctx, dockerfile := "", ""
	switch b := build.(type) {
	case string:
		ctx = b
	case map[string]any:
		ctx, dockerfile = str(b["context"]), str(b["dockerfile"])
		if _, ok := b["dockerfile_inline"]; ok {
			s.skip(i18n.E("compose.note.build_inline"))
			return
		}
		var ignored []string
		for _, k := range []string{"args", "target", "secrets", "ssh", "cache_from", "additional_contexts"} {
			if _, ok := b[k]; ok {
				ignored = append(ignored, k)
			}
		}
		if len(ignored) > 0 {
			s.add(NoteWarn, i18n.E("compose.note.build_ignored", "keys", strings.Join(ignored, ", ")))
		}
	}
	if strings.Contains(ctx, "://") || strings.HasPrefix(ctx, "git@") {
		s.skip(i18n.E("compose.note.build_remote"))
		return
	}
	sub, err := gitsrc.CleanPath(strings.TrimPrefix(ctx, "./"))
	if err != nil {
		s.skip(i18n.E("compose.note.build_path", "path", ctx))
		return
	}
	df, err := gitsrc.CleanPath(strings.TrimPrefix(dockerfile, "./"))
	if err != nil {
		s.skip(i18n.E("compose.note.build_path", "path", dockerfile))
		return
	}
	if df == "" {
		df = defaultDockerfile
	}
	s.Subdir, s.Dockerfile = sub, df
	where := sub
	if where == "" {
		where = "."
	}
	s.add(NoteOK, i18n.E("compose.note.build", "path", path.Join(where, df)))
}

var secretKeyRE = regexp.MustCompile(`(?i)pass|secret|token|key|credential|private|dsn`)

func parseEnv(s *ComposeService, env any) {
	type kv struct {
		k   string
		v   string
		set bool
	}
	var vars []kv
	switch e := env.(type) {
	case map[string]any:
		for k, v := range e {
			vars = append(vars, kv{k, str(v), v != nil})
		}
		sort.Slice(vars, func(i, j int) bool { return vars[i].k < vars[j].k })
	case []any:
		for _, x := range e {
			k, v, ok := strings.Cut(str(x), "=")
			vars = append(vars, kv{k, v, ok})
		}
	}
	var unset, invalid []string
	for _, x := range vars {
		k := strings.TrimSpace(x.k)
		if !envKeyRE.MatchString(k) || strings.ContainsRune(x.v, 0) || len(x.v) > MaxEnvValue {
			invalid = append(invalid, k)
			continue
		}
		v, ok := interpolate(x.v)
		if !x.set || !ok {
			unset = append(unset, k)
		}
		if len(s.Env) >= maxComposeEnv {
			s.add(NoteWarn, i18n.E("compose.note.env_too_many", "max", maxComposeEnv))
			break
		}
		s.Env = append(s.Env, ComposeEnv{Key: k, Value: v, Secret: secretKeyRE.MatchString(k) || hasURLPassword(v)})
	}
	if len(unset) > 0 {
		s.add(NoteWarn, i18n.E("compose.note.env_unset", "keys", strings.Join(unset, ", ")))
	}
	if len(invalid) > 0 {
		s.add(NoteWarn, i18n.E("compose.note.env_invalid", "keys", strings.Join(invalid, ", ")))
	}
}

func hasURLPassword(v string) bool {
	u, err := url.Parse(v)
	if err != nil || u.User == nil {
		return false
	}
	_, ok := u.User.Password()
	return ok
}

// templateFromEnv takes the database's inputs from its variables (the
// password is always generated) and drops the rest: the template sets its
// own.
func templateFromEnv(s *ComposeService) {
	env := map[string]string{}
	for _, e := range s.Env {
		env[e.Key] = e.Value
	}
	s.creds = map[string]string{}
	if s.Template == "postgres" {
		user := env["POSTGRES_USER"]
		if user == "" {
			user = "postgres"
		}
		db := env["POSTGRES_DB"]
		if db == "" {
			db = user
		}
		tpl, _ := templates.Builtin().Get("postgres")
		for _, in := range tpl.Inputs {
			v := map[string]string{"user": user, "database": db}[in.Key]
			if regexp.MustCompile(in.Pattern).MatchString(v) {
				s.Inputs[in.Key] = v
			} else {
				s.Inputs[in.Key] = in.Default
				s.add(NoteWarn, i18n.E("compose.note.template_input", "key", in.Key, "value", v, "default", in.Default))
			}
		}
		s.creds["USER"], s.creds["DATABASE"], s.creds["PASSWORD"] = user, db, env["POSTGRES_PASSWORD"]
	} else {
		s.creds["PASSWORD"] = env["REDIS_PASSWORD"]
	}
	s.add(NoteOK, i18n.E("compose.note.template_password"))
	s.Env = nil
}

func parsePorts(s *ComposeService, raw map[string]any) {
	internal := 0
	if ex, ok := raw["expose"].([]any); ok {
		for _, e := range ex {
			p, _, _ := strings.Cut(str(e), "/")
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
				internal = n
				break
			}
		}
	}
	var published []string
	if ps, ok := raw["ports"].([]any); ok {
		for _, p := range ps {
			target := 0
			switch x := p.(type) {
			case map[string]any:
				target, _ = strconv.Atoi(str(x["target"]))
				published = append(published, str(x["published"])+":"+str(x["target"]))
			default:
				spec := str(x)
				published = append(published, spec)
				spec, _, _ = strings.Cut(spec, "/")
				parts := strings.Split(spec, ":")
				target, _ = strconv.Atoi(parts[len(parts)-1])
			}
			if internal == 0 && target > 0 && target <= 65535 {
				internal = target
			}
		}
	}
	if len(published) > 0 {
		s.add(NoteWarn, i18n.E("compose.note.ports", "ports", strings.Join(published, ", ")))
	}
	if s.Kind == ComposeTemplate {
		return
	}
	if internal > 0 {
		s.Port = internal
		s.add(NoteOK, i18n.E("compose.note.port", "port", internal))
	}
}

func commandOf(c any) []string {
	switch x := c.(type) {
	case string:
		return shellSplit(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, a := range x {
			out = append(out, str(a))
		}
		return out
	}
	return nil
}

func parseCommand(s *ComposeService, c any) {
	cmd := commandOf(c)
	if len(cmd) == 0 {
		return
	}
	for i, a := range cmd {
		v, ok := interpolate(a)
		if !ok {
			s.add(NoteWarn, i18n.E("compose.note.command_variable"))
		}
		cmd[i] = v
	}
	s.Command = cmd
	s.add(NoteOK, i18n.E("compose.note.command", "command", truncate(strings.Join(cmd, " "), 80)))
}

// shellSplit splits a command the way docker compose does: on spaces,
// keeping quoted parts together (no variables, no globbing).
func shellSplit(s string) []string {
	var out []string
	var cur strings.Builder
	in, quote, esc := false, rune(0), false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc, in = false, true
		case r == '\\' && quote != '\'':
			esc = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, in = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

func parseVolumes(s *ComposeService, vols any, bindVolumes map[string]bool) {
	list, _ := vols.([]any)
	var binds []string
	for _, v := range list {
		src, dst, kind := "", "", "volume"
		switch x := v.(type) {
		case string:
			parts := strings.Split(x, ":")
			switch len(parts) {
			case 1:
				dst = parts[0]
			default:
				src, dst = parts[0], parts[1]
			}
			if src != "" && (strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") || strings.Contains(src, "/")) {
				kind = "bind"
			}
		case map[string]any:
			kind, src, dst = str(x["type"]), str(x["source"]), str(x["target"])
			if kind == "" {
				kind = "volume"
			}
		}
		if strings.Contains(src, "docker.sock") || strings.Contains(dst, "docker.sock") {
			s.add(NoteSkip, i18n.E("compose.note.docker_socket"))
			continue
		}
		if kind == "bind" || bindVolumes[src] {
			binds = append(binds, src+":"+dst)
			continue
		}
		if kind != "volume" {
			s.add(NoteInfo, i18n.E("compose.note.volume_type", "type", kind, "path", dst))
			continue
		}
		mount, err := cleanMount(dst)
		if err != nil {
			s.add(NoteWarn, i18n.E("compose.note.volume_path", "path", dst))
			continue
		}
		name := volumeName(src, mount)
		if len(s.Volumes) >= MaxVolumes {
			s.add(NoteWarn, i18n.E("compose.note.volume_too_many", "max", MaxVolumes))
			break
		}
		clash := false
		for _, o := range s.Volumes {
			if o.Name == name || o.Path == mount || strings.HasPrefix(mount, o.Path+"/") || strings.HasPrefix(o.Path, mount+"/") {
				clash = true
			}
		}
		if clash {
			s.add(NoteWarn, i18n.E("compose.note.volume_path", "path", dst))
			continue
		}
		s.Volumes = append(s.Volumes, node.Volume{Name: name, Path: mount})
		s.add(NoteOK, i18n.E("compose.note.volume", "name", name, "path", mount))
	}
	if len(binds) > 0 {
		s.add(NoteSkip, i18n.E("compose.note.bind", "mounts", strings.Join(binds, ", ")))
	}
}

// volumeName turns a compose volume name (or, for an anonymous volume, the
// mount path) into a disk name.
func volumeName(src, mount string) string {
	if src == "" {
		src = path.Base(mount)
	}
	n := Slugify(src)
	if len(n) > 30 {
		n = strings.TrimRight(n[:30], "-")
	}
	if !volumeNameRE.MatchString(n) {
		n = "data"
	}
	return n
}

func parseLimits(s *ComposeService, raw map[string]any) {
	mem, cpus := str(raw["mem_limit"]), str(raw["cpus"])
	if d, ok := raw["deploy"].(map[string]any); ok {
		if r, ok := d["resources"].(map[string]any); ok {
			if l, ok := r["limits"].(map[string]any); ok {
				if v := str(l["memory"]); v != "" {
					mem = v
				}
				if v := str(l["cpus"]); v != "" {
					cpus = v
				}
			}
		}
		if n, _ := strconv.Atoi(str(d["replicas"])); n > 1 {
			s.add(NoteWarn, i18n.E("compose.note.replicas", "n", n))
		}
	}
	if mem != "" {
		if mb := memoryMB(mem); mb >= 16 && mb <= 64*1024 {
			s.MemoryMB = mb
			s.add(NoteOK, i18n.E("compose.note.memory", "mb", mb))
		} else {
			s.add(NoteWarn, i18n.E("compose.note.limit_invalid", "key", "memory", "value", mem))
		}
	}
	if cpus != "" {
		if c, err := strconv.ParseFloat(cpus, 64); err == nil && c >= 0.05 && c <= 64 {
			s.CPUs = c
			s.add(NoteOK, i18n.E("compose.note.cpus", "cpus", strconv.FormatFloat(c, 'f', -1, 64)))
		} else {
			s.add(NoteWarn, i18n.E("compose.note.limit_invalid", "key", "cpus", "value", cpus))
		}
	}
}

// memoryMB reads a compose memory size: bytes, or with a b/k/m/g suffix.
func memoryMB(v string) int {
	v = strings.ToLower(strings.TrimSpace(v))
	mult := 1.0 / (1 << 20)
	for _, u := range []struct {
		suffix string
		mult   float64
	}{{"gb", 1024}, {"mb", 1}, {"kb", 1.0 / 1024}, {"g", 1024}, {"m", 1}, {"k", 1.0 / 1024}, {"b", 1.0 / (1 << 20)}} {
		if strings.HasSuffix(v, u.suffix) {
			v, mult = strings.TrimSuffix(v, u.suffix), u.mult
			break
		}
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 || math.IsInf(f, 0) {
		return 0
	}
	return int(f * mult)
}

// parseStopGrace keeps stop_grace_period (how long a stop waits after
// SIGTERM), capped at node.MaxStopGrace.
func parseStopGrace(s *ComposeService, v any) {
	if v == nil {
		return
	}
	secs, clamped, ok := templates.StopGrace(str(v))
	switch {
	case !ok:
		s.add(NoteWarn, i18n.E("compose.note.stop_grace_invalid", "value", str(v)))
	case clamped:
		s.StopGrace = secs
		s.add(NoteWarn, i18n.E("compose.note.stop_grace_clamped", "value", str(v), "max", secs))
	default:
		s.StopGrace = secs
		s.add(NoteOK, i18n.E("compose.note.stop_grace", "seconds", secs))
	}
}

func dependsOn(d any) []string {
	var out []string
	switch x := d.(type) {
	case []any:
		for _, v := range x {
			out = append(out, str(v))
		}
	case map[string]any:
		for k := range x {
			out = append(out, k)
		}
		sort.Strings(out)
	}
	return out
}

// linkReferences turns the apps' variables that point at an imported
// database by its compose name into references to the template's exports:
// postgres://app:secret@db:5432/app becomes ${{db.DATABASE_URL}}, DB_HOST=db
// becomes ${{db.HOST}}. The password in the file is never kept: the
// template generates a new one and the reference follows it.
func linkReferences(plan *ComposePlan) {
	targets := map[string]*ComposeService{}
	for i := range plan.Services {
		if s := &plan.Services[i]; s.Kind == ComposeTemplate && s.Slug != "" {
			targets[s.Name] = s
		}
	}
	if len(targets) == 0 {
		return
	}
	for i := range plan.Services {
		s := &plan.Services[i]
		if s.Kind == ComposeTemplate || s.Kind == ComposeSkip {
			continue
		}
		for j := range s.Env {
			e := &s.Env[j]
			if ref, ok := referenceFor(e.Key, e.Value, targets); ok {
				e.Value, e.Ref, e.Secret = ref, true, false
				s.add(NoteOK, i18n.E("compose.note.reference", "key", e.Key, "ref", ref))
			}
		}
	}
}

func referenceFor(key, value string, targets map[string]*ComposeService) (string, bool) {
	ref := func(t *ComposeService, k string) string { return "${{" + t.Slug + "." + k + "}}" }
	if u, err := url.Parse(value); err == nil && u.Host != "" {
		t, ok := targets[u.Hostname()]
		if !ok {
			return "", false
		}
		switch {
		case t.Template == "postgres" && strings.HasPrefix(u.Scheme, "postgres"):
			if (u.Scheme == "postgres" || u.Scheme == "postgresql") && u.RawQuery == "" && strings.TrimPrefix(u.Path, "/") == t.Inputs["database"] {
				return ref(t, "DATABASE_URL"), true
			}
			db := strings.TrimPrefix(u.Path, "/")
			if db == t.Inputs["database"] {
				db = ref(t, "DATABASE")
			}
			out := u.Scheme + "://" + ref(t, "USER") + ":" + ref(t, "PASSWORD") + "@" + ref(t, "HOST") + ":" + ref(t, "PORT") + "/" + db
			if u.RawQuery != "" {
				out += "?" + u.RawQuery
			}
			return out, true
		case t.Template != "postgres" && strings.HasPrefix(u.Scheme, "redis"):
			if u.Path == "" || u.Path == "/0" {
				return ref(t, "REDIS_URL"), true
			}
			return "redis://:" + ref(t, "PASSWORD") + "@" + ref(t, "HOST") + ":" + ref(t, "PORT") + u.Path, true
		}
		return "", false
	}
	upper := strings.ToUpper(key)
	for name, t := range targets {
		switch {
		case value == name && strings.Contains(upper, "HOST"):
			return ref(t, "HOST"), true
		case t.creds["PASSWORD"] != "" && value == t.creds["PASSWORD"] && strings.Contains(upper, "PASS"):
			return ref(t, "PASSWORD"), true
		case t.Template == "postgres" && value == t.creds["USER"] && strings.Contains(upper, "USER"):
			return ref(t, "USER"), true
		case t.Template == "postgres" && value == t.creds["DATABASE"] && (strings.HasSuffix(upper, "_NAME") || strings.HasSuffix(upper, "_DB") || strings.HasSuffix(upper, "DATABASE")):
			return ref(t, "DATABASE"), true
		}
	}
	return "", false
}
