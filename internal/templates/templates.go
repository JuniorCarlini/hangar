// Package templates holds the service catalog (docs/08): one click creates
// services that are already secure — generated passwords, limits, volumes and
// healthchecks — and nothing a plain service could not have. Privileged mode,
// the Docker socket, host paths and published ports do not exist in the
// format at all.
//
// Each template is a folder (catalog/<id>/) with a plain Docker Compose file
// restricted to a safe subset (compose.yaml), the metadata Compose cannot
// carry (template.toml), a logo (logo.svg) and an optional README.md. The
// folder is converted into the Template below; everything after loading
// (rendering, creating the services) only sees that struct.
package templates

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/release"
)

// Text is a string per language; "en" is the fallback.
type Text map[string]string

// In returns the text in locale, falling back to English.
func (t Text) In(locale string) string {
	if s, ok := t[locale]; ok {
		return s
	}
	return t["en"]
}

// Categories a template may declare.
var Categories = []string{"database", "cache", "queue", "search", "storage", "automation", "monitoring", "admin", "other"}

// maxEndpoints caps the HTTP endpoints a template may declare.
const maxEndpoints = 6

// Template is one catalog entry.
type Template struct {
	ID       string
	Version  int
	Category string
	// Tags help search ("sql", "s3"); lowercase words.
	Tags        []string
	Name        Text
	Description Text
	Docs        string
	// MinHangar is the oldest Hangar version the template works on ("" for
	// any). Only templates from the community catalog are filtered by it.
	MinHangar string
	Inputs    []Input
	Generated []Generate
	// Services: the main one (it gets the name the user chose and the
	// exports) always comes first.
	Services []Service
	Exports  []Export
	// Backup says how "Download backup" works: "pg_dump" or "" (none).
	Backup string
	// Endpoints are the container ports the service exposes over HTTP and
	// can get an external link (docs/28). Empty = no web page.
	Endpoints []Endpoint
	// Logo is the validated SVG (see CheckSVG).
	Logo []byte
	// Readme is the optional README.md, as Markdown.
	Readme string
	// Remote is set for templates that came from the signed community
	// catalog instead of this binary.
	Remote bool
	// Warnings are what the loader changed instead of refusing (a stop
	// grace period above the cap); hangard template check prints them.
	Warnings []string
}

// Input is a form field.
type Input struct {
	Key     string
	Label   Text
	Default string
	Pattern string
}

// Generate is a value the panel creates and the user never types.
type Generate struct {
	Key  string
	Kind string // "secret": 32 random bytes, base64url
}

// Service is one service the template creates.
type Service struct {
	// Name is the service's name in compose.yaml.
	Name string
	// Suffix is appended to the chosen name ("" for the main service,
	// "-<Name>" for the others).
	Suffix   string
	Image    string
	Port     int
	Env      map[string]string
	Command  []string
	Volumes  []Volume
	MemoryMB int
	CPUs     float64
	// CapAdd nil means the panel's defaults (node.DefaultCaps); an empty,
	// non-nil list means none at all.
	CapAdd    []string
	Health    *Health
	Stateful  bool
	ReadOnly  bool
	DependsOn []string
	// StopGraceS is stop_grace_period in seconds (0 = the panel's default).
	StopGraceS int

	// warnings collected while parsing (Template.Warnings).
	warnings []string
}

// Volume is a named volume in template form.
type Volume struct {
	Name string
	Path string
	// ReadOnly: name:/path:ro, or read_only: true in the long form.
	ReadOnly bool
	// Owner is the compose service whose volume this is when several
	// services mount it ("" for the owner itself; see shareVolumes).
	Owner string
}

// Health is the healthcheck in template form.
type Health struct {
	Test        []string
	Interval    string
	Timeout     string
	StartPeriod string
	Retries     int
}

// Endpoint is a container port the service exposes over HTTP, which can get
// an external link (docs/28).
type Endpoint struct {
	// Name is a short slug used in the automatic hostname when a service
	// exposes more than one public endpoint ("" derives it from the label).
	Name string
	// Port is the container port that answers HTTP.
	Port int
	// Label is shown on the "open" button.
	Label Text
	// Public is the default exposure: true gives an external link, false
	// keeps the port on the project network only (fail-closed default).
	Public bool
}

// Export is something other services may reference as ${{service.KEY}}.
type Export struct {
	Key    string `toml:"key"`
	Value  string `toml:"value"`
	Secret bool   `toml:"secret"`
}

// LogoETag identifies the logo's content (quoted, ready for the header).
func (t *Template) LogoETag() string {
	h := sha256.Sum256(t.Logo)
	return `"` + t.ID + "-v" + strconv.Itoa(t.Version) + "-" + hex.EncodeToString(h[:6]) + `"`
}

// LogoURL is the panel route serving the logo; the query changes with the
// content, so the browser may cache it for good.
func (t *Template) LogoURL() string {
	return "/templates/" + t.ID + "/logo.svg?v=" + strings.Trim(t.LogoETag(), `"`)
}

var (
	idRE        = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	keyRE       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	exportKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	suffixRE    = regexp.MustCompile(`^(-[a-z0-9]{1,12})?$`)
	tagRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)
	endpointRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)
	// A typed field must never be a password: those are always generated.
	secretishRE = regexp.MustCompile(`(?i)pass|secret|token|key`)
)

// builtins are the placeholders every template gets for free.
var builtins = map[string]bool{"name": true, "project": true, "service": true}

// Validate applies the catalog rules (docs/08). A template that fails is
// never offered. Messages are in English: they are for template authors
// (hangard template check) and the logs, not for the panel's users.
func (t *Template) Validate() error {
	switch {
	case !idRE.MatchString(t.ID):
		return fmt.Errorf("id: invalid %q (lowercase letters, digits and -, 2 to 31 characters)", t.ID)
	case t.Version < 1:
		return errors.New("version: must be 1 or more")
	case !slices.Contains(Categories, t.Category):
		return fmt.Errorf("category: %q is not one of %s", t.Category, strings.Join(Categories, ", "))
	case t.Name["en"] == "" || t.Name["pt-BR"] == "":
		return errors.New("name: en and pt-BR are required")
	case t.Description["en"] == "" || t.Description["pt-BR"] == "":
		return errors.New("description: en and pt-BR are required")
	case len(t.Services) == 0:
		return errors.New("compose.yaml: no services")
	case t.Backup != "" && t.Backup != "pg_dump":
		return fmt.Errorf("backup: unknown kind %q", t.Backup)
	case len(t.Tags) > 8:
		return errors.New("tags: at most 8")
	}
	for _, tag := range t.Tags {
		if !tagRE.MatchString(tag) {
			return fmt.Errorf("tags: invalid tag %q", tag)
		}
	}
	for _, txt := range []Text{t.Name, t.Description} {
		for lang, s := range txt {
			if len(s) > 300 {
				return fmt.Errorf("name/description %s: at most 300 characters", lang)
			}
		}
	}
	if t.Docs != "" {
		if u, err := url.Parse(t.Docs); err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("docs: %q must be an https URL", t.Docs)
		}
	}
	if t.MinHangar != "" {
		if _, err := release.ParseVersion(t.MinHangar); err != nil {
			return fmt.Errorf("min_hangar: %q must look like v1.2.3", t.MinHangar)
		}
	}
	if err := CheckSVG(t.Logo); err != nil {
		return fmt.Errorf("logo.svg: %w", err)
	}

	keys := map[string]bool{}
	for k := range builtins {
		keys[k] = true
	}
	reserved := func(k string) bool { return keys[k] || strings.HasPrefix(k, "service_") }
	for _, in := range t.Inputs {
		at := "variables." + in.Key
		if !keyRE.MatchString(in.Key) || reserved(in.Key) {
			return fmt.Errorf("%s: invalid, reserved or repeated name", at)
		}
		if secretishRE.MatchString(in.Key) {
			return fmt.Errorf("%s: looks like a secret; use generate = \"secret\" instead of a typed value", at)
		}
		if in.Label["en"] == "" || in.Label["pt-BR"] == "" {
			return fmt.Errorf("%s: label in en and pt-BR required", at)
		}
		if in.Pattern == "" {
			return fmt.Errorf("%s: pattern required", at)
		}
		if !strings.HasPrefix(in.Pattern, "^") || !strings.HasSuffix(in.Pattern, "$") {
			return fmt.Errorf("%s: pattern must be anchored with ^ and $", at)
		}
		re, err := regexp.Compile(in.Pattern)
		if err != nil {
			return fmt.Errorf("%s: pattern: %w", at, err)
		}
		if !re.MatchString(in.Default) {
			return fmt.Errorf("%s: default %q does not match the pattern", at, in.Default)
		}
		keys[in.Key] = true
	}
	for _, g := range t.Generated {
		at := "variables." + g.Key
		if !keyRE.MatchString(g.Key) || reserved(g.Key) {
			return fmt.Errorf("%s: invalid, reserved or repeated name", at)
		}
		if g.Kind != "secret" {
			return fmt.Errorf("%s: generate must be \"secret\"", at)
		}
		keys[g.Key] = true
	}

	suffixes := map[string]bool{}
	names := map[string]bool{}
	for _, s := range t.Services {
		names[s.Name] = true
	}
	for i, s := range t.Services {
		at := "compose.yaml: services." + s.Name
		if (i == 0) != (s.Suffix == "") {
			return fmt.Errorf("%s: only the main service has no suffix", at)
		}
		if !suffixRE.MatchString(s.Suffix) || suffixes[s.Suffix] {
			return fmt.Errorf("%s: invalid or repeated suffix %q", at, s.Suffix)
		}
		suffixes[s.Suffix] = true
		if err := checkImage(s.Image); err != nil {
			return fmt.Errorf("%s.image: %w", at, err)
		}
		if s.MemoryMB < 16 || s.CPUs <= 0 {
			return fmt.Errorf("%s.deploy.resources.limits: memory (16M or more) and cpus are required", at)
		}
		if s.Port < 0 || s.Port > 65535 {
			return fmt.Errorf("%s.expose: invalid port", at)
		}
		for _, c := range s.CapAdd {
			if _, ok := node.AllowedCaps[c]; !ok {
				return fmt.Errorf("%s.cap_add: capability %s is not allowed", at, c)
			}
		}
		if s.Stateful && s.Health == nil {
			return fmt.Errorf("%s.healthcheck: required for a service with a volume", at)
		}
		if s.Health != nil {
			if _, err := s.Health.toNode(); err != nil {
				return fmt.Errorf("%s.healthcheck: %w", at, err)
			}
		}
		if s.StopGraceS < 0 || time.Duration(s.StopGraceS)*time.Second > node.MaxStopGrace {
			return fmt.Errorf("%s.stop_grace_period: at most %s", at, node.MaxStopGrace)
		}
		for _, d := range s.DependsOn {
			if !names[d] || d == s.Name {
				return fmt.Errorf("%s.depends_on: unknown service %q", at, d)
			}
		}
	}
	for _, s := range t.Services[1:] {
		keys["service_"+s.Name] = true
	}
	seenExport := map[string]bool{}
	for _, e := range t.Exports {
		if !exportKeyRE.MatchString(e.Key) || seenExport[e.Key] {
			return fmt.Errorf("exports: invalid or repeated key %q", e.Key)
		}
		seenExport[e.Key] = true
	}
	if len(t.Endpoints) > maxEndpoints {
		return fmt.Errorf("endpoints: at most %d", maxEndpoints)
	}
	seenEPName := map[string]bool{}
	seenEPPort := map[int]bool{}
	for _, e := range t.Endpoints {
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("endpoints: invalid port %d", e.Port)
		}
		if seenEPPort[e.Port] {
			return fmt.Errorf("endpoints: port %d repeated", e.Port)
		}
		seenEPPort[e.Port] = true
		if e.Label["en"] == "" || e.Label["pt-BR"] == "" {
			return fmt.Errorf("endpoints: port %d: label in en and pt-BR required", e.Port)
		}
		if e.Name != "" {
			if !endpointRE.MatchString(e.Name) || seenEPName[e.Name] {
				return fmt.Errorf("endpoints: invalid or repeated name %q", e.Name)
			}
			seenEPName[e.Name] = true
		}
	}
	// Render once with sample values: catches typos in the placeholders.
	sample := map[string]string{"name": "x", "project": "p", "service": "p_x"}
	for k := range keys {
		if _, ok := sample[k]; !ok {
			sample[k] = "v"
		}
	}
	if _, err := t.Render(sample); err != nil {
		return err
	}
	return nil
}

func checkImage(image string) error {
	if !node.ImageRE.MatchString(image) {
		return fmt.Errorf("invalid image %q", image)
	}
	name, _, _ := strings.Cut(image, "@")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	_, tag, ok := strings.Cut(name, ":")
	if !ok || tag == "" || tag == "latest" {
		return fmt.Errorf("image %q needs an explicit version tag (never latest)", image)
	}
	return nil
}

func (h *Health) toNode() (*node.Health, error) {
	if len(h.Test) < 2 || (h.Test[0] != "CMD" && h.Test[0] != "CMD-SHELL") {
		return nil, errors.New("test must start with CMD or CMD-SHELL")
	}
	out := &node.Health{Test: h.Test, Retries: h.Retries}
	for _, d := range []struct {
		s   string
		dst *time.Duration
	}{{h.Interval, &out.Interval}, {h.Timeout, &out.Timeout}, {h.StartPeriod, &out.StartPeriod}} {
		if d.s == "" {
			continue
		}
		v, err := time.ParseDuration(d.s)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("invalid duration %q", d.s)
		}
		*d.dst = v
	}
	return out, nil
}

// Rendered is a template with every placeholder filled in.
type Rendered struct {
	// Services: the main one first (see Template.Services).
	Services []RenderedService
	Exports  []Export
}

// RenderedService is ready to become a service.
type RenderedService struct {
	Slug     string
	Image    string
	Port     int
	Env      map[string]string
	Command  []string
	Volumes  []node.Volume
	MemoryMB int
	CPUs     float64
	CapAdd   []string
	Health   *node.Health
	Stateful bool
	ReadOnly bool
	// StopGraceS is the stop grace period in seconds (0 = default).
	StopGraceS int
}

// placeholderRE finds what Render replaces: "$$" (a literal dollar, as in
// Compose) and "${name}".
var placeholderRE = regexp.MustCompile(`\$(\$|\{[^}]*\}|.?)`)

// expand fills the placeholders in s. As in Compose, "$$" is a literal "$";
// "${key}" must name a value in vals; any other "$" is an error, so an
// author never writes "$VAR" expecting the shell to see it (Compose would
// have interpolated it).
func expand(s string, vals map[string]string) (string, error) {
	var bad error
	out := placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		switch {
		case m == "$$":
			return "$"
		case strings.HasPrefix(m, "${") && strings.HasSuffix(m, "}"):
			k := m[2 : len(m)-1]
			if v, ok := vals[k]; ok && keyRE.MatchString(k) {
				return v
			}
			if bad == nil {
				bad = fmt.Errorf("unknown placeholder %s", m)
			}
		default:
			if bad == nil {
				bad = fmt.Errorf("a bare $ in %q: write $$ for a literal dollar or ${variable}", s)
			}
		}
		return m
	})
	return out, bad
}

// Render fills the placeholders (${key}) with vals, which must hold "name",
// "project", "service", every input and every generated value; the other
// services' hosts (${service_<name>}) are derived here. A missing key is an
// error, never an empty string.
func (t *Template) Render(vals map[string]string) (Rendered, error) {
	all := make(map[string]string, len(vals)+len(t.Services))
	for k, v := range vals {
		all[k] = v
	}
	suffix := map[string]string{}
	for _, s := range t.Services {
		suffix[s.Name] = s.Suffix
	}
	for _, s := range t.Services[1:] {
		all["service_"+s.Name] = node.ContainerName(vals["project"], vals["name"]+s.Suffix)
	}
	r := func(where, s string) (string, error) {
		v, err := expand(s, all)
		if err != nil {
			return "", fmt.Errorf("%s: %w", where, err)
		}
		return v, nil
	}
	var out Rendered
	for _, s := range t.Services {
		at := "compose.yaml: services." + s.Name
		rs := RenderedService{
			Slug: vals["name"] + s.Suffix, Image: s.Image, Port: s.Port, Env: map[string]string{},
			MemoryMB: s.MemoryMB, CPUs: s.CPUs, CapAdd: s.CapAdd,
			Stateful: s.Stateful, ReadOnly: s.ReadOnly, StopGraceS: s.StopGraceS,
		}
		for k, v := range s.Env {
			rv, err := r(at+".environment."+k, v)
			if err != nil {
				return Rendered{}, err
			}
			rs.Env[k] = rv
		}
		for _, c := range s.Command {
			rc, err := r(at+".command", c)
			if err != nil {
				return Rendered{}, err
			}
			rs.Command = append(rs.Command, rc)
		}
		for _, v := range s.Volumes {
			nv := node.Volume{Name: v.Name, Path: v.Path, ReadOnly: v.ReadOnly}
			if v.Owner != "" {
				nv.Service = vals["name"] + suffix[v.Owner] // its id is set when the rows are written
			}
			rs.Volumes = append(rs.Volumes, nv)
		}
		if s.Health != nil {
			h, err := s.Health.toNode()
			if err != nil {
				return Rendered{}, fmt.Errorf("%s.healthcheck: %w", at, err)
			}
			test := make([]string, len(h.Test))
			for i, x := range h.Test {
				if test[i], err = r(at+".healthcheck.test", x); err != nil {
					return Rendered{}, err
				}
			}
			h.Test = test
			rs.Health = h
		}
		out.Services = append(out.Services, rs)
	}
	for _, e := range t.Exports {
		v, err := r("exports."+e.Key, e.Value)
		if err != nil {
			return Rendered{}, err
		}
		out.Exports = append(out.Exports, Export{Key: e.Key, Value: v, Secret: e.Secret})
	}
	return out, nil
}

// NewSecret returns 32 random bytes as base64url (safe inside URLs).
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
