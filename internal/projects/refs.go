package projects

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"sort"
	"strconv"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// refRE matches ${{service.KEY}} (same project) and ${{project.service.KEY}}
// (a connected project), like Railway's references.
var refRE = regexp.MustCompile(`\$\{\{\s*(?:([a-z][a-z0-9-]*)\.)?([a-z][a-z0-9-]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// RefProblem says why a reference cannot be resolved.
type RefProblem string

const (
	RefNoProject RefProblem = "project" // the project is not connected (or is gone)
	RefNoService RefProblem = "service" // no service with that name
	RefNoKey     RefProblem = "key"     // the service neither offers nor has that key
	RefCycle     RefProblem = "cycle"   // the value leads back to itself, or too deep
)

// maxRefDepth bounds a chain of references (app → api → db): deeper is a
// mistake, not a design.
const maxRefDepth = 5

// BrokenRef is a variable whose reference the next deploy cannot resolve.
type BrokenRef struct {
	ServiceID string
	Service   string // the service holding the variable
	Key       string // the variable
	Project   string // the referenced project ("" = this one)
	Target    string // the referenced service
	TargetKey string // the referenced key
	Problem   RefProblem
}

// refLookup finds what a reference points at, the same way for the deploy
// and for the warnings, caching each target.
type refLookup struct {
	m      *Manager
	p      dbq.Project
	linked map[string]bool
	cache  map[string]refTarget
	// hitSecret is set when a resolution read a secret value on its way
	// (the key itself, or any key a chain of references went through).
	// Callers reset it before each resolution they want to judge.
	hitSecret bool
}

type refTarget struct {
	vals    map[string]string
	secret  map[string]bool // keys whose value is secret
	problem RefProblem      // set when the service itself cannot be reached
}

func (m *Manager) newRefLookup(p dbq.Project) *refLookup {
	return &refLookup{m: m, p: p, cache: map[string]refTarget{}}
}

// target returns the variables and exports of a service, or why it cannot
// be reached.
func (l *refLookup) target(ctx context.Context, projectSlug, serviceSlug string) (refTarget, error) {
	k := projectSlug + "/" + serviceSlug
	if v, ok := l.cache[k]; ok {
		return v, nil
	}
	got, err := l.load(ctx, projectSlug, serviceSlug)
	if err != nil {
		return got, err
	}
	l.cache[k] = got
	return got, nil
}

func (l *refLookup) load(ctx context.Context, projectSlug, serviceSlug string) (refTarget, error) {
	m := l.m
	target := l.p
	if projectSlug != l.p.Slug {
		if l.linked == nil {
			l.linked = map[string]bool{}
			ls, err := m.q.LinkedProjects(ctx, l.p.ID)
			if err != nil {
				return refTarget{}, err
			}
			for _, p := range ls {
				l.linked[p.Slug] = true
			}
		}
		if !l.linked[projectSlug] {
			return refTarget{problem: RefNoProject}, nil
		}
		var err error
		if target, err = m.q.GetProjectBySlug(ctx, projectSlug); err != nil {
			return refTarget{problem: RefNoProject}, nil //nolint:nilerr // a vanished project is just an unresolved reference
		}
	}
	s, err := m.q.GetService(ctx, dbq.GetServiceParams{ProjectID: target.ID, Slug: serviceSlug})
	if errors.Is(err, sql.ErrNoRows) {
		return refTarget{problem: RefNoService}, nil
	}
	if err != nil {
		return refTarget{}, err
	}
	vals, secret := map[string]string{}, map[string]bool{}
	rows, err := m.q.ListEnv(ctx, s.ID)
	if err != nil {
		return refTarget{}, err
	}
	for _, r := range rows {
		plain, err := m.box.Open(r.ValueEnc, envAD(s.ID, r.Key))
		if err != nil {
			return refTarget{}, err
		}
		vals[r.Key] = string(plain)
		secret[r.Key] = r.Secret == 1 || LooksSecret(r.Key)
	}
	exps, err := m.q.ListExports(ctx, s.ID)
	if err != nil {
		return refTarget{}, err
	}
	for _, r := range exps { // exports win over variables with the same name
		plain, err := m.box.Open(r.ValueEnc, exportAD(s.ID, r.Key))
		if err != nil {
			return refTarget{}, err
		}
		vals[r.Key] = string(plain)
		secret[r.Key] = r.Secret == 1 || LooksSecret(r.Key)
	}
	// Every service is reachable on the project's network: HOST and PORT
	// are there even when it declares nothing (a service made by hand).
	host, port := serviceAddress(target, s)
	if _, ok := vals["HOST"]; !ok {
		vals["HOST"] = host
	}
	if _, ok := vals["PORT"]; !ok && port != "" {
		vals["PORT"] = port
	}
	return refTarget{vals: vals, secret: secret}, nil
}

// resolve finds the value of one reference; problem says why there is none.
// A value that is itself a reference (the api offers ${{db.HOST}}) is
// followed, relative to its own project, up to maxRefDepth; a loop is a
// RefCycle, never an endless deploy.
func (l *refLookup) resolve(ctx context.Context, project, service, key string) (string, RefProblem, error) {
	return l.resolveIn(ctx, project, service, key, map[string]bool{}, 0)
}

func (l *refLookup) resolveIn(ctx context.Context, project, service, key string, seen map[string]bool, depth int) (string, RefProblem, error) {
	if project == "" {
		project = l.p.Slug
	}
	id := project + "/" + service + "/" + key
	if seen[id] || depth >= maxRefDepth {
		return "", RefCycle, nil
	}
	t, err := l.target(ctx, project, service)
	if err != nil || t.problem != "" {
		return "", t.problem, err
	}
	v, ok := t.vals[key]
	if !ok {
		return "", RefNoKey, nil
	}
	if t.secret[key] {
		l.hitSecret = true
	}
	if !refRE.MatchString(v) {
		return v, "", nil
	}
	seen[id] = true
	defer delete(seen, id)
	var problem RefProblem
	var failed error
	out := refRE.ReplaceAllStringFunc(v, func(ref string) string {
		if problem != "" || failed != nil {
			return ref
		}
		g := refRE.FindStringSubmatch(ref)
		inner := g[1]
		if inner == "" {
			inner = project // relative to the service that holds the value
		}
		got, p, err := l.resolveIn(ctx, inner, g[2], g[3], seen, depth+1)
		if err != nil {
			failed = err
			return ref
		}
		if p != "" {
			problem = p
			return ref
		}
		return got
	})
	if failed != nil || problem != "" {
		return "", problem, failed
	}
	return out, "", nil
}

// serviceAddress is how the project's other services reach s: its
// container's name on the project network, and its internal port ("" when
// it has none).
func serviceAddress(p dbq.Project, s dbq.Service) (host, port string) {
	host = node.ContainerName(p.Slug, s.Slug)
	if s.InternalPort > 0 {
		port = strconv.FormatInt(s.InternalPort, 10)
	}
	return host, port
}

// ServiceAddress is serviceAddress for the panel: "conector_app:8000".
func ServiceAddress(p dbq.Project, s dbq.Service) string {
	host, port := serviceAddress(p, s)
	if port == "" {
		return host
	}
	return host + ":" + port
}

// resolveRefs replaces references in the variable values with the target's
// export or variable, following chains (see resolve). A reference to a
// project that is not connected, to something that does not exist, or one
// that loops fails the deploy.
func (m *Manager) resolveRefs(ctx context.Context, p dbq.Project, env map[string]string) (map[string]string, error) {
	l := m.newRefLookup(p)
	out := make(map[string]string, len(env))
	for key, val := range env {
		var failed error
		out[key] = refRE.ReplaceAllStringFunc(val, func(ref string) string {
			if failed != nil {
				return ref
			}
			g := refRE.FindStringSubmatch(ref)
			v, problem, err := l.resolve(ctx, g[1], g[2], g[3])
			switch {
			case err != nil:
				failed = err
				return ref
			case problem != "":
				failed = i18n.E("env.error.reference", "key", key, "ref", ref)
				return ref
			}
			return v
		})
		if failed != nil {
			return nil, failed
		}
	}
	return out, nil
}

// BrokenRefs lists the references in a project's variables that the next
// deploy could not resolve, by service and variable, so the panel can warn
// before the deploy fails. Only names leave here, never values.
func (m *Manager) BrokenRefs(ctx context.Context, p dbq.Project) ([]BrokenRef, error) {
	svcs, err := m.q.ListServices(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	l := m.newRefLookup(p)
	var out []BrokenRef
	for _, s := range svcs {
		rows, err := m.q.ListEnv(ctx, s.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			plain, err := m.box.Open(r.ValueEnc, envAD(s.ID, r.Key))
			if err != nil {
				continue
			}
			for _, g := range refRE.FindAllStringSubmatch(string(plain), -1) {
				_, problem, err := l.resolve(ctx, g[1], g[2], g[3])
				if err != nil {
					return nil, err
				}
				if problem == "" {
					continue
				}
				project := g[1]
				if project == p.Slug {
					project = ""
				}
				out = append(out, BrokenRef{
					ServiceID: s.ID, Service: s.Slug, Key: r.Key,
					Project: project, Target: g[2], TargetKey: g[3], Problem: problem,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

// ResolvedValues is what each variable is worth once its references are
// resolved, for the panel's copy buttons: pasting it elsewhere has to work.
// A variable whose reference cannot be resolved is left out. It reads
// secrets: only a response that reveals them (sudo, audited) may use it;
// pages use ResolvedPublicValues.
func (m *Manager) ResolvedValues(ctx context.Context, p dbq.Project, env map[string]string) map[string]string {
	return m.resolvedValues(ctx, p, env, true)
}

// ResolvedPublicValues is ResolvedValues without anything that reads a
// secret on the way: a reference that resolves through a secret value
// (${{db.DATABASE_URL}} carries the password) is left out, so a page never
// holds a secret its viewer did not reveal.
func (m *Manager) ResolvedPublicValues(ctx context.Context, p dbq.Project, env map[string]string) map[string]string {
	return m.resolvedValues(ctx, p, env, false)
}

func (m *Manager) resolvedValues(ctx context.Context, p dbq.Project, env map[string]string, secrets bool) map[string]string {
	l := m.newRefLookup(p)
	out := make(map[string]string, len(env))
	for key, val := range env {
		ok := true
		l.hitSecret = false
		v := refRE.ReplaceAllStringFunc(val, func(ref string) string {
			g := refRE.FindStringSubmatch(ref)
			got, problem, err := l.resolve(ctx, g[1], g[2], g[3])
			if err != nil || problem != "" {
				ok = false
				return ref
			}
			return got
		})
		if ok && (secrets || !l.hitSecret) {
			out[key] = v
		}
	}
	return out
}

// checkRefsFor refuses the references in value that the actor may not
// write (SEC-015). Below admin (Actor.Restricted) nobody sees a secret, so
// nobody may point a variable at one either: the deploy would put the value
// into a container they steer (an app that logs its environment, or a URL
// they chose: X=https://host/?p=${{db.PASSWORD}}). That covers a reference
// that resolves through a secret anywhere along its chain, and any
// reference into a project the actor cannot see. A reference that does not
// resolve (yet) is left for the deploy to report. Admins, who can reveal
// the value anyway, connect secrets.

func (m *Manager) checkRefsFor(ctx context.Context, a Actor, serviceID, value string) error {
	if !a.Restricted || !refRE.MatchString(value) {
		return nil
	}
	s, err := m.q.GetServiceByID(ctx, serviceID)
	if err != nil {
		return err
	}
	p, err := m.q.GetProjectByID(ctx, s.ProjectID)
	if err != nil {
		return err
	}
	l := m.newRefLookup(p)
	for _, g := range refRE.FindAllStringSubmatch(value, -1) {
		if g[1] != "" && g[1] != p.Slug && a.SeesProject != nil && !a.SeesProject(g[1]) {
			return i18n.E("env.error.reference_hidden", "ref", g[0])
		}
		l.hitSecret = false
		if _, _, err := l.resolve(ctx, g[1], g[2], g[3]); err != nil {
			return err
		}
		if l.hitSecret {
			return i18n.E("env.error.secret_reference", "ref", g[0])
		}
	}
	return nil
}
