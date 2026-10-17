package projects

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"sort"

	"github.com/JuniorCarlini/hangar/internal/i18n"
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
)

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
}

type refTarget struct {
	vals    map[string]string
	problem RefProblem // set when the service itself cannot be reached
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
	vals := map[string]string{}
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
	}
	return refTarget{vals: vals}, nil
}

// resolve finds the value of one reference; problem says why there is none.
func (l *refLookup) resolve(ctx context.Context, project, service, key string) (string, RefProblem, error) {
	if project == "" {
		project = l.p.Slug
	}
	t, err := l.target(ctx, project, service)
	if err != nil || t.problem != "" {
		return "", t.problem, err
	}
	v, ok := t.vals[key]
	if !ok {
		return "", RefNoKey, nil
	}
	return v, "", nil
}

// resolveRefs replaces references in the variable values with the target's
// export or variable. Only one level: a referenced value is used as stored,
// so references can never loop. A reference to a project that is not
// connected, or to something that does not exist, fails the deploy.
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
