package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Connecting services (docs/08 "Conectar serviços"). A connection is a
// variable of the service that uses another one whose value references what
// that one offers: DB_HOST = ${{db.HOST}}. The names may differ on each
// side: the variable is the consumer's, the value the provider's. Nothing is
// copied: the reference is read again at every deploy.
//
// A service offers its template's exports, or, made by hand, the variables
// marked as offered. One that offers nothing cannot be connected to.

// Offer is a value a service offers to the others.
type Offer struct {
	Key    string
	Secret bool
	// Variable: offered by marking one of its variables (a service made by
	// hand), not declared by a template.
	Variable bool
}

// Errors of the connect action.
var (
	ErrNothingOffered = &i18n.Error{Key: "connect.error.nothing_offered"}
	ErrConnectSelf    = &i18n.Error{Key: "connect.error.self"}
	ErrConnectNone    = &i18n.Error{Key: "connect.error.none"}
)

// Offers lists what a service offers, under its own names: every variable
// it has (a template's POSTGRES_PASSWORD as such; the service that
// receives it renames it), plus what a template's panel computes on its own
// (HOST, PORT, DATABASE_URL). A template export that only repeats one of
// its variables (PASSWORD for POSTGRES_PASSWORD) is not listed again; a
// reference to it still resolves.
func (m *Manager) Offers(ctx context.Context, serviceID string) ([]Offer, error) {
	vars, err := m.q.ListEnv(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	exps, err := m.q.ListExports(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	out := make([]Offer, 0, len(vars)+len(exps))
	seen := map[string]bool{}
	for _, v := range vars {
		seen[v.Key] = true
		out = append(out, Offer{Key: v.Key, Secret: v.Secret == 1, Variable: true})
	}
	for _, e := range exps {
		repeats := false
		for _, v := range vars {
			repeats = repeats || offerAlias(v.Key, e.Key)
		}
		if !repeats && !seen[e.Key] {
			out = append(out, Offer{Key: e.Key, Secret: e.Secret == 1})
		}
	}
	// HOST and PORT come with every service (a reference resolves them,
	// see refs.go), so one made by hand can be connected to by address.
	if s, err := m.q.GetServiceByID(ctx, serviceID); err == nil {
		if !hasOffer(out, "HOST") {
			out = append(out, Offer{Key: "HOST"})
		}
		if s.InternalPort > 0 && !hasOffer(out, "PORT") {
			out = append(out, Offer{Key: "PORT"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func hasOffer(out []Offer, key string) bool {
	for _, o := range out {
		if o.Key == key {
			return true
		}
	}
	return false
}

// offerAlias reports whether a template's export only repeats one of its
// variables: the image's own prefixed name (POSTGRES_USER for USER,
// POSTGRES_DB for DATABASE).
func offerAlias(variable, export string) bool {
	return variable == export || strings.HasSuffix(variable, "_"+export) ||
		(export == "DATABASE" && strings.HasSuffix(variable, "_DB"))
}

// canonicalKey is what an offered value is, whatever the provider calls
// it, for suggesting the receiving name: POSTGRES_PASSWORD is a PASSWORD,
// POSTGRES_DB a DATABASE.
func canonicalKey(key string) string {
	for _, k := range []string{"PASSWORD", "USER", "HOST", "PORT", "DATABASE"} {
		if strings.HasSuffix(key, "_"+k) {
			return k
		}
	}
	if strings.HasSuffix(key, "_DB") {
		return "DATABASE"
	}
	return key
}

// SetOffered marks one of the service's variables as offered to the others,
// or stops offering it. Services already connected to it keep their
// reference until someone disconnects them (the panel shows who).
func (m *Manager) SetOffered(ctx context.Context, a Actor, serviceID, key string, on bool) error {
	if _, err := m.q.GetEnv(ctx, dbq.GetEnvParams{ServiceID: serviceID, Key: key}); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var err error
	if on {
		err = m.q.AddOffer(ctx, dbq.AddOfferParams{ServiceID: serviceID, Key: key})
	} else {
		err = m.q.DeleteOffer(ctx, dbq.DeleteOfferParams{ServiceID: serviceID, Key: key})
	}
	if err != nil {
		return err
	}
	m.record(ctx, a, "service.env.offer", "service", serviceID, audit.OK, map[string]any{"key": key, "offered": on})
	return nil
}

// ConnectRow is one value the provider offers, with the consumer's variable
// that would receive it.
type ConnectRow struct {
	Key    string // what the provider offers
	Secret bool
	// Var is the consumer's variable: one it already has or its repository
	// suggests when the name matches (Known), else a name made up for it.
	Var   string
	Known bool
	// Current: the variable already exists with a different value, which
	// connecting replaces. Linked: it already references this very value.
	Current bool
	Linked  bool
	// Checked: on by default (the connection string, or a name the
	// consumer already uses).
	Checked bool
}

// ConnectPlan is what connecting one service to another would set, for the
// person to adjust before saving.
type ConnectPlan struct {
	From   string // the consumer
	Target string // the provider, as a reference: "db" or "project.db"
	Rows   []ConnectRow
	// Vars are the consumer's variables, to pick an existing one by hand.
	Vars []string
}

// PlanConnect proposes how the service fromSlug would use what target
// offers. target is a service of the same project ("db") or of a connected
// one ("other.db").
func (m *Manager) PlanConnect(ctx context.Context, projectSlug, fromSlug, target string) (ConnectPlan, error) {
	p, from, err := m.GetService(ctx, projectSlug, fromSlug)
	if err != nil {
		return ConnectPlan{}, err
	}
	to, err := m.connectTarget(ctx, p, target)
	if err != nil {
		return ConnectPlan{}, err
	}
	if to.ID == from.ID {
		return ConnectPlan{}, ErrConnectSelf
	}
	offers, err := m.Offers(ctx, to.ID)
	if err != nil {
		return ConnectPlan{}, err
	}
	if len(offers) == 0 {
		return ConnectPlan{}, ErrNothingOffered
	}
	env, err := m.q.ListEnv(ctx, from.ID)
	if err != nil {
		return ConnectPlan{}, err
	}
	current := map[string]string{}
	plan := ConnectPlan{From: from.Slug, Target: target}
	for _, e := range env {
		plain, err := m.box.Open(e.ValueEnc, envAD(from.ID, e.Key))
		if err != nil {
			return ConnectPlan{}, err
		}
		current[e.Key] = string(plain)
		plan.Vars = append(plan.Vars, e.Key)
	}
	known := map[string]bool{}
	for k := range current {
		known[k] = true
	}
	for _, k := range m.suggestedKeys(ctx, from.ID) {
		known[k] = true
	}
	hasURL := false
	for _, o := range offers {
		if strings.HasSuffix(o.Key, "_URL") {
			hasURL = true
		}
	}
	used := map[string]bool{}
	for _, o := range offers {
		row := ConnectRow{Key: o.Key, Secret: o.Secret}
		ref := "${{" + target + "." + o.Key + "}}"
		// A template's own name (POSTGRES_PASSWORD) is suggested by what it
		// is (a PASSWORD); a hand-made service's names are kept as they are.
		kind := o.Key
		if to.Template != "" {
			kind = canonicalKey(o.Key)
		}
		for _, name := range varCandidates(kind, to) {
			if known[name] && !used[name] {
				row.Var, row.Known = name, true
				break
			}
		}
		if row.Var == "" {
			row.Var = defaultVarName(kind, to)
		}
		used[row.Var] = true
		if v, ok := current[row.Var]; ok {
			row.Linked = v == ref
			row.Current = !row.Linked
		}
		// The connection string alone is enough for most apps; the parts
		// only when the app already uses those names (or there is no URL).
		row.Checked = !row.Linked && (row.Known || strings.HasSuffix(o.Key, "_URL") || !hasURL)
		plan.Rows = append(plan.Rows, row)
	}
	return plan, nil
}

// Mapping is one connected value: the consumer's variable Var receives the
// provider's Key.
type Mapping struct{ Key, Var string }

// Connect sets the consumer's variables to reference what the target
// offers, as chosen in the plan. Each Key must be offered; a variable that
// exists with another value is replaced only with replace (the panel shows
// which ones before saving). It returns how many variables it set.
func (m *Manager) Connect(ctx context.Context, a Actor, projectSlug, fromSlug, target string, maps []Mapping, replace bool) (int, error) {
	p, from, err := m.GetService(ctx, projectSlug, fromSlug)
	if err != nil {
		return 0, err
	}
	to, err := m.connectTarget(ctx, p, target)
	if err != nil {
		return 0, err
	}
	if to.ID == from.ID {
		return 0, ErrConnectSelf
	}
	if len(maps) == 0 {
		return 0, ErrConnectNone
	}
	offers, err := m.Offers(ctx, to.ID)
	if err != nil {
		return 0, err
	}
	offered := map[string]bool{}
	for _, o := range offers {
		offered[o.Key] = true
	}
	vars := map[string]bool{}
	for _, mp := range maps {
		if !offered[mp.Key] {
			return 0, i18n.E("connect.error.not_offered", "service", to.Slug, "key", mp.Key)
		}
		if !envKeyRE.MatchString(mp.Var) {
			return 0, i18n.E("env.error.key")
		}
		if vars[mp.Var] {
			return 0, i18n.E("connect.error.duplicate", "var", mp.Var)
		}
		vars[mp.Var] = true
	}
	// Below admin, a secret may not be connected (checkRefsFor): refuse
	// before setting anything.
	for _, mp := range maps {
		if err := m.checkRefsFor(ctx, a, from.ID, "${{"+target+"."+mp.Key+"}}"); err != nil {
			return 0, err
		}
	}
	set := 0
	for _, mp := range maps {
		ref := "${{" + target + "." + mp.Key + "}}"
		cur, err := m.q.GetEnv(ctx, dbq.GetEnvParams{ServiceID: from.ID, Key: mp.Var})
		switch {
		case err == nil:
			plain, err := m.box.Open(cur.ValueEnc, envAD(from.ID, mp.Var))
			if err != nil {
				return set, err
			}
			if string(plain) == ref {
				continue
			}
			if !replace {
				return set, i18n.E("connect.error.exists", "var", mp.Var)
			}
		case !errors.Is(err, sql.ErrNoRows):
			return set, err
		}
		if err := m.SetEnv(ctx, a, from.ID, mp.Var, ref, false); err != nil {
			return set, err
		}
		set++
	}
	m.record(ctx, a, "service.connect", "service", from.ID, audit.OK, map[string]any{"to": target, "vars": set})
	return set, nil
}

// connectTarget finds the service a connection points at: one of the
// project or, as "project.service", of a project connected to it.
func (m *Manager) connectTarget(ctx context.Context, p dbq.Project, target string) (dbq.Service, error) {
	projectSlug, serviceSlug := p.Slug, target
	if a, b, ok := strings.Cut(target, "."); ok {
		projectSlug, serviceSlug = a, b
		if projectSlug != p.Slug {
			linked, err := m.q.LinkedProjects(ctx, p.ID)
			if err != nil {
				return dbq.Service{}, err
			}
			ok := false
			for _, l := range linked {
				ok = ok || l.Slug == projectSlug
			}
			if !ok {
				return dbq.Service{}, ErrNotFound
			}
		}
	}
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	return s, err
}

// suggestedKeys are the names the service's repository suggests
// (.env.example), dismissed or not: an app that documents DB_HOST wants its
// database host there.
func (m *Manager) suggestedKeys(ctx context.Context, serviceID string) []string {
	row, err := m.q.GetEnvSuggestions(ctx, serviceID)
	if err != nil {
		return nil
	}
	var rows []suggestedVar
	if json.Unmarshal([]byte(row.VarsJson), &rows) != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.K)
	}
	return out
}

// varAliases are the names apps commonly use for what a database or cache
// offers, best first.
var varAliases = map[string][]string{
	"DATABASE_URL": {"DATABASE_URL", "DB_URL", "POSTGRES_URL", "POSTGRESQL_URL", "MYSQL_URL", "MONGODB_URI", "MONGO_URL"},
	"REDIS_URL":    {"REDIS_URL", "CACHE_URL", "CELERY_BROKER_URL", "BROKER_URL", "REDIS_URI"},
	"HOST":         {"DB_HOST", "DATABASE_HOST", "POSTGRES_HOST", "PGHOST", "MYSQL_HOST", "REDIS_HOST"},
	"PORT":         {"DB_PORT", "DATABASE_PORT", "POSTGRES_PORT", "PGPORT", "MYSQL_PORT", "REDIS_PORT"},
	"USER":         {"DB_USER", "DB_USERNAME", "DATABASE_USER", "DATABASE_USERNAME", "POSTGRES_USER", "PGUSER", "MYSQL_USER"},
	"PASSWORD":     {"DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD", "POSTGRES_PASSWORD", "PGPASSWORD", "MYSQL_PASSWORD", "REDIS_PASSWORD"},
	"DATABASE":     {"DB_NAME", "DB_DATABASE", "DATABASE_NAME", "POSTGRES_DB", "PGDATABASE", "MYSQL_DATABASE"},
}

// varCandidates are the consumer names that would receive key, best first.
func varCandidates(key string, to dbq.Service) []string {
	// A cache's HOST is not the database's: DB_HOST is no candidate for a
	// Redis, nor REDIS_HOST for a Postgres.
	cache := varPrefix(to) == "REDIS_"
	var out []string
	for _, a := range varAliases[key] {
		if isCacheName(a) == cache || key == "REDIS_URL" {
			out = append(out, a)
		}
	}
	return append(out, key, varPrefix(to)+key)
}

func isCacheName(name string) bool {
	for _, w := range []string{"REDIS", "CACHE", "BROKER", "CELERY", "VALKEY"} {
		if strings.Contains(name, w) {
			return true
		}
	}
	return false
}

// defaultVarName is the name made up when the consumer has none for it:
// connection strings keep theirs (DATABASE_URL), the parts get the
// provider's prefix (DB_HOST, REDIS_PASSWORD, API_TOKEN).
func defaultVarName(key string, to dbq.Service) string {
	if strings.HasSuffix(key, "_URL") || strings.HasSuffix(key, "_URI") {
		return key
	}
	// A database's parts take the most common names (DB_NAME, not
	// DB_DATABASE).
	if a := varCandidates(key, to); len(a) > 2 && varPrefix(to) == "DB_" {
		return a[0]
	}
	if strings.HasPrefix(key, varPrefix(to)) {
		return key
	}
	return varPrefix(to) + key
}

// varPrefix names a provider in its consumers' variables: DB_ for a
// database, REDIS_ for a cache, else its name (API_ for "api").
func varPrefix(to dbq.Service) string {
	// Templates come in flavours (redis-cache, redis-queue, valkey-cache).
	family, _, _ := strings.Cut(to.Template, "-")
	switch family {
	case "postgres", "mysql", "mariadb", "mongodb":
		return "DB_"
	case "redis", "valkey", "keydb":
		return "REDIS_"
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(to.Slug) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String() + "_"
}

// Dependent is a variable of another service that references this one.
type Dependent struct {
	Project string // "" = the same project
	Service string
	Var     string
	Key     string // what it uses
}

// Dependents lists who uses a service: the variables, in its project and in
// the projects connected to it, that reference it. The panel shows them
// before the service is deleted and next to what it offers.
func (m *Manager) Dependents(ctx context.Context, projectSlug, serviceSlug string) ([]Dependent, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return nil, err
	}
	projects := []dbq.Project{p}
	linked, err := m.q.LinkedProjects(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	projects = append(projects, linked...)
	var out []Dependent
	for _, q := range projects {
		svcs, err := m.q.ListServices(ctx, q.ID)
		if err != nil {
			return nil, err
		}
		for _, s := range svcs {
			if q.ID == p.ID && s.Slug == serviceSlug {
				continue
			}
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
					refProject := g[1]
					if refProject == "" {
						refProject = q.Slug
					}
					if refProject != p.Slug || g[2] != serviceSlug {
						continue
					}
					d := Dependent{Service: s.Slug, Var: r.Key, Key: g[3]}
					if q.ID != p.ID {
						d.Project = q.Slug
					}
					out = append(out, d)
				}
			}
		}
	}
	return out, nil
}

// touchDependents re-seals the variables that reference keys of a service
// whose value just changed, with the same text: their stored bytes change,
// so each consumer shows "changes to apply" and its next deploy carries the
// new value.
func (m *Manager) touchDependents(ctx context.Context, provider dbq.Service, keys map[string]bool) {
	if len(keys) == 0 {
		return
	}
	p, err := m.q.GetProjectByID(ctx, provider.ProjectID)
	if err != nil {
		return
	}
	deps, err := m.Dependents(ctx, p.Slug, provider.Slug)
	if err != nil {
		m.log.Warn("find the services that use this one", "service", p.Slug+"/"+provider.Slug, "error", err)
		return
	}
	for _, d := range deps {
		if !keys[d.Key] {
			continue
		}
		projectSlug := d.Project
		if projectSlug == "" {
			projectSlug = p.Slug
		}
		_, s, err := m.GetService(ctx, projectSlug, d.Service)
		if err != nil {
			continue
		}
		cur, err := m.q.GetEnv(ctx, dbq.GetEnvParams{ServiceID: s.ID, Key: d.Var})
		if err != nil {
			continue
		}
		plain, err := m.box.Open(cur.ValueEnc, envAD(s.ID, d.Var))
		if err != nil {
			continue
		}
		sealed, err := m.box.Seal(plain, envAD(s.ID, d.Var))
		if err != nil {
			continue
		}
		_ = m.q.UpsertEnv(ctx, dbq.UpsertEnvParams{ServiceID: s.ID, Key: d.Var, ValueEnc: sealed, Secret: cur.Secret, UpdatedAt: m.now().Unix()})
	}
}

// syncExports keeps a template's exports in step with the variable they
// were built from: changing the database's POSTGRES_PASSWORD changes the
// PASSWORD and DATABASE_URL it offers (they held the old value). It returns
// the exports it changed. Short values are left alone: replacing "5432" or
// "app" inside a URL could hit the wrong part.
func (m *Manager) syncExports(ctx context.Context, serviceID, oldValue, newValue string) map[string]bool {
	if len(oldValue) < 8 || oldValue == newValue {
		return nil
	}
	exps, err := m.q.ListExports(ctx, serviceID)
	if err != nil {
		return nil
	}
	changed := map[string]bool{}
	for _, e := range exps {
		plain, err := m.box.Open(e.ValueEnc, exportAD(serviceID, e.Key))
		if err != nil || !strings.Contains(string(plain), oldValue) {
			continue
		}
		next := strings.ReplaceAll(string(plain), oldValue, newValue)
		sealed, err := m.box.Seal([]byte(next), exportAD(serviceID, e.Key))
		if err != nil {
			continue
		}
		if err := m.q.UpsertExport(ctx, dbq.UpsertExportParams{ServiceID: serviceID, Key: e.Key, ValueEnc: sealed, Secret: e.Secret}); err != nil {
			m.log.Warn("update an export", "key", e.Key, "error", err)
			continue
		}
		changed[e.Key] = true
	}
	return changed
}
