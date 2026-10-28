package pgroles

import (
	"bufio"
	"crypto/md5" //nolint:gosec // compares with PostgreSQL's md5(), not a security hash
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The roles of a server (pg_dumpall --roles-only) travel with every dump
// of one of its databases: a pg_dump has none, and a copy whose app users
// lost their passwords, attributes (LOGIN, BYPASSRLS) and memberships is
// not a usable copy. A restore recreates each role the target lacks
// exactly as it was, and never touches a role that already exists.

// MaxGlobals bounds the roles script kept with a dump.
const MaxGlobals = 16 << 20

// BootstrapHeader starts the line, written above pg_dumpall's output, that
// names (in hex) the server's bootstrap superuser: the role initdb made,
// which every PostgreSQL has under its own name (POSTGRES_USER) and a
// restore never recreates.
const BootstrapHeader = "-- hangar-bootstrap-superuser: "

// Attrs are a role's attributes as ALTER ROLE ... WITH sets them.
type Attrs struct {
	Superuser   bool `json:"super"`
	Inherit     bool `json:"inherit"`
	CreateRole  bool `json:"createrole"`
	CreateDB    bool `json:"createdb"`
	Login       bool `json:"login"`
	Replication bool `json:"replication"`
	BypassRLS   bool `json:"bypassrls"`
	ConnLimit   int  `json:"connlimit"`
}

// Role is one role of the server.
type Role struct {
	Name  string
	Attrs Attrs
	// password is the stored hash (SCRAM or md5), never shown or logged.
	password string
	// stmts are its CREATE ROLE, ALTER ROLE and COMMENT ON ROLE, as
	// pg_dumpall wrote them.
	stmts []string
}

// HasPassword reports whether the role had a password.
func (r Role) HasPassword() bool { return r.password != "" }

// grant is a GRANT of pg_dumpall (role memberships, privileges on
// parameters), applied when every grantee is a role the restore created.
type grant struct {
	grantees []string
	// needs are the roles that must exist for it to apply (granted roles).
	needs []string
	stmt  string
}

// Globals are the roles of a server, read from pg_dumpall --roles-only.
type Globals struct {
	// Bootstrap is the server's bootstrap superuser, never recreated.
	Bootstrap string
	// Roles are the other roles, in pg_dumpall's order.
	Roles  []Role
	grants []grant
}

// ParseGlobals reads what pg_dumpall --roles-only printed (with the
// BootstrapHeader line Hangar writes above it).
func ParseGlobals(script string) (Globals, error) {
	var g Globals
	if len(script) > MaxGlobals {
		return g, errors.New("the roles of the backup are too large to read")
	}
	sc := bufio.NewScanner(strings.NewReader(script))
	sc.Buffer(make([]byte, 64<<10), MaxGlobals)
	for sc.Scan() {
		if h, ok := strings.CutPrefix(sc.Text(), BootstrapHeader); ok {
			b, err := hex.DecodeString(strings.TrimSpace(h))
			if err != nil {
				return g, errors.New("the roles of the backup name an unreadable superuser")
			}
			g.Bootstrap = string(b)
			break
		}
	}
	idx := map[string]int{}
	role := func(name string) *Role {
		i, ok := idx[name]
		if !ok {
			i = len(g.Roles)
			idx[name] = i
			g.Roles = append(g.Roles, Role{Name: name, Attrs: Attrs{Inherit: true, ConnLimit: -1}})
		}
		return &g.Roles[i]
	}
	text := func(st []token, end int) string { return script[st[0].start:st[end-1].end] }
	for _, st := range statements(tokenize(script)) {
		switch {
		case kw(st, 0, "create", "role"), kw(st, 0, "create", "user"), kw(st, 0, "create", "group"):
			n, ok := name(st, 2)
			if !ok || n == g.Bootstrap || skip(n) {
				continue
			}
			r := role(n)
			readAttrs(st[3:], r)
			r.stmts = append(r.stmts, text(st, len(st)))
		case kw(st, 0, "alter", "role"), kw(st, 0, "alter", "user"), kw(st, 0, "alter", "group"):
			n, ok := name(st, 2)
			if !ok || n == g.Bootstrap || skip(n) || kw(st, 3, "in") || kw(st, 3, "rename") {
				// IN DATABASE settings belong to a database (they come
				// back with it); renames are not part of a roles dump.
				continue
			}
			r := role(n)
			if kw(st, 3, "with") || !kw(st, 3, "set") && !kw(st, 3, "reset") {
				readAttrs(st[3:], r)
			}
			r.stmts = append(r.stmts, text(st, len(st)))
		case kw(st, 0, "comment", "on", "role"):
			n, ok := name(st, 3)
			if !ok || n == g.Bootstrap || skip(n) {
				continue
			}
			r := role(n)
			r.stmts = append(r.stmts, text(st, len(st)))
		case kw(st, 0, "grant"):
			to := find(st, 1, "to")
			if to < 0 {
				continue
			}
			grantees, next := roleList(st, to+1)
			end := len(st)
			if gb := find(st, next, "granted"); gb >= 0 && kw(st, gb+1, "by") {
				// The grantor becomes whoever restores: the original
				// one may not exist where the copy goes.
				end = gb
			}
			gr := grant{grantees: grantees, stmt: text(st, end)}
			if on := find(st, 1, "on"); on < 0 || on > to {
				gr.needs, _ = roleList(st, 1)
			}
			if len(grantees) > 0 {
				g.grants = append(g.grants, gr)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return g, err
	}
	return g, nil
}

// readAttrs reads the options of CREATE/ALTER ROLE ... [WITH] options.
func readAttrs(st []token, r *Role) {
	flags := map[string]*bool{
		"superuser": &r.Attrs.Superuser, "inherit": &r.Attrs.Inherit, "createrole": &r.Attrs.CreateRole,
		"createdb": &r.Attrs.CreateDB, "login": &r.Attrs.Login, "replication": &r.Attrs.Replication,
		"bypassrls": &r.Attrs.BypassRLS,
	}
	for i := 0; i < len(st); i++ {
		t := st[i]
		if t.kind != tWord {
			continue
		}
		if p, ok := flags[t.text]; ok {
			*p = true
			continue
		}
		if p, ok := flags[strings.TrimPrefix(t.text, "no")]; ok && strings.HasPrefix(t.text, "no") {
			*p = false
			continue
		}
		switch {
		case kw(st, i, "connection", "limit"):
			v, neg := i+2, false
			if v < len(st) && st[v].kind == tPunct && st[v].text == "-" {
				v, neg = v+1, true
			}
			if v < len(st) && st[v].kind == tNumber {
				if n, err := strconv.Atoi(st[v].text); err == nil {
					if neg {
						n = -n
					}
					r.Attrs.ConnLimit = n
				}
			}
			i = v
		case t.text == "password":
			switch {
			case i+1 < len(st) && st[i+1].kind == tString:
				r.password = st[i+1].text
			case kw(st, i+1, "null"):
				r.password = ""
			}
			i++
		}
	}
}

// Names are the roles a restore recreates when they are missing.
func (g Globals) Names() []string {
	out := make([]string, 0, len(g.Roles))
	for _, r := range g.Roles {
		out = append(out, r.Name)
	}
	return out
}

// secrets are the password hashes in g, to keep them out of messages.
func (g Globals) secrets() []string {
	var out []string
	for _, r := range g.Roles {
		if r.password != "" {
			out = append(out, r.password)
		}
	}
	return out
}

// hashRE matches the password hashes PostgreSQL stores.
var hashRE = regexp.MustCompile(`SCRAM-SHA-256\$[^\s'"]+|md5[0-9a-f]{32}`)

// Redact removes the password hashes of g (and anything that looks like
// one) from a message: PostgreSQL may quote a statement in an error.
func (g Globals) Redact(msg string) string {
	for _, s := range g.secrets() {
		msg = strings.ReplaceAll(msg, s, "[hidden]")
	}
	return hashRE.ReplaceAllString(msg, "[hidden]")
}

// SavedPrefix starts each line ApplyScript prints for a role it recreated,
// followed by the role name in hex.
const SavedPrefix = "HANGAR-SAVED "

// ApplyScript is a psql script that recreates, in one transaction, each
// role of g the server does not have: its CREATE ROLE, attributes,
// password hash, comment and settings as they were, then the memberships
// and parameter privileges of the roles it recreated: the ones granted to
// them, and the members of a recreated role (a role dropped after the
// backup comes back with its members). A role that already exists is
// never altered (attributes, password, settings), and a grant between two
// roles that already existed is left as the server has it. For each role
// it recreates it prints SavedPrefix and the name in hex.
func (g Globals) ApplyScript() (string, error) {
	if len(g.Roles) == 0 {
		return "", nil
	}
	var names, stmts []string
	ord := 0
	for _, r := range g.Roles {
		if r.Name == "" || strings.ContainsRune(r.Name, 0) || len(r.Name) > 63 {
			return "", fmt.Errorf("invalid role name %q", r.Name)
		}
		names = append(names, "("+strconv.Itoa(len(names))+", "+literal(r.Name)+")")
		for _, s := range r.stmts {
			ord++
			stmts = append(stmts, "("+strconv.Itoa(ord)+", "+literal(r.Name)+", "+literal(s)+")")
		}
	}
	var grants []string
	for i, gr := range g.grants {
		grants = append(grants, "("+strconv.Itoa(i)+", "+textArray(gr.grantees)+", "+textArray(gr.needs)+", "+literal(gr.stmt)+")")
	}
	var b strings.Builder
	b.WriteString("SET standard_conforming_strings = on;\nBEGIN;\n")
	b.WriteString("CREATE TEMP TABLE hangar_new ON COMMIT DROP AS SELECT r.ord, r.name FROM (VALUES " + strings.Join(names, ", ") +
		") AS r(ord, name) WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = r.name);\n")
	b.WriteString("SELECT " + literal(SavedPrefix) + " || encode(convert_to(name, 'UTF8'), 'hex') FROM hangar_new ORDER BY ord;\n")
	b.WriteString("SELECT s.stmt FROM (VALUES " + strings.Join(stmts, ", ") + ") AS s(ord, name, stmt) " +
		"WHERE s.name IN (SELECT name FROM hangar_new) ORDER BY s.ord \\gexec\n")
	if len(grants) > 0 {
		b.WriteString("SELECT g.stmt FROM (VALUES " + strings.Join(grants, ", ") + ") AS g(ord, grantees, needs, stmt) " +
			"WHERE (g.grantees <@ ARRAY(SELECT name FROM hangar_new) OR (cardinality(g.needs) > 0 AND g.needs <@ ARRAY(SELECT name FROM hangar_new))) " +
			"AND NOT EXISTS (SELECT FROM unnest(g.grantees || g.needs) AS n(name) WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = n.name)) " +
			"ORDER BY g.ord \\gexec\n")
	}
	b.WriteString("COMMIT;\n")
	return b.String(), nil
}

// RestoreScript is ApplyScript for a person: from a roles file saved with
// a dump, the psql script that recreates only the roles a server lacks.
func RestoreScript(rolesSQL []byte) ([]byte, error) {
	g, err := ParseGlobals(string(rolesSQL))
	if err != nil {
		return nil, err
	}
	script, err := g.ApplyScript()
	if err != nil {
		return nil, err
	}
	if script == "" {
		script = "-- No roles to create.\n"
	}
	return []byte("-- Recreates, as they were, the roles of the .roles.sql file next to this one\n" +
		"-- that this server lacks; existing roles are not touched. Run as a superuser:\n" +
		"--   psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f <this file>\n" + script), nil
}

func textArray(names []string) string {
	if len(names) == 0 {
		return "ARRAY[]::text[]"
	}
	lits := make([]string, len(names))
	for i, n := range names {
		lits[i] = literal(n)
	}
	return "ARRAY[" + strings.Join(lits, ", ") + "]::text[]"
}

// ParseSaved reads the names ApplyScript reported as recreated.
func ParseSaved(out string) []string { return parseHexLines(out, SavedPrefix) }

func parseHexLines(out, prefix string) []string {
	var names []string
	for line := range strings.SplitSeq(out, "\n") {
		h, ok := strings.CutPrefix(strings.TrimSpace(line), strings.TrimSpace(prefix))
		if !ok {
			continue
		}
		if b, err := hex.DecodeString(strings.TrimSpace(h)); err == nil && len(b) > 0 {
			names = append(names, string(b))
		}
	}
	return names
}

// --- checking what came back -------------------------------------------------

// StatePrefix starts the line StateQuery prints.
const StatePrefix = "HANGAR-STATE "

// StateQuery prints, on one line after StatePrefix, the roles of a server
// as hex-encoded JSON: attributes, an md5 of the stored password hash (to
// compare it without printing it) and the roles each one is a member of.
const StateQuery = `SELECT 'HANGAR-STATE ' || encode(convert_to(coalesce(json_agg(json_build_object(` +
	`'name', a.rolname, 'super', a.rolsuper, 'inherit', a.rolinherit, 'createrole', a.rolcreaterole, ` +
	`'createdb', a.rolcreatedb, 'login', a.rolcanlogin, 'replication', a.rolreplication, 'bypassrls', a.rolbypassrls, ` +
	`'connlimit', a.rolconnlimit, 'pw', md5(a.rolpassword), 'member_of', ARRAY(SELECT r.rolname::text FROM pg_catalog.pg_auth_members m ` +
	`JOIN pg_catalog.pg_roles r ON r.oid = m.roleid WHERE m.member = a.oid ORDER BY 1)))::text, '[]'), 'UTF8'), 'hex') ` +
	`FROM pg_catalog.pg_authid a WHERE a.rolname !~ '^pg_';`

// RoleState is a role as the server has it (StateQuery).
type RoleState struct {
	Name string `json:"name"`
	Attrs
	PasswordMD5 string   `json:"pw"`
	MemberOf    []string `json:"member_of"`
}

// ParseState reads StateQuery's line.
func ParseState(out string) (map[string]RoleState, error) {
	for line := range strings.SplitSeq(out, "\n") {
		h, ok := strings.CutPrefix(strings.TrimSpace(line), strings.TrimSpace(StatePrefix))
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil {
			return nil, err
		}
		var list []RoleState
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
		m := make(map[string]RoleState, len(list))
		for _, r := range list {
			m[r.Name] = r
		}
		return m, nil
	}
	return nil, errors.New("the roles of the restored server were not reported")
}

// Check compares the roles a restore recreated (saved) with what the
// server has now: the same attributes, the same password hash and the
// memberships of the backup. The error names roles and attributes, never
// a password.
func (g Globals) Check(saved []string, state map[string]RoleState) error {
	var probs []string
	for _, r := range g.Roles {
		if !slices.Contains(saved, r.Name) {
			continue
		}
		got, ok := state[r.Name]
		if !ok {
			probs = append(probs, strconv.Quote(r.Name)+" is missing")
			continue
		}
		if got.Attrs != r.Attrs {
			probs = append(probs, fmt.Sprintf("%q has other attributes (%+v, want %+v)", r.Name, got.Attrs, r.Attrs))
		}
		want := ""
		if r.password != "" {
			sum := md5.Sum([]byte(r.password)) //nolint:gosec // see the import
			want = hex.EncodeToString(sum[:])
		}
		if got.PasswordMD5 != want {
			probs = append(probs, strconv.Quote(r.Name)+" has another password")
		}
	}
	all := func(names []string, ok func(string) bool) bool {
		for _, n := range names {
			if !ok(n) {
				return false
			}
		}
		return true
	}
	isSaved := func(n string) bool { return slices.Contains(saved, n) }
	exists := func(n string) bool { _, ok := state[n]; return ok }
	for _, gr := range g.grants {
		ours := all(gr.grantees, isSaved) || all(gr.needs, isSaved)
		if len(gr.needs) == 0 || !ours || !all(gr.grantees, exists) || !all(gr.needs, exists) {
			continue
		}
		for _, m := range gr.grantees {
			for _, need := range gr.needs {
				if !slices.Contains(state[m].MemberOf, need) {
					probs = append(probs, fmt.Sprintf("%q is not a member of %q", m, need))
				}
			}
		}
	}
	if len(probs) > 0 {
		return errors.New("the roles did not come back as they were: " + strings.Join(probs, "; "))
	}
	return nil
}
