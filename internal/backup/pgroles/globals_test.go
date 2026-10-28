package pgroles

import (
	"crypto/md5" //nolint:gosec // as in globals.go
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
)

// testdata/roles.sql is what PostgreSQL 18's pg_dumpall --roles-only
// printed (under Hangar's header) for a server whose bootstrap superuser
// is lobot, with an app user, a BYPASSRLS system user with a connection
// limit and an expiry, a quoted role name, a membership granted by lobot,
// role settings and a role comment. testdata/create.sql is pg_restore
// --create --schema-only of a dump of its database, with a database
// setting, a per-role setting, a comment and GRANTs on the database.
func readGlobals(t *testing.T) (Globals, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/roles.sql")
	if err != nil {
		t.Fatal(err)
	}
	g, err := ParseGlobals(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return g, string(raw)
}

func TestParseGlobalsRealDump(t *testing.T) {
	g, _ := readGlobals(t)
	if g.Bootstrap != "lobot" {
		t.Fatalf("bootstrap: %q", g.Bootstrap)
	}
	// The bootstrap superuser is never recreated: every server has its own.
	if got, want := g.Names(), []string{`Odd "Name"`, "lobot_app", "lobot_system"}; !slices.Equal(got, want) {
		t.Fatalf("roles %q, want %q", got, want)
	}
	byName := map[string]Role{}
	for _, r := range g.Roles {
		byName[r.Name] = r
	}
	if a := byName["lobot_system"].Attrs; !a.Login || !a.BypassRLS || a.Superuser || !a.Inherit || a.ConnLimit != 5 {
		t.Errorf("lobot_system: %+v", a)
	}
	if a := byName["lobot_app"].Attrs; !a.Login || a.BypassRLS || a.ConnLimit != -1 {
		t.Errorf("lobot_app: %+v", a)
	}
	if a := byName[`Odd "Name"`].Attrs; a.Login || byName[`Odd "Name"`].HasPassword() {
		t.Errorf("Odd Name: %+v", a)
	}
	if !byName["lobot_app"].HasPassword() || !strings.HasPrefix(byName["lobot_app"].password, "SCRAM-SHA-256$") {
		t.Error("the password hash must be read")
	}
	// CREATE, ALTER ... WITH, COMMENT and the two settings of lobot_app.
	if n := len(byName["lobot_app"].stmts); n != 5 {
		t.Errorf("lobot_app statements: %q", byName["lobot_app"].stmts)
	}
	if len(g.grants) != 1 || g.grants[0].stmt != "GRANT lobot_app TO lobot_system WITH INHERIT TRUE" ||
		!slices.Equal(g.grants[0].grantees, []string{"lobot_system"}) || !slices.Equal(g.grants[0].needs, []string{"lobot_app"}) {
		t.Errorf("grants: %+v", g.grants)
	}
}

func TestApplyScript(t *testing.T) {
	g, raw := readGlobals(t)
	script, err := g.ApplyScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"BEGIN;", "COMMIT;", "CREATE TEMP TABLE hangar_new", "NOT EXISTS (SELECT FROM pg_catalog.pg_roles",
		`'CREATE ROLE "Odd ""Name"""'`, "BYPASSRLS CONNECTION LIMIT 5 PASSWORD ''SCRAM-SHA-256$",
		"ALTER ROLE lobot_app SET statement_timeout TO ''5s''", "COMMENT ON ROLE lobot_app IS ''the app''",
		"'GRANT lobot_app TO lobot_system WITH INHERIT TRUE'", `\gexec`, SavedPrefix,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %s:\n%s", want, script)
		}
	}
	// Never the bootstrap superuser, nor its password; no GRANTED BY (the
	// grantor may not exist where the copy goes); no psql meta-commands.
	for _, bad := range []string{"'lobot'", "GRANTED BY", `\restrict`, "SUPERUSER INHERIT CREATEROLE"} {
		if strings.Contains(script, bad) {
			t.Errorf("script has %s:\n%s", bad, script)
		}
	}
	if !strings.Contains(raw, "GRANTED BY lobot") {
		t.Fatal("testdata changed")
	}
	if s, _ := (Globals{}).ApplyScript(); s != "" {
		t.Error("no roles, no script")
	}
}

func TestParseGlobalsWithoutHeader(t *testing.T) {
	g, err := ParseGlobals("CREATE ROLE postgres;\nALTER ROLE postgres WITH SUPERUSER LOGIN;\nCREATE ROLE x;\n")
	if err != nil || g.Bootstrap != "" || !slices.Equal(g.Names(), []string{"postgres", "x"}) {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := ParseGlobals(BootstrapHeader + "zz\n"); err == nil {
		t.Fatal("a broken header must fail")
	}
}

func TestRedactAndCheck(t *testing.T) {
	g, _ := readGlobals(t)
	var hash string
	for _, r := range g.Roles {
		if r.Name == "lobot_app" {
			hash = r.password
		}
	}
	msg := g.Redact(`ERROR:  syntax error at or near "` + hash + `" and md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`)
	if strings.Contains(msg, "SCRAM") || strings.Contains(msg, "md5aaaa") || !strings.Contains(msg, "[hidden]") {
		t.Fatalf("redact: %s", msg)
	}

	sum := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) } //nolint:gosec // as above
	state := map[string]RoleState{}
	for _, r := range g.Roles {
		st := RoleState{Name: r.Name, Attrs: r.Attrs}
		if r.password != "" {
			st.PasswordMD5 = sum(r.password)
		}
		state[r.Name] = st
	}
	sys := state["lobot_system"]
	sys.MemberOf = []string{"lobot_app"}
	state["lobot_system"] = sys
	saved := g.Names()
	if err := g.Check(saved, state); err != nil {
		t.Fatal(err)
	}
	// Each difference is caught, and the error never shows a hash.
	sys.BypassRLS = false
	state["lobot_system"] = sys
	app := state["lobot_app"]
	app.PasswordMD5 = sum("other")
	state["lobot_app"] = app
	odd := state[`Odd "Name"`]
	delete(state, `Odd "Name"`)
	err := g.Check(saved, state)
	if err == nil {
		t.Fatal("differences must fail the check")
	}
	for _, want := range []string{`"lobot_system" has other attributes`, `"lobot_app" has another password`, `"Odd \"Name\"" is missing`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v lacks %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "SCRAM") {
		t.Error("the error shows a hash")
	}
	state[`Odd "Name"`] = odd
	sys.BypassRLS, sys.MemberOf = true, nil
	state["lobot_system"] = sys
	state["lobot_app"] = RoleState{Name: "lobot_app", Attrs: g.Roles[1].Attrs, PasswordMD5: sum(g.Roles[1].password)}
	if err := g.Check(saved, state); err == nil || !strings.Contains(err.Error(), `"lobot_system" is not a member of "lobot_app"`) {
		t.Errorf("membership: %v", err)
	}
	// Roles the restore did not recreate are not its business.
	if err := g.Check(nil, map[string]RoleState{}); err != nil {
		t.Error(err)
	}
}

func TestParseStateAndSaved(t *testing.T) {
	js := `[{"name":"a","super":false,"inherit":true,"login":true,"bypassrls":true,"connlimit":-1,"pw":"x","member_of":["b"]}]`
	out := "noise\n" + StatePrefix + hex.EncodeToString([]byte(js)) + "\n" + SavedPrefix + hex.EncodeToString([]byte("a")) + "\n"
	st, err := ParseState(out)
	if err != nil || !st["a"].Login || !st["a"].BypassRLS || st["a"].ConnLimit != -1 || st["a"].MemberOf[0] != "b" {
		t.Fatalf("%+v %v", st, err)
	}
	if got := ParseSaved(out); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("saved: %q", got)
	}
	if _, err := ParseState("nothing"); err == nil {
		t.Fatal("no state line must fail")
	}
}

func TestReadSchemaDatabaseAndOwners(t *testing.T) {
	f, err := os.Open("testdata/create.sql")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s, err := ReadSchema(f, true)
	if err != nil {
		t.Fatal(err)
	}
	// lobot_app from the database GRANT, lobot as the owner of everything.
	if !slices.Contains(s.Roles, "lobot_app") || !slices.Contains(s.Roles, "lobot") {
		t.Errorf("roles: %q", s.Roles)
	}
	want := []string{
		"ALTER DATABASE lobot OWNER TO lobot",
		"COMMENT ON DATABASE lobot IS 'main db'",
		"REVOKE CONNECT,TEMPORARY ON DATABASE lobot FROM PUBLIC",
		"GRANT TEMPORARY ON DATABASE lobot TO PUBLIC",
		"GRANT CONNECT,TEMPORARY ON DATABASE lobot TO lobot_app",
		`ALTER DATABASE lobot SET "TimeZone" TO 'America/Sao_Paulo'`,
		"ALTER ROLE lobot_app IN DATABASE lobot SET work_mem TO '8MB'",
	}
	got := slices.Clone(s.Database)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("database statements:\n%q\nwant\n%q", got, want)
	}
	if s.Database[0] != "ALTER DATABASE lobot OWNER TO lobot" {
		t.Errorf("the owner goes first: %q", s.Database)
	}
	// Without owners (a dump saved without roles): only the permissions.
	_, _ = f.Seek(0, 0)
	s2, _ := ReadSchema(f, false)
	if slices.Contains(s2.Roles, "lobot") {
		t.Errorf("owners counted without owners: %q", s2.Roles)
	}
}

func TestDatabaseScriptRenames(t *testing.T) {
	script := DatabaseScript([]string{
		"ALTER DATABASE lobot OWNER TO lobot",
		`ALTER ROLE lobot_app IN DATABASE "Old DB" SET search_path TO 'database x'`,
		"GRANT CONNECT ON DATABASE lobot TO lobot_app",
	})
	for _, want := range []string{
		`ALTER DATABASE :"hangar_db" OWNER TO lobot;`,
		`ALTER ROLE lobot_app IN DATABASE :"hangar_db" SET search_path TO 'database x';`,
		`GRANT CONNECT ON DATABASE :"hangar_db" TO lobot_app;`,
		"BEGIN;", "COMMIT;",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %s:\n%s", want, script)
		}
	}
	if DatabaseScript(nil) != "" {
		t.Error("nothing to apply, no script")
	}
}

func TestRestoreScript(t *testing.T) {
	raw, _ := os.ReadFile("testdata/roles.sql")
	b, err := RestoreScript(raw)
	if err != nil || !strings.HasPrefix(string(b), "-- Recreates") || !strings.Contains(string(b), "lobot_system") {
		t.Fatalf("%s %v", b, err)
	}
}
