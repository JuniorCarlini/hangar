package pgroles

import (
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
)

// testdata/*.sql are what pg_restore 18 printed for a dump with two app
// roles (one BYPASSRLS), a quoted role name, an RLS policy for two roles,
// column and sequence grants and default privileges: schema.sql with -s,
// acl.sql with -L of the ACL, POLICY and DEFAULT ACL entries only.
func TestFromScriptRealDump(t *testing.T) {
	want := []string{"lobot_system", "lobot_app", `Weird "Role"`, "lobot"}
	for _, file := range []string{"testdata/schema.sql", "testdata/acl.sql"} {
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FromScript(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("%s: %q, want %q", file, got, w)
		}
	}
}

func TestFromSQL(t *testing.T) {
	for _, c := range []struct {
		name, sql string
		want      []string
	}{
		{"plain grant", `GRANT SELECT,INSERT ON TABLE public.pedidos TO lobot_app;`, []string{"lobot_app"}},
		{"public is not a role", `REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO PUBLIC;`, nil},
		{"session forms", `GRANT ALL ON TABLE t TO CURRENT_USER, SESSION_USER, current_role;`, nil},
		{"predefined roles", `GRANT SELECT ON TABLE t TO pg_read_all_data;`, nil},
		{"quoted names", `GRANT USAGE ON SCHEMA "My Schema" TO "App ""Admin""", "UPPER";`, []string{`App "Admin"`, "UPPER"}},
		{"unquoted names fold", `GRANT SELECT ON t TO Lobot_App;`, []string{"lobot_app"}},
		{"multiple grantees", `GRANT SELECT ON t TO a, GROUP b, "c d" WITH GRANT OPTION;`, []string{"a", "b", "c d"}},
		{"granted by", `GRANT SELECT ON t TO a GRANTED BY "boss";`, []string{"a", "boss"}},
		{"revoke", `REVOKE GRANT OPTION FOR SELECT ON t FROM x, y CASCADE;`, []string{"x", "y"}},
		{"column grant", `GRANT SELECT(valor), UPDATE (a, b) ON TABLE public.t TO col_reader;`, []string{"col_reader"}},
		{"function signature", `GRANT ALL ON FUNCTION public.f(to_char text, "to" integer) TO fn_user;`, []string{"fn_user"}},
		{"object named to", `GRANT SELECT ON TABLE public."to" TO reader;`, []string{"reader"}},
		{"policy to two roles", `CREATE POLICY p ON public.t AS RESTRICTIVE FOR SELECT TO a, "b c" USING ((tenant = current_setting('x.to', true)::int)) WITH CHECK (true);`, []string{"a", "b c"}},
		{"policy for public", `CREATE POLICY p ON t USING (true);`, nil},
		{"policy named to", `CREATE POLICY "to" ON "to" TO p_role USING (owner = 'TO x');`, []string{"p_role"}},
		{"alter policy roles", `ALTER POLICY p ON t TO r1, r2;`, []string{"r1", "r2"}},
		{"alter policy rename", `ALTER POLICY p ON t RENAME TO q;`, nil},
		{"default privileges", `ALTER DEFAULT PRIVILEGES FOR ROLE lobot, "Other" IN SCHEMA public, s2 GRANT SELECT ON TABLES TO lobot_app;`, []string{"lobot", "Other", "lobot_app"}},
		{"default privileges revoke", `ALTER DEFAULT PRIVILEGES FOR USER owner1 REVOKE ALL ON FUNCTIONS FROM PUBLIC, x;`, []string{"owner1", "x"}},
		{"default privileges no owner", `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO seq_user;`, []string{"seq_user"}},
		{"role membership", `GRANT admins, "ops team" TO alice WITH ADMIN OPTION;`, []string{"admins", "ops team", "alice"}},
		{"session authorization", `SET SESSION AUTHORIZATION 'grantor'; GRANT SELECT ON t TO x; RESET SESSION AUTHORIZATION;`, []string{"grantor", "x"}},
		{"session authorization ident", `SET SESSION AUTHORIZATION "Grantor"; SET SESSION AUTHORIZATION DEFAULT;`, []string{"Grantor"}},
		{"strings and comments", "-- GRANT x TO commented;\n/* GRANT y TO /* nested */ blocked; */ GRANT SELECT ON t TO real_one; SELECT $q$ GRANT a TO dollar; $q$; SELECT E'GRANT \\' TO esc';", []string{"real_one"}},
		{"dedupe and order", `GRANT SELECT ON t TO b; GRANT SELECT ON t TO a; GRANT SELECT ON u TO b;`, []string{"b", "a"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := FromSQL(c.sql)
			if !slices.Equal(got, c.want) {
				t.Errorf("FromSQL(%s) = %q, want %q", c.sql, got, c.want)
			}
		})
	}
}

// Only the ACL, POLICY and DEFAULT ACL entries are read: a function body
// or a view that happens to contain GRANT is not a role reference.
func TestFromScriptKeepsOnlyPermissionEntries(t *testing.T) {
	script := `--
-- Name: f(); Type: FUNCTION; Schema: public; Owner: lobot
--

CREATE FUNCTION public.f() RETURNS void LANGUAGE sql AS 'GRANT SELECT ON t TO from_function';

\restrict abc

--
-- Name: TABLE t; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.t TO app;

--
-- Data for Name: t; Type: TABLE DATA; Schema: public; Owner: lobot
--

GRANT SELECT ON t TO from_data;
`
	got, err := FromScript(strings.NewReader(script))
	if err != nil || !slices.Equal(got, []string{"app"}) {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestCreateScript(t *testing.T) {
	if s, err := CreateScript(nil); s != "" || err != nil {
		t.Fatal("no roles, no script")
	}
	s, err := CreateScript([]string{"lobot_app", "it's"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"BEGIN;", "COMMIT;", "'lobot_app'", "'it''s'", "NOLOGIN", `\gexec`, "NOT EXISTS (SELECT FROM pg_catalog.pg_roles"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "PASSWORD") || strings.Contains(s, "ALTER ROLE") {
		t.Error("existing roles must never be changed, and none gets a password")
	}
	for _, bad := range []string{"", "a\x00b", strings.Repeat("x", 64)} {
		if _, err := CreateScript([]string{bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestParseCreated(t *testing.T) {
	out := "HANGAR-NEW " + hex.EncodeToString([]byte("lobot_app")) + "\nnoise\nHANGAR-NEW " + hex.EncodeToString([]byte(`Weird "Role"`)) + "\nHANGAR-NEW zz\n"
	if got := ParseCreated(out); !slices.Equal(got, []string{"lobot_app", `Weird "Role"`}) {
		t.Fatalf("got %q", got)
	}
}
