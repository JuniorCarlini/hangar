package backup

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// aclScript is what pg_restore --schema-only prints for a dump whose
// permissions name two app roles (one quoted) and the owner.
const aclScript = `--
-- Name: pedidos; Type: TABLE; Schema: public; Owner: lobot
--

CREATE TABLE public.pedidos (id integer);
ALTER TABLE public.pedidos OWNER TO lobot;

--
-- Name: pedidos tenant; Type: POLICY; Schema: public; Owner: lobot
--

CREATE POLICY tenant ON public.pedidos TO lobot_app, "Weird ""Role""" USING (true);

--
-- Name: TABLE pedidos; Type: ACL; Schema: public; Owner: lobot
--

GRANT SELECT ON TABLE public.pedidos TO lobot_app;
REVOKE ALL ON TABLE public.pedidos FROM PUBLIC;
`

// The test restore reports which roles it needed; the backup counts as
// tested only if reading the dump finds them too (what a restore does).
func TestCheckRolesMatchesTheRestore(t *testing.T) {
	hexOf := func(s string) string { return hex.EncodeToString([]byte(s)) }
	base := "HANGAR-CHECK tables=1 restored=1 rows=3\n"
	c, err := parseCheck("HANGAR-ACL "+hexOf(aclScript)+"\nHANGAR-ROLE "+hexOf("lobot_app")+"\nHANGAR-ROLE "+hexOf(`Weird "Role"`)+"\n"+base, nil)
	if err != nil || !slices.Equal(c.Roles, []string{"lobot_app", `Weird "Role"`}) {
		t.Fatalf("matching roles: %+v %v", c, err)
	}
	if _, err := parseCheck("HANGAR-ACL "+hexOf(aclScript)+"\nHANGAR-ROLE "+hexOf("hidden_role")+"\n"+base, nil); err == nil || !strings.Contains(err.Error(), "hidden_role") {
		t.Fatalf("a role the restore would not create must fail the check: %v", err)
	}
	if c, err := parseCheck(base, nil); err != nil || c.Roles != nil {
		t.Fatalf("no roles: %+v %v", c, err)
	}
	// Text from the database cannot fake the counts (they must be a line
	// of their own).
	if _, err := parseCheck("-- Name: HANGAR-CHECK tables=0 restored=0 rows=0; Type: ACL\n", nil); err == nil {
		t.Fatal("the counts must be on their own line")
	}
}
