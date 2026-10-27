package projects

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A service made by hand offers every variable it has, with nothing to
// mark first, plus its address (HOST, PORT) even with no variables; a
// deleted variable takes its offer with it.
func TestHandMadeServiceOffersItsVariables(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t) // lab/web
	api, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "api", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	// With no variables it still offers its address on the network.
	plan, err := f.m.PlanConnect(ctx, "lab", "web", "api")
	if err != nil || len(plan.Rows) != 2 || plan.Rows[0].Key != "HOST" || plan.Rows[1].Key != "PORT" {
		t.Fatalf("plan with no variables: %+v %v", plan.Rows, err)
	}
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "api", []Mapping{{Key: "TOKEN", Var: "API_TOKEN"}}, false); err == nil {
		t.Fatal("connected to a value nobody offers")
	}
	for k, v := range map[string]string{"TOKEN": "tok-123456789", "INTERNAL": "x"} {
		if err := f.m.SetEnv(ctx, f.who, api.ID, k, v, false); err != nil {
			t.Fatal(err)
		}
	}
	plan, err = f.m.PlanConnect(ctx, "lab", "web", "api")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 4 || plan.Rows[3].Key != "TOKEN" || plan.Rows[3].Var != "API_TOKEN" {
		t.Fatalf("plan = %+v", plan.Rows)
	}
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "api", []Mapping{{Key: "INTERNAL", Var: "X"}}, false); err != nil {
		t.Errorf("connect to a variable of a hand-made service: %v", err)
	}
	if _, err := f.m.PlanConnect(ctx, "lab", "web", "web"); !errors.Is(err, ErrConnectSelf) {
		t.Errorf("plan to itself: %v", err)
	}
	for _, k := range []string{"TOKEN", "INTERNAL"} {
		if err := f.m.DeleteEnv(ctx, f.who, api.ID, k); err != nil {
			t.Fatal(err)
		}
	}
	if offers, _ := f.m.Offers(ctx, api.ID); len(offers) != 2 {
		t.Errorf("offers after deleting the variables: %+v (want only HOST and PORT)", offers)
	}
}

// The .env file is the whole truth when saved from a full editor: lines set
// the variables, a missing one is deleted, an empty file deletes them all.
func TestEnvFileReplaces(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	for k, v := range map[string]string{"KEEP": "1", "GONE": "2", "SECRET_KEY": "s3cret"} {
		if err := f.m.SetEnv(ctx, f.who, webID, k, v, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.m.SetEnvFile(ctx, f.who, webID, "KEEP=1\nSECRET_KEY=s3cret\nNEW=${{db.HOST}}\n"); err != nil {
		t.Fatal(err)
	}
	vals, err := f.m.ListEnvValues(ctx, webID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vals {
		got[v.Key] = v.Value
	}
	if len(got) != 3 || got["KEEP"] != "1" || got["SECRET_KEY"] != "s3cret" || got["NEW"] != "${{db.HOST}}" {
		t.Errorf("after the file: %v", got)
	}
	if _, err := f.m.SetEnvFile(ctx, f.who, webID, ""); err != nil {
		t.Fatal(err)
	}
	if vals, _ := f.m.ListEnvValues(ctx, webID); len(vals) != 0 {
		t.Errorf("an empty file left %+v", vals)
	}
}

// The plan matches the names the app already uses (a bridge: DB_HOST
// receives the database's HOST), proposes the connection string otherwise,
// and Connect never replaces another value without being told to.
func TestConnectBridgesDifferentNames(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	for k, v := range map[string]string{"POSTGRES_HOST": "localhost", "PGPASSWORD": "old"} {
		if err := f.m.SetEnv(ctx, f.who, webID, k, v, false); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := f.m.PlanConnect(ctx, "lab", "web", "db")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]ConnectRow{}
	for _, r := range plan.Rows {
		rows[r.Key] = r
	}
	if r := rows["HOST"]; r.Var != "POSTGRES_HOST" || !r.Known || !r.Current || !r.Checked {
		t.Errorf("HOST row = %+v", r)
	}
	// A template offers its own names; the plan suggests by what the value
	// is (POSTGRES_PASSWORD is a password, which this app reads as
	// PGPASSWORD), and the repeated export (PASSWORD) is not offered again.
	if r := rows["POSTGRES_PASSWORD"]; r.Var != "PGPASSWORD" || !r.Checked {
		t.Errorf("POSTGRES_PASSWORD row = %+v", r)
	}
	if _, ok := rows["PASSWORD"]; ok {
		t.Error("the export repeating POSTGRES_PASSWORD is offered again")
	}
	if r := rows["DATABASE_URL"]; r.Var != "DATABASE_URL" || r.Known || !r.Checked {
		t.Errorf("DATABASE_URL row = %+v", r)
	}
	if r := rows["POSTGRES_USER"]; r.Var != "DB_USER" || r.Checked {
		t.Errorf("POSTGRES_USER row = %+v (a part the app does not use stays off)", r)
	}

	maps := []Mapping{{Key: "HOST", Var: "POSTGRES_HOST"}, {Key: "DATABASE_URL", Var: "DATABASE_URL"}}
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "db", maps, false); err == nil {
		t.Fatal("replaced POSTGRES_HOST without being told to")
	}
	n, err := f.m.Connect(ctx, f.who, "lab", "web", "db", maps, true)
	if err != nil || n != 2 {
		t.Fatalf("connect: %d %v", n, err)
	}
	if v := f.envValue(t, webID, "POSTGRES_HOST"); v != "${{db.HOST}}" {
		t.Errorf("POSTGRES_HOST = %q", v)
	}
	// Connecting again changes nothing; the plan shows it as linked.
	if n, err := f.m.Connect(ctx, f.who, "lab", "web", "db", maps, false); err != nil || n != 0 {
		t.Errorf("reconnect: %d %v", n, err)
	}
	plan, _ = f.m.PlanConnect(ctx, "lab", "web", "db")
	for _, r := range plan.Rows {
		if r.Key == "HOST" && (!r.Linked || r.Checked) {
			t.Errorf("HOST after connecting = %+v", r)
		}
	}
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "db", []Mapping{{Key: "HOST", Var: "A"}, {Key: "PORT", Var: "A"}}, true); err == nil {
		t.Error("two values into one variable")
	}

	deps, err := f.m.Dependents(ctx, "lab", "db")
	if err != nil || len(deps) != 2 {
		t.Fatalf("dependents = %+v %v", deps, err)
	}
}

// Changing the database password updates what it offers, and the app that
// uses it shows changes to apply.
func TestProviderChangeReachesTheConsumer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "db", []Mapping{{Key: "DATABASE_URL", Var: "DATABASE_URL"}}, false); err != nil {
		t.Fatal(err)
	}
	_, web, _ := f.m.GetService(ctx, "lab", "web")
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if pending, _ := f.m.PendingChanges(ctx, web.ID); pending {
		t.Fatal("pending right after the deploy")
	}
	_, db, _ := f.m.GetService(ctx, "lab", "db")
	old := f.envValue(t, db.ID, "POSTGRES_PASSWORD")
	if err := f.m.SetEnv(ctx, f.who, db.ID, "POSTGRES_PASSWORD", "a-brand-new-password-1", true); err != nil {
		t.Fatal(err)
	}
	p, _ := f.m.GetProject(ctx, "lab")
	got, err := f.m.resolveRefs(ctx, p, map[string]string{"U": "${{db.DATABASE_URL}}", "P": "${{db.PASSWORD}}"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["U"], "a-brand-new-password-1") || strings.Contains(got["U"], old) || got["P"] != "a-brand-new-password-1" {
		t.Errorf("exports after the change: %q %q", got["U"], got["P"])
	}
	if pending, _ := f.m.PendingChanges(ctx, web.ID); !pending {
		t.Error("the app does not show changes to apply")
	}
	_ = webID
}

// A reference to a value that is itself a reference is followed; a loop is
// reported, never sent to the app as text.
func TestChainedReferences(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	api, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "api", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	_ = f.m.SetEnv(ctx, f.who, api.ID, "DB", "${{db.HOST}}", false)
	_ = f.m.SetEnv(ctx, f.who, api.ID, "LOOP", "${{web.BACK}}", false)
	_ = f.m.SetEnv(ctx, f.who, webID, "BACK", "${{api.LOOP}}", false)
	p, _ := f.m.GetProject(ctx, "lab")
	got, err := f.m.resolveRefs(ctx, p, map[string]string{"H": "${{api.DB}}"})
	if err != nil || got["H"] == "" || strings.Contains(got["H"], "${{") {
		t.Fatalf("chain: %q %v", got["H"], err)
	}
	if _, err := f.m.resolveRefs(ctx, p, map[string]string{"X": "${{api.LOOP}}"}); err == nil {
		t.Error("a loop resolved")
	}
	broken, _ := f.m.BrokenRefs(ctx, p)
	cycles := 0
	for _, b := range broken {
		if b.Problem == RefCycle {
			cycles++
		}
	}
	if cycles != 2 {
		t.Errorf("cycles reported: %+v", broken)
	}
}

func (f *fixture) envValue(t *testing.T, serviceID, key string) string {
	t.Helper()
	r, err := f.m.q.GetEnv(context.Background(), dbq.GetEnvParams{ServiceID: serviceID, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := f.m.box.Open(r.ValueEnc, envAD(serviceID, key))
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

// The .env keeps what the operator wrote: comments, sections, blank lines,
// commented-out variables and order. Changes made elsewhere are reconciled
// into it, and a secret hidden from the editor survives a save.
func TestEnvTextKeepsTheFile(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	file := `# ======
# app — variables
# ======

# Django
SECRET_KEY="long-random"
DEBUG=True

# Database
DATABASE_URL=${{db.DATABASE_URL}}
# OPTIONAL_FLAG=1
EMPTY=
`
	if _, err := f.m.SetEnvFile(ctx, f.who, webID, file); err != nil {
		t.Fatal(err)
	}
	got, keys, err := f.m.EnvText(ctx, webID, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != file {
		t.Errorf("the file came back changed:\n%s", got)
	}
	if !slices.Equal(keys, []string{"SECRET_KEY", "DEBUG", "DATABASE_URL", "EMPTY"}) {
		t.Errorf("order = %v", keys)
	}

	// Changed elsewhere: a new variable goes to the end, a deleted one loses
	// its line, a changed value shows the new one.
	if err := f.m.SetEnv(ctx, f.who, webID, "DB_HOST", "${{db.HOST}}", false); err != nil {
		t.Fatal(err)
	}
	if err := f.m.DeleteEnv(ctx, f.who, webID, "EMPTY"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetEnv(ctx, f.who, webID, "DEBUG", "False", false); err != nil {
		t.Fatal(err)
	}
	got, _, _ = f.m.EnvText(ctx, webID, true)
	for _, want := range []string{"# Database\n", "# OPTIONAL_FLAG=1\n", "DEBUG=False\n", "DB_HOST=${{db.HOST}}\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("reconciled file lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "EMPTY=") || !strings.HasSuffix(got, "DB_HOST=${{db.HOST}}\n") {
		t.Errorf("reconciled file:\n%s", got)
	}

	// Below admin a secret is "KEY=••••"; saving that text keeps the value.
	hidden, _, _ := f.m.EnvText(ctx, webID, false)
	if !strings.Contains(hidden, "SECRET_KEY="+HiddenValue) || strings.Contains(hidden, "long-random") {
		t.Fatalf("the secret reached a hidden editor:\n%s", hidden)
	}
	if _, err := f.m.SetEnvFile(ctx, f.who, webID, hidden+"NEW=1\n"); err != nil {
		t.Fatal(err)
	}
	vals, _ := f.m.ListEnvValues(ctx, webID)
	for _, v := range vals {
		if v.Key == "SECRET_KEY" && v.Value != "long-random" {
			t.Errorf("the hidden secret became %q", v.Value)
		}
	}
	if full, _, _ := f.m.EnvText(ctx, webID, true); !strings.Contains(full, `SECRET_KEY="long-random"`) {
		t.Errorf("the stored file lost the secret's line:\n%s", full)
	}
}

// Copying the .env gives the file as the container gets it: references
// resolved, comments and order kept, so it works pasted outside Hangar.
func TestResolvedEnvText(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if _, err := f.m.SetEnvFile(ctx, f.who, webID, "# banco\nDB_HOST=${{db.HOST}}\nOLD=${{db.PASSWORD}}\nNEW=${{db.POSTGRES_PASSWORD}}\nDEBUG=0\n"); err != nil {
		t.Fatal(err)
	}
	p, _, err := f.m.GetService(ctx, "lab", "web")
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.m.ResolvedEnvText(ctx, p, webID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "# banco\nDB_HOST=") || strings.Contains(got, "${{") || !strings.HasSuffix(got, "DEBUG=0\n") {
		t.Errorf("resolved file:\n%s", got)
	}
	// An older connection to the template's repeated name (PASSWORD) and a
	// new one to its own (POSTGRES_PASSWORD) give the same password.
	var oldV, newV string
	for _, line := range strings.Split(got, "\n") {
		if v, ok := strings.CutPrefix(line, "OLD="); ok {
			oldV = v
		}
		if v, ok := strings.CutPrefix(line, "NEW="); ok {
			newV = v
		}
	}
	if oldV == "" || oldV != newV {
		t.Errorf("old %q and new %q connections differ", oldV, newV)
	}
}

// A cache's values never take the database's names: with DB_HOST already
// in the app, a Redis still suggests REDIS_HOST, not DB_HOST.
func TestCacheNamesStayApartFromTheDatabase(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "redis-cache", "redis", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	for _, k := range []string{"DB_HOST", "DB_PASSWORD"} {
		if err := f.m.SetEnv(ctx, f.who, webID, k, "x", false); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := f.m.PlanConnect(ctx, "lab", "web", "redis")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range plan.Rows {
		if strings.HasPrefix(r.Var, "DB_") {
			t.Errorf("%s suggested as %s", r.Key, r.Var)
		}
		if r.Key == "HOST" && r.Var != "REDIS_HOST" {
			t.Errorf("HOST suggested as %s, want REDIS_HOST", r.Var)
		}
	}
}
