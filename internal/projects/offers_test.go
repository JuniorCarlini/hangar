package projects

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A service that offers nothing cannot be connected to; marking one of its
// variables as offered makes it connectable, and only that value shows.
func TestConnectNeedsSomethingOffered(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t) // lab/web
	api, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "api", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if _, err := f.m.PlanConnect(ctx, "lab", "web", "api"); !errors.Is(err, ErrNothingOffered) {
		t.Fatalf("plan with nothing offered: %v", err)
	}
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "api", []Mapping{{Key: "TOKEN", Var: "API_TOKEN"}}, false); err == nil {
		t.Fatal("connected to a value nobody offers")
	}
	for k, v := range map[string]string{"TOKEN": "tok-123456789", "INTERNAL": "x"} {
		if err := f.m.SetEnv(ctx, f.who, api.ID, k, v, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.m.SetOffered(ctx, f.who, api.ID, "TOKEN", true); err != nil {
		t.Fatal(err)
	}
	plan, err := f.m.PlanConnect(ctx, "lab", "web", "api")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 1 || plan.Rows[0].Key != "TOKEN" || plan.Rows[0].Var != "API_TOKEN" || !plan.Rows[0].Checked {
		t.Fatalf("plan = %+v", plan.Rows)
	}
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "api", []Mapping{{Key: "INTERNAL", Var: "X"}}, false); err == nil {
		t.Error("connected to a variable that is not offered")
	}
	if _, err := f.m.PlanConnect(ctx, "lab", "web", "web"); !errors.Is(err, ErrConnectSelf) {
		t.Errorf("plan to itself: %v", err)
	}
	// Deleting the variable takes its offer with it.
	if err := f.m.DeleteEnv(ctx, f.who, api.ID, "TOKEN"); err != nil {
		t.Fatal(err)
	}
	if offers, _ := f.m.Offers(ctx, api.ID); len(offers) != 0 {
		t.Errorf("offers after deleting the variable: %+v", offers)
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
	if r := rows["PASSWORD"]; r.Var != "PGPASSWORD" || !r.Checked {
		t.Errorf("PASSWORD row = %+v", r)
	}
	if r := rows["DATABASE_URL"]; r.Var != "DATABASE_URL" || r.Known || !r.Checked {
		t.Errorf("DATABASE_URL row = %+v", r)
	}
	if r := rows["USER"]; r.Var != "DB_USER" || r.Checked {
		t.Errorf("USER row = %+v (a part the app does not use stays off)", r)
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
