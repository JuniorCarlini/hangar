package projects

import (
	"context"
	"errors"
	"testing"
)

type countingEdge struct{ applied int }

func (c *countingEdge) Apply(context.Context) error { c.applied++; return nil }

func TestReservedProjectNames(t *testing.T) {
	f := newFixture(t)
	for _, slug := range []string{"edge", "hangar"} {
		if _, err := f.m.CreateProject(context.Background(), f.who, slug, ""); err == nil {
			t.Errorf("project %q would collide with Hangar's own network or containers", slug)
		}
	}
}

func TestFixedDomainsReloadEdgeAndJoinNetwork(t *testing.T) {
	f := newFixture(t)
	e := &countingEdge{}
	f.m.SetEdge(e)
	_, svcID := f.service(t)
	ctx := context.Background()

	if err := f.m.AddDomain(ctx, f.who, "lab", "web", "App.Exemplo.com.br.", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.m.AddDomain(ctx, f.who, "lab", "web", "app.exemplo.com.br", ""); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate domain: %v", err)
	}
	for _, bad := range []string{"1.2.3.4", "localhost", "a b.com", "x.com/evil"} {
		if err := f.m.AddDomain(ctx, f.who, "lab", "web", bad, ""); err == nil {
			t.Errorf("invalid hostname accepted: %q", bad)
		}
	}
	doms, _ := f.m.ListDomains(ctx, svcID)
	if len(doms) != 1 || doms[0].Hostname != "app.exemplo.com.br" {
		t.Fatalf("domains: %+v", doms)
	}
	if e.applied != 1 {
		t.Errorf("edge applied %d times, want 1", e.applied)
	}

	// A wildcard is stored as typed (lowercased); over a public suffix it
	// would claim every site there.
	if err := f.m.AddDomain(ctx, f.who, "lab", "web", "*.Lojas.com.br", ""); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"*.com.br", "a.*.lojas.com.br", "*"} {
		if err := f.m.AddDomain(ctx, f.who, "lab", "web", bad, ""); err == nil {
			t.Errorf("invalid wildcard accepted: %q", bad)
		}
	}
	doms, _ = f.m.ListDomains(ctx, svcID)
	if len(doms) != 2 {
		t.Fatalf("domains with the wildcard: %+v", doms)
	}
	for _, dm := range doms {
		if dm.Hostname == "*.lojas.com.br" {
			if err := f.m.RemoveDomain(ctx, f.who, svcID, dm.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	doms, _ = f.m.ListDomains(ctx, svcID)
	e.applied = 1

	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if spec, _ := f.n.spec("lab_web"); !spec.Edge {
		t.Error("a service with a domain must join the edge network")
	}

	if err := f.m.RemoveDomain(ctx, f.who, svcID, doms[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.m.RemoveDomain(ctx, f.who, svcID, doms[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing twice: %v", err)
	}
}

func TestDynamicDomainsInjectSecretAndAreExclusive(t *testing.T) {
	f := newFixture(t)
	_, svcID := f.service(t)
	ctx := context.Background()

	// A variable of the same name (an operator may set one) never replaces
	// the secret the edge signs with.
	if err := f.m.SetEnv(ctx, f.who, svcID, CheckSecretEnv, "valor-do-operador", false); err != nil {
		t.Fatal(err)
	}
	if err := f.m.EnableDynamicDomains(ctx, f.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	if pending, _ := f.m.PendingChanges(ctx, svcID); !pending {
		t.Error("turning dynamic domains on must ask for a deploy (the app needs the secret)")
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_web")
	secret := spec.Env[CheckSecretEnv]
	if len(secret) != 64 || !spec.Edge {
		t.Fatalf("secret not delivered or not on the edge network: %q edge=%v", secret, spec.Edge)
	}
	if got, _ := f.m.CheckSecret(ctx, svcID); got != secret {
		t.Error("revealed secret differs from the delivered one")
	}

	if _, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "api", Image: "nginx:1.29-alpine", Port: 80}); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if err := f.m.EnableDynamicDomains(ctx, f.who, "lab", "api"); err == nil {
		t.Error("only one service per server may take dynamic domains")
	}

	if err := f.m.DisableDynamicDomains(ctx, f.who, svcID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CheckSecret(ctx, svcID); !errors.Is(err, ErrNotFound) {
		t.Error("the secret must be gone after turning dynamic domains off")
	}
}

func TestMaintenanceReloadsEdgeAndAudits(t *testing.T) {
	f := newFixture(t)
	e := &countingEdge{}
	f.m.SetEdge(e)
	_, svcID := f.service(t)
	ctx := context.Background()

	if err := f.m.SetMaintenance(ctx, f.who, svcID, true); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.m.q.GetServiceByID(ctx, svcID); s.Maintenance != 1 {
		t.Error("maintenance mode not stored")
	}
	if err := f.m.SetMaintenance(ctx, f.who, svcID, false); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.m.q.GetServiceByID(ctx, svcID); s.Maintenance != 0 {
		t.Error("maintenance mode not turned off")
	}
	if e.applied != 2 {
		t.Errorf("edge applied %d times, want one per toggle", e.applied)
	}
	var on, off int
	_ = f.st.DB.QueryRow("SELECT count(*) FROM audit_log WHERE action = 'service.maintenance.on' AND target_id = ?", svcID).Scan(&on)
	_ = f.st.DB.QueryRow("SELECT count(*) FROM audit_log WHERE action = 'service.maintenance.off' AND target_id = ?", svcID).Scan(&off)
	if on != 1 || off != 1 {
		t.Errorf("audit: on=%d off=%d", on, off)
	}
	if err := f.m.SetMaintenance(ctx, f.who, "svc_nope", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown service: %v", err)
	}
}

// The hourly cap set in the panel wins over hangar.toml's, stays within its
// bounds, and the ownership TXT switch only applies to the service that
// takes customer domains and reloads the edge (dropping cached decisions).
func TestHourCapAndOwnershipTXT(t *testing.T) {
	f := newFixture(t)
	e := &countingEdge{}
	f.m.SetEdge(e)
	f.m.SetEdgeCap(30)
	_, svcID := f.service(t)
	ctx := context.Background()

	if got := f.m.HourCap(ctx); got != 30 {
		t.Fatalf("default cap %d, want hangar.toml's 30", got)
	}
	for _, bad := range []string{"0", "1001", "-3", "dez", ""} {
		if err := f.m.SetHourCap(ctx, f.who, bad); err == nil {
			t.Errorf("cap %q accepted", bad)
		}
	}
	if err := f.m.SetHourCap(ctx, f.who, " 120 "); err != nil {
		t.Fatal(err)
	}
	if got := f.m.HourCap(ctx); got != 120 {
		t.Errorf("cap %d after saving 120", got)
	}

	if err := f.m.SetDomainRequireTXT(ctx, f.who, svcID, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("TXT on a service without customer domains: %v", err)
	}
	if err := f.m.EnableDynamicDomains(ctx, f.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	before := e.applied
	if err := f.m.SetDomainRequireTXT(ctx, f.who, svcID, true); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.m.q.GetServiceByID(ctx, svcID); s.DomainRequireTxt != 1 {
		t.Error("the TXT requirement was not saved")
	}
	if e.applied != before+1 {
		t.Error("turning the TXT on must reload the edge")
	}
}
