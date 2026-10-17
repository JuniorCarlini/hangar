package projects

import (
	"context"
	"testing"
)

func TestConnectNewWiresTheConnectionString(t *testing.T) {
	f := newFixture(t)
	f.service(t) // lab/web
	ctx := context.Background()
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	key, err := f.m.ConnectNew(ctx, f.who, "lab", "web", "db")
	if err != nil || key != "DATABASE_URL" {
		t.Fatalf("connect: %q %v", key, err)
	}
	_, web, _ := f.m.GetService(ctx, "lab", "web")
	env, _ := f.m.q.ListEnv(ctx, web.ID)
	found := false
	for _, e := range env {
		found = found || e.Key == "DATABASE_URL"
	}
	if !found {
		t.Fatal("web did not get DATABASE_URL")
	}
	// Never overwrites what the origin already has, never connects to itself.
	if key, _ := f.m.ConnectNew(ctx, f.who, "lab", "web", "db"); key != "" {
		t.Errorf("second connect set %q", key)
	}
	if key, _ := f.m.ConnectNew(ctx, f.who, "lab", "web", "web"); key != "" {
		t.Errorf("self connect set %q", key)
	}
}
