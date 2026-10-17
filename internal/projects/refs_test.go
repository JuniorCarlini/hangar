package projects

import (
	"context"
	"testing"
)

func TestBrokenRefs(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t) // project lab, service web
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateProject(ctx, f.who, "outro", ""); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	for k, v := range map[string]string{
		"DATABASE_URL": "${{ db.DATABASE_URL }}",     // an export: fine
		"DB_USER":      "${{db.POSTGRES_USER}}",      // a plain variable also resolves
		"REDIS_URL":    "${{cache.REDIS_URL}}",       // no such service
		"X":            "${{db.NOPE}}",               // db does not have it
		"OTHER":        "${{outro.cache.REDIS_URL}}", // project not connected
		"MIXED":        "${{db.HOST}}:${{db.PORTA}}", // one of two broken
		"PLAIN":        "nada aqui",
	} {
		if err := f.m.SetEnv(ctx, f.who, webID, k, v, false); err != nil {
			t.Fatal(err)
		}
	}
	p, err := f.m.GetProject(ctx, "lab")
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.m.BrokenRefs(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	want := []BrokenRef{
		{ServiceID: webID, Service: "web", Key: "MIXED", Target: "db", TargetKey: "PORTA", Problem: RefNoKey},
		{ServiceID: webID, Service: "web", Key: "OTHER", Project: "outro", Target: "cache", TargetKey: "REDIS_URL", Problem: RefNoProject},
		{ServiceID: webID, Service: "web", Key: "REDIS_URL", Target: "cache", TargetKey: "REDIS_URL", Problem: RefNoService},
		{ServiceID: webID, Service: "web", Key: "X", Target: "db", TargetKey: "NOPE", Problem: RefNoKey},
	}
	if len(got) != len(want) {
		t.Fatalf("broken refs = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Connecting the project leaves only the missing service there; the
	// deploy agrees with the list and refuses while anything is broken.
	if err := f.m.LinkProjects(ctx, f.who, "lab", "outro"); err != nil {
		t.Fatal(err)
	}
	got, _ = f.m.BrokenRefs(ctx, p)
	if len(got) != 4 || got[1].Key != "OTHER" || got[1].Problem != RefNoService {
		t.Errorf("after linking: %+v", got)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err == nil {
		t.Error("deploy with broken references must fail")
	}
	for _, k := range []string{"MIXED", "OTHER", "REDIS_URL", "X"} {
		if err := f.m.DeleteEnv(ctx, f.who, webID, k); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ = f.m.BrokenRefs(ctx, p); len(got) != 0 {
		t.Errorf("nothing should be broken: %+v", got)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Errorf("deploy with valid references: %v", err)
	}
	f.m.Wait()
}
