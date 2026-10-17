//go:build integration

package deps

import (
	"context"
	"testing"
	"time"
)

// TestRealOSV asks the real api.osv.dev about a Django release with known
// advisories. Needs network: run with `go test -tags integration ./internal/deps/`.
func TestRealOSV(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	o := NewOSV("", nil)
	advs, err := o.Check(ctx, []Package{
		{Ecosystem: "PyPI", Name: "django", Version: "3.2.0"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs[0]) == 0 || len(advs[1]) == 0 {
		t.Fatalf("expected advisories for django 3.2.0 and lodash 4.17.20: %+v", advs)
	}
	fixed := false
	for _, a := range advs[0] {
		if a.Fixed != "" && CompareVersions(a.Fixed, "3.2.0") > 0 {
			fixed = true
		}
		if a.Severity == "" {
			t.Errorf("%s without a severity", a.ID)
		}
	}
	if !fixed {
		t.Error("no fixed version found for django 3.2.0")
	}
}

// TestRealRegistry lists postgres tags on Docker Hub.
func TestRealRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ups, err := NewRegistry(nil).Updates(ctx, "postgres:16.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) == 0 {
		t.Fatal("postgres:16.0 should have newer tags")
	}
}
