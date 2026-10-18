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

// TestRealOSVGoAndMaven checks name matching and fixed versions on real
// records of the ecosystems the image scan brought: a Go module, Go's
// standard library and a Maven artifact.
func TestRealOSVGoAndMaven(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pkgs := []Package{
		{Ecosystem: "Go", Name: "golang.org/x/crypto", Version: "0.16.0"},
		{Ecosystem: "Go", Name: "stdlib", Version: "1.24.6"},
		{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
	}
	advs, err := NewOSV("", nil).Check(ctx, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]struct{ alias, fixed string }{
		0: {"CVE-2023-48795", "0.17.0"}, // Terrapin
		2: {"CVE-2021-44228", "2.15.0"}, // Log4Shell
	}
	for i, p := range pkgs {
		if len(advs[i]) == 0 {
			t.Errorf("%s %s: no advisories", p.Name, p.Version)
			continue
		}
		for _, a := range advs[i] {
			if a.Fixed != "" && CompareVersions(a.Fixed, p.Version) <= 0 {
				t.Errorf("%s %s: %s fixed in %q, not newer", p.Name, p.Version, a.ID, a.Fixed)
			}
		}
		w, ok := want[i]
		if !ok {
			continue
		}
		found := false
		for _, a := range advs[i] {
			for _, al := range append(a.Aliases, a.ID) {
				if al == w.alias {
					found = true
					if a.Fixed != w.fixed {
						t.Errorf("%s %s: %s fixed = %q, want %q", p.Name, p.Version, a.ID, a.Fixed, w.fixed)
					}
				}
			}
		}
		if !found {
			t.Errorf("%s %s: %s not reported", p.Name, p.Version, w.alias)
		}
	}
}
