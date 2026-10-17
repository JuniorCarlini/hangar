package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func (f *fixture) withSetup(t *testing.T) string {
	t.Helper()
	f.svc.setupFile = filepath.Join(t.TempDir(), "setup-code")
	return f.svc.setupFile
}

func TestPrepareSetupWritesOneCode(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if open, err := f.svc.PrepareSetup(ctx); err != nil || open {
		t.Fatalf("without a setup file the browser setup stays closed: %v, %v", open, err)
	}
	file := f.withSetup(t)
	if open, err := f.svc.PrepareSetup(ctx); err != nil || !open {
		t.Fatalf("PrepareSetup = %v, %v", open, err)
	}
	first, _ := os.ReadFile(file)
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}\n$`).Match(first) {
		t.Fatalf("setup code %q", first)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 {
		t.Errorf("setup code readable by others: %v", st.Mode())
	}
	// A restart keeps the code the installer already printed.
	if _, err := f.svc.PrepareSetup(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(file); string(again) != string(first) {
		t.Error("a second start replaced the setup code")
	}
}

func TestCreateOwnerNeedsTheCode(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	file := f.withSetup(t)
	if _, err := f.svc.PrepareSetup(ctx); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	code := strings.TrimSpace(string(raw))
	c := Client{IP: "189.10.20.30"}

	for _, wrong := range []string{"", "AAAA-AAAA-AAAA-AAAA"} {
		if _, err := f.svc.CreateOwner(ctx, wrong, "dono@hangar.dev", goodPassword, c); !errors.Is(err, ErrSetupCode) {
			t.Errorf("code %q: %v", wrong, err)
		}
	}
	// Typed in lower case and without dashes, it still matches.
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	token, err := f.svc.CreateOwner(ctx, typed, "dono@hangar.dev", goodPassword, c)
	if err != nil || token == "" {
		t.Fatalf("CreateOwner = %q, %v", token, err)
	}
	p, err := f.svc.Authenticate(ctx, token)
	if err != nil || p.Role != RoleOwner || p.Email != "dono@hangar.dev" {
		t.Fatalf("owner session: %+v, %v", p, err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Error("the setup code must be gone once the owner exists")
	}
	if f.svc.SetupOpen(ctx) {
		t.Error("setup still open with an owner")
	}
	if _, err := f.svc.CreateOwner(ctx, code, "outro@hangar.dev", goodPassword, c); !errors.Is(err, ErrSetupClosed) {
		t.Errorf("second owner: %v", err)
	}
}

func TestCreateOwnerChecksThePassword(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	file := f.withSetup(t)
	if _, err := f.svc.PrepareSetup(ctx); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	if _, err := f.svc.CreateOwner(ctx, string(raw), "dono@hangar.dev", "curta", Client{IP: "189.10.20.30"}); err == nil {
		t.Fatal("a weak password created the owner")
	}
	if !f.svc.SetupOpen(ctx) {
		t.Error("a refused attempt must keep setup open")
	}
}

// An emptied or damaged code file never matches an empty answer.
func TestEmptySetupFileNeverMatches(t *testing.T) {
	f := newFixture(t)
	file := f.withSetup(t)
	if err := os.WriteFile(file, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateOwner(context.Background(), "", "dono@hangar.dev", goodPassword, Client{}); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("empty code file: %v", err)
	}
}

// Two people with the code racing each other: only one becomes the owner.
func TestOnlyOneOwnerWinsTheRace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	file := f.withSetup(t)
	if _, err := f.svc.PrepareSetup(ctx); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = f.svc.CreateOwner(ctx, string(raw), "dono"+string(rune('a'+i))+"@hangar.dev", goodPassword, Client{IP: "189.10.20.3" + string(rune('0'+i))})
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range results {
		if err == nil {
			ok++
		}
	}
	if n, _ := f.svc.CountUsers(ctx); ok != 1 || n != 1 {
		t.Fatalf("%d owners created, %d users: %v", ok, n, results)
	}
}

func TestOwnerFromTheCommandLineClosesSetup(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	file := f.withSetup(t)
	if _, err := f.svc.PrepareSetup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateUser(ctx, "dono@hangar.dev", goodPassword, RoleOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Error("an owner from the CLI must remove the setup code")
	}
}
