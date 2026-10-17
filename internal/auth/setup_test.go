package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// openSetup turns the browser setup on and opens its window, as a panel
// starting with no user does.
func (f *fixture) openSetup(t *testing.T) time.Time {
	t.Helper()
	f.svc.firstRun = true
	until, err := f.svc.PrepareSetup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return until
}

func TestSetupWindowLastsThirtyMinutes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if st, _ := f.svc.Setup(ctx); st != SetupDone {
		t.Fatalf("browser setup off: state %v", st)
	}
	until := f.openSetup(t)
	if want := f.clock.t.Add(SetupWindow); !until.Equal(want.Truncate(time.Second)) && !until.Equal(want) {
		t.Fatalf("window until %v, want %v", until, want)
	}
	if st, _ := f.svc.Setup(ctx); st != SetupAvailable {
		t.Fatalf("right after start: state %v", st)
	}
	f.clock.advance(SetupWindow)
	if st, _ := f.svc.Setup(ctx); st != SetupExpired {
		t.Fatalf("after the window: state %v", st)
	}
	if _, err := f.svc.CreateOwner(ctx, "dono@hangar.dev", goodPassword, Client{IP: "189.10.20.30"}); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("owner after the window: %v", err)
	}
	// A restart (PrepareSetup again) opens a new window.
	f.openSetup(t)
	if st, _ := f.svc.Setup(ctx); st != SetupAvailable {
		t.Fatalf("after a restart: state %v", st)
	}
}

func TestCreateOwnerOpensASession(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.openSetup(t)
	token, err := f.svc.CreateOwner(ctx, "dono@hangar.dev", goodPassword, Client{IP: "189.10.20.30"})
	if err != nil || token == "" {
		t.Fatalf("CreateOwner = %q, %v", token, err)
	}
	p, err := f.svc.Authenticate(ctx, token)
	if err != nil || p.Role != RoleOwner || p.Email != "dono@hangar.dev" {
		t.Fatalf("owner session: %+v, %v", p, err)
	}
	if st, _ := f.svc.Setup(ctx); st != SetupDone {
		t.Errorf("setup still open with an owner: %v", st)
	}
	if _, err := f.svc.CreateOwner(ctx, "outro@hangar.dev", goodPassword, Client{IP: "189.10.20.31"}); !errors.Is(err, ErrSetupClosed) {
		t.Errorf("second owner: %v", err)
	}
}

func TestCreateOwnerChecksThePassword(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.openSetup(t)
	if _, err := f.svc.CreateOwner(ctx, "dono@hangar.dev", "curta", Client{IP: "189.10.20.30"}); err == nil {
		t.Fatal("a weak password created the owner")
	}
	if st, _ := f.svc.Setup(ctx); st != SetupAvailable {
		t.Error("a refused attempt must keep setup open")
	}
}

// Two people racing each other: only one becomes the owner.
func TestOnlyOneOwnerWinsTheRace(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.openSetup(t)
	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = f.svc.CreateOwner(ctx, "dono"+string(rune('a'+i))+"@hangar.dev", goodPassword, Client{IP: "189.10.20.3" + string(rune('0'+i))})
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

// An owner created on the command line closes the browser setup.
func TestOwnerFromTheCommandLineClosesSetup(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.openSetup(t)
	if _, err := f.svc.CreateUser(ctx, "dono@hangar.dev", goodPassword, RoleOwner); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.svc.Setup(ctx); st != SetupDone {
		t.Errorf("state %v", st)
	}
}
