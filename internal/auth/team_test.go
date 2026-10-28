package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func (f *fixture) project(t *testing.T, slug string) {
	t.Helper()
	if _, err := f.st.DB.Exec(`INSERT INTO projects (id, slug, name, created_at, updated_at) VALUES (?, ?, ?, 0, 0)`, "prj_"+slug, slug, slug); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) owner(t *testing.T) *Principal {
	t.Helper()
	id, err := f.svc.CreateUser(context.Background(), "dono@hangar.dev", goodPassword, RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	return &Principal{UserID: id, Role: RoleOwner, AllProjects: true}
}

func TestInviteGivesTheChosenAccessOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.project(t, "lab")
	f.project(t, "loja")
	own := f.owner(t)
	c := Client{IP: "189.10.20.30"}

	token, err := f.svc.CreateInvite(ctx, own, "maria@hangar.dev", Access{Role: RoleOperator, Projects: []string{"lab"}}, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.InviteFor(ctx, token); err != nil {
		t.Fatalf("open invitation: %v", err)
	}
	sess, err := f.svc.AcceptInvite(ctx, token, goodPassword, c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.Authenticate(ctx, sess)
	if err != nil || p == nil || p.Role != RoleOperator || p.Email != "maria@hangar.dev" {
		t.Fatalf("invited user's session: %+v, %v", p, err)
	}
	if !p.Limited() || !p.CanSeeProject("lab") || p.CanSeeProject("loja") {
		t.Errorf("access: limited %v, lab %v, loja %v", p.Limited(), p.CanSeeProject("lab"), p.CanSeeProject("loja"))
	}
	if _, err := f.svc.AcceptInvite(ctx, token, goodPassword, c); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("a link must work only once: %v", err)
	}
}

func TestInviteExpiresAndChecksInput(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.project(t, "lab")
	own := f.owner(t)
	c := Client{IP: "189.10.20.30"}
	if _, err := f.svc.CreateInvite(ctx, own, "x@hangar.dev", Access{Role: RoleOwner}, c); !errors.Is(err, ErrInviteRole) {
		t.Errorf("owners are not invited: %v", err)
	}
	if _, err := f.svc.CreateInvite(ctx, own, "x@hangar.dev", Access{Role: RoleViewer}, c); !errors.Is(err, ErrNoProjects) {
		t.Errorf("limited access needs projects: %v", err)
	}
	if _, err := f.svc.CreateInvite(ctx, own, "x@hangar.dev", Access{Role: RoleViewer, Projects: []string{"nope"}}, c); err == nil {
		t.Error("an unknown project must be refused")
	}
	if _, err := f.svc.CreateInvite(ctx, own, "dono@hangar.dev", Access{Role: RoleViewer, AllProjects: true}, c); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("an existing e-mail: %v", err)
	}
	token, err := f.svc.CreateInvite(ctx, own, "x@hangar.dev", Access{Role: RoleAdmin, Projects: []string{"lab"}}, c)
	if err != nil {
		t.Fatal(err)
	}
	inv, _ := f.svc.InviteFor(ctx, token)
	if !inv.Access.AllProjects {
		t.Error("an admin always sees every project")
	}
	f.clock.advance(InviteTTL)
	if _, err := f.svc.AcceptInvite(ctx, token, goodPassword, c); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("an expired link: %v", err)
	}
}

func TestTheLastOwnerStays(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	own := f.owner(t)
	c := Client{IP: "189.10.20.30"}
	if err := f.svc.UpdateMember(ctx, own, own.UserID, Access{Role: RoleViewer, AllProjects: true}, c); !errors.Is(err, ErrSelf) {
		t.Errorf("changing oneself: %v", err)
	}
	if err := f.svc.RemoveMember(ctx, own, own.UserID, c); !errors.Is(err, ErrSelf) {
		t.Errorf("removing oneself: %v", err)
	}
	other, err := f.svc.CreateUser(ctx, "socio@hangar.dev", goodPassword, RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	// Another owner acting on the first one: allowed while two remain.
	second := &Principal{UserID: other, Role: RoleOwner, AllProjects: true}
	if err := f.svc.UpdateMember(ctx, second, own.UserID, Access{Role: RoleAdmin}, c); err != nil {
		t.Fatal(err)
	}
	// Now the second is the only owner left: the first (an admin now)
	// cannot be the one removing it, and it cannot be demoted.
	third, _ := f.svc.CreateUser(ctx, "outro@hangar.dev", goodPassword, RoleOwner)
	if err := f.svc.RemoveMember(ctx, &Principal{UserID: third, Role: RoleOwner}, other, c); err != nil {
		t.Fatalf("removing one of two owners: %v", err)
	}
	if err := f.svc.UpdateMember(ctx, own, third, Access{Role: RoleAdmin}, c); !errors.Is(err, ErrLastOwner) {
		t.Errorf("demoting the last owner: %v", err)
	}
	if err := f.svc.RemoveMember(ctx, own, third, c); !errors.Is(err, ErrLastOwner) {
		t.Errorf("removing the last owner: %v", err)
	}
}

// Changing someone's access signs them out, so the new access applies at once.
func TestUpdatingAccessEndsSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.project(t, "lab")
	own := f.owner(t)
	c := Client{IP: "189.10.20.30"}
	token, _ := f.svc.CreateInvite(ctx, own, "maria@hangar.dev", Access{Role: RoleOperator, AllProjects: true}, c)
	sess, err := f.svc.AcceptInvite(ctx, token, goodPassword, c)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := f.svc.Authenticate(ctx, sess)
	if err := f.svc.UpdateMember(ctx, own, p.UserID, Access{Role: RoleViewer, Projects: []string{"lab"}}, c); err != nil {
		t.Fatal(err)
	}
	if again, _ := f.svc.Authenticate(ctx, sess); again != nil {
		t.Error("the old session must end")
	}
	members, _, _ := f.svc.Team(ctx)
	for _, m := range members {
		if m.ID == p.UserID && (m.Access.Role != RoleViewer || m.Access.AllProjects || len(m.Access.Projects) != 1) {
			t.Errorf("stored access: %+v", m.Access)
		}
	}
}

// Guessing invitation links: after LimitFailures wrong tokens from one IP,
// that IP is blocked, even for a right token, until the window passes.
func TestGuessingInviteLinksIsRateLimited(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	own := f.owner(t)
	token, err := f.svc.CreateInvite(ctx, own, "maria@hangar.dev", Access{Role: RoleViewer, AllProjects: true}, Client{IP: "189.10.20.30"})
	if err != nil {
		t.Fatal(err)
	}
	attacker := Client{IP: "45.1.2.3"}
	for i := range LimitFailures {
		if _, err := f.svc.AcceptInvite(ctx, randomToken(), goodPassword, attacker); !errors.Is(err, ErrInviteInvalid) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	var rl *RateLimitedError
	if _, err := f.svc.AcceptInvite(ctx, token, goodPassword, attacker); !errors.As(err, &rl) {
		t.Fatalf("after %d wrong guesses the IP must be blocked: %v", LimitFailures, err)
	}
	// Someone else, from another address, still joins with the real link.
	if _, err := f.svc.AcceptInvite(ctx, token, goodPassword, Client{IP: "189.10.20.30"}); err != nil {
		t.Fatalf("the invited person: %v", err)
	}
}

// TestOnlyTheLatestInviteLinkWorks: inviting the same address again replaces
// the open link, and no link for an address outlives its account.
func TestOnlyTheLatestInviteLinkWorks(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	own := f.owner(t)
	c := Client{IP: "189.10.20.30"}
	all := Access{Role: RoleViewer, AllProjects: true}

	first, err := f.svc.CreateInvite(ctx, own, "maria@hangar.dev", all, c)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.CreateInvite(ctx, own, "Maria@hangar.dev", all, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.InviteFor(ctx, first); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("the replaced link still works: %v", err)
	}
	if _, invites, _ := f.svc.Team(ctx); len(invites) != 1 {
		t.Fatalf("open invites = %d, want 1", len(invites))
	}
	if _, err := f.svc.AcceptInvite(ctx, second, goodPassword, c); err != nil {
		t.Fatal(err)
	}
	if _, invites, _ := f.svc.Team(ctx); len(invites) != 0 {
		t.Fatalf("open invites after the account exists = %d", len(invites))
	}
}

// TestLastSeenOutlivesSessions: once someone logged in, the team page keeps
// showing when, even after every session of theirs is gone.
func TestLastSeenOutlivesSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	own := f.owner(t)
	c := Client{IP: "189.10.20.30"}
	token, err := f.svc.CreateInvite(ctx, own, "maria@hangar.dev", Access{Role: RoleViewer, AllProjects: true}, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.AcceptInvite(ctx, token, goodPassword, c); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.DB.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		t.Fatal(err)
	}
	members, _, err := f.svc.Team(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.Email == "maria@hangar.dev" && m.LastSeen.IsZero() {
			t.Fatal("shows as never logged in after the sessions ended")
		}
	}
}

// Two owners demoting each other at the same moment: both pass the early
// count, but only one change may land, or the panel is left with no owner.
func TestOwnersDemotingEachOtherKeepOne(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := Client{IP: "189.10.20.30"}
	for i := range 20 {
		a, _ := f.svc.CreateUser(ctx, fmt.Sprintf("a%d@hangar.dev", i), goodPassword, RoleOwner)
		b, _ := f.svc.CreateUser(ctx, fmt.Sprintf("b%d@hangar.dev", i), goodPassword, RoleOwner)
		// Only these two are owners in this round.
		if _, err := f.st.DB.ExecContext(ctx, `UPDATE users SET role = 'admin' WHERE role = 'owner' AND id NOT IN (?, ?)`, a, b); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for _, pair := range [][2]string{{a, b}, {b, a}} {
			wg.Go(func() {
				_ = f.svc.UpdateMember(ctx, &Principal{UserID: pair[0], Role: RoleOwner, AllProjects: true}, pair[1], Access{Role: RoleAdmin, AllProjects: true}, c)
			})
		}
		wg.Wait()
		var n int
		if err := f.st.DB.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'owner'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n < 1 {
			t.Fatalf("round %d: no owner left", i)
		}
	}
}
