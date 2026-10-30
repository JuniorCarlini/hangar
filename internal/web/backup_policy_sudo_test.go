package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// SEC-016: an Admin without a recent password confirmation cannot switch a
// service's backups or WAL off; changing the schedule still works.
func TestTurningBackupsOffNeedsSudo(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	created, err := e.pm.CreateFromTemplate(ctx, a, "lab", "postgres", "db", nil)
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	s := created[0]
	now := time.Now().Unix()
	if err := e.st.Q.UpsertBackupPolicy(ctx, dbq.UpsertBackupPolicyParams{
		ID: "bp_" + s.ID, ServiceID: sql.NullString{String: s.ID, Valid: true}, Enabled: 1, EveryHours: 24, AtMinute: 180,
		Wal: 1, WalSince: sql.NullInt64{Int64: now, Valid: true}, NextRunAt: now + 3600, Consistency: "pause", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	policy := func() dbq.BackupPolicy {
		p, err := e.st.Q.GetBackupPolicyByService(ctx, sql.NullString{String: s.ID, Valid: true})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	c, p := e.session(t, auth.RoleAdmin)
	post := func(c *http.Cookie, form url.Values) int {
		form.Set("csrf", p.CSRFToken)
		return e.do(req{method: "POST", target: "/p/lab/s/db/backups/policy", form: form, cookies: []*http.Cookie{c}}).Code
	}

	for name, form := range map[string]url.Values{
		"routine off": {"every_hours": {"24"}, "at": {"03:00"}, "wal": {"1"}},
		"wal off":     {"enabled": {"1"}, "every_hours": {"24"}, "at": {"03:00"}},
	} {
		if code := post(c, form); code != http.StatusForbidden {
			t.Errorf("%s without sudo: %d, want 403", name, code)
		}
		if got := policy(); got.Enabled != 1 || got.Wal != 1 {
			t.Fatalf("%s without sudo changed the policy: %+v", name, got)
		}
	}
	var denied int
	_ = e.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'backup.policy.set' AND outcome = 'denied'`).Scan(&denied)
	if denied != 2 {
		t.Fatalf("%d denied audit records, want 2", denied)
	}
	// Keeping both on (only the schedule moves) is not held by sudo.
	if code := post(c, url.Values{"enabled": {"1"}, "wal": {"1"}, "every_hours": {"12"}, "at": {"04:00"}}); code == http.StatusForbidden {
		t.Fatal("changing the schedule must not need sudo")
	}

	// With a fresh confirmation the routine goes off.
	e.now = e.now.Add(30 * time.Second)
	rec := e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sudo: %d", rec.Code)
	}
	sc := cookie(rec, sessionCookie)
	sp, _ := e.svc.Authenticate(ctx, sc.Value)
	p = sp
	if code := post(sc, url.Values{"every_hours": {"24"}, "at": {"03:00"}}); code != http.StatusSeeOther {
		t.Fatalf("routine off with sudo: %d", code)
	}
	if got := policy(); got.Enabled != 0 || got.Wal != 0 {
		t.Fatalf("policy after turning off: %+v", got)
	}
}
