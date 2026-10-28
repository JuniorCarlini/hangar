package web

import (
	"context"
	"database/sql"
	"html"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A failed restore is said on top of the service's Backups tab with its
// reason and what became of the new service; a restore that created roles
// says which ones need a password, also on the copy it created.
func TestServiceBackupsTabShowsRestoreOutcome(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"db", "db-novo"} {
		if _, err := e.pm.CreateFromTemplate(ctx, a, "lab", "postgres", slug, nil); err != nil {
			t.Fatal(err)
		}
	}
	e.pm.Wait()
	_, src, _ := e.pm.GetService(ctx, "lab", "db")
	_, cp, _ := e.pm.GetService(ctx, "lab", "db-novo")
	q := dbq.New(e.st.DB)
	now := time.Now().Unix()
	add := func(id, dest, status, errText, roles, cleanup string, started int64) {
		t.Helper()
		if err := q.CreateBackupRestore(ctx, dbq.CreateBackupRestoreParams{
			ID: id, ServiceID: sql.NullString{String: src.ID, Valid: true}, Label: "lab/db", Mode: "dump", Point: "diario/lab/db/x.dump.age",
			Destination: "new", NewService: dest, Step: "restore", StartedAt: started,
		}); err != nil {
			t.Fatal(err)
		}
		_ = q.FinishBackupRestore(ctx, dbq.FinishBackupRestoreParams{
			Status: status, Error: sql.NullString{String: errText, Valid: errText != ""}, FinishedAt: sql.NullInt64{Int64: now, Valid: true}, ID: id,
		})
		_ = q.SetBackupRestoreRoles(ctx, dbq.SetBackupRestoreRolesParams{CreatedRoles: roles, ID: id})
		_ = q.SetBackupRestoreCleanup(ctx, dbq.SetBackupRestoreCleanupParams{Cleanup: cleanup, ID: id})
	}
	add("bkr_ok", "db-novo", "ok", "", `["lobot_app","lobot_system"]`, "", cp.CreatedAt-1)
	add("bkr_fail", "db-copia", "failed", `pg_restore: role "lobot_app" does not exist`, "[]", "removed", now)

	c, _ := e.session(t, auth.RoleAdmin)
	body := html.UnescapeString(e.do(req{method: "GET", target: "/p/lab/s/db?tab=backups", cookies: []*http.Cookie{c}}).Body.String())
	for _, want := range []string{
		`class="tuc-alert is-danger" role="alert"`,
		"para db-copia falhou",
		`role "lobot_app" does not exist`,
		"O serviço novo db-copia foi removido",
		"Papéis criados sem senha: lobot_app, lobot_system",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("source tab lacks %q", want)
		}
	}
	// The copy shows the restore that created it, where from, and the
	// roles to give a password; not the failure of another copy.
	body = html.UnescapeString(e.do(req{method: "GET", target: "/p/lab/s/db-novo?tab=backups", cookies: []*http.Cookie{c}}).Body.String())
	if !strings.Contains(body, "de lab/db") || !strings.Contains(body, "Papéis criados sem senha: lobot_app, lobot_system") || strings.Contains(body, "db-copia") {
		t.Error("the copy's tab must show the restore that created it")
	}
}
