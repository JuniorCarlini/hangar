package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// SEC-014: a user limited to some projects never sees the names of a
// connected project outside their list: not on the canvas, not in the
// settings' "connected projects", not in "used by", not in the connector.
func TestLimitedUserDoesNotLearnLinkedProjects(t *testing.T) {
	e := newEnv(t)
	c := e.limitedSession(t) // sees lab, not loja
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	web, err := e.pm.CreateService(ctx, a, "lab", projects.ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	vit, err := e.pm.CreateService(ctx, a, "loja", projects.ServiceInput{Slug: "vitrine", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.pm.LinkProjects(ctx, a, "lab", "loja"); err != nil {
		t.Fatal(err)
	}
	// lab/web uses loja/vitrine; loja/vitrine uses lab/web back.
	if err := e.pm.SetEnv(ctx, a, web.ID, "VITRINE_HOST", "${{loja.vitrine.HOST}}", false); err != nil {
		t.Fatal(err)
	}
	if err := e.pm.SetEnv(ctx, a, vit.ID, "WEB_HOST", "${{lab.web.HOST}}", false); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/p/lab", "/p/lab/settings", "/p/lab/s/web?tab=variables", "/p/lab/s/web/connect"} {
		body := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}}).Body.String()
		if strings.Contains(body, ">loja<") || strings.Contains(body, "loja/vitrine") || strings.Contains(body, `data-project="loja"`) ||
			strings.Contains(body, "loja.vitrine\"") || strings.Contains(body, ">vitrine<") {
			t.Errorf("%s names the hidden project", target)
		}
	}
	if rec := e.do(req{method: "GET", target: "/p/lab/s/web/connect?to=loja.vitrine", cookies: []*http.Cookie{c}}); rec.Code != http.StatusNotFound {
		t.Errorf("the connector for a hidden project's service: %d", rec.Code)
	}
}

// SEC-013/015: the live logs mask the same secrets as the deploy log, for
// every role: an app that prints its environment gives nothing away.
func TestLiveLogsMaskSecrets(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	ctx := context.Background()
	if err := e.pm.SetEnv(ctx, projects.Actor{UserID: "usr_x"}, id, "API_TOKEN", "tok-sem-marca-998877", false); err != nil {
		t.Fatal(err)
	}
	e.node.logs = []node.LogLine{{Stream: "stdout", Time: time.Now(), Text: "SECRET_KEY=valor-super-secreto-42 API_TOKEN=tok-sem-marca-998877"}}
	c, _ := e.session(t, auth.RoleViewer)
	body := e.do(req{method: "GET", target: "/p/lab/s/web/logs", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(body, "valor-super-secreto-42") || strings.Contains(body, "tok-sem-marca-998877") || !strings.Contains(body, "SECRET_KEY=••••") {
		t.Errorf("live logs: %s", body)
	}
}

// SEC-024: the .env's comments reach the page only from admin up.
func TestEnvCommentsMaskedBelowAdmin(t *testing.T) {
	for role, visible := range map[auth.Role]bool{auth.RoleOperator: false, auth.RoleViewer: false, auth.RoleAdmin: true} {
		e := newEnv(t)
		id := e.labService(t)
		if _, err := e.pm.SetEnvFile(context.Background(), projects.Actor{UserID: "usr_x"}, id, "# senha velha: hunter2-velha\nDEBUG=1\n"); err != nil {
			t.Fatal(err)
		}
		e.optional2FA(t)
		c, _ := e.session(t, role)
		body := e.do(req{method: "GET", target: "/p/lab/s/web?tab=variables", cookies: []*http.Cookie{c}}).Body.String()
		if strings.Contains(body, "hunter2-velha") != visible {
			t.Errorf("%s: comment visible = %v, want %v", role, !visible, visible)
		}
	}
}
