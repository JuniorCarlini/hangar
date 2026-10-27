package web

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// The connect dialog proposes the bridge, the save sets the references,
// and a service that offers nothing is refused with a reason.
func TestConnectDialogAndSave(t *testing.T) {
	e := newEnv(t)
	webID := e.labService(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	api, err := e.pm.CreateService(ctx, a, "lab", projects.ServiceInput{Slug: "api", Image: "nginx:1.29-alpine"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateFromTemplate(ctx, a, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.pm.SetEnv(ctx, a, webID, "PGHOST", "localhost", false); err != nil {
		t.Fatal(err)
	}
	c, p := e.session(t, auth.RoleAdmin)
	get := func(target string) string {
		return html.UnescapeString(e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}}).Body.String())
	}
	post := func(target string, form url.Values) int {
		form.Set("csrf", p.CSRFToken)
		return e.do(req{method: "POST", target: target, form: form, cookies: []*http.Cookie{c}}).Code
	}

	body := get("/p/lab/s/web/connect?to=db")
	for _, want := range []string{`name="var_db|HOST" value="PGHOST"`, `name="var_db|DATABASE_URL" value="DATABASE_URL"`, "Já existe com outro valor", `<option value="SECRET_KEY">`} {
		if !strings.Contains(body, want) {
			t.Errorf("dialog lacks %q", want)
		}
	}
	if body := get("/p/lab/s/web/connect?to=api"); !strings.Contains(body, "não oferece nenhum valor") {
		t.Error("connecting to a service that offers nothing is not refused")
	}

	form := url.Values{"to": {"db"}, "key": {"HOST", "DATABASE_URL"}, "var_HOST": {"PGHOST"}, "var_DATABASE_URL": {"DATABASE_URL"}}
	if code := post("/p/lab/s/web/connect", form); code != http.StatusSeeOther {
		t.Fatalf("connect: %d", code)
	}
	tab := get("/p/lab/s/web?tab=variables")
	if !strings.Contains(tab, `title="${{db.HOST}}"`) {
		t.Error("the connected variable is not shown as a connection")
	}
	if db := get("/p/lab/s/db?tab=variables"); !strings.Contains(db, "Usado por: web.") || !strings.Contains(db, "web (DATABASE_URL ← DATABASE_URL), web (PGHOST ← HOST)") {
		t.Error("the database does not list who uses it")
	}

	// Offering a variable of a service made by hand makes it connectable.
	if err := e.pm.SetEnv(ctx, a, api.ID, "API_TOKEN", "tok-123456789", true); err != nil {
		t.Fatal(err)
	}
	if code := post("/p/lab/s/api/env/offer", url.Values{"key": {"API_TOKEN"}, "on": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("offer: %d", code)
	}
	if canvas := get("/p/lab"); !strings.Contains(canvas, `data-exports="API_TOKEN"`) {
		t.Error("the canvas card does not offer the variable")
	}
	if body := get("/p/lab/s/web/connect?to=api"); !strings.Contains(body, `name="var_api|API_TOKEN" value="API_TOKEN"`) {
		t.Error("the offered variable is not proposed")
	}

	// Without ?to= the dialog lists every service that offers something,
	// by name, and one variable cannot take values from two of them.
	all := get("/p/lab/s/web/connect")
	if a, b := strings.Index(all, `value="api|API_TOKEN"`), strings.Index(all, `value="db|HOST"`); a < 0 || b < 0 || a > b {
		t.Errorf("the list is not every offering service in order (api %d, db %d)", a, b)
	}
	dup := url.Values{"key": {"api|API_TOKEN", "db|POSTGRES_PASSWORD"}, "var_api|API_TOKEN": {"SHARED"}, "var_db|POSTGRES_PASSWORD": {"SHARED"}}
	if code := post("/p/lab/s/web/connect", dup); code != http.StatusBadRequest {
		t.Errorf("one variable for two services: %d", code)
	}
	both := url.Values{"key": {"api|API_TOKEN", "db|POSTGRES_PASSWORD"}, "var_api|API_TOKEN": {"UPSTREAM_TOKEN"}, "var_db|POSTGRES_PASSWORD": {"DB_PASS"}}
	if code := post("/p/lab/s/web/connect", both); code != http.StatusSeeOther {
		t.Fatalf("connect two services at once: %d", code)
	}
	tab = get("/p/lab/s/web?tab=variables")
	if !strings.Contains(tab, `title="${{api.API_TOKEN}}"`) || !strings.Contains(tab, `title="${{db.POSTGRES_PASSWORD}}"`) {
		t.Error("connecting two services at once did not set both")
	}

	// The connector writes a service's lines into the .env editor, under
	// the names the app uses, and saving the editor is the whole file: a
	// line taken out is deleted, a secret it could not show stays.
	if !strings.Contains(tab, `id="connector"`) || !strings.Contains(tab, "PGHOST=${{db.HOST}}") {
		t.Error("the connector does not offer the database's lines for the .env")
	}
	file := url.Values{"mode": {"replace"}, "env": {"PGHOST=${{db.HOST}}\nSECRET_KEY=••••\n"}}
	if code := post("/p/lab/s/web/env/bulk", file); code != http.StatusSeeOther {
		t.Fatalf("save the .env: %d", code)
	}
	vals, err := e.pm.ListEnvValues(ctx, webID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, v := range vals {
		got[v.Key] = true
	}
	if !got["PGHOST"] || !got["SECRET_KEY"] || got["UPSTREAM_TOKEN"] || got["DB_PASS"] {
		t.Errorf("after saving the .env: %v", got)
	}
}
