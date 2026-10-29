package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

func TestRebuildRoute(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleViewer)
	rec := e.do(req{method: "POST", target: "/p/lab/s/web/rebuild", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer rebuilding: %d", rec.Code)
	}
	e2 := newEnv(t)
	id := e2.labService(t)
	c, p = e2.session(t, auth.RoleOperator)
	rec = e2.do(req{method: "POST", target: "/p/lab/s/web/rebuild", form: url.Values{"csrf": {p.CSRFToken}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("rebuild: %d %s", rec.Code, rec.Body)
	}
	e2.pm.Wait()
	deps, _ := e2.pm.Deployments(context.Background(), id, 1)
	if len(deps) == 0 || deps[0].Trigger != "rebuild" {
		t.Fatalf("history: %+v", deps)
	}
}

func TestDeploySettingsValidateFields(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	c, p := e.session(t, auth.RoleAdmin)
	post := func(form url.Values) int {
		form.Set("csrf", p.CSRFToken)
		return e.do(req{method: "POST", target: "/p/lab/s/web/deploy-settings", form: form, cookies: []*http.Cookie{c}}).Code
	}
	settings := func() (string, time.Duration) {
		_, s, err := e.pm.GetService(context.Background(), "lab", "web")
		if err != nil || s.ID != id {
			t.Fatal(err)
		}
		ds := e.pm.GetDeploySettings(s)
		return ds.Validate, ds.ValidateTimeout
	}
	if code := post(url.Values{"validate": {"python manage.py check --deploy"}, "validate_timeout": {"3"}}); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	if v, d := settings(); v != "python manage.py check --deploy" || d != 3*time.Minute {
		t.Errorf("stored: %q %s", v, d)
	}
	// A form without the fields (the old card) keeps them.
	if code := post(url.Values{"predeploy": {"true"}}); code != http.StatusSeeOther {
		t.Fatalf("save: %d", code)
	}
	if v, d := settings(); v != "python manage.py check --deploy" || d != 3*time.Minute {
		t.Errorf("kept: %q %s", v, d)
	}
	if code := post(url.Values{"validate": {"true"}, "validate_timeout": {"999"}}); code == http.StatusSeeOther {
		t.Error("a time limit out of range was accepted")
	}
}

// "Tempo para ligar" sits next to the healthcheck path: minutes, empty for
// the default, kept by a form without it, refused out of range.
func TestDeploySettingsStartupGrace(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	c, p := e.session(t, auth.RoleAdmin)
	post := func(form url.Values) *httptest.ResponseRecorder {
		form.Set("csrf", p.CSRFToken)
		return e.do(req{method: "POST", target: "/p/lab/s/web/deploy-settings", form: form, cookies: []*http.Cookie{c}})
	}
	grace := func() time.Duration {
		_, s, err := e.pm.GetService(context.Background(), "lab", "web")
		if err != nil {
			t.Fatal(err)
		}
		return e.pm.GetDeploySettings(s).StartupGrace
	}
	page := func() string {
		rec := e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("settings page: %d", rec.Code)
		}
		return rec.Body.String()
	}

	body := page()
	for _, want := range []string{
		`name="startup_grace"`, `placeholder="5"`, `max="15"`, "Tempo para ligar",
		"Apps que rodam migrações ou enviam arquivos ao ligar podem precisar de mais tempo.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("deploy card without %q", want)
		}
	}
	if i, j := strings.Index(body, `id="health_path"`), strings.Index(body, `id="startup_grace"`); i < 0 || j < i {
		t.Error("the startup time must sit next to the healthcheck path")
	}

	if rec := post(url.Values{"health_path": {"/health/"}, "startup_grace": {"8"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if got := grace(); got != 8*time.Minute {
		t.Errorf("stored: %s", got)
	}
	if !strings.Contains(page(), `name="startup_grace" type="number" min="1" max="15" step="1" value="8"`) {
		t.Error("the stored value must fill the field")
	}
	// The old card (no field) keeps it.
	if rec := post(url.Values{"health_path": {"/health/"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	if got := grace(); got != 8*time.Minute {
		t.Errorf("kept: %s", got)
	}
	for _, bad := range []string{"0", "16", "abc", "-3"} {
		rec := post(url.Values{"health_path": {"/health/"}, "startup_grace": {bad}})
		if rec.Code == http.StatusSeeOther {
			t.Errorf("accepted %q minutes", bad)
		} else if !strings.Contains(rec.Body.String(), "O tempo para ligar vai de 1 a 15 minutos.") {
			t.Errorf("%q: no message", bad)
		}
	}
	if got := grace(); got != 8*time.Minute {
		t.Errorf("a refused value must keep the stored one: %s", got)
	}
	// Emptied: back to the default.
	if rec := post(url.Values{"health_path": {"/health/"}, "startup_grace": {""}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	if got := grace(); got != 0 {
		t.Errorf("emptied: %s", got)
	}
}
