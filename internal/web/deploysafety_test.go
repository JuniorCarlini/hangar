package web

import (
	"context"
	"net/http"
	"net/url"
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
