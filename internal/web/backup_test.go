package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// sudo re-confirms the session and returns the new cookie and principal.
func (e *env) sudo(t *testing.T, c *http.Cookie, p *auth.Principal) (*http.Cookie, *auth.Principal) {
	t.Helper()
	e.now = e.now.Add(30 * time.Second)
	rec := e.do(req{method: "POST", target: "/sudo", form: url.Values{"csrf": {p.CSRFToken}, "code": {e.code(t)}, "next": {"/backups"}}, cookies: []*http.Cookie{c}})
	sc := cookie(rec, sessionCookie)
	if sc == nil {
		t.Fatalf("sudo failed: %d", rec.Code)
	}
	sp, _ := e.svc.Authenticate(context.Background(), sc.Value)
	return sc, sp
}

func TestBackupsPageShowsSetupToEveryone(t *testing.T) {
	e := newEnv(t)
	c, _ := e.session(t, auth.RoleViewer)
	rec := e.do(req{method: "GET", target: "/backups", cookies: []*http.Cookie{c}})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Como ligar os backups") || !strings.Contains(body, "O que é salvo e quando") || !strings.Contains(body, "diario/") {
		t.Fatalf("backups page: %d", rec.Code)
	}
	if strings.Contains(body, `href="/backups/kit"`) {
		t.Error("a viewer must not get the kit button")
	}
	if rec := e.do(req{method: "GET", target: "/backups/kit", cookies: []*http.Cookie{c}}); rec.Code != http.StatusForbidden {
		t.Errorf("kit page for a viewer: %d", rec.Code)
	}
}

// The kit flow over HTTP: only the public key and the code hash are
// posted, sudo is required, and the code confirms the key.
func TestKitRegistrationNeedsOwnerSudoAndCode(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleOwner)
	id, _ := age.GenerateX25519Identity()
	code := archive.ConfirmCode(id)
	form := url.Values{"csrf": {p.CSRFToken}, "label": {"Junior"}, "public_key": {id.Recipient().String()}, "code_hash": {archive.CodeHash(code)}}
	if rec := e.do(req{method: "POST", target: "/backups/keys", form: form, cookies: []*http.Cookie{c}}); rec.Code != http.StatusForbidden {
		t.Fatalf("registering a key without sudo: %d", rec.Code)
	}
	sc, sp := e.sudo(t, c, p)
	kit := e.do(req{method: "GET", target: "/backups/kit", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(kit, "/assets/kit.js") || !strings.Contains(kit, "data-kit-generate") || regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]{50,}`).MatchString(kit) {
		t.Fatal("the kit page must generate in the browser, with no key in the HTML")
	}
	form.Set("csrf", sp.CSRFToken)
	if rec := e.do(req{method: "POST", target: "/backups/keys", form: form, cookies: []*http.Cookie{sc}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("registering a key with sudo: %d %s", rec.Code, rec.Body)
	}
	keys, _ := e.bm.Recipients(context.Background())
	if len(keys) != 1 || keys[0].Confirmed {
		t.Fatalf("keys: %+v", keys)
	}
	page := e.do(req{method: "GET", target: "/backups", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, "aguardando confirmação") || !strings.Contains(page, `data-kit-file`) {
		t.Fatal("the pending key must offer the confirmation form")
	}
	rec := e.do(req{method: "POST", target: "/backups/keys/confirm", form: url.Values{"csrf": {sp.CSRFToken}, "id": {keys[0].ID}, "code": {"AAAA-AAAA-AAAA"}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	rec = e.do(req{method: "POST", target: "/backups/keys/confirm", form: url.Values{"csrf": {sp.CSRFToken}, "id": {keys[0].ID}, "code": {code}}, cookies: []*http.Cookie{sc}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("right code: %d", rec.Code)
	}
	if keys, _ := e.bm.Recipients(context.Background()); !keys[0].Confirmed {
		t.Fatal("key not confirmed")
	}
}

func TestBackupRoutesPolicies(t *testing.T) {
	registered := map[string]Policy{}
	rt := newRouter(nil, nil)
	routes(rt, &handlers{})
	for _, r := range rt.Routes() {
		registered[r.Pattern] = r.Policy
	}
	want := map[string]struct {
		role auth.Role
		sudo auth.SudoTier
	}{
		"POST /backups/keys":                            {auth.RoleOwner, auth.SudoCritical},
		"POST /backups/keys/delete":                     {auth.RoleOwner, auth.SudoCritical},
		"POST /backups/targets":                         {auth.RoleOwner, auth.SudoCritical},
		"POST /backups/targets/delete":                  {auth.RoleOwner, auth.SudoCritical},
		"POST /p/{project}/s/{service}/backups/restore": {auth.RoleAdmin, auth.SudoCritical},
		"POST /p/{project}/s/{service}/backup":          {auth.RoleAdmin, auth.SudoCritical},
		"GET /backups/download/{token}":                 {auth.RoleAdmin, auth.SudoCritical},
		"GET /backups/runs/{id}/download":               {auth.RoleAdmin, auth.SudoCritical},
	}
	for pattern, w := range want {
		p, ok := registered[pattern]
		if !ok {
			t.Errorf("%s not registered", pattern)
			continue
		}
		if p.Role != w.role || p.Sudo != w.sudo {
			t.Errorf("%s: role %v sudo %v, want %v %v", pattern, p.Role, p.Sudo, w.role, w.sudo)
		}
	}
}

func TestServiceBackupsTab(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := projects.Actor{UserID: "usr_x"}
	if _, err := e.pm.CreateProject(ctx, a, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateFromTemplate(ctx, a, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	c, p := e.session(t, auth.RoleAdmin)
	body := e.do(req{method: "GET", target: "/p/lab/s/db?tab=backups", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(body, "Backup automático") || !strings.Contains(body, "/p/lab/s/db/backups/policy") {
		t.Fatal("backups tab missing")
	}
	// Without a kit the plain download still works (the existing button).
	if !strings.Contains(body, "Baixar backup") {
		t.Fatal("download button missing")
	}
	// The schedule cannot be turned on before a kit and a destination exist.
	rec := e.do(req{method: "POST", target: "/p/lab/s/db/backups/policy", form: url.Values{"csrf": {p.CSRFToken}, "enabled": {"1"}, "every_hours": {"24"}, "at": {"03:00"}}, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "kit de recuperação") {
		t.Fatalf("policy before the kit: %d", rec.Code)
	}
	// Restore without sudo is refused before anything is read.
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	_ = mw.WriteField("csrf", p.CSRFToken)
	_ = mw.WriteField("mode", "dump")
	fw, _ := mw.CreateFormFile("kit", "hangar-kit.txt")
	_, _ = fw.Write([]byte("AGE-SECRET-KEY-1XXXX"))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/p/lab/s/db/backups/restore", &mb)
	r.Host = testHost
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("restore without sudo: %d", w.Code)
	}
}

func TestParseMoment(t *testing.T) {
	got, err := parseMoment("2026-10-15T14:32", "180") // UTC-3
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 15, 17, 32, 59, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v (the whole minute, in the browser's zone)", got.UTC(), want)
	}
	if _, err := parseMoment("ontem", ""); err == nil {
		t.Fatal("garbage accepted")
	}
	if defaultRestoreName("db") != "db-restaurado" || len(defaultRestoreName(strings.Repeat("a", 32))) > 32 {
		t.Fatal("defaultRestoreName")
	}
}

// A kit confirmed more than KitCheckEvery ago brings a bar to the top of
// every page for the owner, and a "confirm again" form on the key.
func TestOldKitConfirmationAsksAgain(t *testing.T) {
	e := newEnv(t)
	e.createUser(t, auth.RoleOwner)
	session := e.login(t)
	old := time.Now().Add(-backup.KitCheckEvery - time.Hour).Unix()
	if _, err := e.st.DB.Exec(`INSERT INTO backup_recipients (id, label, age_public_key, confirm_hash, confirmed_at, created_at) VALUES ('bkr_1', 'Junior', 'age1qqq', 'x', ?, ?)`, old, old); err != nil {
		t.Fatal(err)
	}
	rec := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{session}})
	if !strings.Contains(rec.Body.String(), i18n.Tl("pt-BR", "backups.kit_check.banner")) {
		t.Fatal("the overview should ask about the kit")
	}
	rec = e.do(req{method: "GET", target: "/backups", cookies: []*http.Cookie{session}})
	body := rec.Body.String()
	if !strings.Contains(body, i18n.Tl("pt-BR", "backups.keys.due")) || !strings.Contains(body, `action="/backups/keys/confirm"`) {
		t.Fatal("the backups page should offer to confirm the key again")
	}
}
