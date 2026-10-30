package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// postUpload sends the "A partir de um backup" form as a browser does: a
// multipart body whose first field is the CSRF token, then the file.
// lateCSRF puts the token after the name instead (not accepted).
func (e *env) postUpload(t *testing.T, c *http.Cookie, query string, file []byte, bodyCSRF string, lateCSRF ...bool) *httptest.ResponseRecorder {
	t.Helper()
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	late := len(lateCSRF) > 0 && lateCSRF[0]
	if bodyCSRF != "" && !late {
		_ = mw.WriteField("csrf", bodyCSRF)
	}
	_ = mw.WriteField("name", "Cópia")
	if bodyCSRF != "" && late {
		_ = mw.WriteField("csrf", bodyCSRF)
	}
	fw, _ := mw.CreateFormFile("file", "lab.hangar.zip")
	_, _ = fw.Write(file)
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "http://"+testHost+projectRestorePath+query, &mb)
	r.Host = testHost
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// Restoring a project takes an upload past the panel's body limit, with
// sudo and the CSRF token as the form's first field; a restore that cannot start comes
// back to the dialog with the reason (here: no Docker, once the whole file
// was read), and nothing is created.
func TestRestoreProjectUpload(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	big := bytes.Repeat([]byte("x"), 2*maxBodyBytes)
	if rec := e.postUpload(t, c, "", big, p.CSRFToken); rec.Code != http.StatusForbidden {
		t.Fatalf("without sudo: %d", rec.Code)
	}
	sc, sp := e.sudo(t, c, p)
	if rec := e.postUpload(t, sc, "", big, sp.CSRFToken, true); rec.Code != http.StatusForbidden {
		t.Fatalf("a token after other fields must not be looked for (it could sit past the file): %d", rec.Code)
	}
	// SEC-024: the token in the URL leaks into history and logs; refused.
	if rec := e.postUpload(t, sc, "?csrf="+url.QueryEscape(sp.CSRFToken), big, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("the token in the URL must not be accepted: %d", rec.Code)
	}
	rec := e.postUpload(t, sc, "", big, sp.CSRFToken)
	body := rec.Body.String()
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `role="alert"`) || !strings.Contains(body, `id="new-project" aria-labelledby="new-project-title" data-open="true"`) {
		t.Fatalf("a restore that cannot start: %d %s", rec.Code, body)
	}
	if strings.Contains(body, "não é um backup de projeto") {
		t.Fatal("the upload must be read whole, past the panel's body limit")
	}
	if ps, _ := e.pm.ListProjects(context.Background()); len(ps) != 0 {
		t.Fatalf("a refused file created projects: %+v", ps)
	}
	// Other routes keep the panel's body limit.
	if !uploadRoutes["POST "+projectRestorePath] || len(uploadRoutes) != 1 {
		t.Fatalf("upload routes: %v", uploadRoutes)
	}
}

// testMaxUpload is the project backup upload limit of the test panel.
const testMaxUpload = 4 * maxBodyBytes

// SEC-018: an upload over the limit is refused with 413 (the backup
// package checks the staging dir is left empty, also for a file that
// only turns out too large as it streams in).
func TestRestoreProjectUploadLimit(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	sc, sp := e.sudo(t, c, p)
	huge := bytes.Repeat([]byte("x"), testMaxUpload+1)
	rec := e.postUpload(t, sc, "?csrf="+url.QueryEscape(sp.CSRFToken), huge, "")
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "max_restore_upload_gb") {
		t.Fatalf("over the limit: %d", rec.Code)
	}
	if ps, _ := e.pm.ListProjects(context.Background()); len(ps) != 0 {
		t.Fatalf("a refused file created projects: %+v", ps)
	}
}

// Only the listed upload route may take an upload policy.
func TestUploadPolicyOnlyOnUploadRoutes(t *testing.T) {
	rt := newRouter(nil, nil)
	ok := func(http.ResponseWriter, *http.Request) {}
	rt.HandleFunc("POST /elsewhere", ok, Policy{Role: auth.RoleAdmin, Audit: "x", Upload: true})
	if rt.Validate() == nil {
		t.Fatal("an upload policy on another route must refuse to start")
	}
}

// The new-project dialog offers "A partir de um backup"; the project's
// settings offer "Baixar backup do projeto" (behind sudo).
func TestProjectBackupButtons(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	if _, err := e.pm.CreateProject(context.Background(), projects.Actor{UserID: p.UserID}, "lab", "Lab"); err != nil {
		t.Fatal(err)
	}
	home := e.do(req{method: "GET", target: "/?new=1&from=backup", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(home, "A partir de um backup") || !strings.Contains(home, `action="/sudo"`) {
		t.Fatal("the dialog must offer the backup, after confirming the password")
	}
	sc, _ := e.sudo(t, c, p)
	home = e.do(req{method: "GET", target: "/?new=1&from=backup", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(home, `action="/projects/restore" enctype="multipart/form-data" class="flex flex-col gap-4"><input type="hidden" name="csrf"`) {
		t.Fatal("with sudo, the upload form")
	}
	page := e.do(req{method: "GET", target: "/p/lab/settings", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, "Baixar backup do projeto") || !strings.Contains(page, `action="/p/lab/backup"`) {
		t.Fatal("the settings must offer the project's backup")
	}
}
