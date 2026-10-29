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
// multipart body with the file, the CSRF token in the URL.
func (e *env) postUpload(t *testing.T, c *http.Cookie, query string, file []byte, bodyCSRF string) *httptest.ResponseRecorder {
	t.Helper()
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	if bodyCSRF != "" {
		_ = mw.WriteField("csrf", bodyCSRF)
	}
	_ = mw.WriteField("name", "Cópia")
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
// sudo and the CSRF token in the URL; a restore that cannot start comes
// back to the dialog with the reason (here: no Docker, once the whole file
// was read), and nothing is created.
func TestRestoreProjectUpload(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleAdmin)
	big := bytes.Repeat([]byte("x"), 2*maxBodyBytes)
	if rec := e.postUpload(t, c, "?csrf="+url.QueryEscape(p.CSRFToken), big, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("without sudo: %d", rec.Code)
	}
	sc, sp := e.sudo(t, c, p)
	if rec := e.postUpload(t, sc, "", big, sp.CSRFToken); rec.Code != http.StatusForbidden {
		t.Fatalf("the token only in the body must not be read (it would read the whole file): %d", rec.Code)
	}
	rec := e.postUpload(t, sc, "?csrf="+url.QueryEscape(sp.CSRFToken), big, "")
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
	if !strings.Contains(home, `action="/projects/restore?csrf=`) || !strings.Contains(home, `enctype="multipart/form-data"`) {
		t.Fatal("with sudo, the upload form")
	}
	page := e.do(req{method: "GET", target: "/p/lab/settings", cookies: []*http.Cookie{sc}}).Body.String()
	if !strings.Contains(page, "Baixar backup do projeto") || !strings.Contains(page, `action="/p/lab/backup"`) {
		t.Fatal("the settings must offer the project's backup")
	}
}
