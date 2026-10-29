package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// A whole project's backup (docs/09 "Backup do projeto"): "Baixar backup
// do projeto" in the project's settings, and "A partir de um backup" in
// the new-project dialog, which always restores into a new project.

// projectRestorePath takes the uploaded project backup.
const projectRestorePath = "/projects/restore"

// downloadProjectBackup prepares the project's backup in the background;
// the settings page shows it until the link is ready.
func (h *handlers) downloadProjectBackup(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	if err := h.backups.PrepareProjectDownload(r.Context(), actor(r), slug); err != nil {
		code, msg := userError(r, err)
		h.renderProject(w, r, code, msg)
		return
	}
	redirectLocal(w, r, "/p/"+slug+"/settings?ok=project-backup")
}

// projectBackupView is the project's prepared (or preparing) backup.
func (h *handlers) projectBackupView(ctx context.Context, projectID string) *views.DownloadView {
	dl, ok := h.backups.PendingProjectDownload(PrincipalFrom(ctx).UserID, projectID)
	if !ok {
		return nil
	}
	return &views.DownloadView{
		Token: dl.Token, FileName: dl.FileName, Ready: dl.Ready, Error: dl.Error,
		Size: fmtBytes(ctx, uint64(max(dl.Size, 0))), Expires: dl.Expires.Format("15:04"), //nolint:gosec // sizes are never negative
	}
}

// maxFieldBytes bounds a text field of the upload form.
const maxFieldBytes = 4 << 10

// restoreProject takes an uploaded project backup and restores it into a
// new project. The body is streamed (Policy.Upload): the file goes to the
// staging dir as it arrives, checked against the free disk; the kit is
// read in memory only and handed to the restore, never written anywhere.
func (h *handlers) restoreProject(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Time{}) // a big file takes a while
	var name, pass, file, fileName string
	var kit []byte
	defer func() {
		clear(kit)
		if file != "" {
			// StartProjectRestore owns the file once called; before
			// that, a failed request leaves nothing behind.
			_ = os.Remove(file) //nolint:gosec // a path StageUpload made in the staging dir
		}
	}()
	mr, err := r.MultipartReader()
	if err != nil {
		h.restoreProjectFailed(w, r, name, backup.ErrProjectFile)
		return
	}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			h.restoreProjectFailed(w, r, name, backup.ErrProjectFile)
			return
		}
		switch part.FormName() {
		case "name":
			name, err = readField(part, maxFieldBytes)
		case "passphrase":
			pass, err = readField(part, maxFieldBytes)
		case "kit":
			kit, err = io.ReadAll(io.LimitReader(part, maxKitBytes))
		case "file":
			if file == "" && part.FileName() != "" {
				fileName = part.FileName()
				file, err = h.backups.StageUpload(part, r.ContentLength)
			}
		}
		_ = part.Close()
		if err != nil {
			h.restoreProjectFailed(w, r, name, err)
			return
		}
	}
	if file == "" {
		h.restoreProjectFailed(w, r, name, backup.ErrProjectFile)
		return
	}
	var keys []*age.X25519Identity
	if len(kit) > 0 {
		keys, err = archive.ParseKit(kit, pass)
		switch {
		case errors.Is(err, archive.ErrKitPassphrase):
			h.restoreProjectFailed(w, r, name, i18n.E("backup.error.kit_passphrase"))
			return
		case err != nil:
			h.restoreProjectFailed(w, r, name, i18n.E("backup.error.kit"))
			return
		}
	}
	staged := file
	file = "" // the restore removes it from here on
	slug, err := h.backups.StartProjectRestore(r.Context(), actor(r), backup.ProjectRestoreRequest{
		Name: strings.TrimSpace(name), File: staged, FileName: fileName, Identities: archive.Identities(keys),
	})
	if err != nil {
		h.restoreProjectFailed(w, r, name, err)
		return
	}
	redirectLocal(w, r, "/p/"+slug)
}

// restoreProjectFailed shows the overview again with the dialog open on
// "A partir de um backup" and the reason.
func (h *handlers) restoreProjectFailed(w http.ResponseWriter, r *http.Request, name string, err error) {
	code, msg := userError(r, err)
	n := views.NavFrom(r.Context())
	n.NewProject = views.NewProjectForm{Open: true, Error: msg, Name: name, Backup: true}
	h.renderOverview(w, r.WithContext(views.WithNav(r.Context(), n)), code)
}

func readField(r io.Reader, limit int64) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit))
	return string(b), err
}

// projectRestoreView is the banner of a project made by a restore: while
// it runs, and for a while after it ended, with what it left to decide.
func projectRestoreView(ctx context.Context, r backup.ProjectRestore, now time.Time) *views.ProjectRestoreView {
	if r.Status != "running" && now.Sub(r.FinishedAt) > backup.RestoreAlertFor {
		return nil
	}
	n := r.Notes
	v := &views.ProjectRestoreView{
		Running: r.Status == "running", OK: r.Status == "ok", Source: r.Source, File: r.FileName, Error: r.Error,
		Domains: n.Domains, Public: n.Public, Unlinked: n.Unlinked, NoGit: n.NoGitAccess, NoLogin: n.NoLogin, NotStarted: n.NotStarted,
	}
	step, svc, _ := strings.Cut(r.Step, ":")
	switch step {
	case "verify":
		v.Step = i18n.T(ctx, "projrestore.step.verify")
	case "restore":
		v.Step = i18n.T(ctx, "projrestore.step.restore", "service", svc)
	case "start":
		v.Step = i18n.T(ctx, "projrestore.step.start", "service", svc)
	}
	switch n.Cleanup {
	case backup.CleanupRemoved:
		v.Cleanup = i18n.T(ctx, "projrestore.cleanup_removed")
	case backup.CleanupKept:
		v.Cleanup = i18n.T(ctx, "projrestore.cleanup_kept")
	}
	return v
}
