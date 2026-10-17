package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// Backups (docs/09): overview, recovery kit, destinations, service tab,
// downloads and restores.

const backupTime = "02/01 15:04"

// --- overview ---------------------------------------------------------------

func (h *handlers) backupsPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch ok := r.URL.Query().Get("ok"); ok {
	case "key-added", "key-confirmed", "key-deleted", "target-added", "target-checked", "target-deleted", "panel-queued":
		flash = i18n.T(r.Context(), "flash.backups."+ok)
	}
	h.renderBackups(w, r, http.StatusOK, "", flash)
}

func (h *handlers) renderBackups(w http.ResponseWriter, r *http.Request, status int, errMsg, flash string) {
	ctx := r.Context()
	pr := PrincipalFrom(ctx)
	d := views.BackupsData{
		CSRF: pr.CSRFToken, CanOperate: pr.Role >= auth.RoleOperator, CanAdmin: pr.Role >= auth.RoleAdmin,
		CanOwner: pr.Role >= auth.RoleOwner, SudoActive: time.Now().Before(pr.SudoUntil), Error: errMsg, Flash: flash,
	}
	o, err := h.backups.Overview(ctx)
	if err != nil {
		code, msg := userError(r, err)
		status, d.Error = code, msg
	}
	d.Ready = o.Ready
	for _, k := range o.Recipients {
		d.Keys = append(d.Keys, views.BackupKeyRow{ID: k.ID, Label: k.Label, Public: k.PublicKey, Confirmed: k.Confirmed, Created: k.CreatedAt.Format(backupTime)})
	}
	for _, t := range o.Targets {
		row := views.BackupTargetRow{
			ID: t.ID, Name: t.Name, Provider: t.Provider, Where: t.Endpoint + "/" + t.Bucket + "/" + t.Prefix,
			Lock:  i18n.T(ctx, "backups.targets.lock_value", "mode", lockModeLabel(ctx, t.LockMode), "days", t.LockDays),
			Error: t.CheckError, Primary: t.Primary,
		}
		if !t.CheckedAt.IsZero() {
			row.Checked = i18n.T(ctx, "backups.targets.checked", "when", t.CheckedAt.Format(backupTime))
		}
		d.Targets = append(d.Targets, row)
	}
	now := time.Now()
	for _, s := range o.Services {
		d.Services = append(d.Services, h.backupRow(ctx, s, now, servicePath(s.Project, s.Service)+"?tab=backups"))
	}
	d.Panel = h.backupRow(ctx, o.Panel, now, "")
	for _, run := range o.Runs {
		d.Runs = append(d.Runs, runRow(ctx, run))
	}
	for _, f := range archive.Folders {
		d.Folders = append(d.Folders, views.BackupFolder{Folder: f, Days: archive.DefaultRetentionDays[f], What: i18n.T(ctx, "backups.rules.folders."+f)})
	}
	d.Status = "ok"
	switch {
	case !o.Ready:
		d.Status = "setup"
	case len(o.Alerts) > 0:
		d.Status = "warning"
	}
	for _, a := range o.Alerts {
		if a.Kind == backup.AlertNoKit || a.Kind == backup.AlertNoTarget {
			continue
		}
		tone := "warning"
		if a.Kind == backup.AlertStale || a.Kind == backup.AlertFailed || a.Kind == backup.AlertWALLag || a.Kind == backup.AlertWALFailing || a.Kind == backup.AlertTargetError {
			tone, d.Status = "danger", "danger"
		}
		d.Alerts = append(d.Alerts, views.BackupAlert{Tone: tone, Text: alertText(ctx, a)})
	}
	render(w, r, status, views.Backups(d))
}

func lockModeLabel(ctx context.Context, mode string) string {
	if mode == s3.Governance {
		return i18n.T(ctx, "target.lock_governance")
	}
	return i18n.T(ctx, "target.lock_compliance")
}

func alertText(ctx context.Context, a backup.Alert) string {
	label := a.Label
	if label == backup.PanelLabel {
		label = i18n.T(ctx, "backups.services.panel")
	}
	switch a.Kind {
	case backup.AlertSize:
		return i18n.T(ctx, "backups.alert.size", "label", label, "change", i18n.T(ctx, "backups.warning."+a.Info))
	case backup.AlertTargetError, backup.AlertFailed, backup.AlertWALLag:
		return i18n.T(ctx, "backups.alert."+a.Kind, "label", label, "error", a.Info)
	}
	return i18n.T(ctx, "backups.alert."+a.Kind, "label", label)
}

// backupRow is one line of the services table.
func (h *handlers) backupRow(ctx context.Context, s backup.Row, now time.Time, href string) views.BackupServiceRow {
	row := views.BackupServiceRow{Label: s.Label, Href: href, Schedule: scheduleText(ctx, s.Policy, s.HasPolicy)}
	if s.Last != nil {
		row.HasRun = true
		row.Last = ago(ctx, s.Last.Started.Format(time.RFC3339Nano), now)
		row.LastTone = "success"
		switch s.Last.Status {
		case "failed":
			row.LastTone, row.Last = "danger", i18n.T(ctx, "backups.services.failed_at", "when", row.Last)
		case "running":
			row.LastTone, row.Last = "info", i18n.T(ctx, "backups.status_running")
		}
	}
	if s.LastOK != nil {
		row.Size = fmtBytes(ctx, uint64(max(s.LastOK.Size, 0))) //nolint:gosec // sizes are never negative
		row.Tested = s.LastOK.Verified
	}
	if s.Policy.WAL {
		row.WAL, row.WALTone = walText(ctx, s.WAL, now)
	}
	return row
}

func scheduleText(ctx context.Context, p backup.Policy, has bool) string {
	if !has || !p.Enabled {
		return i18n.T(ctx, "backups.services.off")
	}
	return i18n.T(ctx, "backups.services.every", "n", p.EveryHours, "at", fmt.Sprintf("%02d:%02d", p.AtMinute/60, p.AtMinute%60))
}

func walText(ctx context.Context, w *backup.WALState, now time.Time) (string, string) {
	switch {
	case w == nil:
		return i18n.T(ctx, "backups.wal.waiting"), "info"
	case w.Error == backup.WALRestartNeeded:
		return i18n.T(ctx, "backups.wal.restart"), "warning"
	case w.Error == backup.WALArchiveFails:
		return i18n.T(ctx, "backups.wal.failing"), "danger"
	case w.Lagging(now):
		return i18n.T(ctx, "backups.wal.late", "n", w.Pending), "danger"
	case w.LastAt.IsZero():
		return i18n.T(ctx, "backups.wal.waiting"), "info"
	}
	return ago(ctx, w.LastAt.Format(time.RFC3339Nano), now), "success"
}

func runRow(ctx context.Context, r backup.Run) views.BackupRunRow {
	row := views.BackupRunRow{
		ID: r.ID, When: r.Started.Format(backupTime), Label: r.Label, Kind: i18n.T(ctx, "backups.kind."+r.Kind),
		Trigger: i18n.T(ctx, "backups.trigger."+r.Trigger), Verified: r.Verified, Error: r.Error,
		CanLink: r.Status == "ok" && r.Key != "",
	}
	if r.Label == backup.PanelLabel {
		row.Label = i18n.T(ctx, "backups.services.panel")
	}
	if r.Class != "" {
		row.Class = i18n.T(ctx, "backups.class."+r.Class)
	}
	if r.Size > 0 {
		row.Size = fmtBytes(ctx, uint64(r.Size)) //nolint:gosec // sizes are never negative
	}
	if r.Kind == archive.KindDump && r.Verified {
		row.Checked = i18n.T(ctx, "backups.history.counts", "tables", r.Tables, "rows", r.Rows)
	}
	row.Status, row.Tone = i18n.T(ctx, "backups.run_status."+r.Status), map[string]string{"ok": "success", "failed": "danger", "running": "info"}[r.Status]
	if r.Warning != "" {
		row.Warning = i18n.T(ctx, "backups.warning."+r.Warning)
	}
	var names []string
	for _, u := range r.UploadList() {
		mark := "✓"
		if !u.OK {
			mark = "✗"
		}
		names = append(names, u.Target+" "+mark)
	}
	row.Uploads = strings.Join(names, " · ")
	return row
}

func (h *handlers) backupsDone(w http.ResponseWriter, r *http.Request, ok string, err error) {
	if err != nil {
		code, msg := userError(r, err)
		h.renderBackups(w, r, code, msg, "")
		return
	}
	redirectLocal(w, r, "/backups?ok="+ok)
}

func (h *handlers) backupPanelNow(w http.ResponseWriter, r *http.Request) {
	h.backupsDone(w, r, "panel-queued", h.backups.Enqueue(r.Context(), actor(r), "", ""))
}

// --- recovery kit -------------------------------------------------------------

func (h *handlers) kitPage(w http.ResponseWriter, r *http.Request) {
	h.renderKit(w, r, http.StatusOK, "")
}

func (h *handlers) renderKit(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	pr := PrincipalFrom(r.Context())
	label := i18n.T(r.Context(), "kit.default_label")
	if keys, err := h.backups.Recipients(r.Context()); err == nil && len(keys) > 0 {
		label = i18n.T(r.Context(), "kit.spare_label")
	}
	render(w, r, status, views.BackupKit(views.KitData{
		CSRF: pr.CSRFToken, SudoActive: time.Now().Before(pr.SudoUntil), DefaultLabel: label,
		Template: i18n.T(r.Context(), "kit.file_text"), Error: errMsg,
	}))
}

// addKey stores a kit's public key. The form never carries the private
// key: kit.js keeps it in the page.
func (h *handlers) addKey(w http.ResponseWriter, r *http.Request) {
	_, err := h.backups.AddRecipient(r.Context(), actor(r), strings.TrimSpace(r.PostFormValue("label")),
		strings.TrimSpace(r.PostFormValue("public_key")), strings.TrimSpace(r.PostFormValue("code_hash")))
	if err != nil {
		code, msg := userError(r, err)
		h.renderKit(w, r, code, msg)
		return
	}
	redirectLocal(w, r, "/backups?ok=key-added#kit-app")
}

func (h *handlers) confirmKey(w http.ResponseWriter, r *http.Request) {
	h.backupsDone(w, r, "key-confirmed", h.backups.ConfirmRecipient(r.Context(), actor(r), r.PostFormValue("id"), r.PostFormValue("code")))
}

func (h *handlers) deleteKey(w http.ResponseWriter, r *http.Request) {
	h.backupsDone(w, r, "key-deleted", h.backups.DeleteRecipient(r.Context(), actor(r), r.PostFormValue("id")))
}

// --- destinations -------------------------------------------------------------

func (h *handlers) targetPage(w http.ResponseWriter, r *http.Request) {
	h.renderTarget(w, r, http.StatusOK, "", views.TargetFormData{Provider: "b2", LockMode: s3.Compliance, LockDays: "30", PathStyle: true})
}

func (h *handlers) renderTarget(w http.ResponseWriter, r *http.Request, status int, errMsg string, d views.TargetFormData) {
	pr := PrincipalFrom(r.Context())
	d.CSRF, d.SudoActive, d.Error, d.Providers = pr.CSRFToken, time.Now().Before(pr.SudoUntil), errMsg, backup.Providers
	render(w, r, status, views.BackupTargetForm(d))
}

func (h *handlers) addTarget(w http.ResponseWriter, r *http.Request) {
	f := views.TargetFormData{
		Name: r.PostFormValue("name"), Provider: r.PostFormValue("provider"), Endpoint: r.PostFormValue("endpoint"),
		Region: r.PostFormValue("region"), Bucket: r.PostFormValue("bucket"), Prefix: r.PostFormValue("prefix"),
		LockMode: r.PostFormValue("lock_mode"), LockDays: r.PostFormValue("lock_days"), PathStyle: r.PostFormValue("path_style") == "1",
	}
	days, err := strconv.Atoi(strings.TrimSpace(f.LockDays))
	if err != nil {
		h.renderTarget(w, r, http.StatusUnprocessableEntity, i18n.T(r.Context(), "backup.error.lock_days"), f)
		return
	}
	_, err = h.backups.AddTarget(r.Context(), actor(r), backup.TargetInput{
		Name: f.Name, Provider: f.Provider, LockMode: f.LockMode, LockDays: days,
		Config: backup.TargetConfig{
			Endpoint: f.Endpoint, Region: f.Region, Bucket: f.Bucket, Prefix: f.Prefix, PathStyle: f.PathStyle,
			AccessKey: r.PostFormValue("access_key"), SecretKey: r.PostFormValue("secret_key"),
		},
	})
	if err != nil {
		code, msg := userError(r, err)
		h.renderTarget(w, r, code, msg, f)
		return
	}
	redirectLocal(w, r, "/backups?ok=target-added")
}

func (h *handlers) checkTarget(w http.ResponseWriter, r *http.Request) {
	h.backupsDone(w, r, "target-checked", h.backups.CheckTarget(r.Context(), actor(r), r.PostFormValue("id")))
}

func (h *handlers) deleteTarget(w http.ResponseWriter, r *http.Request) {
	h.backupsDone(w, r, "target-deleted", h.backups.DeleteTarget(r.Context(), actor(r), r.PostFormValue("id")))
}

// --- service tab ----------------------------------------------------------------

// serviceBackups fills the service's Backups tab.
func (h *handlers) serviceBackups(r *http.Request, p dbq.Project, s dbq.Service) views.ServiceBackups {
	ctx := r.Context()
	b := views.ServiceBackups{Supported: h.projects.CanDownloadBackup(s.Template)}
	if !b.Supported {
		return b
	}
	now := time.Now()
	b.Ready = h.backups.Ready(ctx)
	if keys, err := h.backups.Recipients(ctx); err == nil {
		for _, k := range keys {
			b.HasKit = b.HasKit || k.Confirmed
		}
	}
	pol, has := h.backups.ServicePolicy(ctx, s.ID)
	b.Enabled, b.EveryHours, b.WAL = has && pol.Enabled, pol.EveryHours, has && pol.WAL
	b.AtTime = fmt.Sprintf("%02d:%02d", pol.AtMinute/60, pol.AtMinute%60)
	if b.Enabled {
		b.NextRun = pol.NextRun.Format(backupTime)
	}
	b.WALSupported = true
	if b.WAL {
		b.WALState, b.WALTone = walText(ctx, h.backups.ServiceWAL(ctx, s.ID), now)
	}
	if b.Ready {
		if win := h.backups.Window(ctx, p.Slug, s.Slug); win.OK {
			b.WindowOK = true
			b.Window = i18n.T(ctx, "svcbackup.window", "from", win.From.Format(backupTime), "to", win.To.Format(backupTime))
		}
		if dumps, err := h.backups.Dumps(ctx, p.Slug, s.Slug); err == nil {
			for i, o := range dumps {
				if i >= 60 {
					break
				}
				ob, _ := archive.ParseKey(o.Key)
				b.Dumps = append(b.Dumps, views.DumpChoice{Key: o.Key, Label: i18n.T(ctx, "svcbackup.dump_label",
					"when", o.LastModified.Local().Format("02/01/2006 15:04"), "class", i18n.T(ctx, "backups.class."+ob.Class), "size", fmtBytes(ctx, uint64(max(o.Size, 0))))}) //nolint:gosec // sizes are never negative
			}
		}
	}
	b.MaxAt = now.Format("2006-01-02T15:04")
	b.DefaultNew = defaultRestoreName(s.Slug)
	pr := PrincipalFrom(ctx)
	if dl, ok := h.backups.PendingDownload(pr.UserID, s.ID); ok {
		b.Download = &views.DownloadView{
			Token: dl.Token, FileName: dl.FileName, Ready: dl.Ready, Error: dl.Error,
			Size: fmtBytes(ctx, uint64(max(dl.Size, 0))), Expires: dl.Expires.Format("15:04"),
		} //nolint:gosec // sizes are never negative
		b.Busy = !dl.Ready && dl.Error == ""
	}
	if runs, err := h.backups.ServiceRuns(ctx, s.ID, 15); err == nil {
		for _, run := range runs {
			if run.Kind == archive.KindBase && run.Status == "ok" && b.LastBase == "" {
				b.LastBase = run.Started.Format(backupTime)
			}
			b.Runs = append(b.Runs, runRow(ctx, run))
			b.Busy = b.Busy || run.Status == "running"
		}
	}
	if rs, err := h.backups.Restores(ctx, s.ID, 10); err == nil {
		for _, x := range rs {
			row := views.RestoreRow{
				When: x.StartedAt.Format(backupTime), Status: i18n.T(ctx, "backups.run_status."+x.Status), Error: x.Error,
				Tone: map[string]string{"ok": "success", "failed": "danger", "running": "info"}[x.Status],
			}
			if x.Mode == backup.ModePITR {
				if at, err := time.Parse(time.RFC3339, x.Point); err == nil {
					row.What = i18n.T(ctx, "svcbackup.restore_to", "when", at.Local().Format("02/01/2006 15:04:05"))
				}
			} else {
				row.What = i18n.T(ctx, "svcbackup.restore_from_dump")
			}
			row.Dest = s.Slug
			if x.Destination == backup.DestNew {
				row.Dest = x.NewService
			}
			if x.Status == "running" && x.Step != "" {
				row.Step = i18n.T(ctx, "svcbackup.step."+x.Step)
				b.Busy = true
			}
			b.Restores = append(b.Restores, row)
		}
	}
	return b
}

// defaultRestoreName is "<service>-restaurado", shortened to stay a valid
// service name.
func defaultRestoreName(slug string) string {
	const suffix = "-restaurado"
	if len(slug)+len(suffix) > 32 {
		slug = strings.TrimRight(slug[:32-len(suffix)], "-")
	}
	return slug + suffix
}

func (h *handlers) setBackupPolicy(w http.ResponseWriter, r *http.Request) {
	in := backup.PolicyInput{Enabled: r.PostFormValue("enabled") == "1", WAL: r.PostFormValue("wal") == "1"}
	var err error
	if in.EveryHours, err = strconv.Atoi(r.PostFormValue("every_hours")); err == nil {
		var at time.Time
		if at, err = time.Parse("15:04", r.PostFormValue("at")); err == nil {
			in.AtMinute = at.Hour()*60 + at.Minute()
		}
	}
	if err != nil {
		h.renderService(w, r, serviceView{status: http.StatusUnprocessableEntity, errMsg: i18n.T(r.Context(), "backup.error.schedule")})
		return
	}
	if err := h.backups.SetServicePolicy(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service"), in); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=backup-policy")
}

func (h *handlers) runBackupNow(w http.ResponseWriter, r *http.Request) {
	if err := h.backups.Enqueue(r.Context(), actor(r), r.PathValue("project"), r.PathValue("service")); err != nil {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=backup-queued")
}

// maxKitBytes bounds the uploaded kit (a few hundred bytes in practice).
const maxKitBytes = 64 << 10

// restoreBackup starts a restore. The kit arrives in this request only; it
// is parsed in memory (the multipart form stays in memory under the body
// limit) and handed to the restore, never written anywhere.
func (h *handlers) restoreBackup(w http.ResponseWriter, r *http.Request) {
	fail := func(err error) {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseMultipartForm(maxBodyBytes); err != nil { //nolint:gosec // the body is capped right above (and by limitBody)
		fail(i18n.E("backup.error.kit"))
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	file, _, err := r.FormFile("kit")
	if err != nil {
		fail(i18n.E("backup.error.kit"))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxKitBytes))
	_ = file.Close()
	if err != nil {
		fail(i18n.E("backup.error.kit"))
		return
	}
	keys, err := archive.ParseKit(raw, r.PostFormValue("passphrase"))
	clear(raw)
	switch {
	case errors.Is(err, archive.ErrKitPassphrase):
		fail(i18n.E("backup.error.kit_passphrase"))
		return
	case err != nil:
		fail(i18n.E("backup.error.kit"))
		return
	}
	req := backup.RestoreRequest{
		Project: r.PathValue("project"), Service: r.PathValue("service"), Mode: r.PostFormValue("mode"),
		Key: r.PostFormValue("key"), Destination: r.PostFormValue("destination"),
		NewService: strings.TrimSpace(r.PostFormValue("new_service")), Confirm: r.PostFormValue("confirm"),
		Identities: archive.Identities(keys),
	}
	if req.Mode == backup.ModePITR {
		if req.At, err = parseMoment(r.PostFormValue("at"), r.PostFormValue("tz_offset")); err != nil {
			fail(i18n.E("backup.error.when"))
			return
		}
	}
	if _, err := h.backups.StartRestore(r.Context(), actor(r), req); err != nil {
		fail(err)
		return
	}
	redirectLocal(w, r, h.serviceBase(r)+"?ok=restore-started")
}

// parseMoment reads the datepicker's "2026-10-15T14:32" in the browser's
// time zone (tz_offset, from getTimezoneOffset: minutes behind UTC), or
// the server's when the browser did not say.
func parseMoment(v, offset string) (time.Time, error) {
	loc := time.Local
	if off, err := strconv.Atoi(strings.TrimSpace(offset)); err == nil && off >= -14*60 && off <= 14*60 {
		loc = time.FixedZone("", -off*60)
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "02/01/2006 15:04"} {
		if t, err := time.ParseInLocation(layout, strings.TrimSpace(v), loc); err == nil {
			// The whole chosen minute is kept (14:32 means up to 14:32:59).
			if layout != "2006-01-02T15:04:05" {
				t = t.Add(59 * time.Second)
			}
			return t, nil
		}
	}
	return time.Time{}, errors.New("invalid moment")
}

// downloadBackup is "Baixar backup agora". With a recovery kit, the dump is
// tested and encrypted in the background and offered as a single-use link
// (docs/09); before a kit exists, it streams the plain dump as before.
func (h *handlers) downloadBackup(w http.ResponseWriter, r *http.Request) {
	p, s, err := h.projects.GetService(r.Context(), r.PathValue("project"), r.PathValue("service"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !h.projects.CanDownloadBackup(s.Template) {
		h.renderService(w, r, serviceView{status: http.StatusUnprocessableEntity, errMsg: i18n.T(r.Context(), "backup.error.unsupported")})
		return
	}
	if st, err := h.projects.Status(r.Context(), p.Slug, s.Slug); err != nil || !st.Running {
		h.renderService(w, r, serviceView{status: http.StatusConflict, errMsg: i18n.T(r.Context(), "backup.error.not_running")})
		return
	}
	if err := h.backups.PrepareDownload(r.Context(), actor(r), p.Slug, s.Slug); err == nil {
		redirectLocal(w, r, h.serviceBase(r)+"?ok=backup-preparing")
		return
	} else if !errors.Is(err, backup.ErrNotReady) {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // a big database takes a while
	name := fmt.Sprintf("%s_%s-%s.dump", p.Slug, s.Slug, time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if err := h.projects.DownloadBackup(r.Context(), actor(r), p.Slug, s.Slug, w); err != nil {
		// Headers are gone: the download ends short and the browser shows it
		// as failed. The cause is in the log and the audit.
		loggerFrom(r.Context()).Error("backup download", "service", p.Slug+"/"+s.Slug, "error", err)
	}
}

// takeDownload serves a prepared encrypted dump once.
func (h *handlers) takeDownload(w http.ResponseWriter, r *http.Request) {
	f, name, done, err := h.backups.TakeDownload(r.Context(), actor(r), r.PathValue("token"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer done()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if _, err := io.Copy(w, f); err != nil {
		loggerFrom(r.Context()).Error("backup download", "error", err)
	}
}

// runDownload sends the browser to a short-lived signed link in the
// bucket.
func (h *handlers) runDownload(w http.ResponseWriter, r *http.Request) {
	u, err := h.backups.RunDownloadURL(r.Context(), actor(r), r.PathValue("id"))
	if err != nil {
		code, msg := userError(r, err)
		h.renderBackups(w, r, code, msg, "")
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther) //nolint:gosec // a link this panel just signed for its own bucket
}
