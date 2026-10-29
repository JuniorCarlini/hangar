package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/keyset"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// Backups (docs/09): overview, recovery kit, destinations, service tab,
// downloads and restores.

const backupTime = "02/01 15:04"

// --- overview ---------------------------------------------------------------

// The backup history pages by keyset (docs/20).
const (
	runsParam          = "runs"
	runsPerPage        = 50
	serviceRunsPerPage = 20
)

func (h *handlers) backupsPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	switch ok := r.URL.Query().Get("ok"); ok {
	case "key-added", "key-confirmed", "key-deleted", "target-added", "target-checked", "target-deleted", "panel-queued", "mode":
		flash = i18n.T(r.Context(), "flash.backups."+ok)
	}
	h.renderBackups(w, r, http.StatusOK, "", flash)
}

// backupsTab is the overview's tab: the kit and the destinations live in
// "config", and what was done there comes back to it.
func backupsTab(r *http.Request) string {
	ok := r.URL.Query().Get("ok")
	if r.URL.Query().Get("tab") == "config" || strings.HasPrefix(ok, "key-") || strings.HasPrefix(ok, "target-") || ok == "mode" ||
		strings.HasPrefix(r.URL.Path, "/backups/keys") || strings.HasPrefix(r.URL.Path, "/backups/targets") ||
		r.URL.Path == "/backups/mode" || r.URL.Path == "/backups/server-key" {
		return "config"
	}
	return ""
}

// setBackupMode switches between the simple mode and the recovery kit.
func (h *handlers) setBackupMode(w http.ResponseWriter, r *http.Request) {
	if err := h.backups.SetMode(r.Context(), actor(r), r.PostFormValue("mode")); err != nil {
		code, msg := userError(r, err)
		h.renderBackups(w, r, code, msg, "")
		return
	}
	redirectLocal(w, r, "/backups?tab=config&ok=mode")
}

// revealServerKey shows the simple mode's key once, on this response only.
func (h *handlers) revealServerKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.backups.ServerKey(r.Context(), actor(r))
	if err != nil {
		code, msg := userError(r, err)
		h.renderBackups(w, r, code, msg, "")
		return
	}
	h.renderBackupsWith(w, r, http.StatusOK, "", "", key)
}

func (h *handlers) renderBackups(w http.ResponseWriter, r *http.Request, status int, errMsg, flash string) {
	h.renderBackupsWith(w, r, status, errMsg, flash, "")
}

func (h *handlers) renderBackupsWith(w http.ResponseWriter, r *http.Request, status int, errMsg, flash, serverKey string) {
	ctx := r.Context()
	pr := PrincipalFrom(ctx)
	d := views.BackupsData{
		CSRF: pr.CSRFToken, CanOperate: pr.Role >= auth.RoleOperator, CanAdmin: pr.Role >= auth.RoleAdmin,
		CanOwner: pr.Role >= auth.RoleOwner, SudoActive: pr.SudoFor(auth.SudoCritical, time.Now()), Error: errMsg, Flash: flash,
		PanelQueued: h.backups.Queued(""), Tab: backupsTab(r), ServerKey: serverKey,
	}
	o, err := h.backups.Overview(ctx)
	if err != nil {
		code, msg := userError(r, err)
		status, d.Error = code, msg
	}
	d.Ready, d.Simple = o.Ready, o.Mode == backup.ModeSimple
	for _, k := range o.Recipients {
		d.Keys = append(d.Keys, views.BackupKeyRow{ID: k.ID, Label: k.Label, Public: k.PublicKey, Confirmed: k.Confirmed, Due: k.CheckDue(time.Now()), Created: k.CreatedAt.Format(backupTime)})
	}
	for _, t := range o.Targets {
		row := views.BackupTargetRow{
			ID: t.ID, Name: t.Name, Provider: t.Provider,
			Where: targetWhere(t.Endpoint, t.Bucket, t.Prefix), WhereFull: t.Endpoint + "/" + t.Bucket + "/" + t.Prefix,
			Lock:     i18n.T(ctx, "backups.targets.lock_value", "mode", lockModeName(t.LockMode), "days", t.LockDays),
			LockHint: lockModeLabel(ctx, t.LockMode),
			Error:    t.CheckError, Primary: t.Primary,
		}
		if !t.CheckedAt.IsZero() {
			row.Checked = t.CheckedAt.Format(backupTime)
			row.CheckedHint = i18n.T(ctx, "backups.targets.checked", "when", row.Checked)
		}
		d.Targets = append(d.Targets, row)
	}
	now := time.Now()
	for _, s := range o.Services {
		d.Services = append(d.Services, h.backupRow(ctx, s, now, servicePath(s.Project, s.Service)+"?tab=backups"))
	}
	d.Panel = h.backupRow(ctx, o.Panel, now, "")
	if page, err := h.backups.RunsPage(ctx, "", keyset.Parse(r.URL.Query().Get(runsParam)), runsPerPage); err == nil {
		for _, run := range page.Rows {
			d.Runs = append(d.Runs, runRow(ctx, run))
		}
		d.RunsPage = views.NewCursor("/backups", r.URL.Query(), runsParam, page.Older, page.Newer, "history")
	}
	for _, f := range archive.Folders {
		d.Folders = append(d.Folders, views.BackupFolder{Folder: f, Days: archive.DefaultRetentionDays[f], What: i18n.T(ctx, "backups.rules.folders."+f)})
	}
	for _, a := range o.Alerts {
		if a.Kind == backup.AlertNoKit || a.Kind == backup.AlertNoTarget {
			continue
		}
		tone := "warning"
		if a.Kind == backup.AlertStale || a.Kind == backup.AlertFailed || a.Kind == backup.AlertWALLag || a.Kind == backup.AlertWALFailing || a.Kind == backup.AlertTargetError || a.Kind == backup.AlertRestore {
			tone = "danger"
		}
		d.Alerts = append(d.Alerts, views.BackupAlert{Tone: tone, Text: alertText(ctx, a)})
	}
	render(w, r, status, views.Backups(d))
}

// targetWhere is a destination's place, short: the endpoint's host and
// the bucket (and folder), "s3.us-east-005.backblazeb2.com / hangar-backups".
func targetWhere(endpoint, bucket, prefix string) string {
	host := endpoint
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		host = u.Host
	}
	out := host + " / " + bucket
	if p := strings.Trim(prefix, "/"); p != "" {
		out += "/" + p
	}
	return out
}

// lockModeName is the Object Lock mode's own name ("Compliance").
func lockModeName(mode string) string {
	if mode == s3.Governance {
		return "Governance"
	}
	return "Compliance"
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
	case backup.AlertTargetError, backup.AlertFailed, backup.AlertWALLag, backup.AlertRestore:
		return i18n.T(ctx, "backups.alert."+a.Kind, "label", label, "error", a.Info)
	}
	return i18n.T(ctx, "backups.alert."+a.Kind, "label", label)
}

// backupRow is one line of the services table.
func (h *handlers) backupRow(ctx context.Context, s backup.Row, now time.Time, href string) views.BackupServiceRow {
	row := views.BackupServiceRow{Label: s.Label, Href: href, Schedule: scheduleText(ctx, s.Policy, s.HasPolicy), Covered: s.Covered()}
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
	// The panel's backup holds the master key: only an owner may download it
	// (backup.Manager.OpenRun refuses the rest).
	if r.Kind == archive.KindPanel {
		if p := PrincipalFrom(ctx); p == nil || p.Role < auth.RoleOwner {
			row.CanLink = false
		}
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
	if r.Kind == archive.KindVolume && r.Verified {
		row.Checked = i18n.T(ctx, "backups.history.files", "n", r.Files)
		if r.PauseMS > 0 {
			secs := fmt.Sprintf("%.1f", float64(r.PauseMS)/1000)
			if r.Held == backup.ConsistencyStop {
				row.Checked += " · " + i18n.T(ctx, "backups.history.stopped", "seconds", secs)
			} else {
				row.Checked += " · " + i18n.T(ctx, "backups.history.paused", "seconds", secs)
			}
		}
	}
	if r.Kind == archive.KindRecipe && r.Verified {
		row.Checked = countsText(ctx, r.Counts)
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

// countNames are the counts of a recipe's verify the UI names; others
// show as they come ("name=n").
var countNames = []string{"databases", "tables", "rows", "users", "roles", "collections", "documents", "keys"}

// countsText says what a recipe's test restore found: "3 tabelas · 1.500
// linhas · 2 usuários".
func countsText(ctx context.Context, counts []backup.Count) string {
	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		if slices.Contains(countNames, c.Name) {
			parts = append(parts, i18n.T(ctx, "backups.count."+c.Name, "n", c.N))
		} else {
			parts = append(parts, c.Name+"="+strconv.FormatInt(c.N, 10))
		}
	}
	return strings.Join(parts, " · ")
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
		CSRF: pr.CSRFToken, SudoActive: pr.SudoFor(auth.SudoCritical, time.Now()), DefaultLabel: label,
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
	redirectLocal(w, r, "/backups?ok=key-added")
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
	d.CSRF, d.SudoActive, d.Error, d.Providers = pr.CSRFToken, pr.SudoFor(auth.SudoCritical, time.Now()), errMsg, backup.Providers
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
	method := h.projects.BackupMethod(ctx, s)
	b := views.ServiceBackups{
		Supported: method != "", Volumes: method == projects.BackupVolume, Method: methodKey(method, h.projects.IsDatabase(s)),
		OpenRoutine: r.URL.Query().Get("routine") == "1",
	}
	if !b.Supported {
		return b
	}
	now := time.Now()
	b.Ready = h.backups.Ready(ctx)
	b.Simple = h.backups.Mode(ctx) == backup.ModeSimple
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
	b.WALSupported = method == projects.BackupPGDump
	if b.WAL {
		b.WALState, b.WALTone = walText(ctx, h.backups.ServiceWAL(ctx, s.ID), now)
	}
	if b.Ready {
		if win := h.backups.Window(ctx, p.Slug, s.Slug); b.WALSupported && win.OK {
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
	b.Busy = b.Busy || h.backups.Queued(s.ID)
	// The latest base backup and whether one is running come from the
	// newest runs, whatever page of the history is on screen.
	if runs, err := h.backups.ServiceRuns(ctx, s.ID, 15); err == nil {
		for _, run := range runs {
			if run.Kind == archive.KindBase && run.Status == "ok" && b.LastBase == "" {
				b.LastBase = run.Started.Format(backupTime)
			}
			b.Busy = b.Busy || run.Status == "running"
		}
	}
	if page, err := h.backups.RunsPage(ctx, s.ID, keyset.Parse(r.URL.Query().Get(runsParam)), serviceRunsPerPage); err == nil {
		for _, run := range page.Rows {
			b.Runs = append(b.Runs, runRow(ctx, run))
		}
		q := r.URL.Query()
		q.Set("tab", "backups")
		b.RunsPage = views.NewCursor(servicePath(p.Slug, s.Slug), q, runsParam, page.Older, page.Newer, "")
	}
	if rs, err := h.backups.ServiceRestores(ctx, p.Slug, s, 10); err == nil {
		for i, x := range rs {
			row := views.RestoreRow{
				When: x.StartedAt.Format(backupTime), Status: i18n.T(ctx, "svcbackup.restore_status."+x.Status), Error: x.Error,
				Tone: map[string]string{"ok": "success", "failed": "danger", "running": "info"}[x.Status],
			}
			if x.Mode == backup.ModePITR {
				if at, err := time.Parse(time.RFC3339, x.Point); err == nil {
					row.What = i18n.T(ctx, "svcbackup.restore_to", "when", at.Local().Format("02/01/2006 15:04:05"))
				}
			} else if o, ok := archive.ParseKey(x.Point); ok && o.Kind == archive.KindVolume {
				row.What = i18n.T(ctx, "svcbackup.restore_from_volumes")
			} else if ok && o.Kind == archive.KindRecipe {
				row.What = i18n.T(ctx, "svcbackup.restore_from_recipe")
			} else {
				row.What = i18n.T(ctx, "svcbackup.restore_from_dump")
			}
			row.Dest = s.Slug
			if x.Destination == backup.DestNew {
				row.Dest = x.NewService
			}
			if x.Source != p.Slug+"/"+s.Slug {
				// This service is the copy: say where it came from.
				row.From = x.Source
			}
			if x.Status == "running" && x.Step != "" {
				row.Step = i18n.T(ctx, "svcbackup.step."+x.Step)
				b.Busy = true
			}
			// The roles exist where the data went, unless that was a new
			// service that a failure removed.
			if len(x.SavedRoles) > 0 && x.Cleanup != backup.CleanupRemoved {
				row.Saved = i18n.T(ctx, "svcbackup.restore_saved_roles", "roles", strings.Join(x.SavedRoles, ", "))
			}
			if len(x.CreatedRoles) > 0 && x.Cleanup != backup.CleanupRemoved {
				row.Roles = i18n.T(ctx, "svcbackup.restore_roles", "roles", strings.Join(x.CreatedRoles, ", "))
			}
			switch x.Cleanup {
			case backup.CleanupRemoved:
				row.Cleanup = i18n.T(ctx, "svcbackup.restore_removed", "service", x.NewService)
			case backup.CleanupKept:
				row.Cleanup = i18n.T(ctx, "svcbackup.restore_kept", "service", x.NewService)
			}
			// The newest restore failed lately: said on top of the tab,
			// with the reason, not only as a badge in the history.
			if i == 0 && x.Status == "failed" && now.Sub(x.FinishedAt) < backup.RestoreAlertFor {
				b.RestoreFailed = &row
			}
			b.Restores = append(b.Restores, row)
		}
	}
	return b
}

// methodKey names how a service is backed up, for the UI
// (svcbackup.method.*): Hangar picks it, the tab only says which.
func methodKey(method string, database bool) string {
	switch method {
	case projects.BackupVolume:
		if database {
			return "volume_stop"
		}
		return "volume_pause"
	case projects.BackupPGDump, projects.BackupRecipe:
		return method
	}
	return ""
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
	// The kit is optional in the simple mode: the server's key opens it.
	var keys []*age.X25519Identity
	if file, _, err := r.FormFile("kit"); err == nil {
		raw, err := io.ReadAll(io.LimitReader(file, maxKitBytes))
		_ = file.Close()
		if err != nil {
			fail(i18n.E("backup.error.kit"))
			return
		}
		keys, err = archive.ParseKit(raw, r.PostFormValue("passphrase"))
		clear(raw)
		switch {
		case errors.Is(err, archive.ErrKitPassphrase):
			fail(i18n.E("backup.error.kit_passphrase"))
			return
		case err != nil:
			fail(i18n.E("backup.error.kit"))
			return
		}
	} else if h.backups.Mode(r.Context()) != backup.ModeSimple {
		fail(i18n.E("backup.error.kit"))
		return
	}
	var err error
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

// downloadBackup is "Baixar backup": the whole service in one .zip, its
// data with its users and its configuration (docs/09). It is made, tested
// and encrypted in the background and offered as a single-use link; a
// PostgreSQL in the simple mode streams the plain dump instead.
func (h *handlers) downloadBackup(w http.ResponseWriter, r *http.Request) {
	p, s, err := h.projects.GetService(r.Context(), r.PathValue("project"), r.PathValue("service"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch h.projects.BackupMethod(r.Context(), s) {
	case projects.BackupPGDump:
	case projects.BackupVolume, projects.BackupRecipe:
		// The backup is made first (a copy of volumes holds the services
		// only for the copy), then fetched once: decrypted in the simple
		// mode, as it is with the kit.
		if err := h.backups.PrepareDownload(r.Context(), actor(r), p.Slug, s.Slug); err != nil {
			code, msg := userError(r, err)
			h.renderService(w, r, serviceView{status: code, errMsg: msg})
			return
		}
		redirectLocal(w, r, h.serviceBase(r)+"?ok=backup-preparing")
		return
	default:
		h.renderService(w, r, serviceView{status: http.StatusUnprocessableEntity, errMsg: i18n.T(r.Context(), "backup.error.unsupported")})
		return
	}
	if st, err := h.projects.Status(r.Context(), p.Slug, s.Slug); err != nil || !st.Running {
		h.renderService(w, r, serviceView{status: http.StatusConflict, errMsg: i18n.T(r.Context(), "backup.error.not_running")})
		return
	}
	if h.backups.Mode(r.Context()) == backup.ModeSimple {
		// No kit to encrypt to for this browser: the plain dump below.
	} else if err := h.backups.PrepareDownload(r.Context(), actor(r), p.Slug, s.Slug); err == nil {
		redirectLocal(w, r, h.serviceBase(r)+"?ok=backup-preparing")
		return
	} else if !errors.Is(err, backup.ErrNotReady) {
		code, msg := userError(r, err)
		h.renderService(w, r, serviceView{status: code, errMsg: msg})
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // a big database takes a while
	// One .zip: the dump, the roles of its server and how to restore
	// them (backup.DownloadPlain).
	name := archive.BundleName(p.Slug, s.Slug, time.Now()) + archive.ExtBundle
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if err := h.backups.DownloadPlain(r.Context(), actor(r), p.Slug, s.Slug, w); err != nil {
		// Headers are gone: the download ends short and the browser shows it
		// as failed. The cause is in the log and the audit.
		loggerFrom(r.Context()).Error("backup download", "service", p.Slug+"/"+s.Slug, "error", err)
	}
}

// takeDownload serves a prepared encrypted bundle (dump and roles) once.
func (h *handlers) takeDownload(w http.ResponseWriter, r *http.Request) {
	bundle, name, done, err := h.backups.TakeDownload(r.Context(), actor(r), r.PathValue("token"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer done()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if err := bundle(w); err != nil {
		loggerFrom(r.Context()).Error("backup download", "error", err)
	}
}

// runDownload sends an older backup. A dump with the roles of its server
// goes as one .zip with both (opened by the server in the simple mode);
// anything else goes as before: open in the simple mode, else through a
// short-lived signed link in the bucket.
func (h *handlers) runDownload(w http.ResponseWriter, r *http.Request) {
	simple := h.backups.Mode(r.Context()) == backup.ModeSimple
	if rc, name, ok, err := h.backups.OpenRunBundle(r.Context(), actor(r), r.PathValue("id"), simple); ok || err != nil {
		if err != nil {
			code, msg := userError(r, err)
			h.renderBackups(w, r, code, msg, "")
			return
		}
		defer func() { _ = rc.Close() }()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{}) // a big backup takes a while
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		if _, err := io.Copy(w, rc); err != nil {
			loggerFrom(r.Context()).Error("backup download", "run", r.PathValue("id"), "error", err)
		}
		return
	}
	// The simple mode's server holds the key: the file arrives open.
	if simple {
		owner := PrincipalFrom(r.Context()).Role >= auth.RoleOwner
		rc, name, err := h.backups.OpenRun(r.Context(), actor(r), r.PathValue("id"), owner)
		if err != nil {
			code, msg := userError(r, err)
			h.renderBackups(w, r, code, msg, "")
			return
		}
		defer func() { _ = rc.Close() }()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{}) // a big backup takes a while
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		if _, err := io.Copy(w, rc); err != nil {
			loggerFrom(r.Context()).Error("backup download", "run", r.PathValue("id"), "error", err)
		}
		return
	}
	u, err := h.backups.RunDownloadURL(r.Context(), actor(r), r.PathValue("id"))
	if err != nil {
		code, msg := userError(r, err)
		h.renderBackups(w, r, code, msg, "")
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther) //nolint:gosec // a link this panel just signed for its own bucket
}
