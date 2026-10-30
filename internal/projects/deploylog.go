package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

const (
	deployLogMax   = 16 << 10
	deployLogEvery = time.Second
	rollbackDepth  = 5
)

// Strategy picks how a service is deployed: services that keep state in a
// volume (two processes on one volume corrupt it) or publish a host port
// (two containers cannot bind it) are recreated; everything else rolls with
// no downtime.
func Strategy(s dbq.Service, x specExtras) string {
	if s.Stateful == 1 || len(x.volumes) > 0 || len(x.ports) > 0 {
		return node.StrategyRecreate
	}
	return node.StrategyRolling
}

// deployLog keeps the deploy's phase and a bounded log in the database, so
// the timeline shows progress while the deploy runs.
type deployLog struct {
	m     *Manager
	ctx   context.Context
	id    string
	mu    sync.Mutex
	phase string
	// failedAt is the phase that was running when the deploy went into
	// "restore" (the alert names where it failed, not the undo).
	failedAt string
	buf      strings.Builder
	last     time.Time
	// mask hides known secrets in every line before it is stored (docs/17:
	// the build log never shows a secret variable or the Git token).
	mask *masker
}

func newDeployLog(m *Manager, ctx context.Context, id string) *deployLog {
	return &deployLog{m: m, ctx: ctx, id: id}
}

func (d *deployLog) progress(phase, line string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if phase != "log" {
		if phase == node.PhaseRestore && d.failedAt == "" {
			d.failedAt = d.phase
		}
		d.phase = phase
	}
	line = strings.Map(func(r rune) rune {
		if r == '\u2028' || r == '\u2029' {
			return '\n' // Unicode line and paragraph separators break lines too
		}
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, d.mask.apply(line))
	// Only the first line of a message carries the phase marker; every
	// other line is indented like process output. Text from outside (a
	// commit message, a build step) can hold newlines, and must never
	// start a line that looks like the panel's own "[deploy] ..."
	// (SEC-019, CWE-117).
	first := true
	for l := range strings.SplitSeq(line, "\n") {
		if l = strings.TrimRightFunc(l, unicode.IsSpace); l == "" {
			continue
		}
		prefix := "  "
		if first && phase != "log" {
			prefix = "[" + phase + "] "
		}
		first = false
		d.buf.WriteString(prefix + l + "\n")
	}
	if time.Since(d.last) >= deployLogEvery {
		d.writeLocked()
	}
}

// failedPhase is the phase in which the deploy failed.
func (d *deployLog) failedPhase() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.failedAt != "":
		return d.failedAt
	case d.phase != "":
		return d.phase
	}
	return node.PhaseStart
}

func (d *deployLog) flush() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writeLocked()
}

func (d *deployLog) writeLocked() {
	d.last = time.Now()
	text := d.buf.String()
	if len(text) > deployLogMax {
		text = text[len(text)-deployLogMax:]
	}
	_ = d.m.q.SetDeploymentProgress(d.ctx, dbq.SetDeploymentProgressParams{Phase: d.phase, Log: text, ID: d.id})
}

// Rollback deploys again the exact image of one of the last live deploys
// (no rebuild, no re-pull of a moved tag). Variables are the current ones.
func (m *Manager) Rollback(ctx context.Context, a Actor, projectSlug, serviceSlug, deploymentID string) (string, error) {
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return "", err
	}
	d, err := m.q.GetDeployment(ctx, dbq.GetDeploymentParams{ID: deploymentID, ServiceID: s.ID})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if !m.canRollBackTo(ctx, s.ID, d) {
		return "", i18n.E("deploy.error.rollback")
	}
	id, err := m.deploy(ctx, a, projectSlug, serviceSlug, deployRequest{
		trigger: "rollback", image: d.ImageRef,
		commit: gitsrc.Commit{SHA: d.CommitSha, Message: d.CommitMessage},
	})
	if err == nil {
		m.record(ctx, a, "service.rollback", "service", s.ID, audit.OK, map[string]any{"to_deploy": d.ID, "image_ref": d.ImageRef})
	}
	return id, err
}

// canRollBackTo: one of the last few deploys that went live, with a pinned
// image, and not the one live right now.
func (m *Manager) canRollBackTo(ctx context.Context, serviceID string, d dbq.Deployment) bool {
	if d.ImageRef == "" || d.Status != "superseded" {
		return false
	}
	deps, err := m.q.ListDeployments(ctx, dbq.ListDeploymentsParams{ServiceID: serviceID, Limit: 50})
	if err != nil {
		return false
	}
	n := 0
	for _, x := range deps {
		if x.Status != "live" && x.Status != "superseded" {
			continue
		}
		if x.ID == d.ID {
			return n <= rollbackDepth
		}
		n++
	}
	return false
}

// RollbackTargets returns the deploy ids the UI may offer to roll back to.
func (m *Manager) RollbackTargets(ctx context.Context, serviceID string, deps []dbq.Deployment) map[string]bool {
	out := map[string]bool{}
	for _, d := range deps {
		if m.canRollBackTo(ctx, serviceID, d) {
			out[d.ID] = true
		}
	}
	return out
}

// Bounds of the validation command's time limit.
const (
	DefaultValidateTimeout = 5 * time.Minute
	MinValidateTimeout     = 10 * time.Second
	MaxValidateTimeout     = 30 * time.Minute
)

// Bounds of the startup grace: how long a new version may take to answer
// its health check. Zero means node.DefaultHealthTimeout; it cannot
// outlast the deploy itself.
const (
	MinStartupGrace = time.Minute
	MaxStartupGrace = deployTimeout
)

// DeploySettings is the "Deploy" card of a service.
type DeploySettings struct {
	PreDeploy  string
	HealthPath string
	// Validate runs inside the new container once it is healthy, before it
	// takes over (e.g. python manage.py check --deploy); a failure keeps
	// or brings back the previous version.
	Validate string
	// ValidateTimeout limits it (zero = DefaultValidateTimeout).
	ValidateTimeout time.Duration
	// StartupGrace is how long the new version may take to start
	// answering before the deploy gives up (zero = node.DefaultHealthTimeout):
	// an app that migrates or uploads static files before it listens.
	StartupGrace time.Duration
}

// GetDeploySettings reads the pre-deploy command, health path and
// validation command.
func (m *Manager) GetDeploySettings(s dbq.Service) DeploySettings {
	var cmd, validate []string
	_ = json.Unmarshal([]byte(s.PredeployJson), &cmd)
	_ = json.Unmarshal([]byte(s.ValidateJson), &validate)
	return DeploySettings{
		PreDeploy: JoinCommand(cmd), HealthPath: s.HealthPath,
		Validate: JoinCommand(validate), ValidateTimeout: time.Duration(s.ValidateTimeoutS) * time.Second,
		StartupGrace: time.Duration(s.StartupGraceS) * time.Second,
	}
}

// SetDeploySettings stores the pre-deploy command, health path, startup
// grace and validation command; they apply from the next deploy.
func (m *Manager) SetDeploySettings(ctx context.Context, a Actor, serviceID string, in DeploySettings) error {
	cmd, err := SplitCommand(in.PreDeploy)
	if err != nil {
		return i18n.E("deploy.error.command")
	}
	validate, err := SplitCommand(in.Validate)
	if err != nil {
		return i18n.E("deploy.error.command")
	}
	path, timeout, grace, err := checkDeploySettings(in.HealthPath, in.ValidateTimeout, in.StartupGrace)
	if err != nil {
		return err
	}
	if err := m.q.SetServiceDeploySettings(ctx, dbq.SetServiceDeploySettingsParams{
		PredeployJson: commandJSON(cmd), HealthPath: path,
		ValidateJson: commandJSON(validate), ValidateTimeoutS: int64(timeout / time.Second),
		StartupGraceS: int64(grace / time.Second), UpdatedAt: m.now().Unix(), ID: serviceID,
	}); err != nil {
		return err
	}
	m.record(ctx, a, "service.deploy_settings", "service", serviceID, audit.OK, map[string]any{
		"predeploy": cmd, "health_path": path, "validate": validate, "validate_timeout_s": int(timeout / time.Second),
		"startup_grace_s": int64(grace / time.Second),
	})
	return nil
}

// checkDeploySettings applies the bounds of the deploy settings: the
// validation timeout (zero: the default), the startup grace (zero: the
// node's default) and the health path. Every way in goes through it: the
// form and a project restore, whose file comes from a browser.
//
// The health path is appended to "http://<container address>" by the
// deploy: anything but a plain absolute path ("@169.254.169.254/...",
// "//host/...") could send the check to another host.
func checkDeploySettings(healthPath string, timeout, grace time.Duration) (string, time.Duration, time.Duration, error) {
	if timeout == 0 {
		timeout = DefaultValidateTimeout
	}
	if timeout < MinValidateTimeout || timeout > MaxValidateTimeout {
		return "", 0, 0, i18n.E("deploy.error.validate_timeout", "max", int(MaxValidateTimeout.Minutes()))
	}
	if grace != 0 && (grace < MinStartupGrace || grace > MaxStartupGrace) {
		return "", 0, 0, i18n.E("deploy.error.startup_grace", "min", int(MinStartupGrace.Minutes()), "max", int(MaxStartupGrace.Minutes()))
	}
	path := strings.TrimSpace(healthPath)
	if path != "" && (!strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || len(path) > 200 ||
		strings.ContainsAny(path, " #") || strings.IndexFunc(path, unicode.IsControl) >= 0) {
		return "", 0, 0, i18n.E("deploy.error.health_path")
	}
	return path, timeout, grace, nil
}

// checkCommand applies SplitCommand's bounds to a command already split
// (a project restore's file keeps them as JSON lists).
func checkCommand(cmd []string) error {
	n := 0
	for _, a := range cmd {
		if strings.ContainsRune(a, 0) {
			return i18n.E("deploy.error.command")
		}
		n += len(a) + 1
	}
	if len(cmd) > 64 || n > 2000 {
		return i18n.E("deploy.error.command")
	}
	return nil
}

func commandJSON(cmd []string) string {
	if cmd == nil {
		return "[]"
	}
	b, _ := json.Marshal(cmd)
	return string(b)
}

// restorePolicy says whether a failed recreate may start the previous
// version again (node.DeployOptions.Restore). Services not marked stateful
// (apps, even with a volume of uploads): always. Databases (stateful
// templates): only when the image keeps its major version (the tag's
// leading number, same repository: postgres:16.4 to postgres:16.6), or when
// the new container runs the very same image (a configuration change; the
// node checks that). A new major may convert the data on its first start,
// and the old binary would then refuse it or, worse, misread it; tags
// without a number (latest) give no such guarantee. A previous deploy that
// was itself a rollback says nothing reliable about the image it ran (the
// history shows the current tag), so it gets the strict rule.
func (m *Manager) restorePolicy(ctx context.Context, s dbq.Service, image string) string {
	if s.Stateful != 1 {
		return node.RestoreAlways
	}
	last, err := m.q.LastLiveDeployment(ctx, s.ID)
	if err != nil || last.Trigger == "rollback" || !sameMajor(last.Image, image) {
		return node.RestoreSameImage
	}
	return node.RestoreAlways
}

// sameMajor reports whether two image references name the same repository
// with tags of the same major version (the leading number of the tag).
func sameMajor(a, b string) bool {
	ra, ma := imageMajor(a)
	rb, mb := imageMajor(b)
	return ma != "" && ra == rb && ma == mb
}

func imageMajor(image string) (repo, major string) {
	image, _, _ = strings.Cut(image, "@")
	tag := ""
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image, tag = image[:i], image[i+1:]
	}
	image = strings.TrimPrefix(image, "docker.io/")
	image = strings.TrimPrefix(image, "library/")
	tag = strings.TrimPrefix(tag, "v")
	end := 0
	for end < len(tag) && tag[end] >= '0' && tag[end] <= '9' {
		end++
	}
	return image, tag[:end]
}

// SplitCommand splits a command line like a shell does for words and quotes
// (no variables, no pipes: the command runs without a shell unless you write
// sh -c '...').
func SplitCommand(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inWord := false
	var quote rune
	for _, r := range strings.TrimSpace(line) {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case unicode.IsSpace(r):
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote")
	}
	if inWord {
		out = append(out, cur.String())
	}
	if len(out) > 64 || len(line) > 2000 {
		return nil, errors.New("command too long")
	}
	return out, nil
}

// JoinCommand is the inverse of SplitCommand, for showing it back.
func JoinCommand(cmd []string) string {
	parts := make([]string, len(cmd))
	for i, c := range cmd {
		if c == "" || strings.ContainsAny(c, " \t\"'") {
			parts[i] = "'" + strings.ReplaceAll(c, "'", `'"'"'`) + "'"
		} else {
			parts[i] = c
		}
	}
	return strings.Join(parts, " ")
}

// DeployPending deploys every service of the project with changes waiting
// (variables or references changed since its last deploy). It returns the
// services it started.
func (m *Manager) DeployPending(ctx context.Context, a Actor, projectSlug string) ([]string, error) {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return nil, err
	}
	svcs, err := m.q.ListServices(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	var started []string
	for _, s := range svcs {
		pending, err := m.PendingChanges(ctx, s.ID)
		if err != nil || !pending {
			continue
		}
		if _, err := m.Deploy(ctx, a, p.Slug, s.Slug, "manual"); err != nil {
			return started, err
		}
		started = append(started, s.Slug)
	}
	return started, nil
}
