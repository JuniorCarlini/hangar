// Package deps is the dependency and vulnerability monitor (docs/14): it
// inventories what runs in each service (OS and language packages, image
// tag), checks it against OSV.dev and the image registries, keeps the
// findings in the database and hands summaries to the alert channels.
//
// It never updates anything by itself: the decision is the operator's.
package deps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// EdgeTarget is the target name of the Caddy edge image.
const EdgeTarget = "edge"

// Finding kinds.
const (
	KindVuln  = "vuln"
	KindPatch = "patch"
	KindMinor = "minor"
	KindMajor = "major"
)

// Errors shown to the user.
var (
	ErrNotFound   = &i18n.Error{Key: "deps.error.not_found"}
	ErrReason     = &i18n.Error{Key: "deps.error.reason"}
	ErrIgnoreMode = &i18n.Error{Key: "deps.error.ignore_mode"}
)

// Notice is a summary ready for the alert channels (Telegram, e-mail,
// webhook — docs/06). It never carries IPs, secrets or customer data: only
// project/service names, packages, versions and advisory ids.
type Notice struct {
	Level string   // critical (send now), security (daily), updates (weekly)
	Title string   // e.g. "Hangar — vulnerabilidade crítica"
	Lines []string // one per finding
	Path  string   // panel path with the details (/updates)
}

// Notifier delivers notices. The alerts system (Etapa 8) implements it; until
// it is plugged in, LogNotifier writes them to the log.
type Notifier interface {
	Notify(ctx context.Context, n Notice) error
}

// LogNotifier logs every notice.
type LogNotifier struct{ Log *slog.Logger }

// Notify writes the notice to the log.
func (l LogNotifier) Notify(_ context.Context, n Notice) error {
	l.Log.Info("dependency notice", "level", n.Level, "title", n.Title, "lines", n.Lines, "path", n.Path)
	return nil
}

// Options configure a Monitor.
type Options struct {
	OSV      *OSV
	Registry *Registry
	// Images inventories the image each container runs (every language
	// OSV-SCALIBR knows); nil falls back to Exec.
	Images ImageInventory
	// Exec reads the containers when their image cannot be scanned; nil
	// with no Images (Docker unavailable) checks only the image tags.
	Exec Execer
	// Prober reads images no container runs (a newer build of the tag, a
	// newer tag) to tell whether a deploy or a tag change fixes a
	// vulnerability; nil leaves those undecided (Remedy "unchecked").
	Prober ImageProber
	// EdgeImage is Caddy's image, checked for tag updates and, with
	// Images, inventoried ("" = no edge).
	EdgeImage string
	Notifier  Notifier
	Audit     *audit.Logger
	Log       *slog.Logger
	// Locale of the notices (the panel's default language).
	Locale string
}

// Monitor runs scans and serves their results.
type Monitor struct {
	q       *dbq.Queries
	o       Options
	now     func() time.Time
	running atomic.Bool

	mu       sync.Mutex
	notifier Notifier
	lastRun  time.Time
	lastErr  string
}

// New creates a monitor on the panel database.
func New(db *sql.DB, o Options) *Monitor {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.OSV == nil {
		o.OSV = NewOSV("", nil)
	}
	if o.Registry == nil {
		o.Registry = NewRegistry(nil)
	}
	if o.Locale == "" {
		o.Locale = i18n.Default
	}
	m := &Monitor{q: dbq.New(db), o: o, now: time.Now, notifier: o.Notifier}
	if m.notifier == nil {
		m.notifier = LogNotifier{Log: o.Log}
	}
	return m
}

// SetNotifier plugs the alert channels in (Etapa 8) after construction.
func (m *Monitor) SetNotifier(n Notifier) {
	if m == nil || n == nil {
		return
	}
	m.mu.Lock()
	m.notifier = n
	m.mu.Unlock()
}

// Running reports whether a scan is in progress.
func (m *Monitor) Running() bool { return m != nil && m.running.Load() }

// LastRun is when the last scan finished and its error ("" = fine).
func (m *Monitor) LastRun() (time.Time, string) {
	if m == nil {
		return time.Time{}, ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRun, m.lastErr
}

// Run scans every day at hour:00 (local time) until ctx ends.
func (m *Monitor) Run(ctx context.Context, hour int) {
	if m == nil {
		return
	}
	// Findings from a version that did not classify them would show stale
	// advice until the next daily scan: classify them shortly after start.
	if n, err := m.q.CountUnclassifiedFindings(ctx); err == nil && n > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
		if err := m.Scan(ctx); err != nil && ctx.Err() == nil {
			m.o.Log.Warn("dependency scan", "error", err)
		}
	}
	for {
		now := m.now()
		next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
		if !next.After(now) {
			next = next.AddDate(0, 0, 1)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next.Sub(now)):
		}
		if err := m.Scan(ctx); err != nil && ctx.Err() == nil {
			m.o.Log.Warn("dependency scan", "error", err)
		}
	}
}

// ScanAsync starts a scan in the background; false when one is running.
// The scan is marked running before this returns, so the page the caller
// shows next already sees it.
func (m *Monitor) ScanAsync(ctx context.Context) bool {
	if m == nil || !m.running.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer m.running.Store(false)
		if err := m.runScan(context.WithoutCancel(ctx)); err != nil {
			m.o.Log.Warn("dependency scan", "error", err)
		}
	}()
	return true
}

// errBusy means another scan holds the lock.
var errBusy = errors.New("a dependency scan is already running")

// ImageInventory reads the packages of the image a container runs
// (*ImageScanner).
type ImageInventory interface {
	ScanContainer(ctx context.Context, container string) ([]Package, error)
}

// target is one thing scanned: a service, or the edge image.
type target struct {
	serviceID string // "" for the edge
	name      string // EdgeTarget for the edge, "" for services
	project   string
	service   string
	image     string
	running   bool
	// imageRef is what the live deploy pinned (name@sha256:… for pulled
	// images); stateful and git as the service says.
	imageRef string
	stateful bool
	git      bool
}

func (t target) key() string {
	if t.serviceID != "" {
		return t.serviceID
	}
	return t.name
}

// observation is a finding as seen in this scan.
type observation struct {
	t        target
	pkg      Package
	kind     string
	advisory Advisory
	latest   string
	// remedy and remedyTag: what fixes a vulnerability (classify).
	remedy    string
	remedyTag string
}

// Scan inventories every target, checks it and stores the findings, then
// sends what is new. Only one scan runs at a time.
func (m *Monitor) Scan(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if !m.running.CompareAndSwap(false, true) {
		return errBusy
	}
	defer m.running.Store(false)
	return m.runScan(ctx)
}

// runScan scans and records the result; the caller holds running.
func (m *Monitor) runScan(ctx context.Context) error {
	err := m.scan(ctx)
	m.mu.Lock()
	m.lastRun, m.lastErr = m.now(), ""
	if err != nil {
		m.lastErr = err.Error()
	}
	m.mu.Unlock()
	return err
}

func (m *Monitor) scan(ctx context.Context) error {
	start := m.now()
	svcs, err := m.q.ListLiveServiceImages(ctx)
	if err != nil {
		return err
	}
	var targets []target
	for _, s := range svcs {
		targets = append(targets, target{
			serviceID: s.ID, project: s.ProjectSlug, service: s.Slug, image: s.Image,
			running: s.DesiredState == "running", imageRef: s.ImageRef, stateful: s.Stateful == 1, git: s.BuiltFromGit == 1,
		})
	}
	if m.o.EdgeImage != "" {
		targets = append(targets, target{name: EdgeTarget, image: m.o.EdgeImage})
	}

	// Inventory each target, one at a time (an image scan holds the image
	// on disk and a few dozen MB in memory).
	type inv struct {
		pkgs   []Package
		invErr error
		tags   []TagUpdate
		tagErr error
	}
	invs := make([]inv, len(targets))
	var all []Package
	index := map[string]int{}
	for i, t := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		invs[i].pkgs, invs[i].invErr = m.inventory(ctx, t)
		if !t.git { // a built image is local: no registry has its tags
			invs[i].tags, invs[i].tagErr = m.o.Registry.Updates(ctx, t.image)
		}
		for _, p := range invs[i].pkgs {
			if _, ok := index[queryKey(p)]; !ok {
				index[queryKey(p)] = len(all)
				all = append(all, p)
			}
		}
	}
	advs, osvErr := m.o.OSV.Check(ctx, all)

	var errs []error
	if osvErr != nil {
		errs = append(errs, osvErr)
	}
	for i, t := range targets {
		var obs []observation
		if osvErr == nil {
			for _, p := range invs[i].pkgs {
				for _, a := range advs[index[queryKey(p)]] {
					// A low or unrated advisory with no fix leaves nothing to
					// do: distributions carry hundreds of those ("unimportant",
					// "no-dsa"). Showing them would bury what matters.
					if a.Fixed == "" && a.Severity != SevCritical && a.Severity != SevHigh {
						continue
					}
					obs = append(obs, observation{t: t, pkg: p, kind: KindVuln, advisory: a})
				}
			}
		}
		m.classify(ctx, t, invs[i].tags, obs)
		if ref, ok := ParseImage(t.image); ok && !t.git {
			for _, u := range invs[i].tags {
				obs = append(obs, observation{
					t: t, kind: u.Kind, latest: u.Latest,
					pkg: Package{Ecosystem: "image", Name: ref.Name(), Version: u.Current, Source: t.image},
				})
			}
		}
		if err := m.store(ctx, obs); err != nil {
			return err
		}
		// Resolve only what this scan could actually see again.
		var kinds []string
		if osvErr == nil && (invs[i].invErr == nil || len(invs[i].pkgs) > 0) && (t.running || t.serviceID == "") {
			kinds = append(kinds, KindVuln)
		}
		if invs[i].tagErr == nil {
			kinds = append(kinds, KindPatch, KindMinor, KindMajor)
		}
		if len(kinds) > 0 {
			if _, err := m.q.ResolveDependencyFindings(ctx, dbq.ResolveDependencyFindingsParams{
				ResolvedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ServiceID: sql.NullString{String: t.serviceID, Valid: true},
				Target: t.name, LastSeenAt: start.Unix(), Kinds: kinds,
			}); err != nil {
				return err
			}
		}
		scanErr := errors.Join(invs[i].invErr, invs[i].tagErr)
		msg := ""
		if scanErr != nil {
			msg = clip(scanErr.Error(), 500)
			errs = append(errs, fmt.Errorf("%s: %w", t.key(), scanErr))
		}
		if err := m.q.UpsertDependencyScan(ctx, dbq.UpsertDependencyScanParams{
			TargetKey: t.key(), ScannedAt: m.now().Unix(), Packages: int64(len(invs[i].pkgs)), Error: msg,
		}); err != nil {
			return err
		}
	}
	if err := m.notify(ctx); err != nil {
		errs = append(errs, err)
	}
	m.o.Log.Info("dependency scan finished", "targets", len(targets), "packages", len(all), "duration", m.now().Sub(start).Round(time.Millisecond))
	return errors.Join(errs...)
}

// inventory reads a target's packages: from its image when it can be
// scanned, else (services only) from the running container.
func (m *Monitor) inventory(ctx context.Context, t target) ([]Package, error) {
	if t.serviceID != "" && !t.running {
		return nil, nil
	}
	container := node.EdgeContainer
	if t.serviceID != "" {
		container = node.ContainerName(t.project, t.service)
	}
	var imgErr error
	if m.o.Images != nil {
		pkgs, err := m.o.Images.ScanContainer(ctx, container)
		if err == nil {
			return pkgs, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		imgErr = err
		m.o.Log.Warn("dependency image scan failed, reading the container instead", "target", t.key(), "container", container, "reason", err)
	}
	if t.serviceID == "" || m.o.Exec == nil {
		return nil, imgErr
	}
	return Inventory(ctx, m.o.Exec, t.project, t.service)
}

func (m *Monitor) store(ctx context.Context, obs []observation) error {
	now := m.now().Unix()
	seen := map[string]bool{}
	for _, o := range obs {
		f := dbq.InsertDependencyFindingParams{
			ServiceID: sql.NullString{String: o.t.serviceID, Valid: o.t.serviceID != ""}, Target: o.t.name,
			Ecosystem: o.pkg.Ecosystem, Package: o.pkg.Name, CurrentVersion: o.pkg.Version,
			Source: clip(o.pkg.Source, 300), Kind: o.kind, Severity: SevNone,
		}
		if o.kind == KindVuln {
			f.AdvisoryID, f.FixedVersion, f.Severity = o.advisory.ID, o.advisory.Fixed, o.advisory.Severity
			f.Aliases, f.Summary = strings.Join(o.advisory.Aliases, ","), o.advisory.Summary
			f.Level = vulnLevel(f.Severity, f.FixedVersion)
			f.Remedy, f.RemedyTag = o.remedy, o.remedyTag
		} else {
			f.LatestVersion, f.Level = o.latest, LevelMinor
			if o.kind == KindMajor {
				f.Level = LevelMajor
			}
		}
		k := strings.Join([]string{f.Ecosystem, f.Package, f.AdvisoryID, f.Kind}, "|")
		if seen[k] {
			continue // the same advisory through two copies of a package
		}
		seen[k] = true
		cur, err := m.q.FindDependencyFinding(ctx, dbq.FindDependencyFindingParams{
			ServiceKey: sql.NullString{String: o.t.serviceID, Valid: true}, Target: f.Target, Ecosystem: f.Ecosystem,
			Package: f.Package, AdvisoryID: f.AdvisoryID, Kind: f.Kind,
		})
		switch {
		case errors.Is(err, sql.ErrNoRows):
			f.ID, f.FirstSeenAt, f.LastSeenAt = ids.New("dep_"), now, now
			if err := m.q.InsertDependencyFinding(ctx, f); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if err := m.q.RefreshDependencyFinding(ctx, dbq.RefreshDependencyFindingParams{
				CurrentVersion: f.CurrentVersion, LatestVersion: f.LatestVersion, FixedVersion: f.FixedVersion,
				Severity: f.Severity, Level: f.Level, Aliases: f.Aliases, Summary: f.Summary, Source: f.Source,
				Remedy: f.Remedy, RemedyTag: f.RemedyTag, LastSeenAt: now, ID: cur.ID,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Finding is an open finding as the panel shows it.
type Finding struct {
	ID        string
	ServiceID string
	Project   string // "" for server-level targets
	Service   string
	Target    string // EdgeTarget for the edge image
	Ecosystem string
	Package   string
	Current   string
	Suggested string // fixed version (vulnerability) or newest tag (update)
	Severity  string
	Level     string
	Kind      string
	Advisory  string
	Aliases   []string
	Summary   string
	Source    string
	// Remedy says what fixes a vulnerability (Remedy* constants) and
	// RemedyTag the tag that does, for RemedyTag and RemedyMajor.
	Remedy    string
	RemedyTag string
	// Image is the service's image now ("" for the edge).
	Image     string
	FirstSeen time.Time
	Ignored   bool
	notified  bool
}

// Where names the finding's place: "project/service" or the target.
func (f Finding) Where() string {
	if f.Project != "" {
		return f.Project + "/" + f.Service
	}
	return f.Target
}

// Counts are open findings (not ignored) per level.
type Counts map[string]int

// Findings lists the open findings, the loudest first, with the ignored ones
// flagged.
func (m *Monitor) Findings(ctx context.Context) ([]Finding, error) {
	rows, err := m.q.ListOpenDependencyFindings(ctx)
	if err != nil {
		return nil, err
	}
	ign, err := m.q.ListFindingIgnores(ctx, sql.NullInt64{Int64: m.now().Unix(), Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(rows))
	for _, r := range rows {
		f := Finding{
			ID: r.ID, ServiceID: r.ServiceID.String, Project: r.ProjectSlug, Service: r.ServiceSlug, Target: r.Target,
			Ecosystem: r.Ecosystem, Package: r.Package, Current: r.CurrentVersion, Severity: r.Severity, Level: r.Level,
			Kind: r.Kind, Advisory: r.AdvisoryID, Summary: r.Summary, Source: r.Source, FirstSeen: time.Unix(r.FirstSeenAt, 0),
			Suggested: r.FixedVersion, Remedy: r.Remedy, RemedyTag: r.RemedyTag, Image: r.ServiceImage,
		}
		if r.Kind != KindVuln {
			f.Suggested = r.LatestVersion
		}
		if r.Aliases != "" {
			f.Aliases = strings.Split(r.Aliases, ",")
		}
		f.Ignored = ignored(f, ign)
		f.notified = r.NotifiedAt.Valid
		out = append(out, f)
	}
	return out, nil
}

// ignored: an ignore of the same target and package, for this advisory (or
// all), still in time, and — when it names a version — the suggested
// version is not newer than it.
func ignored(f Finding, ign []dbq.ListFindingIgnoresRow) bool {
	for _, i := range ign {
		if i.ServiceID.String != f.ServiceID || i.Target != f.Target || i.Package != f.Package {
			continue
		}
		if i.AdvisoryID != "" && i.AdvisoryID != f.Advisory {
			continue
		}
		if i.UntilVersion != "" && (f.Suggested == "" || CompareVersions(f.Suggested, i.UntilVersion) > 0) {
			continue
		}
		return true
	}
	return false
}

// Count returns the open, not ignored findings per level.
func (m *Monitor) Count(ctx context.Context) (Counts, error) {
	c := Counts{}
	if m == nil {
		return c, nil
	}
	fs, err := m.Findings(ctx)
	if err != nil {
		return c, err
	}
	for _, f := range fs {
		if !f.Ignored {
			c[f.Level]++
		}
	}
	return c, nil
}

// ScanInfo is a target's last inventory.
type ScanInfo struct {
	At       time.Time
	Packages int
	Error    string
}

// Scans returns the last inventory of each target, by target key.
func (m *Monitor) Scans(ctx context.Context) (map[string]ScanInfo, error) {
	rows, err := m.q.ListDependencyScans(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]ScanInfo{}
	for _, r := range rows {
		out[r.TargetKey] = ScanInfo{At: time.Unix(r.ScannedAt, 0), Packages: int(r.Packages), Error: r.Error}
	}
	return out, nil
}

// Ignore modes.
const (
	IgnoreDays    = "days"    // 30 days
	IgnoreVersion = "version" // until a version newer than the suggested one
)

// Actor is who does something, for the audit log.
type Actor struct {
	UserID string
	IP     string
}

// Ignore hides a finding (and its future repeats) with a reason.
func (m *Monitor) Ignore(ctx context.Context, a Actor, findingID, mode, reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) < 3 || len(reason) > 300 {
		return ErrReason
	}
	f, err := m.q.GetDependencyFinding(ctx, findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	p := dbq.InsertFindingIgnoreParams{
		ID: ids.New("ign_"), ServiceID: f.ServiceID, Target: f.Target, Package: f.Package, AdvisoryID: f.AdvisoryID,
		Reason: reason, CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, CreatedAt: m.now().Unix(),
	}
	suggested := f.FixedVersion
	if f.Kind != KindVuln {
		suggested = f.LatestVersion
	}
	switch mode {
	case IgnoreDays:
		p.UntilAt = sql.NullInt64{Int64: m.now().Add(30 * 24 * time.Hour).Unix(), Valid: true}
	case IgnoreVersion:
		if suggested == "" {
			return ErrIgnoreMode
		}
		p.UntilVersion = suggested
	default:
		return ErrIgnoreMode
	}
	if err := m.q.InsertFindingIgnore(ctx, p); err != nil {
		return err
	}
	m.record(ctx, a, "deps.ignore", f.ID, map[string]any{
		"package": f.Package, "advisory": f.AdvisoryID, "mode": mode, "until_version": p.UntilVersion, "reason": reason,
	})
	return nil
}

// maxIgnoreGroup bounds how many findings one ignore may cover.
const maxIgnoreGroup = 1000

// IgnoreGroup hides the packages of a row of the updates page (every
// advisory of each package, now and later), with one reason. "Until a
// newer version" waits for a version newer than the highest one suggested
// for each package.
func (m *Monitor) IgnoreGroup(ctx context.Context, a Actor, findingIDs []string, mode, reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) < 3 || len(reason) > 300 {
		return ErrReason
	}
	if mode != IgnoreDays && mode != IgnoreVersion {
		return ErrIgnoreMode
	}
	if len(findingIDs) == 0 || len(findingIDs) > maxIgnoreGroup {
		return ErrNotFound
	}
	type rule struct {
		f       dbq.DependencyFinding
		version string
		noFix   bool
	}
	var order []string
	rules := map[string]*rule{}
	for _, id := range findingIDs {
		f, err := m.q.GetDependencyFinding(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		k := f.ServiceID.String + "|" + f.Target + "|" + f.Package
		r, ok := rules[k]
		if !ok {
			r = &rule{f: f}
			rules[k] = r
			order = append(order, k)
		}
		suggested := f.FixedVersion
		if f.Kind != KindVuln {
			suggested = f.LatestVersion
		}
		if suggested == "" {
			r.noFix = true
		} else if r.version == "" || CompareVersions(suggested, r.version) > 0 {
			r.version = suggested
		}
	}
	if mode == IgnoreVersion {
		for _, k := range order {
			if rules[k].noFix {
				return ErrIgnoreMode
			}
		}
	}
	for _, k := range order {
		r := rules[k]
		p := dbq.InsertFindingIgnoreParams{
			ID: ids.New("ign_"), ServiceID: r.f.ServiceID, Target: r.f.Target, Package: r.f.Package,
			Reason: reason, CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, CreatedAt: m.now().Unix(),
		}
		if mode == IgnoreDays {
			p.UntilAt = sql.NullInt64{Int64: m.now().Add(30 * 24 * time.Hour).Unix(), Valid: true}
		} else {
			p.UntilVersion = r.version
		}
		if err := m.q.InsertFindingIgnore(ctx, p); err != nil {
			return err
		}
		m.record(ctx, a, "deps.ignore", r.f.ID, map[string]any{
			"package": r.f.Package, "findings": len(findingIDs), "mode": mode, "until_version": p.UntilVersion, "reason": reason,
		})
	}
	return nil
}

// Ignore is an active ignore rule.
type Ignore struct {
	ID           string
	Where        string
	Package      string
	Advisory     string
	UntilVersion string
	UntilAt      time.Time // zero = no time limit
	Reason       string
}

// Ignores lists the rules still in force.
func (m *Monitor) Ignores(ctx context.Context) ([]Ignore, error) {
	rows, err := m.q.ListFindingIgnores(ctx, sql.NullInt64{Int64: m.now().Unix(), Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Ignore, 0, len(rows))
	for _, r := range rows {
		i := Ignore{ID: r.ID, Where: r.Target, Package: r.Package, Advisory: r.AdvisoryID, UntilVersion: r.UntilVersion, Reason: r.Reason}
		if r.ProjectSlug != "" {
			i.Where = r.ProjectSlug + "/" + r.ServiceSlug
		}
		if r.UntilAt.Valid {
			i.UntilAt = time.Unix(r.UntilAt.Int64, 0)
		}
		out = append(out, i)
	}
	return out, nil
}

// Unignore removes an ignore rule.
func (m *Monitor) Unignore(ctx context.Context, a Actor, id string) error {
	n, err := m.q.DeleteFindingIgnore(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	m.record(ctx, a, "deps.unignore", id, nil)
	return nil
}

func (m *Monitor) record(ctx context.Context, a Actor, action, id string, summary map[string]any) {
	if m.o.Audit == nil {
		return
	}
	if err := m.o.Audit.Record(context.WithoutCancel(ctx), audit.Entry{
		ActorID: a.UserID, IP: a.IP, Action: action, Outcome: audit.OK,
		TargetType: "dependency_finding", TargetID: id, Summary: summary,
	}); err != nil {
		m.o.Log.Error("failed to write audit record", "action", action, "error", err)
	}
}

// --- notices ----------------------------------------------------------------

const (
	digestDailyKey  = "deps.digest.daily"
	digestWeeklyKey = "deps.digest.weekly"
)

// notify sends what is new: critical findings right away; the security
// ones once a day; updates once a week. A finding is only ever announced
// once (until it is resolved and comes back).
func (m *Monitor) notify(ctx context.Context) error {
	fs, err := m.Findings(ctx)
	if err != nil {
		return err
	}
	pending := map[string][]Finding{}
	for _, f := range fs {
		if !f.Ignored && !f.notified {
			pending[f.Level] = append(pending[f.Level], f)
		}
	}
	now := m.now()
	var errs []error
	if fs := pending[LevelCritical]; len(fs) > 0 {
		errs = append(errs, m.send(ctx, "critical", i18n.Tl(m.o.Locale, "deps.notice.critical", "n", len(fs)), fs))
	}
	if fs := pending[LevelSecurity]; len(fs) > 0 && m.due(ctx, digestDailyKey, now, 20*time.Hour) {
		if err := m.send(ctx, "security", i18n.Tl(m.o.Locale, "deps.notice.daily", "n", len(fs)), fs); err == nil {
			m.stamp(ctx, digestDailyKey, now)
		} else {
			errs = append(errs, err)
		}
	}
	updates := append(pending[LevelMinor], pending[LevelMajor]...)
	if len(updates) > 0 && m.due(ctx, digestWeeklyKey, now, 6*24*time.Hour+12*time.Hour) {
		if err := m.send(ctx, "updates", i18n.Tl(m.o.Locale, "deps.notice.weekly", "n", len(updates)), updates); err == nil {
			m.stamp(ctx, digestWeeklyKey, now)
		} else {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (m *Monitor) send(ctx context.Context, level, title string, fs []Finding) error {
	n := Notice{Level: level, Title: title, Path: "/updates"}
	idList := make([]string, 0, len(fs))
	for _, f := range fs {
		n.Lines = append(n.Lines, NoticeLine(m.o.Locale, f))
		idList = append(idList, f.ID)
	}
	m.mu.Lock()
	nt := m.notifier
	m.mu.Unlock()
	if err := nt.Notify(ctx, n); err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	return m.q.MarkDependencyFindingsNotified(ctx, dbq.MarkDependencyFindingsNotifiedParams{
		NotifiedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, Ids: idList,
	})
}

// NoticeLine is one finding in a notice: where, what, current → suggested
// and the advisory.
func NoticeLine(locale string, f Finding) string {
	line := f.Where() + " · " + f.Package + " " + f.Current
	if f.Suggested != "" {
		line += " → " + f.Suggested
	} else if f.Kind == KindVuln {
		line += " · " + i18n.Tl(locale, "deps.notice.no_fix")
	}
	if f.Advisory != "" {
		line += " · " + f.Advisory
	}
	return line
}

func (m *Monitor) due(ctx context.Context, key string, now time.Time, every time.Duration) bool {
	raw, err := m.q.GetSetting(ctx, key)
	if err != nil {
		return true
	}
	var at int64
	if json.Unmarshal([]byte(raw), &at) != nil {
		return true
	}
	return now.Sub(time.Unix(at, 0)) >= every
}

func (m *Monitor) stamp(ctx context.Context, key string, now time.Time) {
	b, _ := json.Marshal(now.Unix())
	if err := m.q.SetSetting(ctx, dbq.SetSettingParams{Key: key, ValueJson: string(b)}); err != nil {
		m.o.Log.Warn("store digest time", "error", err)
	}
}
