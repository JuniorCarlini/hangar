package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Drift is a mismatch between what the panel wants and what Docker has.
type Drift struct {
	ServiceID string
	Name      string
	Problem   string // "missing", "stopped" or "orphan"
}

// Reconcile compares intent (database) with reality (Docker). It does not
// fix anything on its own: it reports. Auto-fixing would hide whoever changed
// things outside the panel.
func (m *Manager) Reconcile(ctx context.Context) ([]Drift, error) {
	if m.node == nil {
		return nil, ErrDockerDisabled
	}
	svcs, err := m.q.ListAllServices(ctx)
	if err != nil {
		return nil, err
	}
	managed, err := m.node.ListManaged(ctx)
	if err != nil {
		return nil, err
	}
	byService := map[string]node.Managed{}
	for _, c := range managed {
		byService[c.ServiceID] = c
	}
	var out []Drift
	known := map[string]bool{}
	for _, s := range svcs {
		known[s.ID] = true
		name := node.ContainerName(s.ProjectSlug, s.Slug)
		if n, _ := m.q.HasRunningDeployment(ctx, s.ID); n > 0 {
			continue // deploy in progress: the container disappears and returns on purpose
		}
		if m.Held(s.ProjectSlug, s.Slug) {
			continue // paused or stopped by a backup, which lets it go on
		}
		c, ok := byService[s.ID]
		switch {
		case !ok:
			if last, err := m.q.LastLiveDeployment(ctx, s.ID); err == nil && last.ID != "" {
				out = append(out, Drift{ServiceID: s.ID, Name: name, Problem: "missing"})
			}
		case s.DesiredState == "running" && c.State != "running" && c.State != "restarting":
			out = append(out, Drift{ServiceID: s.ID, Name: name, Problem: "stopped"})
		}
	}
	for _, c := range managed {
		if c.ServiceID != "" && !known[c.ServiceID] {
			out = append(out, Drift{ServiceID: c.ServiceID, Name: c.Name, Problem: "orphan"})
		}
	}
	return out, nil
}

// interruptedError is what the deploy history shows for a deploy the panel
// did not see to the end.
const interruptedError = "interrupted: the panel stopped before this deploy finished; deploy again"

// RecoverInterrupted runs once at startup, before anything can start a new
// deploy. A deploy left "running" by a killed panel would otherwise block
// every later deploy of the service (ErrDeployRunning) and hide it from the
// reconciler and the alert rules for good. Each one is marked failed, and
// the containers it left half-way are tidied (node.Recoverer): the site
// keeps the version that was serving it.
func (m *Manager) RecoverInterrupted(ctx context.Context) (int, error) {
	rows, err := m.q.ListRunningDeployments(ctx)
	if err != nil {
		return 0, err
	}
	rec, _ := m.node.(node.Recoverer)
	for _, d := range rows {
		action := ""
		if rec != nil {
			if action, err = rec.RecoverDeploy(ctx, d.ProjectSlug, d.ServiceSlug); err != nil {
				// The deploy is still marked failed: a stuck "running" row is
				// worse than a leftover container the next deploy removes.
				m.log.Warn("tidy interrupted deploy", "service", d.ProjectSlug+"/"+d.ServiceSlug, "error", err)
			}
		}
		if err := m.q.FinishDeployment(ctx, dbq.FinishDeploymentParams{
			Status: "failed", Error: sql.NullString{String: interruptedError, Valid: true},
			FinishedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: d.ID,
		}); err != nil {
			return 0, err
		}
		if action == "promoted-next" {
			// The new version had passed the health check and is the one
			// serving now: the history must say so, or a rollback would
			// pick the wrong "previous" version.
			// The container was created from the pinned image: it is the
			// image_ref the deploy would have recorded.
			if st, err := m.node.Status(ctx, d.ProjectSlug, d.ServiceSlug); err == nil && st.Image != "" {
				_ = m.q.SetDeploymentImageRef(ctx, dbq.SetDeploymentImageRefParams{ImageRef: st.Image, ID: d.ID})
			}
			_ = m.q.SupersedeLive(ctx, dbq.SupersedeLiveParams{ServiceID: d.ServiceID, ID: d.ID})
			_ = m.q.FinishDeployment(ctx, dbq.FinishDeploymentParams{
				Status: "live", FinishedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: d.ID,
			})
		}
		m.log.Warn("deploy interrupted by a panel restart", "service", d.ProjectSlug+"/"+d.ServiceSlug, "deploy", d.ID, "containers", action)
		m.record(ctx, Actor{}, "service.deploy", "service", d.ServiceID, audit.Error,
			map[string]any{"deploy": d.ID, "error": "interrupted", "containers": action})
	}
	return len(rows), nil
}

// RunReconciler checks every interval and records each new mismatch once
// (without flooding the audit log while it persists).
func (m *Manager) RunReconciler(ctx context.Context, every time.Duration) {
	seen := m.recordedDrifts(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		drifts, err := m.Reconcile(ctx)
		if err != nil {
			continue
		}
		current := map[string]bool{}
		for _, d := range drifts {
			key := d.Name + "|" + d.Problem
			current[key] = true
			if seen[key] {
				continue
			}
			m.log.Warn("panel and Docker disagree", "container", d.Name, "problem", d.Problem)
			m.record(ctx, Actor{}, "service.drift", "service", d.ServiceID, audit.Error,
				map[string]any{"container": d.Name, "problem": d.Problem})
		}
		seen = current
	}
}

// recordedDrifts are the mismatches already in the audit log: a panel
// restart must not record the same leftover container again each time.
func (m *Manager) recordedDrifts(ctx context.Context) map[string]bool {
	seen := map[string]bool{}
	if m.audit == nil {
		return seen
	}
	rows, err := m.audit.Recent(ctx, []string{"service.drift"}, 200)
	if err != nil {
		return seen
	}
	for _, r := range rows {
		var sum struct{ Container, Problem string }
		if json.Unmarshal([]byte(r.SummaryJson), &sum) == nil && sum.Container != "" {
			seen[sum.Container+"|"+sum.Problem] = true
		}
	}
	return seen
}

// Watched is a service that should be running right now, with its
// container's state: what the alert rules look at.
type Watched struct {
	ServiceID string
	Name      string // project_service
	Status    node.Status
}

// WatchedServices lists the services that should be running: wanted
// running, deployed at least once and not in the middle of a deploy (when
// the container disappears on purpose) and not held by a backup (paused
// or stopped for a copy). Stopped by the user is not "down".
func (m *Manager) WatchedServices(ctx context.Context) ([]Watched, error) {
	if m.node == nil {
		return nil, ErrDockerDisabled
	}
	svcs, err := m.q.ListAllServices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Watched, 0, len(svcs))
	for _, s := range svcs {
		if s.DesiredState != "running" {
			continue
		}
		if n, err := m.q.HasRunningDeployment(ctx, s.ID); err != nil || n > 0 {
			continue
		}
		if m.Held(s.ProjectSlug, s.Slug) {
			continue // paused or stopped by a backup: not down
		}
		if last, err := m.q.LastLiveDeployment(ctx, s.ID); err != nil || last.ID == "" {
			continue
		}
		// One failed reading fails the whole list: the caller then keeps its
		// previous picture instead of thinking the service went away.
		st, err := m.node.Status(ctx, s.ProjectSlug, s.Slug)
		if err != nil {
			return nil, err
		}
		out = append(out, Watched{ServiceID: s.ID, Name: node.ContainerName(s.ProjectSlug, s.Slug), Status: st})
	}
	return out, nil
}
