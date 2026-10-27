package projects

import (
	"context"
	"errors"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Automatic deploys by polling, as Easypanel does it: one switch per
// service, nothing to set up on GitHub and no public address for the
// panel. Every minute the panel reads the branch's head (ls-remote, with
// the service's credential) and deploys a new commit; the deploy only goes
// live after its checks pass, as any other.

// SetAutoDeploy turns automatic deploys on or off. Turning them on reads
// the branch now: it proves the credential still reaches it and makes the
// current head the one already seen, so only the next push deploys.
func (m *Manager) SetAutoDeploy(ctx context.Context, a Actor, serviceID string, on bool) error {
	g, ok, err := m.gitRow(ctx, serviceID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	seen := ""
	if on {
		s, err := m.q.GetServiceByID(ctx, serviceID)
		if err != nil {
			return err
		}
		if seen, err = m.branchHead(ctx, s, g); err != nil {
			return err
		}
	}
	var flag int64
	if on {
		flag = 1
	}
	if err := m.q.SetServiceGitAuto(ctx, dbq.SetServiceGitAutoParams{AutoDeploy: flag, AutoSeen: seen, UpdatedAt: m.now().Unix(), ServiceID: serviceID}); err != nil {
		return err
	}
	m.record(ctx, a, "service.git.auto", "service", serviceID, audit.OK, map[string]any{"on": on})
	return nil
}

func (m *Manager) branchHead(ctx context.Context, s dbq.Service, g dbq.ServiceGit) (string, error) {
	token, err := m.cloneToken(ctx, s, g)
	if err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return gitsrc.Head(cctx, gitsrc.Source{URL: g.RepoUrl, Branch: g.Branch, Token: token})
}

// RunAutoDeploy looks at every switched-on branch each interval until ctx
// ends.
func (m *Manager) RunAutoDeploy(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.autoDeployOnce(ctx)
		}
	}
}

func (m *Manager) autoDeployOnce(ctx context.Context) {
	rows, err := m.q.ListAutoDeployServices(ctx)
	if err != nil {
		m.log.Error("automatic deploys", "error", err)
		return
	}
	for _, r := range rows {
		if ctx.Err() != nil {
			return
		}
		m.autoDeploy(ctx, r)
	}
}

// autoDeploy deploys one service when its branch moved since the last look.
// A branch it cannot read (token revoked, GitHub down) is only logged and
// tried again next time.
func (m *Manager) autoDeploy(ctx context.Context, r dbq.ListAutoDeployServicesRow) {
	g, ok, err := m.gitRow(ctx, r.ServiceID)
	if err != nil || !ok {
		return
	}
	s, err := m.q.GetServiceByID(ctx, r.ServiceID)
	if err != nil {
		return
	}
	head, err := m.branchHead(ctx, s, g)
	if err != nil {
		m.log.Warn("automatic deploy: read the branch", "service", r.ProjectSlug+"/"+r.ServiceSlug, "error", err)
		return
	}
	if head == g.AutoSeen {
		return
	}
	if err := m.q.SetServiceGitSeen(ctx, dbq.SetServiceGitSeenParams{AutoSeen: head, ServiceID: r.ServiceID}); err != nil {
		m.log.Error("automatic deploy: note the head", "error", err)
		return
	}
	if g.AutoSeen == "" {
		return // first look: note where the branch is, deploy the next push
	}
	a := Actor{}
	summary := map[string]any{"commit": shortSHA(head), "branch": g.Branch}
	_, err = m.Deploy(ctx, a, r.ProjectSlug, r.ServiceSlug, "auto")
	switch {
	case errors.Is(err, ErrDeployRunning):
		m.queue(r.ServiceID, queuedDeploy{project: r.ProjectSlug, service: r.ServiceSlug, actor: a, trigger: "auto"})
		if n, err := m.q.HasRunningDeployment(ctx, r.ServiceID); err == nil && n == 0 {
			m.runQueued(context.WithoutCancel(ctx), r.ServiceID)
		}
		summary["queued"] = true
	case err != nil:
		m.record(ctx, a, "service.git.auto_deploy", "service", r.ServiceID, audit.Error, summary)
		m.log.Warn("automatic deploy", "service", r.ProjectSlug+"/"+r.ServiceSlug, "error", err)
		return
	}
	m.record(ctx, a, "service.git.auto_deploy", "service", r.ServiceID, audit.OK, summary)
}
