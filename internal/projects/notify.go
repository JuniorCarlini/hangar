package projects

import (
	"context"
	"strings"
)

// DeployFailure is what the alert channels hear about a failed deploy. It
// carries no secret: Reason went through the deploy's mask.
type DeployFailure struct {
	ServiceID  string
	Service    string // project/service
	Deployment string
	Trigger    string // manual, webhook, rebuild…
	Phase      string // node.Phase* where it failed
	Reason     string // short, masked
	// Previous is node.PreviousLive, PreviousRestored, PreviousDown or
	// PreviousNone.
	Previous string
}

// DeployNotifier tells the operator about deploys that failed (manual,
// webhook, rebuild, any trigger), and that a service deploys fine again.
type DeployNotifier interface {
	DeployFailed(ctx context.Context, f DeployFailure)
	DeploySucceeded(ctx context.Context, serviceID, service string)
}

// SetDeployNotifier plugs the alert channels in. Call it before deploys run.
func (m *Manager) SetDeployNotifier(n DeployNotifier) { m.notifier = n }

// reasonMax keeps the alert to a line: the full error is in the history.
const reasonMax = 160

// shortReason is the first line of an (already masked) error, cut short.
func shortReason(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if r := []rune(s); len(r) > reasonMax {
		s = string(r[:reasonMax]) + "…"
	}
	return s
}
