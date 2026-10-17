package alerts

import "context"

// EventKinds are alerts raised by something that happened in the panel
// (neither a server rule nor a security event). They reach the channels by
// severity, like server alerts, and can be muted.
var EventKinds = []string{"deploy_failed"}

// What became of the previous version of a failed deploy (the values of
// node.Previous*, repeated here so alerts does not depend on node).
const (
	previousLive     = "live"
	previousRestored = "restored"
	previousDown     = "down"
	previousNone     = "none"
)

// DeployFailure is a failed deploy as the alert shows it. Reason must
// already be masked: it goes to the channels as written.
type DeployFailure struct {
	ServiceID string
	Service   string // project/service
	Trigger   string // deploy.trigger.* key
	Phase     string // deploy.phase.* key
	Reason    string
	Previous  string // live, restored, down or none
}

// deployKey groups one service's failures of one severity: retries within
// the dedup window count as repeats, and a service that went down after a
// warning is still told at once (another key).
func deployKey(serviceID string, sev Severity) string {
	return "deploy_failed:" + serviceID + ":" + string(sev)
}

// DeployFailedEvent builds the alert: critical when the service was left
// down, a warning when the previous version kept serving or came back (or
// there was none: nothing that served is gone).
func DeployFailedEvent(f DeployFailure) Event {
	sev := Warning
	if f.Previous == previousDown {
		sev = Critical
	}
	switch f.Previous {
	case previousLive, previousRestored, previousDown, previousNone:
	default:
		f.Previous = previousNone
	}
	return Event{
		Kind: "deploy_failed", Severity: sev, Category: Server, Key: deployKey(f.ServiceID, sev),
		Params: map[string]string{
			"service": f.Service, "trigger": f.Trigger, "phase": f.Phase, "reason": f.Reason, "previous": f.Previous,
		},
	}
}

// DeployFailed raises the alert of a failed deploy.
func (s *Service) DeployFailed(ctx context.Context, f DeployFailure) error {
	_, err := s.Notify(ctx, DeployFailedEvent(f))
	return err
}

// DeploySucceeded closes the service's open deploy alerts with a "back to
// normal" notice (nothing is sent when none was open).
func (s *Service) DeploySucceeded(ctx context.Context, serviceID, service string) error {
	for _, sev := range []Severity{Warning, Critical} {
		if _, err := s.Notify(ctx, Event{
			Kind: "deploy_failed", Severity: sev, Category: Server, Key: deployKey(serviceID, sev),
			Params: map[string]string{"service": service}, Resolved: true,
		}); err != nil {
			return err
		}
	}
	return nil
}
