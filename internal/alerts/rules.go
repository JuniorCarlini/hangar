package alerts

import (
	"context"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// RuleDef is a server rule and its defaults (docs/06).
type RuleDef struct {
	Kind     string
	Severity Severity
	// Threshold is the default limit; 0 means the rule has none.
	Threshold int
	Min, Max  int
	// For is how long the condition must hold before the alert fires.
	For time.Duration
}

// Rules are the server rules, in display order.
var Rules = []RuleDef{
	{Kind: "container_down", Severity: Critical, For: 30 * time.Second},
	{Kind: "restart_loop", Severity: Critical, Threshold: 3, Min: 1, Max: 50},
	{Kind: "oom", Severity: Warning},
	{Kind: "service_memory", Severity: Warning, Threshold: 90, Min: 50, Max: 99, For: 5 * time.Minute},
	{Kind: "host_cpu", Severity: Warning, Threshold: 90, Min: 50, Max: 100, For: 5 * time.Minute},
	{Kind: "host_memory", Severity: Warning, Threshold: 90, Min: 50, Max: 99, For: 5 * time.Minute},
	{Kind: "host_disk", Severity: Warning, Threshold: 85, Min: 50, Max: 99, For: time.Minute},
	// A volume with a size limit (docs/05): a warning early, a critical
	// alert when the app is about to get "no space left".
	{Kind: "volume_disk", Severity: Warning, Threshold: 80, Min: 50, Max: 99, For: time.Minute},
	{Kind: "volume_full", Severity: Critical, Threshold: 95, Min: 50, Max: 99, For: time.Minute},
}

// RuleSetting is a rule as configured.
type RuleSetting struct {
	RuleDef
	Enabled bool
	Value   int // the threshold in use
}

func ruleDef(kind string) (RuleDef, bool) {
	for _, r := range Rules {
		if r.Kind == kind {
			return r, true
		}
	}
	return RuleDef{}, false
}

// RuleSettings returns every server rule with its saved settings (or the
// defaults).
func (s *Service) RuleSettings(ctx context.Context) ([]RuleSetting, error) {
	rows, err := s.q.ListAlertRules(ctx)
	if err != nil {
		return nil, err
	}
	saved := map[string]dbq.AlertRule{}
	for _, r := range rows {
		saved[r.Kind] = r
	}
	out := make([]RuleSetting, 0, len(Rules))
	for _, d := range Rules {
		rs := RuleSetting{RuleDef: d, Enabled: true, Value: d.Threshold}
		if r, ok := saved[d.Kind]; ok {
			rs.Enabled = r.Enabled == 1
			if d.Threshold > 0 && r.Threshold >= int64(d.Min) && r.Threshold <= int64(d.Max) {
				rs.Value = int(r.Threshold)
			}
		}
		out = append(out, rs)
	}
	return out, nil
}

// RuleInput is one rule from the settings form.
type RuleInput struct {
	Kind    string
	Enabled bool
	Value   int
}

// SaveRules stores the rule settings. Unknown kinds and thresholds out of
// range are refused as a whole.
func (s *Service) SaveRules(ctx context.Context, a Actor, in []RuleInput) error {
	now := s.opt.Now().Unix()
	changes := map[string]any{}
	for _, r := range in {
		d, ok := ruleDef(r.Kind)
		if !ok {
			return i18n.E("alerts.error.rule")
		}
		if d.Threshold > 0 && (r.Value < d.Min || r.Value > d.Max) {
			return i18n.E("alerts.error.threshold", "min", d.Min, "max", d.Max)
		}
		if d.Threshold == 0 {
			r.Value = 0
		}
		changes[r.Kind] = map[string]any{"enabled": r.Enabled, "threshold": r.Value}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)
	for _, r := range in {
		d, _ := ruleDef(r.Kind)
		v := r.Value
		if d.Threshold == 0 {
			v = 0
		}
		if err := q.UpsertAlertRule(ctx, dbq.UpsertAlertRuleParams{Kind: r.Kind, Enabled: boolInt(r.Enabled), Threshold: int64(v), UpdatedAt: now}); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.Record(context.WithoutCancel(ctx), audit.Entry{
			ActorID: a.UserID, IP: a.IP, Action: "alerts.rules.update", Outcome: audit.OK, Summary: changes,
		})
	}
	return nil
}
