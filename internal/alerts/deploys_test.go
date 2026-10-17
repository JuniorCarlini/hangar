package alerts

import (
	"context"
	"strings"
	"testing"
)

func TestDeployFailureAlert(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "warning")
	ctx := context.Background()

	// The previous version came back: a warning, saying so, in words.
	err := e.svc.DeployFailed(ctx, DeployFailure{
		ServiceID: "svc_1", Service: "lab/web", Trigger: "webhook", Phase: "validate",
		Reason: "the validation command exited with 1", Previous: "restored",
	})
	if err != nil {
		t.Fatal(err)
	}
	msgs := e.tg.messages()
	if len(msgs) != 1 {
		t.Fatalf("messages: %+v", msgs)
	}
	text := msgs[0].Text
	for _, want := range []string{"lab/web", "validando", "webhook", "exited with 1", "voltou ao ar automaticamente"} {
		if !strings.Contains(text, want) {
			t.Errorf("message lacks %q:\n%s", want, text)
		}
	}
	if strings.HasPrefix(text, "🔴") {
		t.Errorf("a restored service is not critical:\n%s", text)
	}

	// Left down: critical, and not swallowed by the open warning.
	if err := e.svc.DeployFailed(ctx, DeployFailure{
		ServiceID: "svc_1", Service: "lab/web", Trigger: "manual", Phase: "health", Reason: "not healthy", Previous: "down",
	}); err != nil {
		t.Fatal(err)
	}
	msgs = e.tg.messages()
	if len(msgs) != 2 || !strings.HasPrefix(msgs[1].Text, "🔴") || !strings.Contains(msgs[1].Text, "fora do ar") {
		t.Fatalf("down: %+v", msgs)
	}

	// A good deploy closes both, once.
	if err := e.svc.DeploySucceeded(ctx, "svc_1", "lab/web"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeploySucceeded(ctx, "svc_1", "lab/web"); err != nil {
		t.Fatal(err)
	}
	if n := len(e.tg.messages()); n != 4 {
		t.Fatalf("resolved notices: %d messages", n)
	}
}

func TestDeployFailedEventSeverity(t *testing.T) {
	for prev, want := range map[string]Severity{"live": Warning, "restored": Warning, "none": Warning, "down": Critical, "bogus": Warning} {
		ev := DeployFailedEvent(DeployFailure{ServiceID: "svc_1", Previous: prev})
		if ev.Severity != want || ev.Category != Server {
			t.Errorf("%s: %+v", prev, ev)
		}
		if prev == "bogus" && ev.Params["previous"] != "none" {
			t.Errorf("an unknown state must not reach the template: %q", ev.Params["previous"])
		}
	}
	_, text := Texts("en", "deploy_failed", false, map[string]string{
		"service": "lab/web", "trigger": "rebuild", "phase": "build", "reason": "boom", "previous": "live",
	})
	if !strings.Contains(text, "from scratch") || !strings.Contains(text, "still live") {
		t.Errorf("en text: %s", text)
	}
}
