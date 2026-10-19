package alerts

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// A limited volume warns at 80 %, goes critical at 95 % (once each
// crossing) and says when it is back to normal.
func TestMonitorLimitedVolumes(t *testing.T) {
	e := newTestEnv(t, nil)
	e.telegram(t, "info")
	ctx := context.Background()
	var mu sync.Mutex
	used := uint64(10)
	var fail error
	m := e.svc.NewMonitor(nil, nil)
	m.SetVolumes(func(context.Context) ([]VolumeUsage, error) {
		mu.Lock()
		defer mu.Unlock()
		return []VolumeUsage{{Key: "hangar_lab_db_data", Name: "lab/db/data", Used: used, Total: 100}}, fail
	})
	set := func(n uint64, err error) {
		mu.Lock()
		used, fail = n, err
		mu.Unlock()
	}
	round := func() {
		m.Check(ctx)
		e.clock.add(2 * time.Minute)
		m.Check(ctx)
	}
	kinds := func() string {
		var out []string
		for _, a := range must(e.svc.Recent(ctx, true, 20)) {
			out = append(out, a.Kind)
		}
		return strings.Join(out, ",")
	}

	round()
	if len(e.tg.messages()) != 0 {
		t.Fatal("alert at 10 %")
	}
	set(85, nil)
	round()
	round() // still above: no second message
	if got := e.tg.messages(); len(got) != 1 || !strings.Contains(got[0].Text, "lab/db/data") || !strings.Contains(got[0].Text, "85") {
		t.Fatalf("messages = %v", got)
	}
	set(97, nil)
	round()
	if !strings.Contains(kinds(), "volume_full") {
		t.Fatalf("alerts = %s", kinds())
	}
	// The warning stays (no "back to normal" while it got worse).
	if n := len(e.tg.messages()); n != 2 {
		t.Fatalf("%d messages after going critical", n)
	}
	// Docker or the unit cannot be read: nothing fires or clears.
	n := len(e.tg.messages())
	set(10, errors.New("boom"))
	round()
	if len(e.tg.messages()) != n {
		t.Fatal("a failed reading changed the alerts")
	}
	set(10, nil)
	round()
	if len(e.tg.messages()) == n {
		t.Fatal("no back-to-normal notice")
	}
	// The thresholds are rules like the others.
	if err := e.svc.SaveRules(ctx, Actor{}, []RuleInput{{Kind: "volume_disk", Enabled: true, Value: 60}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SaveRules(ctx, Actor{}, []RuleInput{{Kind: "volume_full", Enabled: true, Value: 20}}); err == nil {
		t.Error("threshold below the minimum accepted")
	}
}
