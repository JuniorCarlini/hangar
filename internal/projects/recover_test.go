package projects

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A panel killed in the middle of a deploy leaves the row "running". Until
// startup recovery, that blocked every later deploy of the service and hid
// it from the reconciler and the alert rules.
func TestInterruptedDeployIsRecoveredAtStartup(t *testing.T) {
	f := newFixture(t)
	_, serviceID := f.service(t)
	ctx := context.Background()

	// What a SIGKILL during "pull" leaves behind.
	if err := f.m.q.CreateDeployment(ctx, dbq.CreateDeploymentParams{
		ID: "dep_killed", ServiceID: serviceID, Image: "nginx:1.29-alpine", EnvHash: "x", Trigger: "manual",
		StartedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); !errors.Is(err, ErrDeployRunning) {
		t.Fatalf("before recovery the stuck row blocks deploys: err = %v", err)
	}
	if w, _ := f.m.WatchedServices(ctx); len(w) != 0 {
		t.Fatalf("before recovery the service is invisible to the alert rules: %+v", w)
	}

	n, err := f.m.RecoverInterrupted(ctx)
	if err != nil || n != 1 {
		t.Fatalf("RecoverInterrupted = %d, %v", n, err)
	}
	d, err := f.m.q.GetDeployment(ctx, dbq.GetDeploymentParams{ID: "dep_killed", ServiceID: serviceID})
	if err != nil || d.Status != "failed" || !d.Error.Valid || !d.FinishedAt.Valid {
		t.Fatalf("interrupted deploy = %+v, %v", d, err)
	}
	if w, _ := f.m.WatchedServices(ctx); len(w) != 1 {
		t.Errorf("after recovery the service is watched again: %+v", w)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatalf("after recovery deploys work: %v", err)
	}
	f.m.Wait()

	// Nothing left to recover the second time.
	if n, err := f.m.RecoverInterrupted(ctx); err != nil || n != 0 {
		t.Errorf("second run = %d, %v", n, err)
	}
}
