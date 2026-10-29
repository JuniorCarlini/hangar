package docker

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestWaitReport(t *testing.T) {
	for _, c := range []struct {
		name          string
		elapsed       time.Duration
		newest        string
		quiet         time.Duration
		want, without string
	}{
		{
			"app writing", 80*time.Second + 400*time.Millisecond, "Copying '/app/static/admin/css/base.css'", 0,
			"waiting for the app to answer GET /health/ on port 8000: 1m20s of 5m0s; last output: Copying '/app/static/admin/css/base.css'", "",
		},
		{
			"app quiet", 45 * time.Second, "", 30 * time.Second,
			"waiting for the app to answer GET /health/ on port 8000: 45s of 5m0s; no output for 30s", "last output",
		},
		{
			"first report", 15 * time.Second, "", 0,
			"waiting for the app to answer GET /health/ on port 8000: 15s of 5m0s", "no output",
		},
	} {
		got := waitReport("the app to answer GET /health/ on port 8000", c.elapsed, 5*time.Minute, c.newest, c.quiet)
		if got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		if c.without != "" && strings.Contains(got, c.without) {
			t.Errorf("%s: %q must not say %q", c.name, got, c.without)
		}
	}
}

func TestHealthTarget(t *testing.T) {
	running := container.InspectResponse{State: &container.State{Running: true}}
	checked := container.InspectResponse{State: &container.State{Running: true, Health: &container.Health{Status: container.Starting}}}
	for _, c := range []struct {
		name string
		c    container.InspectResponse
		opt  node.DeployOptions
		want string
	}{
		{"image healthcheck", checked, node.DeployOptions{Port: 8000, HealthPath: "/health/"}, "the healthcheck to pass"},
		{"http path", running, node.DeployOptions{Port: 8000, HealthPath: "/health/"}, "the app to answer GET /health/ on port 8000"},
		{"port only", running, node.DeployOptions{Port: 5432}, "the app to accept connections on port 5432"},
		{"no port", running, node.DeployOptions{}, ""},
	} {
		if got := healthTarget(c.c, c.opt); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The reason stays on the first line (alerts show only that), with what
// became of the previous version; the app's output goes below.
func TestStartFailureCarriesTheOutput(t *testing.T) {
	sf := &startFailure{
		reason: "the new container stopped (exit code 1) after 3s",
		output: []string{"Operations to perform:", "django.db.utils.OperationalError: connection refused"},
	}
	wrapped := fmt.Errorf("%w (the previous version is still live)", sf)
	var got *startFailure
	if !errors.As(wrapped, &got) {
		t.Fatal("the start failure must stay reachable through the wrapping")
	}
	err := &withOutput{err: wrapped, output: got.output}
	want := "the new container stopped (exit code 1) after 3s (the previous version is still live)\n" +
		"last output:\nOperations to perform:\ndjango.db.utils.OperationalError: connection refused"
	if err.Error() != want {
		t.Errorf("got %q\nwant %q", err.Error(), want)
	}
	if !errors.Is(err, sf) {
		t.Error("withOutput must unwrap to the deploy error")
	}
	if sf.Error() != sf.reason {
		t.Errorf("a start failure alone is its reason: %q", sf.Error())
	}
}
