package node

import (
	"testing"
	"time"
)

func TestHealthWait(t *testing.T) {
	const limit = 15 * time.Minute
	slow := &Health{StartPeriod: 5 * time.Minute, Interval: 30 * time.Second, Timeout: 10 * time.Second, Retries: 4}
	for _, c := range []struct {
		name  string
		h     *Health
		grace time.Duration
		want  time.Duration
	}{
		{"no healthcheck", nil, 0, DefaultHealthTimeout},
		{"quick check", &Health{Interval: 10 * time.Second, Timeout: 5 * time.Second, Retries: 5}, 0, DefaultHealthTimeout},
		{"Docker defaults", &Health{}, 0, DefaultHealthTimeout}, // 0 + 30s×3 + 30s = 2m
		{"slow start", slow, 0, 7*time.Minute + 10*time.Second},
		{"defaults after a start period", &Health{StartPeriod: 4 * time.Minute}, 0, 6 * time.Minute},
		{"beyond the deploy timeout", &Health{StartPeriod: time.Hour}, 0, limit},
		{"grace set on the service", nil, 10 * time.Minute, 10 * time.Minute},
		{"short grace", nil, time.Minute, time.Minute},
		{"grace shorter than the healthcheck", slow, time.Minute, 7*time.Minute + 10*time.Second},
		{"grace longer than the healthcheck", &Health{Interval: 10 * time.Second}, 12 * time.Minute, 12 * time.Minute},
		{"grace beyond the deploy timeout", nil, time.Hour, limit},
	} {
		if got := HealthWait(c.h, c.grace, limit); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if got := HealthWait(&Health{StartPeriod: time.Hour}, 0, 0); got <= time.Hour {
		t.Errorf("no limit: %s", got)
	}
	// Django or Rails migrating and collecting static files before it
	// listens takes a few minutes: the default must cover it.
	if DefaultHealthTimeout < 5*time.Minute {
		t.Errorf("default %s is too short for a typical app boot", DefaultHealthTimeout)
	}
}
