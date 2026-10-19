package node

import (
	"testing"
	"time"
)

func TestHealthWait(t *testing.T) {
	const limit = 15 * time.Minute
	for _, c := range []struct {
		name string
		h    *Health
		want time.Duration
	}{
		{"no healthcheck", nil, DefaultHealthTimeout},
		{"quick check", &Health{Interval: 10 * time.Second, Timeout: 5 * time.Second, Retries: 5}, DefaultHealthTimeout},
		{"Docker defaults", &Health{}, DefaultHealthTimeout}, // 0 + 30s×3 + 30s = 2m
		{"slow start", &Health{StartPeriod: 5 * time.Minute, Interval: 30 * time.Second, Timeout: 10 * time.Second, Retries: 4}, 7*time.Minute + 10*time.Second},
		{"defaults after a start period", &Health{StartPeriod: 3 * time.Minute}, 5 * time.Minute},
		{"beyond the deploy timeout", &Health{StartPeriod: time.Hour}, limit},
	} {
		if got := HealthWait(c.h, limit); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if got := HealthWait(&Health{StartPeriod: time.Hour}, 0); got <= time.Hour {
		t.Errorf("no limit: %s", got)
	}
}
