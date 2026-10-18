package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeEdge struct {
	mu       sync.Mutex
	checkErr error
	healed   int
	applied  int
	degraded string
}

func (e *fakeEdge) Apply(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applied++
	e.degraded = ""
	return nil
}

func (e *fakeEdge) Check(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.checkErr
}

func (e *fakeEdge) Heal(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healed++
	e.checkErr = nil
	return nil
}

func (e *fakeEdge) Degraded() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.degraded
}

func (e *fakeEdge) WritePages(map[string][]byte) error { return nil }

func (e *fakeEdge) counts() (healed, applied int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.healed, e.applied
}

// keeperRecorder collects what the keeper reported.
type keeperRecorder struct {
	mu     sync.Mutex
	starts int
	wired  int
	opens  int
	status string
}

func (r *keeperRecorder) get() (starts, wired, opens int, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.starts, r.wired, r.opens, r.status
}

func fastKeeper(t *testing.T) {
	t.Helper()
	oldMin, oldMax, oldCheck := edgeRetryMin, edgeRetryMax, edgeCheckEvery
	edgeRetryMin, edgeRetryMax, edgeCheckEvery = time.Millisecond, 4*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { edgeRetryMin, edgeRetryMax, edgeCheckEvery = oldMin, oldMax, oldCheck })
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// An edge that fails at boot (Caddy or Docker late) is retried until it comes
// up, then wired once; a busy public listener port is retried too, never
// fatal. Nothing needs a restart over SSH.
func TestEdgeKeeperRetriesUntilUp(t *testing.T) {
	fastKeeper(t)
	rec := &keeperRecorder{}
	e := &fakeEdge{}
	k := &edgeKeeper{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		start: func(context.Context) (edgeProxy, error) {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			rec.starts++
			if rec.starts < 3 {
				return nil, errors.New("caddy admin: connection refused")
			}
			return e, nil
		},
		wire: func(edgeProxy) { rec.mu.Lock(); rec.wired++; rec.mu.Unlock() },
		public: func(context.Context) error {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			rec.opens++
			if rec.opens < 2 {
				return errors.New("address already in use")
			}
			return nil
		},
		status: func(s string) { rec.mu.Lock(); rec.status = s; rec.mu.Unlock() },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if k.tryUp(ctx) {
		t.Fatal("the first attempt fails")
	}
	if _, _, _, s := rec.get(); !strings.HasPrefix(s, "edge down: ") {
		t.Errorf("status = %q, want the reason the edge is down", s)
	}
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	eventually(t, "the edge and the public listener", k.ready)
	starts, wired, opens, status := rec.get()
	if starts != 3 || wired != 1 || opens != 2 || status != "" {
		t.Errorf("starts=%d wired=%d opens=%d status=%q", starts, wired, opens, status)
	}
	if k.current() != e {
		t.Error("the keeper should hold the started edge")
	}
	cancel()
	<-done
}

// A Caddy that stops answering is healed by the periodic check, and one on a
// fallback config is offered the full config again.
func TestEdgeKeeperHealsAndRetriesTheFullConfig(t *testing.T) {
	fastKeeper(t)
	e := &fakeEdge{checkErr: errors.New("caddy admin: no such file"), degraded: "caddy rejected the config"}
	var mu sync.Mutex
	status := "unset"
	k := &edgeKeeper{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		start:  func(context.Context) (edgeProxy, error) { return e, nil },
		wire:   func(edgeProxy) {},
		status: func(s string) { mu.Lock(); status = s; mu.Unlock() },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !k.tryUp(ctx) {
		t.Fatal("start succeeds")
	}
	mu.Lock()
	if !strings.HasPrefix(status, "edge degraded: ") {
		t.Errorf("status = %q, want degraded", status)
	}
	mu.Unlock()
	done := make(chan struct{})
	go func() { k.run(ctx); close(done) }()
	eventually(t, "heal and full config", func() bool {
		h, a := e.counts()
		mu.Lock()
		defer mu.Unlock()
		return h == 1 && a >= 1 && status == ""
	})
	cancel()
	<-done
}
