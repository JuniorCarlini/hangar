package auth

import (
	"context"
	"errors"
	"runtime"
	"runtime/debug"
	"time"
)

// Each argon2id verification uses ~64 MiB on purpose (it makes brute force
// expensive). Without a limit, many simultaneous login attempts from
// different IPs would take the panel down for lack of memory. The pool caps
// how many run at once and how many wait; the rest get ErrBusy right away.
const (
	argonConcurrent = 2
	argonQueue      = 16
	argonWait       = 10 * time.Second
)

// ErrBusy is returned when too many verifications are queued.
var ErrBusy = errors.New("too many login attempts right now; try again shortly")

type argonPool struct {
	run   chan struct{}
	queue chan struct{}
}

func newArgonPool() *argonPool {
	return &argonPool{run: make(chan struct{}, argonConcurrent), queue: make(chan struct{}, argonQueue)}
}

// do runs fn within the limit.
func (p *argonPool) do(ctx context.Context, fn func()) error {
	select {
	case p.queue <- struct{}{}:
	default:
		return ErrBusy
	}
	defer func() { <-p.queue }()

	ctx, cancel := context.WithTimeout(ctx, argonWait)
	defer cancel()
	select {
	case p.run <- struct{}{}:
	case <-ctx.Done():
		return ErrBusy
	}
	// Collect the previous verification's buffer before allocating a new
	// one: under a burst, garbage from finished ones would otherwise pile up
	// next to the two running (load test: 211 MB peak before,
	// within the unit's MemoryHigh but far above GOMEMLIMIT).
	runtime.GC()
	fn()
	<-p.run
	// Give the ~64 MiB argon2 used back to the OS when no other verification is
	// running; otherwise Go keeps the memory for a long time and an idle panel
	// shows ~80 MB. Logins are rare, so the cost is negligible.
	if len(p.run) == 0 {
		go debug.FreeOSMemory()
	}
	return nil
}
