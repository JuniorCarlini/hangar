package auth

import (
	"sync"
	"time"
)

// limiter counts failures per key (IP or e-mail) in a fixed window. It lives
// in memory: restarting the panel resets the windows, but the persistent
// account lock (20 failures) lives in the database.
//
// Attempts still being checked count too (inflight): otherwise many requests
// sent at once all pass the check before the first failure is recorded, and
// an attacker gets ~20 guesses per window instead of 5.
type limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	entries map[string]*window
	now     func() time.Time
}

type window struct {
	start    time.Time
	failures int
	inflight int
}

func newLimiter(maxFailures int, w time.Duration, now func() time.Time) *limiter {
	return &limiter{max: maxFailures, window: w, entries: map[string]*window{}, now: now}
}

// current returns the key's entry with an expired window cleared (nil when
// there is nothing to remember). Called with mu held.
func (l *limiter) current(key string) *window {
	e, ok := l.entries[key]
	if !ok {
		return nil
	}
	if l.now().Sub(e.start) >= l.window {
		if e.inflight == 0 {
			delete(l.entries, key)
			return nil
		}
		e.start, e.failures = l.now(), 0
	}
	return e
}

// blockedLocked reports whether the key is at the limit (failures plus
// attempts running) and how long until it is released.
func (l *limiter) blockedLocked(key string) (bool, time.Duration) {
	e := l.current(key)
	if e == nil || e.failures+e.inflight < l.max {
		return false, 0
	}
	if e.failures >= l.max {
		return true, l.window - l.now().Sub(e.start)
	}
	// Full only because of attempts still running: they end in seconds.
	return true, time.Second
}

// begin reserves an attempt on every key, or none when one is full.
func (l *limiter) begin(keys ...string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if blocked, wait := l.blockedLocked(k); blocked {
			return false, wait
		}
	}
	for _, k := range keys {
		e := l.current(k)
		if e == nil {
			e = &window{start: l.now()}
			l.entries[k] = e
		}
		e.inflight++
	}
	return true, 0
}

// end releases attempts reserved with begin.
func (l *limiter) end(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if e, ok := l.entries[k]; ok && e.inflight > 0 {
			e.inflight--
		}
	}
}

// fail records a failure and returns how many the key has in the window.
func (l *limiter) fail(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.current(key)
	if e == nil {
		e = &window{start: now}
		l.entries[key] = e
	}
	e.failures++
	// Without periodic cleanup an attack from many IPs would grow the map
	// forever; piggyback on the write to sweep expired windows.
	if len(l.entries) > 10_000 {
		for k, v := range l.entries {
			if now.Sub(v.start) >= l.window && v.inflight == 0 {
				delete(l.entries, k)
			}
		}
	}
	return e.failures
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
