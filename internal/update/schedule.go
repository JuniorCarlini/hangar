package update

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

// Schedule says how often Run looks for a new version.
type Schedule struct {
	// Every is the wait between two lookups while they succeed.
	Every time.Duration
	// Jitter: up to this much is added at random to every wait, so panels
	// started together do not query GitHub in step.
	Jitter time.Duration
	// StartDelay is the wait before the first lookup after the panel
	// starts (let it come up first).
	StartDelay time.Duration
	// MaxBackoff caps the wait after failures in a row (each one doubles
	// Every).
	MaxBackoff time.Duration
}

// DefaultSchedule finds a new release within about 12 minutes: 10 min + up
// to 2 min of jitter, at most 6 lookups an hour (~130 a day). Without a
// token a lookup is one bodyless redirect from github.com, outside the API
// and its 60-calls-an-hour-per-IP limit; the API is called once per new
// release, for its notes. With a token the lookup is a conditional API
// call, and GitHub does not count an authenticated 304.
var DefaultSchedule = Schedule{
	Every:      10 * time.Minute,
	Jitter:     2 * time.Minute,
	StartDelay: 20 * time.Second,
	MaxBackoff: 2 * time.Hour,
}

// maxBackoffShift bounds the doubling, so the shift cannot overflow.
const maxBackoffShift = 8

// Run looks for a new version on schedule s until ctx ends. A lookup made
// meanwhile by someone else (the button, CheckSoon) counts: the next one
// waits a full interval from it.
func (c *Checker) Run(ctx context.Context, s Schedule, onErr func(error)) {
	t := time.NewTimer(s.StartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if c.untilDue(s, time.Now()) <= 0 {
			if _, err := c.Check(ctx); err != nil && onErr != nil {
				onErr(err)
			}
		}
		t.Reset(max(c.untilDue(s, time.Now()), time.Second) + jitter(s.Jitter))
	}
}

// CheckSoon starts a lookup in the background when the last one is older
// than maxAge, unless one is running or GitHub asked us to wait. It never
// blocks; it reports whether a lookup started. The update page calls it, so
// whoever opens it sees fresh news without clicking.
func (c *Checker) CheckSoon(maxAge time.Duration) bool {
	if !c.fetch.TryLock() {
		return false
	}
	now := time.Now()
	c.mu.Lock()
	stale := c.lastAttempt.IsZero() || now.Sub(c.lastAttempt) >= maxAge
	limited := now.Before(c.retryAt)
	c.mu.Unlock()
	if !stale || limited {
		c.fetch.Unlock()
		return false
	}
	c.checking.Store(true) // seen by the page that called us right away
	go func() {
		defer c.fetch.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = c.check(ctx)
	}()
	return true
}

// Checking reports whether a lookup is running now.
func (c *Checker) Checking() bool { return c.checking.Load() }

// LastCheck is when the last lookup ran (zero before the first).
func (c *Checker) LastCheck() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastAttempt
}

// attempted records a finished lookup; the caller holds c.mu.
func (c *Checker) attempted(err error) {
	c.lastAttempt = time.Now()
	if err != nil {
		c.failures++
		return
	}
	c.failures = 0
	c.retryAt = time.Time{}
}

// untilDue is how long until the next scheduled lookup, without jitter:
// Every after the last one, doubled for every failure in a row (up to
// MaxBackoff), and never before the time GitHub's rate limit asked for.
func (c *Checker) untilDue(s Schedule, now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastAttempt.IsZero() {
		return 0
	}
	wait := s.Every
	if c.failures > 0 {
		wait = s.Every << min(c.failures-1, maxBackoffShift)
		if s.MaxBackoff > 0 && wait > s.MaxBackoff {
			wait = s.MaxBackoff
		}
	}
	due := c.lastAttempt.Add(wait)
	if c.retryAt.After(due) {
		due = c.retryAt
	}
	return due.Sub(now)
}

// maxRateWait caps how long a rate-limit answer can silence the checker (a
// broken clock or header must not stop it for days).
const maxRateWait = 2 * time.Hour

// rateLimitedUntil reads GitHub's rate-limit answer (403 or 429): until
// when it asks us to wait, from Retry-After (seconds or a date) or, once the
// quota is spent, X-RateLimit-Reset. Zero when the answer is not a rate
// limit.
func rateLimitedUntil(status int, h http.Header, now time.Time) time.Time {
	if status != http.StatusForbidden && status != http.StatusTooManyRequests {
		return time.Time{}
	}
	var until time.Time
	if ra := h.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			until = now.Add(time.Duration(secs) * time.Second)
		} else if at, err := http.ParseTime(ra); err == nil {
			until = at
		}
	}
	if until.IsZero() && h.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			until = time.Unix(reset, 0)
		}
	}
	if until.IsZero() && status == http.StatusTooManyRequests {
		until = now.Add(time.Minute) // GitHub's advice when it says no more
	}
	if until.IsZero() {
		return time.Time{}
	}
	if until.Before(now) {
		return now
	}
	if until.After(now.Add(maxRateWait)) {
		until = now.Add(maxRateWait)
	}
	return until
}

// jitter is a random duration in [0, n).
func jitter(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return n / 2
	}
	return time.Duration(v.Int64())
}
