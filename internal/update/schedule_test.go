package update

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/release"
)

// The background lookup costs one redirect; the signed manifest and the
// notes are fetched once per new release, not on every lookup.
func TestBackgroundLookupIsCheap(t *testing.T) {
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", []byte("binario-novo"))
	srv := fakeGitHub(t, &rel)

	c, _ := newChecker(t, srv, "v1.0.0")
	for i := range 3 {
		av, err := c.Check(context.Background())
		if err != nil || av == nil || av.Version != "v1.1.0" || av.Notes != "novidades" {
			t.Fatalf("lookup %d: Check = %+v, %v", i, av, err)
		}
	}
	if got := rel.hits.get("probe"); got != 3 {
		t.Errorf("redirect probes = %d, want 3", got)
	}
	if got := rel.hits.get("manifest"); got != 1 {
		t.Errorf("manifest downloads = %d, want 1 (verified once)", got)
	}
	if got := rel.hits.get("api") + rel.hits.get("api304"); got != 1 {
		t.Errorf("API calls = %d, want 1 (the notes, once)", got)
	}

	// Up to date: nothing but the probe.
	same, _ := newChecker(t, srv, "v1.1.0")
	if av, err := same.Check(context.Background()); err != nil || av != nil {
		t.Fatalf("up to date: Check = %+v, %v", av, err)
	}
	if got := rel.hits.get("manifest"); got != 1 {
		t.Errorf("an up-to-date panel downloaded the manifest (%d)", got)
	}
}

// A release whose manifest does not verify is never announced.
func TestUnsignedReleaseIsNotAnnounced(t *testing.T) {
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", []byte("binario-novo"))
	_, other, _ := ed25519.GenerateKey(nil)
	rel.sig = release.Sign(rel.manifest, other)
	c, _ := newChecker(t, fakeGitHub(t, &rel), "v1.0.0")
	if av, err := c.Check(context.Background()); err == nil || av != nil {
		t.Fatalf("Check = %+v, %v; want a signature error", av, err)
	}
	if av, _ := c.Latest(); av != nil {
		t.Fatalf("Latest = %+v after a bad signature", av)
	}
}

// With a token the lookup is a conditional API call: the second one is a
// 304 and still reports the version.
func TestTokenLookupIsConditional(t *testing.T) {
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", []byte("binario-novo"))
	srv := fakeGitHub(t, &rel)
	c := NewChecker(Config{Repo: "JuniorCarlini/hangar", APIBase: srv.URL, Token: "tok", Dir: t.TempDir()}, "v1.0.0")
	for i := range 2 {
		if av, err := c.Check(context.Background()); err != nil || av == nil || av.Version != "v1.1.0" {
			t.Fatalf("lookup %d: Check = %+v, %v", i, av, err)
		}
	}
	if rel.hits.get("api") != 1 || rel.hits.get("api304") != 1 || rel.hits.get("probe") != 0 {
		t.Fatalf("hits = %v, want one 200 and one 304 from the API", rel.hits.n)
	}
}

// A development build made after a tag only sees newer releases; any
// other development build sees every release.
func TestDevBuildCompare(t *testing.T) {
	priv := useTestKey(t)
	for _, tc := range []struct {
		current, latest string
		want            bool
	}{
		{"v1.0.0-2-g8a2c7b0-dirty", "v1.0.0", false},
		{"v1.0.0-2-g8a2c7b0-dirty", "v1.0.1", true},
		{"v1.0.0-2-g8a2c7b0", "v0.9.0", false},
		{"dev", "v1.0.0", true},
	} {
		rel := signedRelease(t, priv, tc.latest, []byte("b"))
		c, _ := newChecker(t, fakeGitHub(t, &rel), tc.current)
		av, err := c.Check(context.Background())
		if err != nil || (av != nil) != tc.want {
			t.Errorf("%s vs %s: Check = %+v, %v; want available=%v", tc.current, tc.latest, av, err, tc.want)
		}
	}
}

// A failed lookup keeps the version found before (no blinking badge).
func TestFailureKeepsKnownVersion(t *testing.T) {
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", []byte("b"))
	srv := fakeGitHub(t, &rel)
	c, _ := newChecker(t, srv, "v1.0.0")
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if _, err := c.Check(context.Background()); err == nil {
		t.Fatal("Check against a closed server succeeded")
	}
	if av, err := c.Latest(); av == nil || av.Version != "v1.1.0" || err == nil {
		t.Fatalf("Latest = %+v, %v; want v1.1.0 and the error", av, err)
	}
}

func TestUntilDueBacksOff(t *testing.T) {
	s := Schedule{Every: 10 * time.Minute, MaxBackoff: time.Hour}
	now := time.Now()
	c := NewChecker(Config{}, "v1.0.0")
	if d := c.untilDue(s, now); d != 0 {
		t.Fatalf("never checked: untilDue = %v, want 0", d)
	}
	c.lastAttempt = now
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{0, 10 * time.Minute},
		{1, 10 * time.Minute},
		{2, 20 * time.Minute},
		{3, 40 * time.Minute},
		{4, time.Hour},
		{100, time.Hour},
	} {
		c.failures = tc.failures
		if d := c.untilDue(s, now); d != tc.want {
			t.Errorf("%d failures: untilDue = %v, want %v", tc.failures, d, tc.want)
		}
	}
	// GitHub's rate limit wins when it asks for longer.
	c.failures = 1
	c.retryAt = now.Add(50 * time.Minute)
	if d := c.untilDue(s, now); d != 50*time.Minute {
		t.Errorf("rate limited: untilDue = %v, want 50m", d)
	}
	// A success clears failures and the rate limit.
	c.attempted(nil)
	if c.failures != 0 || !c.retryAt.IsZero() {
		t.Errorf("after success: failures=%d retryAt=%v", c.failures, c.retryAt)
	}
}

func TestRateLimitedUntil(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	type answer struct {
		status int
		h      http.Header
	}
	resp := func(status int, h map[string]string) answer {
		a := answer{status, http.Header{}}
		for k, v := range h {
			a.h.Set(k, v)
		}
		return a
	}
	for _, tc := range []struct {
		name string
		resp answer
		want time.Time
	}{
		{"ok", resp(200, nil), time.Time{}},
		{"forbidden, not a rate limit", resp(403, nil), time.Time{}},
		{"retry-after seconds", resp(403, map[string]string{"Retry-After": "120"}), now.Add(2 * time.Minute)},
		{"retry-after date", resp(429, map[string]string{"Retry-After": now.Add(5 * time.Minute).UTC().Format(http.TimeFormat)}), now.Add(5 * time.Minute)},
		{"quota spent", resp(403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": strconv.FormatInt(now.Add(30*time.Minute).Unix(), 10)}), now.Add(30 * time.Minute)},
		{"429 without headers", resp(429, nil), now.Add(time.Minute)},
		{"capped", resp(429, map[string]string{"Retry-After": "999999"}), now.Add(maxRateWait)},
		{"reset in the past", resp(403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"}), now},
	} {
		if got := rateLimitedUntil(tc.resp.status, tc.resp.h, now); !got.Equal(tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A rate-limited answer silences the page-triggered lookup until the reset.
func TestRateLimitHoldsCheckSoon(t *testing.T) {
	reset := time.Now().Add(20 * time.Minute)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := NewChecker(Config{Repo: "JuniorCarlini/hangar", APIBase: srv.URL, Dir: t.TempDir()}, "v1.0.0")
	if _, err := c.Check(context.Background()); err == nil {
		t.Fatal("Check succeeded against a rate limit")
	}
	if c.CheckSoon(0) {
		t.Error("CheckSoon started a lookup while rate limited")
	}
	if d := c.untilDue(DefaultSchedule, time.Now()); d < 19*time.Minute {
		t.Errorf("untilDue = %v, want until the reset (~20m)", d)
	}
}

func TestCheckSoonOnlyWhenStale(t *testing.T) {
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", []byte("b"))
	c, _ := newChecker(t, fakeGitHub(t, &rel), "v1.0.0")
	if !c.CheckSoon(time.Minute) {
		t.Fatal("first CheckSoon did not start a lookup")
	}
	waitFor(t, func() bool { return !c.Checking() && !c.LastCheck().IsZero() })
	if av, _ := c.Latest(); av == nil || av.Version != "v1.1.0" {
		t.Fatalf("Latest = %+v after CheckSoon", av)
	}
	if c.CheckSoon(time.Minute) {
		t.Error("CheckSoon looked again right after a lookup")
	}
	if got := rel.hits.get("probe"); got != 1 {
		t.Errorf("probes = %d, want 1", got)
	}
}

// Run waits StartDelay for the first lookup and stops with its context.
func TestRunChecksAfterStartDelay(t *testing.T) {
	priv := useTestKey(t)
	rel := signedRelease(t, priv, "v1.1.0", []byte("b"))
	c, _ := newChecker(t, fakeGitHub(t, &rel), "v1.0.0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, Schedule{Every: time.Hour, StartDelay: 10 * time.Millisecond}, nil)
		close(done)
	}()
	waitFor(t, func() bool { av, _ := c.Latest(); return av != nil })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	if got := rel.hits.get("probe"); got != 1 {
		t.Errorf("probes = %d, want 1 (next one an hour later)", got)
	}
}

func TestTagFromDownload(t *testing.T) {
	for _, tc := range []struct {
		path, tag string
		ok        bool
	}{
		{"/JuniorCarlini/hangar/releases/download/v0.5.24/release.json", "v0.5.24", true},
		{"/JuniorCarlini/hangar/releases/download/latest/release.json", "", false},
		{"/JuniorCarlini/hangar/releases/download/v0.5.24", "", false},
		{"/JuniorCarlini/hangar/releases", "", false},
		{"/login", "", false},
	} {
		tag, ok := tagFromDownload(tc.path)
		if tag != tc.tag || ok != tc.ok {
			t.Errorf("%s: %q %v, want %q %v", tc.path, tag, ok, tc.tag, tc.ok)
		}
	}
}

func TestWebBaseFollowsAPIBase(t *testing.T) {
	if c := NewChecker(Config{APIBase: "https://api.github.com"}, "v1"); c.cfg.WebBase != "https://github.com" {
		t.Errorf("GitHub: WebBase = %q", c.cfg.WebBase)
	}
	if c := NewChecker(Config{APIBase: "http://127.0.0.1:9"}, "v1"); c.cfg.WebBase != "http://127.0.0.1:9" {
		t.Errorf("elsewhere: WebBase = %q", c.cfg.WebBase)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
