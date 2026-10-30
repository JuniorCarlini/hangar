package edge

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fillAskLog puts maxAskRows denial rows in tls_ask_log: the state anyone on
// the internet could reach with that many made-up names.
func fillAskLog(t *testing.T, f *fixture) {
	t.Helper()
	_, err := f.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i + 1 < ?)
		INSERT INTO tls_ask_log (hostname, decision, reason, hour, last_at)
		SELECT 'lixo-' || i || '.example', 'deny', 'app_denied', ?, 1 FROM n`, maxAskRows, time.Now().Unix()/3600)
	if err != nil {
		t.Fatal(err)
	}
}

// SEC-002: a full ask log must not switch the hourly cap off.
func TestHourlyCapHoldsWithTheAskLogFull(t *testing.T) {
	f := newFixture(t, true)
	f.a.MaxNewPerHour = 3
	fillAskLog(t, f)
	ctx := context.Background()
	allowed := 0
	for i := range 10 {
		if ok, why := f.a.Decide(ctx, "loja-extra-"+strconv.Itoa(i)+".com"); ok {
			allowed++
		} else if why != ReasonRateLimited {
			t.Errorf("unexpected reason %s", why)
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed %d new hostnames with the log full, want the cap of 3", allowed)
	}
	// An approved host still renews, and its approval is on record even
	// though the log had no room for a new row.
	f.a.Forget()
	if ok, why := f.a.Decide(ctx, "loja-extra-0.com"); !ok {
		t.Fatalf("renewal of an approved host: %s", why)
	}
	if n, _ := f.q.WasApproved(ctx, "loja-extra-0.com"); n != 1 {
		t.Fatal("the approval must be recorded apart from the ask log")
	}
}

// SEC-002: concurrent handshakes for new names cannot all pass under the
// same count.
func TestHourlyCapHoldsUnderConcurrency(t *testing.T) {
	f := newFixture(t, true)
	f.a.MaxNewPerHour = 3
	ctx := context.Background()
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			if ok, _ := f.a.Decide(ctx, "loja-extra-"+strconv.Itoa(i)+".com"); ok {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if n := allowed.Load(); n != 3 {
		t.Fatalf("allowed %d, want 3", n)
	}
}

// SEC-002: made-up names are not logged one row each.
func TestInvalidNamesShareOneRow(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	for i := range 50 {
		f.a.Decide(ctx, "bad_name_"+strconv.Itoa(i))
	}
	if n, _ := f.q.CountAskRows(ctx); n != 1 {
		t.Fatalf("%d rows for 50 invalid names, want 1", n)
	}
}

// SEC-002: at the ceiling only rows that exist keep counting.
func TestFullLogOnlyBumpsExistingRows(t *testing.T) {
	f := newFixture(t, false)
	fillAskLog(t, f)
	ctx := context.Background()
	f.a.Decide(ctx, "lixo-1.example")
	f.a.Decide(ctx, "outro-nome.example")
	if n, _ := f.q.CountAskRows(ctx); n != maxAskRows {
		t.Fatalf("%d rows, want %d", n, maxAskRows)
	}
	var count int64
	if err := f.db.QueryRowContext(ctx, `SELECT count FROM tls_ask_log WHERE hostname = 'lixo-1.example' AND decision = 'deny'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("existing row count = %d, want 2", count)
	}
}

// SEC-003: the decision cache stays bounded whatever names arrive.
func TestDecisionCacheIsBounded(t *testing.T) {
	c := newDecisionCache(100)
	now := time.Now()
	for i := range 1000 {
		c.put("h"+strconv.Itoa(i)+".example", cached{expires: now.Add(time.Hour)})
	}
	if n := c.len(); n != 100 {
		t.Fatalf("cache holds %d, want 100", n)
	}
	if _, ok := c.get("h999.example", now); !ok {
		t.Fatal("the most recent entry must stay")
	}
	if _, ok := c.get("h0.example", now); ok {
		t.Fatal("the least recently used entry must be evicted")
	}
	c.put("old.example", cached{expires: now.Add(-time.Second)})
	if _, ok := c.get("old.example", now); ok {
		t.Fatal("an expired entry must not be served")
	}
	if n := c.len(); n != 99 {
		t.Fatalf("an expired entry must be dropped on read: %d entries", n)
	}
}

// SEC-003: through the authorizer, N+1 distinct names keep the cache at N.
func TestAuthorizerCacheIsBounded(t *testing.T) {
	f := newFixture(t, false)
	f.a.cache = newDecisionCache(20)
	ctx := context.Background()
	for i := range 50 {
		f.a.Decide(ctx, "nome-"+strconv.Itoa(i)+".example")
	}
	if n := f.a.cache.len(); n != 20 {
		t.Fatalf("cache holds %d, want 20", n)
	}
}
