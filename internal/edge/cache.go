package edge

import (
	"container/list"
	"sync"
	"time"
)

type cached struct {
	allow   bool
	reason  string
	via     Path
	expires time.Time
}

// decisionCache is a bounded LRU of ask decisions with a per-entry expiry.
// Every SNI is chosen by whoever connects, so an unbounded map would let
// random names grow the panel's memory until it is killed.
type decisionCache struct {
	mu    sync.Mutex
	max   int
	order *list.List // front: most recently used
	byKey map[string]*list.Element
}

type cacheEntry struct {
	host string
	val  cached
}

func newDecisionCache(maxEntries int) *decisionCache {
	return &decisionCache{max: maxEntries, order: list.New(), byKey: map[string]*list.Element{}}
}

// get returns the live decision for host; an expired one is dropped.
func (c *decisionCache) get(host string, now time.Time) (cached, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[host]
	if !ok {
		return cached{}, false
	}
	e := entryOf(el)
	if !now.Before(e.val.expires) {
		c.order.Remove(el)
		delete(c.byKey, host)
		return cached{}, false
	}
	c.order.MoveToFront(el)
	return e.val, true
}

// put stores a decision, evicting the least recently used ones when the
// cache is full (expired entries are never read, so they sink to the back
// and go first).
func (c *decisionCache) put(host string, v cached) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[host]; ok {
		entryOf(el).val = v
		c.order.MoveToFront(el)
		return
	}
	c.byKey[host] = c.order.PushFront(&cacheEntry{host: host, val: v})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.byKey, entryOf(last).host)
	}
}

func (c *decisionCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *decisionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.byKey = map[string]*list.Element{}
}

func entryOf(el *list.Element) *cacheEntry {
	e, _ := el.Value.(*cacheEntry)
	return e
}
