package projects

import "sync"

// heldSet holds the services a backup paused or stopped on purpose (a
// consistent copy of their volumes, a restore). While held, a service
// that is not running is not drift and not down: the reconciler and the
// alert rules leave it alone, and nothing starts it but the backup that
// holds it. A count per service, since two copies may hold a service
// they share volumes with.
type heldSet struct {
	mu sync.Mutex
	n  map[string]int
}

func heldKey(project, service string) string { return project + "/" + service }

// Hold marks project/service as held by a backup until the returned
// release is called (safe to call more than once).
func (m *Manager) Hold(project, service string) (release func()) {
	k := heldKey(project, service)
	m.held.mu.Lock()
	if m.held.n == nil {
		m.held.n = map[string]int{}
	}
	m.held.n[k]++
	m.held.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.held.mu.Lock()
			defer m.held.mu.Unlock()
			if m.held.n[k]--; m.held.n[k] <= 0 {
				delete(m.held.n, k)
			}
		})
	}
}

// Held reports whether a backup holds project/service right now.
func (m *Manager) Held(project, service string) bool {
	m.held.mu.Lock()
	defer m.held.mu.Unlock()
	return m.held.n[heldKey(project, service)] > 0
}
