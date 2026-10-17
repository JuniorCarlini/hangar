// Package lockdown is the panic button (docs/17 § 1.6): every session ends
// at once and the panel stops answering anything but the server itself
// (127.0.0.1, reached through an SSH tunnel) until someone with a shell on
// the server releases it. Containers are not touched: the sites stay up.
package lockdown

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

const settingKey = "panel.lockdown"

// cacheTTL bounds how long the panel takes to notice a change made by the
// command line in another process.
const cacheTTL = 2 * time.Second

// State is the lock as stored.
type State struct {
	Locked bool   `json:"locked"`
	At     int64  `json:"at,omitempty"`
	By     string `json:"by,omitempty"` // user id, empty from the command line
	Via    string `json:"via,omitempty"`
}

// Lock reads and changes the lockdown state.
type Lock struct {
	db    *sql.DB
	q     *dbq.Queries
	audit *audit.Logger
	now   func() time.Time

	mu       sync.Mutex
	cached   State
	cachedAt time.Time
}

// New creates the Lock over the panel database.
func New(db *sql.DB, al *audit.Logger) *Lock {
	return &Lock{db: db, q: dbq.New(db), audit: al, now: time.Now}
}

// State reads the current state from the database.
func (l *Lock) State(ctx context.Context) (State, error) {
	v, err := l.q.GetSetting(ctx, settingKey)
	if errors.Is(err, sql.ErrNoRows) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal([]byte(v), &st); err != nil {
		return State{}, fmt.Errorf("lockdown state: %w", err)
	}
	return st, nil
}

// Locked reports whether the panel is locked, from a short cache (the
// command line changes the state from another process).
func (l *Lock) Locked(ctx context.Context) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.now().Sub(l.cachedAt) < cacheTTL {
		return l.cached.Locked
	}
	st, err := l.State(ctx)
	if err != nil {
		// Without the database nothing else works either; keep the last
		// known answer rather than flipping.
		return l.cached.Locked
	}
	l.cached, l.cachedAt = st, l.now()
	return st.Locked
}

// Engage locks the panel and ends every session, including the caller's.
// It returns how many sessions were closed.
func (l *Lock) Engage(ctx context.Context, userID, ip, via string) (int64, error) {
	st := State{Locked: true, At: l.now().Unix(), By: userID, Via: via}
	raw, _ := json.Marshal(st)
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	q := l.q.WithTx(tx)
	if err := q.SetSetting(ctx, dbq.SetSettingParams{Key: settingKey, ValueJson: string(raw)}); err != nil {
		return 0, err
	}
	n, err := q.DeleteAllSessions(ctx)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	l.setCache(st)
	l.record(ctx, audit.Entry{
		ActorID: userID, IP: ip, Action: "system.lockdown", Outcome: audit.OK,
		Summary: map[string]any{"via": via, "sessions": n},
	})
	return n, nil
}

// Release unlocks the panel. Only the command line on the server calls it.
func (l *Lock) Release(ctx context.Context, via string) error {
	raw, _ := json.Marshal(State{})
	if err := l.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingKey, ValueJson: string(raw)}); err != nil {
		return err
	}
	l.setCache(State{})
	l.record(ctx, audit.Entry{Action: "system.lockdown.release", Outcome: audit.OK, Summary: map[string]any{"via": via}})
	return nil
}

func (l *Lock) setCache(st State) {
	l.mu.Lock()
	l.cached, l.cachedAt = st, l.now()
	l.mu.Unlock()
}

func (l *Lock) record(ctx context.Context, e audit.Entry) {
	if l.audit == nil {
		return
	}
	_ = l.audit.Record(context.WithoutCancel(ctx), e)
}

// LocalOnly reports whether the request came from the server itself: both
// ends of the connection on loopback. Through Caddy (public mode) the peer
// is Caddy's container address, so it is refused; through an SSH tunnel
// (ssh -L 7700:127.0.0.1:7700) both ends are 127.0.0.1.
func LocalOnly(r *http.Request) bool {
	if !loopback(r.RemoteAddr) {
		return false
	}
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return ok && loopback(la.String())
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
