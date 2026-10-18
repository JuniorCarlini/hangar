package app

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JuniorCarlini/hangar/internal/docker"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// After install nothing may need SSH: Docker or Caddy late at boot, a Caddy
// that dies later, or a port that was busy for a moment must heal by
// themselves, and what is still wrong shows in the panel (EdgeDown).

// edgeProxy is what the keeper needs from the edge manager (*edge.Manager).
type edgeProxy interface {
	projects.EdgeApplier
	Check(ctx context.Context) error
	Heal(ctx context.Context) error
	Degraded() string
	WritePages(pages map[string][]byte) error
}

// Retry and health-check timing; tests shorten them.
var (
	edgeRetryMin   = 5 * time.Second
	edgeRetryMax   = time.Minute
	edgeCheckEvery = time.Minute
)

// edgeKeeper brings the edge proxy up and keeps it up: it retries starting
// Caddy (with backoff) until it works, wires it into the panel, opens the
// public panel's listener, and then checks Caddy every minute, healing it
// when its admin API stops answering.
type edgeKeeper struct {
	log *slog.Logger
	// start brings the edge up from scratch (startEdge).
	start func(ctx context.Context) (edgeProxy, error)
	// wire connects a started edge to the rest of the panel (projects,
	// firewall); called once, when it first comes up.
	wire func(e edgeProxy)
	// public opens the public panel's listener behind Caddy; nil when the
	// panel is private. Retried until it works.
	public func(ctx context.Context) error
	// status receives why the edge is down or degraded ("" = fine).
	status func(reason string)

	em       atomic.Pointer[edgeBox]
	publicUp bool
	mu       sync.Mutex // serializes up (boot and loop)
}

type edgeBox struct{ e edgeProxy }

// current is the running edge, or nil.
func (k *edgeKeeper) current() edgeProxy {
	if b := k.em.Load(); b != nil {
		return b.e
	}
	return nil
}

// WritePages writes the error pages into the running edge. Without one there
// is nothing to do: the edge renders them itself when it starts.
func (k *edgeKeeper) WritePages(pages map[string][]byte) error {
	if e := k.current(); e != nil {
		return e.WritePages(pages)
	}
	return nil
}

// tryUp makes one attempt at everything still missing: the edge, then the
// public listener. It reports whether all is up.
func (k *edgeKeeper) tryUp(ctx context.Context) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	e := k.current()
	if e == nil {
		var err error
		if e, err = k.start(ctx); err != nil {
			k.log.Error("start edge proxy; retrying", "error", err)
			k.status("edge down: " + err.Error())
			return false
		}
		k.em.Store(&edgeBox{e})
		k.wire(e)
		k.log.Info("edge proxy up")
	}
	if k.public != nil && !k.publicUp {
		if err := k.public(ctx); err != nil {
			k.log.Error("open the public panel listener; retrying", "error", err)
			k.status("public panel down: " + err.Error())
			return false
		}
		k.publicUp = true
	}
	k.reportDegraded(e)
	return true
}

func (k *edgeKeeper) reportDegraded(e edgeProxy) {
	if d := e.Degraded(); d != "" {
		k.status("edge degraded: " + d)
		return
	}
	k.status("")
}

// ready reports whether the edge and the public listener are both up.
func (k *edgeKeeper) ready() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.current() != nil && (k.public == nil || k.publicUp)
}

// run retries what failed at boot (the first attempt, tryUp, is the
// caller's), then checks the edge every minute, until ctx ends.
func (k *edgeKeeper) run(ctx context.Context) {
	wait := edgeRetryMin
	for !k.ready() {
		if !sleep(ctx, wait) {
			return
		}
		wait = min(wait*2, edgeRetryMax)
		k.tryUp(ctx)
	}
	for sleep(ctx, edgeCheckEvery) {
		e := k.current()
		if err := e.Check(ctx); err != nil {
			k.log.Warn("edge proxy not answering; bringing it back", "error", err)
			if err := e.Heal(ctx); err != nil {
				k.log.Error("heal edge proxy", "error", err)
				k.status("edge down: " + err.Error())
				continue
			}
			k.log.Info("edge proxy healed")
		} else if e.Degraded() != "" {
			// On the fallback config: try the full one again, in case what
			// Caddy rejected was passing. The reason stays in the status.
			if err := e.Apply(ctx); err == nil {
				k.log.Info("edge proxy back on the full config")
			}
		}
		k.reportDegraded(e)
	}
}

// sleep waits d or until ctx ends; false when ctx ended.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// waitDocker retries connecting to Docker (with backoff) after the panel came
// up without it. Most of the panel (projects, metrics, backups, the edge) is
// wired to Docker at startup, so once it answers the panel restarts itself
// (systemd brings it back in seconds) instead of staying read-only until
// someone restarts it over SSH. It returns the reason to restart, or nil when
// ctx ends.
func waitDocker(ctx context.Context, host string, log *slog.Logger) error {
	wait := edgeRetryMin
	for sleep(ctx, wait) {
		d, err := docker.New(ctx, host)
		if err != nil {
			log.Warn("docker still unavailable; retrying", "error", err, "next", min(wait*2, edgeRetryMax).String())
			wait = min(wait*2, edgeRetryMax)
			continue
		}
		_ = d.Close()
		log.Warn("docker is available now; restarting the panel to connect it")
		return i18n.E("app.error.docker_back")
	}
	return nil
}
