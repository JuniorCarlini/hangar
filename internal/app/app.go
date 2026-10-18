// Package app wires hangard's dependencies and starts the servers.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/JuniorCarlini/hangar/internal/alerts"
	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/config"
	"github.com/JuniorCarlini/hangar/internal/deps"
	"github.com/JuniorCarlini/hangar/internal/docker"
	"github.com/JuniorCarlini/hangar/internal/edge"
	"github.com/JuniorCarlini/hangar/internal/errpages"
	"github.com/JuniorCarlini/hangar/internal/firewall"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/lockdown"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/statuspage"
	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
	"github.com/JuniorCarlini/hangar/internal/update"
	"github.com/JuniorCarlini/hangar/internal/web"
)

// OpenStore opens the panel database inside DataDir.
func OpenStore(ctx context.Context, cfg config.Config, log *slog.Logger) (*store.Store, error) {
	if err := refuseForeignOwner(cfg.DataDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data_dir: %w", err)
	}
	return store.Open(ctx,
		filepath.Join(cfg.DataDir, "hangar.db"),
		filepath.Join(cfg.DataDir, "backups", "painel"),
		log)
}

// Core bundles what the panel and the CLI use.
type Core struct {
	Store  *store.Store
	Box    *secrets.Box
	Audit  *audit.Logger
	Auth   *auth.Service
	Alerts *alerts.Service
	Lock   *lockdown.Lock
}

// Open opens the database, master key and services. Callers close it with
// Close.
func Open(ctx context.Context, cfg config.Config, log *slog.Logger) (*Core, error) {
	st, err := OpenStore(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	box, err := secrets.LoadOrCreateKey(cfg.MasterKeyFile)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	al := audit.New(st.DB)
	svc, err := auth.NewService(st.DB, box, al, auth.Options{
		Require2FA: cfg.Auth.Require2FA, FirstRunSetup: true,
	})
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	// Security events in the audit log become alerts. Without Start (the
	// command line) they are delivered before the command returns.
	notifier := alerts.New(st.DB, box, al, log, alerts.Options{TelegramAPI: cfg.Alerts.TelegramAPI})
	notifier.Observe(al)
	return &Core{Store: st, Box: box, Audit: al, Auth: svc, Alerts: notifier, Lock: lockdown.New(st.DB, al)}, nil
}

// Close closes the database.
func (c *Core) Close() error { return c.Store.Close() }

// PanelPublicHost is the panel's public hostname when [panel] public is on:
// public_host, or "hangar." under the base domain, or "hangar.<ip>.sslip.io"
// from the first public IPv4. Empty when the panel stays private (or no
// name can be built).
func PanelPublicHost(cfg config.Config) string {
	if !cfg.Panel.Public || !cfg.Edge.Enabled {
		return ""
	}
	if cfg.Panel.PublicHost != "" {
		return strings.ToLower(cfg.Panel.PublicHost)
	}
	var ips []netip.Addr
	for _, s := range cfg.Edge.PublicIPs {
		if ip, err := netip.ParseAddr(s); err == nil {
			ips = append(ips, ip)
		}
	}
	return edge.AutoHost(cfg.Edge.BaseDomain, edge.PublicAutoIP(ips), "hangar")
}

// Serve runs the panel on every panel.listen address and blocks until ctx
// is canceled or a server fails.
func Serve(ctx context.Context, cfg config.Config, version string, log *slog.Logger) error {
	core, err := Open(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = core.Close() }()
	st, al := core.Store, core.Audit
	core.Alerts.Start(ctx)

	checker, err := NewChecker(cfg, version)
	if err != nil {
		return err
	}
	// Without Docker the panel stays up (for login, updates and reading);
	// container actions report that Docker is unavailable.
	var n node.Node
	if d, err := docker.New(ctx, cfg.Docker.Host); err != nil {
		log.Warn("docker unavailable; projects are read-only", "error", err)
	} else {
		defer func() { _ = d.Close() }()
		n = d
	}
	pm := projects.New(st.DB, core.Box, n, al, log)
	defer pm.Wait()
	pm.SetFirewall(firewall.Writer{Dir: FirewallDir(cfg)})
	pm.SetBuildDir(filepath.Join(cfg.DataDir, "builds"))
	// The embedded templates, plus the signed community catalog saved by
	// the last sync; the sync itself starts below with the other jobs.
	tplReg := templates.NewRegistry(templates.Builtin())
	pm.SetTemplates(tplReg)
	pm.SetBaseDomain(cfg.Edge.BaseDomain)
	// The base domain set from the panel (edge_settings) wins over hangar.toml.
	if err := pm.LoadEdgeDNS(ctx); err != nil {
		log.Warn("edge dns settings", "error", err)
	}
	tplSync, err := templates.NewSyncer(cfg.Templates.CatalogURL, filepath.Join(cfg.DataDir, "templates"), version, tplReg, log)
	if err != nil {
		return err
	}
	if err := tplSync.LoadStored(); err != nil {
		log.Warn("stored community template catalog ignored", "error", err)
	}
	// A deploy that fails (by hand, by webhook, from scratch) reaches the
	// alert channels, saying whether the site kept, got back or lost its
	// previous version.
	pm.SetDeployNotifier(deployNotifier{a: core.Alerts, log: log})
	// Before anything can start a deploy: one a killed panel left half-way
	// would block the service's deploys and monitoring for good.
	if n, err := pm.RecoverInterrupted(ctx); err != nil {
		return fmt.Errorf("recover interrupted deploys: %w", err)
	} else if n > 0 {
		log.Warn("interrupted deploys marked as failed", "count", n)
	}
	// Endpoints for services older than them, and a unique link name for
	// each, before the edge builds its routes from them.
	// A failure here is logged, not fatal: the panel must come up to fix it.
	// No user yet: the owner can be created from the browser for a while.
	// v0.2.0 asked for a setup code; the window below replaces it.
	_ = os.Remove(filepath.Join(cfg.DataDir, "setup-code"))
	panelHost := PanelPublicHost(cfg)
	if until, err := core.Auth.PrepareSetup(ctx); err != nil {
		log.Error("prepare first-run setup", "error", err)
	} else if !until.IsZero() {
		log.Warn("no user yet: open the panel to create the owner before the setup window closes",
			"until", until.Format(time.RFC3339), "public_url", publicURL(panelHost))
	}
	if n, err := pm.EnsureEndpoints(ctx); err != nil {
		log.Error("prepare endpoints", "error", err)
	} else if n > 0 {
		log.Info("endpoints prepared", "count", n)
	}
	// GitHub webhooks reach the panel only through Caddy, on their own
	// hostname and path (the panel itself stays private).
	var hooks http.Handler
	hooksBase := ""
	if cfg.Edge.Enabled && cfg.Edge.HooksHostname != "" {
		hooks = web.HookHandler(pm, log, edge.ForwardedIP)
		hooksBase = "https://" + cfg.Edge.HooksHostname
	}
	// The brand settings re-render the error pages Caddy serves (nothing
	// to do while the edge is off: it renders them when it starts).
	var pages func(map[string][]byte) error
	edgeUp := false
	pm.SetPanelHost(panelHost)
	if cfg.Edge.Enabled {
		if n == nil {
			log.Error("edge enabled but docker is unavailable; domains are not served")
		} else if em, err := startEdge(ctx, cfg, core, n, hooks, panelHost, pm, log); err != nil {
			// The panel stays up so the problem can be seen and fixed.
			log.Error("start edge proxy", "error", err)
		} else {
			pm.SetEdge(em)
			edgeUp = true
			// Caddy must reach the ask and panel listeners on the gateway
			// even where the image's own firewall rejects new connections
			// to the host (the root unit applies it).
			_, gw, caddyIP := cfg.Edge.EdgeAddrs()
			if err := (firewall.Writer{Dir: FirewallDir(cfg)}).SetEdge(&firewall.EdgeAccess{
				Caddy: caddyIP, Gateway: gw, Ports: []int{edge.AskPort, edge.PanelPort},
			}); err != nil {
				log.Error("allow caddy to reach the panel", "error", err)
			}
			pm.SetEdgeCap(cfg.Edge.MaxNewCertsPerHour)
			pages = em.WritePages
		}
	}
	// Containers are measured only when the node can report usage; the host
	// is always measured.
	src, _ := n.(metrics.Source)
	mc := metrics.New(st.DB, src, cfg.DataDir, log)
	// The dependency monitor reads containers through the node (fixed
	// cat/find commands); without Docker it only checks image tags.
	var ex deps.Execer
	if n != nil {
		ex = n
	}
	edgeImage := ""
	if cfg.Edge.Enabled {
		edgeImage = cfg.Edge.Image
	}
	dm := deps.New(st.DB, deps.Options{
		OSV: deps.NewOSV(cfg.Scan.OSVAPI, nil), Exec: ex, EdgeImage: edgeImage, Audit: al, Log: log,
	})
	sp := statuspage.New(st.DB, mc, al, log)
	bm, err := NewBackups(core, pm, cfg, version, log)
	if err != nil {
		return err
	}
	defer bm.Wait()
	handler, err := web.New(web.Deps{
		Hosts: panelHosts(cfg, panelHost), Log: log, Audit: al, Auth: core.Auth,
		Updates: checker, UpdateDir: UpdateDir(cfg), PanelURL: publicURL(panelHost), Projects: pm, Metrics: mc, HooksBase: hooksBase, Backups: bm, ServerIP: serverIP(ctx, cfg), BaseDomain: cfg.Edge.BaseDomain, AutoLinkIP: autoLinkIP(cfg), ErrorPages: pages, Brand: errpages.NewStore(core.Store.DB),
		Deps: dm, Status: sp, StatusHosts: cfg.Status.Hosts,
		Alerts: core.Alerts, Lock: core.Lock,
	})
	if err != nil {
		return fmt.Errorf("routes: %w", err)
	}

	// Listen on everything before serving anything: if one address fails, the
	// process does not come up half-way.
	listeners := make([]net.Listener, 0, len(cfg.Panel.Listen))
	for _, addr := range cfg.Panel.Listen {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return i18n.E("app.error.listen", "addr", addr, "error", err)
		}
		listeners = append(listeners, ln)
	}

	// The public panel: Caddy terminates HTTPS on its hostname and proxies
	// to this listener on the edge gateway, which only Caddy may reach.
	var edgeLn net.Listener
	if panelHost != "" && edgeUp {
		_, gw, _ := cfg.Edge.EdgeAddrs()
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(gw.String(), strconv.Itoa(edge.PanelPort)))
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return i18n.E("app.error.listen", "addr", gw.String(), "error", err)
		}
		edgeLn = ln
	}

	if err := al.Record(ctx, audit.Entry{
		Action: "system.start", Outcome: audit.OK,
		Summary: map[string]any{"version": version, "listen": cfg.Panel.Listen},
	}); err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	go st.RunMaintenance(ctx, 6*time.Hour, log)
	go cleanupSessions(ctx, core.Auth, log)
	go mc.Run(ctx)
	if cfg.Scan.Enabled {
		go dm.Run(ctx, cfg.Scan.Hour)
	}
	am := monitor(core.Alerts, pm, mc)
	// The two halves built in parallel meet here: vulnerability notices go
	// out through the alert channels, and public status pages count the
	// firing alerts.
	dm.SetNotifier(depsNotifier{core.Alerts})
	sp.SetAlerts(am)
	go am.Run(ctx, 10*time.Second)
	go alerts.WatchListeners(ctx, time.Minute, "/proc", expectedPorts(cfg, pm), al, log)
	go checker.Run(ctx, 6*time.Hour, func(err error) { log.Warn("check for new version", "error", err) })
	go bm.Run(ctx)
	if cfg.Templates.Sync {
		go tplSync.Run(ctx)
	}
	if pm.DockerAvailable() {
		go pm.RunReconciler(ctx, 30*time.Second)
		go pm.RunPortExpiry(ctx, time.Minute)
	}
	// The applier writes the result only after this version marked itself
	// ready: wait for it in the background instead of reading it now.
	go auditUpdateResult(ctx, core, cfg, log)

	errc := make(chan error, len(listeners)+1)
	for _, ln := range listeners {
		log.Info("panel listening", "address", ln.Addr().String(), "version", version)
		go func() { errc <- srv.Serve(ln) }()
	}
	var pubSrv *http.Server
	if edgeLn != nil {
		_, _, caddyIP := cfg.Edge.EdgeAddrs()
		pubSrv = &http.Server{
			Handler:           web.BehindEdge(handler, caddyIP),
			ReadHeaderTimeout: srv.ReadHeaderTimeout, ReadTimeout: srv.ReadTimeout,
			WriteTimeout: srv.WriteTimeout, IdleTimeout: srv.IdleTimeout,
			MaxHeaderBytes: srv.MaxHeaderBytes, ErrorLog: srv.ErrorLog,
		}
		log.Info("panel public", "url", publicURL(panelHost), "address", edgeLn.Addr().String())
		go func() { errc <- pubSrv.Serve(edgeLn) }()
	}
	// Only now is this version up: database migrated and listening. It is the
	// signal the update applier waits for before giving up on a rollback.
	if err := markReady(cfg.DataDir, version); err != nil {
		log.Error("mark version ready", "error", err)
	}
	defer func() { _ = os.Remove(filepath.Join(cfg.DataDir, update.ReadyFile)) }()

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("servidor: %w", err)
		}
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if pubSrv != nil {
		_ = pubSrv.Shutdown(shutdownCtx)
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return al.Record(shutdownCtx, audit.Entry{Action: "system.stop", Outcome: audit.OK})
}

// panelHosts are the Host values the panel accepts: the configured ones and
// its public hostname.
func panelHosts(cfg config.Config, public string) []string {
	hosts := slices.Clone(cfg.Panel.Hosts)
	if public != "" {
		hosts = append(hosts, public)
	}
	return hosts
}

// publicURL is the panel's public address ("" when private).
func publicURL(host string) string {
	if host == "" {
		return ""
	}
	return "https://" + host
}

// expectedPorts are the host ports allowed to listen to the internet: the
// configured ones (SSH), 80/443 with the edge, the panel's own addresses
// and every port opened from the panel.
func expectedPorts(cfg config.Config, pm *projects.Manager) func(context.Context) map[int]bool {
	return func(ctx context.Context) map[int]bool {
		ok := map[int]bool{}
		for _, p := range cfg.Alerts.AllowedPorts {
			ok[p] = true
		}
		if cfg.Edge.Enabled {
			ok[80], ok[443] = true, true
		}
		for _, l := range cfg.Panel.Listen {
			if _, port, err := net.SplitHostPort(l); err == nil {
				if n, err := strconv.Atoi(port); err == nil {
					ok[n] = true
				}
			}
		}
		if ports, err := pm.ListAllPorts(ctx); err == nil {
			for _, p := range ports {
				ok[int(p.HostPort)] = true
			}
		}
		return ok
	}
}

// monitor wires the server rules to Docker (when available) and the metrics.
func monitor(a *alerts.Service, pm *projects.Manager, mc *metrics.Collector) *alerts.Monitor {
	var states alerts.StatesFunc
	if pm.DockerAvailable() {
		states = func(ctx context.Context) ([]alerts.ServiceState, error) {
			list, err := pm.WatchedServices(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]alerts.ServiceState, 0, len(list))
			for _, w := range list {
				out = append(out, alerts.ServiceState{
					ID: w.ServiceID, Name: w.Name, Exists: w.Status.Exists, Running: w.Status.Running,
					State: w.Status.State, RestartCount: w.Status.RestartCount, OOMKilled: w.Status.OOMKilled,
				})
			}
			return out, nil
		}
	}
	return a.NewMonitor(states, mc.Latest)
}

// NewBackups builds the backup engine (docs/09). Panel backups work without
// Docker; database backups say Docker is missing.
func NewBackups(core *Core, pm *projects.Manager, cfg config.Config, version string, log *slog.Logger) (*backup.Manager, error) {
	return backup.New(core.Store.DB, core.Box, pm, core.Audit, log, backup.Options{
		StagingDir:            filepath.Join(cfg.DataDir, "backups", "staging"),
		AllowPrivateEndpoints: cfg.Backup.AllowPrivateEndpoints,
		DBPath:                filepath.Join(cfg.DataDir, "hangar.db"),
		MasterKeyFile:         cfg.MasterKeyFile,
		ConfigFile:            cfg.Path,
		CertsDir:              filepath.Join(cfg.DataDir, "edge", "data"),
		Version:               version,
	})
}

// startEdge brings Caddy up with the domains in the database and starts the
// endpoint that authorizes on-demand certificates.
func startEdge(ctx context.Context, cfg config.Config, core *Core, n node.Node, hooks http.Handler, panelHost string, dns edge.DNSSource, log *slog.Logger) (*edge.Manager, error) {
	subnet, gw, caddyIP := cfg.Edge.EdgeAddrs()
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		return nil, errors.New("refusing to run Caddy as root; run hangard as the hangar user")
	}
	auth := edge.NewAuthorizer(core.Store.DB, core.Box, n)
	auth.MaxNewPerHour = cfg.Edge.MaxNewCertsPerHour
	for _, ip := range cfg.Edge.PublicIPs {
		auth.PublicIPs = append(auth.PublicIPs, netip.MustParseAddr(ip))
	}
	em := edge.NewManager(dbq.New(core.Store.DB), n, auth, edge.Options{
		Spec: node.EdgeSpec{
			Image: cfg.Edge.Image, Subnet: subnet, Gateway: gw, CaddyIP: caddyIP,
			AdminDir: filepath.Join(cfg.DataDir, "edge", "admin"),
			DataDir:  filepath.Join(cfg.DataDir, "edge", "data"),
			UID:      uid, GID: gid,
		},
		Email: cfg.Edge.ACMEEmail, ACMECA: cfg.Edge.ACMECA, ACMECARoot: cfg.Edge.ACMECARoot,
		HooksHost: cfg.Edge.HooksHostname, Hooks: hooks, PanelHost: panelHost, BaseDomain: cfg.Edge.BaseDomain,
		DNSProvider: cfg.Edge.DNSProvider, DNSToken: cfg.Edge.DNSToken,
		PublicIPs: auth.PublicIPs,
		Pages: func(ctx context.Context) (map[string][]byte, error) {
			b, err := errpages.Load(ctx, dbq.New(core.Store.DB))
			if err != nil {
				return nil, err
			}
			return errpages.Render(b)
		},
	}, log)
	// The base domain, DNS provider and token set from the panel win over
	// hangar.toml; set before Start so the first config already has them.
	em.SetDNSSource(dns)
	startCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := em.Start(startCtx, ctx); err != nil {
		return nil, err
	}
	log.Info("edge proxy running", "image", cfg.Edge.Image, "ask", gw.String())
	return em, nil
}

func cleanupSessions(ctx context.Context, svc *auth.Service, log *slog.Logger) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := svc.CleanupSessions(ctx); err != nil {
				log.Error("clean up sessions", "error", err)
			} else if n > 0 {
				log.Info("expired sessions removed", "count", n)
			}
		}
	}
}

// refuseForeignOwner prevents running the panel (or the CLI) as a user other
// than data_dir's owner. As root, SQLite would create root-owned -wal and
// -shm files and the service (user hangar) could no longer open the
// database.
func refuseForeignOwner(dataDir string) error {
	info, err := os.Stat(dataDir)
	if err != nil {
		return nil // does not exist yet: whoever creates it becomes the owner
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if uid := os.Geteuid(); uint32(uid) != st.Uid { //nolint:gosec // uid is never negative
		return i18n.E("app.error.foreign_owner", "dir", dataDir, "uid", st.Uid)
	}
	return nil
}

// deployNotifier sends failed deploys through the alert channels.
type deployNotifier struct {
	a   *alerts.Service
	log *slog.Logger
}

func (n deployNotifier) DeployFailed(ctx context.Context, f projects.DeployFailure) {
	err := n.a.DeployFailed(ctx, alerts.DeployFailure{
		ServiceID: f.ServiceID, Service: f.Service, Trigger: f.Trigger, Phase: f.Phase, Reason: f.Reason, Previous: f.Previous,
	})
	if err != nil {
		n.log.Warn("deploy failure alert", "service", f.Service, "error", err)
	}
}

func (n deployNotifier) DeploySucceeded(ctx context.Context, serviceID, service string) {
	if err := n.a.DeploySucceeded(ctx, serviceID, service); err != nil {
		n.log.Warn("deploy recovery alert", "service", service, "error", err)
	}
}

// depsNotifier sends the dependency monitor's notices (critical now,
// security daily, updates weekly) through the alert channels.
type depsNotifier struct{ a *alerts.Service }

func (n depsNotifier) Notify(ctx context.Context, x deps.Notice) error {
	sev := alerts.Warning
	switch x.Level {
	case "critical":
		sev = alerts.Critical
	case "updates":
		sev = alerts.Info
	}
	_, err := n.a.Notify(ctx, alerts.Event{
		Kind: "deps", Severity: sev, Category: alerts.Server,
		// Each summary is its own message: the key changes with the content.
		Key:    "deps:" + x.Level + ":" + strings.Join(x.Lines, "|"),
		Params: map[string]string{"title": x.Title, "lines": strings.Join(x.Lines, "\n"), "path": x.Path},
	})
	return err
}
