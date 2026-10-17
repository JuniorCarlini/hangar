// Package statuspage manages the public status links (docs/15): links that
// show the server's health without login and without anything useful to an
// attacker.
//
// The public side only ever sees a Public snapshot: a struct built here with
// the allowed fields only (percentages, rates, states, public labels). Real
// names, images, versions, IPs and domains never enter it, so no template or
// encoder downstream can leak them by mistake.
package statuspage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/metrics"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Naming modes: how services appear on a link.
const (
	NamingAlias   = "alias"   // the service's public label ("Loja principal")
	NamingGeneric = "generic" // "Serviço A", "Serviço B"…
	NamingHidden  = "hidden"  // server totals only
)

// Expiry choices offered when creating a link.
var Expiries = map[string]time.Duration{"never": 0, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

// Errors.
var (
	// ErrNotFound covers every way a public token can fail (unknown,
	// revoked, expired, address not allowed): the visitor always gets the
	// same 404.
	ErrNotFound  = errors.New("status link not found")
	ErrName      = &i18n.Error{Key: "statuslink.error.name"}
	ErrNaming    = &i18n.Error{Key: "statuslink.error.naming"}
	ErrExpiry    = &i18n.Error{Key: "statuslink.error.expiry"}
	ErrCIDR      = &i18n.Error{Key: "statuslink.error.cidr"}
	ErrServices  = &i18n.Error{Key: "statuslink.error.services"}
	ErrAlias     = &i18n.Error{Key: "statuslink.error.alias"}
	ErrNoSuchURL = &i18n.Error{Key: "statuslink.error.not_found"}
)

// Metrics is the read-only view of the collector the snapshot needs.
type Metrics interface {
	Latest() metrics.Snapshot
	History(ctx context.Context, key string, p metrics.Period) ([]metrics.Point, error)
}

// AlertCounter counts active alerts (Etapa 8). nil = always 0.
type AlertCounter interface {
	ActiveAlerts(ctx context.Context) int
}

// Service manages links and builds their snapshots.
type Service struct {
	q      *dbq.Queries
	m      Metrics
	audit  *audit.Logger
	log    *slog.Logger
	now    func() time.Time
	alerts AlertCounter

	mu    sync.Mutex
	cache map[string]cachedSnap // link id + locale → snapshot
}

type cachedSnap struct {
	s  Public
	at time.Time
}

// CacheFor is how long a snapshot is reused: a thousand visits cost one
// reading of the metrics.
const CacheFor = 10 * time.Second

// New creates the service.
func New(db *sql.DB, m Metrics, al *audit.Logger, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{q: dbq.New(db), m: m, audit: al, log: log, now: time.Now, cache: map[string]cachedSnap{}}
}

// SetAlerts plugs the alert counter in (Etapa 8).
func (s *Service) SetAlerts(a AlertCounter) {
	s.mu.Lock()
	s.alerts = a
	s.mu.Unlock()
}

// Actor is who changes links, for the audit log.
type Actor struct {
	UserID string
	IP     string
}

// Input is a new link's configuration.
type Input struct {
	Name       string
	Naming     string
	ServiceIDs []string
	Expiry     string // never, 24h, 7d, 30d
	CIDRs      string // comma or space separated; "" = any address
}

// Link is a link as the panel shows it (never the token).
type Link struct {
	ID          string
	Name        string
	Naming      string
	Services    int
	CIDRs       []string
	ExpiresAt   time.Time // zero = never
	Expired     bool
	CreatedAt   time.Time
	LastAccess  time.Time // zero = never opened
	LastIP      string    // masked
	AccessCount int64
	AccessToday int64
}

// TokenBytes is the token's random length (docs/15: 32 bytes).
const TokenBytes = 32

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Create stores a new link and returns its token, shown only this once.
func (s *Service) Create(ctx context.Context, a Actor, in Input, knownServices map[string]bool) (string, Link, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > 60 {
		return "", Link{}, ErrName
	}
	if in.Naming != NamingAlias && in.Naming != NamingGeneric && in.Naming != NamingHidden {
		return "", Link{}, ErrNaming
	}
	ttl, ok := Expiries[in.Expiry]
	if !ok {
		return "", Link{}, ErrExpiry
	}
	cidrs, err := parseCIDRs(in.CIDRs)
	if err != nil {
		return "", Link{}, err
	}
	var svcs []string
	seen := map[string]bool{}
	if in.Naming != NamingHidden {
		for _, id := range in.ServiceIDs {
			if !knownServices[id] {
				return "", Link{}, ErrServices
			}
			if !seen[id] {
				seen[id] = true
				svcs = append(svcs, id)
			}
		}
	}
	svcJSON, _ := json.Marshal(append([]string{}, svcs...))

	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", Link{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now()
	p := dbq.CreateStatusLinkParams{
		ID: ids.New("stl_"), Name: name, TokenHash: hashToken(token), Naming: in.Naming,
		ServiceIdsJson: string(svcJSON), AllowedCidrs: strings.Join(cidrs, ","),
		CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, CreatedAt: now.Unix(),
	}
	if ttl > 0 {
		p.ExpiresAt = sql.NullInt64{Int64: now.Add(ttl).Unix(), Valid: true}
	}
	if err := s.q.CreateStatusLink(ctx, p); err != nil {
		return "", Link{}, err
	}
	s.record(ctx, a, "status_link.create", p.ID, map[string]any{
		"name": name, "naming": in.Naming, "services": len(svcs), "expiry": in.Expiry, "cidrs": p.AllowedCidrs,
	})
	l := Link{ID: p.ID, Name: name, Naming: in.Naming, Services: len(svcs), CIDRs: cidrs, CreatedAt: now}
	if p.ExpiresAt.Valid {
		l.ExpiresAt = time.Unix(p.ExpiresAt.Int64, 0)
	}
	return token, l, nil
}

func parseCIDRs(in string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(in, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked().String())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, ErrCIDR
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String())
	}
	if len(out) > 20 {
		return nil, ErrCIDR
	}
	return out, nil
}

// Revoke disables a link for good: its URL answers 404 from now on.
func (s *Service) Revoke(ctx context.Context, a Actor, id string) error {
	n, err := s.q.RevokeStatusLink(ctx, dbq.RevokeStatusLinkParams{RevokedAt: sql.NullInt64{Int64: s.now().Unix(), Valid: true}, ID: id})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoSuchURL
	}
	s.mu.Lock()
	for k := range s.cache {
		if strings.HasPrefix(k, id+"|") {
			delete(s.cache, k)
		}
	}
	s.mu.Unlock()
	s.record(ctx, a, "status_link.revoke", id, nil)
	return nil
}

// RevokeAll disables every link (the lockdown button, docs/17 § 1.6).
func (s *Service) RevokeAll(ctx context.Context, a Actor) (int64, error) {
	n, err := s.q.RevokeAllStatusLinks(ctx, sql.NullInt64{Int64: s.now().Unix(), Valid: true})
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.cache = map[string]cachedSnap{}
	s.mu.Unlock()
	s.record(ctx, a, "status_link.revoke_all", "", map[string]any{"count": n})
	return n, nil
}

// List returns the links not revoked, newest first.
func (s *Service) List(ctx context.Context) ([]Link, error) {
	rows, err := s.q.ListStatusLinks(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]Link, 0, len(rows))
	for _, r := range rows {
		l := Link{
			ID: r.ID, Name: r.Name, Naming: r.Naming, CreatedAt: time.Unix(r.CreatedAt, 0),
			LastIP: r.LastAccessIp, AccessCount: r.AccessCount,
		}
		var svcs []string
		_ = json.Unmarshal([]byte(r.ServiceIdsJson), &svcs)
		l.Services = len(svcs)
		if r.AllowedCidrs != "" {
			l.CIDRs = strings.Split(r.AllowedCidrs, ",")
		}
		if r.ExpiresAt.Valid {
			l.ExpiresAt = time.Unix(r.ExpiresAt.Int64, 0)
			l.Expired = !now.Before(l.ExpiresAt)
		}
		if r.LastAccessAt.Valid {
			l.LastAccess = time.Unix(r.LastAccessAt.Int64, 0)
		}
		if r.AccessDay == dayOf(now) {
			l.AccessToday = r.AccessToday
		}
		out = append(out, l)
	}
	return out, nil
}

func dayOf(t time.Time) int64 { return t.Unix() / 86400 }

// Aliases returns the public label of each service that has one.
func (s *Service) Aliases(ctx context.Context) (map[string]string, error) {
	rows, err := s.q.ListServiceAliases(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.ServiceID] = r.PublicLabel
	}
	return out, nil
}

// SetAlias sets (or clears, with "") a service's public label.
func (s *Service) SetAlias(ctx context.Context, a Actor, serviceID, label string, knownServices map[string]bool) error {
	if !knownServices[serviceID] {
		return ErrServices
	}
	label = strings.Join(strings.Fields(label), " ")
	if utf8.RuneCountInString(label) > 40 {
		return ErrAlias
	}
	var err error
	if label == "" {
		err = s.q.DeleteServiceAlias(ctx, serviceID)
	} else {
		err = s.q.SetServiceAlias(ctx, dbq.SetServiceAliasParams{ServiceID: serviceID, PublicLabel: label})
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cache = map[string]cachedSnap{}
	s.mu.Unlock()
	s.record(ctx, a, "status_link.alias", serviceID, map[string]any{"label": label})
	return nil
}

func (s *Service) record(ctx context.Context, a Actor, action, id string, summary map[string]any) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(context.WithoutCancel(ctx), audit.Entry{
		ActorID: a.UserID, IP: a.IP, Action: action, Outcome: audit.OK,
		TargetType: "status_link", TargetID: id, Summary: summary,
	}); err != nil {
		s.log.Error("failed to write audit record", "action", action, "error", err)
	}
}

// --- public side ------------------------------------------------------------

// Resolved is a valid link as the public handler sees it.
type Resolved struct {
	id       string
	naming   string
	services []string
}

// Resolve checks a token for a visitor at ip. Any failure is ErrNotFound.
// The lookup is by the token's hash, so the database never compares raw
// tokens and both a good and a bad token cost one indexed query.
func (s *Service) Resolve(ctx context.Context, token string, ip netip.Addr) (Resolved, error) {
	if len(token) < 20 || len(token) > 100 {
		// Still hash, so a malformed token takes the same path.
		_ = hashToken(token)
		return Resolved{}, ErrNotFound
	}
	r, err := s.q.GetStatusLinkByHash(ctx, hashToken(token))
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.log.Error("status link lookup", "error", err)
		}
		return Resolved{}, ErrNotFound
	}
	now := s.now()
	if r.RevokedAt.Valid || (r.ExpiresAt.Valid && !now.Before(time.Unix(r.ExpiresAt.Int64, 0))) {
		return Resolved{}, ErrNotFound
	}
	if r.AllowedCidrs != "" && !allowed(r.AllowedCidrs, ip) {
		return Resolved{}, ErrNotFound
	}
	var svcs []string
	_ = json.Unmarshal([]byte(r.ServiceIdsJson), &svcs)
	if err := s.q.RecordStatusLinkAccess(ctx, dbq.RecordStatusLinkAccessParams{
		Day: dayOf(now), Now: sql.NullInt64{Int64: now.Unix(), Valid: true}, Ip: MaskIP(ip), ID: r.ID,
	}); err != nil {
		s.log.Warn("record status link access", "error", err)
	}
	return Resolved{id: r.ID, naming: r.Naming, services: svcs}, nil
}

func allowed(list string, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, c := range strings.Split(list, ",") {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// MaskIP keeps only the network part, for the access counter shown in the
// panel ("189.x.x.x").
func MaskIP(ip netip.Addr) string {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid():
		return ""
	case ip.Is4():
		b := ip.As4()
		return fmt.Sprintf("%d.x.x.x", b[0])
	}
	b := ip.As16()
	return fmt.Sprintf("%x:%x::x", uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3]))
}

// Public is everything a status link may show. Nothing else exists in it.
type Public struct {
	GeneratedAt  time.Time       `json:"generated_at"`
	Server       PublicServer    `json:"server"`
	Services     []PublicService `json:"services"`
	AlertsActive int             `json:"alerts_active"`
	// History of the server (percent per bar, -1 = no data), for the page.
	CPUHist map[string][]int `json:"-"`
	MemHist map[string][]int `json:"-"`
}

// PublicServer are the server totals.
type PublicServer struct {
	CPUPct   float64 `json:"cpu_pct"`
	MemPct   float64 `json:"mem_pct"`
	DiskPct  float64 `json:"disk_pct"`
	NetRxBps float64 `json:"net_rx_bps"`
	NetTxBps float64 `json:"net_tx_bps"`
	UptimeS  int64   `json:"uptime_s"`
}

// Public service states.
const (
	StateRunning  = "running"
	StateDegraded = "degraded"
	StateStopped  = "stopped"
)

// PublicService is a service under its public label.
type PublicService struct {
	Label        string  `json:"label"`
	State        string  `json:"state"`
	CPUPct       float64 `json:"cpu_pct"` // of the whole server
	MemPct       float64 `json:"mem_pct"` // of its own limit
	NetBps       float64 `json:"net_bps"`
	UptimePct24h float64 `json:"uptime_pct_24h"`
}

// HistoryPeriods are the windows the public page offers.
var HistoryPeriods = []string{"1h", "24h", "7d"}

// Snapshot builds (or reuses, for CacheFor) the public view of a link.
// locale only affects generic labels ("Serviço A" / "Service A").
func (s *Service) Snapshot(ctx context.Context, l Resolved, locale string) Public {
	key := l.id + "|" + locale
	now := s.now()
	s.mu.Lock()
	if c, ok := s.cache[key]; ok && now.Sub(c.at) < CacheFor {
		s.mu.Unlock()
		return c.s
	}
	alerts := s.alerts
	s.mu.Unlock()

	p := s.build(ctx, l, locale, now)
	if alerts != nil {
		p.AlertsActive = alerts.ActiveAlerts(ctx)
	}
	s.mu.Lock()
	s.cache[key] = cachedSnap{s: p, at: now}
	if len(s.cache) > 1000 { // many links × languages: start over rather than grow
		s.cache = map[string]cachedSnap{key: {s: p, at: now}}
	}
	s.mu.Unlock()
	return p
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func pctOf(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return round1(float64(used) * 100 / float64(total))
}

func (s *Service) build(ctx context.Context, l Resolved, locale string, now time.Time) Public {
	snap := s.m.Latest()
	cpus := max(snap.CPUs, 1)
	p := Public{
		GeneratedAt: now.UTC().Truncate(time.Second),
		Server: PublicServer{
			CPUPct: round1(snap.Host.CPU), MemPct: pctOf(snap.Host.Mem, snap.Host.MemLimit),
			DiskPct: pctOf(snap.Host.DiskUsed, snap.Host.DiskTotal), NetRxBps: math.Round(snap.Host.Rx),
			NetTxBps: math.Round(snap.Host.Tx), UptimeS: int64(snap.Uptime.Seconds()),
		},
		Services: []PublicService{},
		CPUHist:  map[string][]int{}, MemHist: map[string][]int{},
	}
	for _, name := range HistoryPeriods {
		pts, err := s.m.History(ctx, metrics.HostKey, metrics.ParsePeriod(name))
		if err != nil {
			s.log.Warn("status history", "error", err)
			continue
		}
		p.CPUHist[name] = bars(pts, func(pt metrics.Point) float64 { return pt.CPU })
		p.MemHist[name] = bars(pts, func(pt metrics.Point) float64 { return pctOf(pt.Mem, pt.MemLimit) })
	}
	if l.naming == NamingHidden {
		return p
	}
	aliases := map[string]string{}
	if l.naming == NamingAlias {
		aliases, _ = s.Aliases(ctx)
	}
	byKey := map[string]metrics.Container{}
	for _, c := range snap.Containers {
		byKey[c.Key] = c
	}
	day := metrics.ParsePeriod("24h")
	for i, id := range l.services {
		ps := PublicService{Label: GenericLabel(locale, i), State: StateStopped}
		if a := aliases[id]; a != "" {
			ps.Label = a
		}
		if c, ok := byKey[id]; ok {
			ps.State = publicState(c.State)
			ps.CPUPct = round1(c.CPU / float64(cpus))
			ps.MemPct = pctOf(c.Mem, c.MemLimit)
			ps.NetBps = math.Round(c.Rx + c.Tx)
		}
		if pts, err := s.m.History(ctx, id, day); err == nil {
			ps.UptimePct24h = uptimePct(pts)
		}
		p.Services = append(p.Services, ps)
	}
	return p
}

// GenericLabel is "Serviço A", "Serviço B"… "Serviço AA" in the locale.
func GenericLabel(locale string, i int) string {
	letters := ""
	for n := i; ; n = n/26 - 1 {
		letters = string(rune('A'+n%26)) + letters
		if n < 26 {
			break
		}
	}
	return i18n.Tl(locale, "status.generic_label", "letter", letters)
}

func publicState(docker string) string {
	switch docker {
	case "running":
		return StateRunning
	case "restarting", "paused", "created":
		return StateDegraded
	}
	return StateStopped
}

// uptimePct is the share of the 24 h bars with readings, counted from the
// first one (a service created 3 h ago that never stopped is at 100%).
func uptimePct(pts []metrics.Point) float64 {
	first := -1
	up := 0
	for i, pt := range pts {
		if pt.At.IsZero() {
			continue
		}
		if first < 0 {
			first = i
		}
		up++
	}
	if first < 0 {
		return 0
	}
	// The bar still being filled may lack a reading only because it just
	// started: do not count it as down.
	total := len(pts) - first
	if pts[len(pts)-1].At.IsZero() && total > 1 {
		total--
	}
	return round1(math.Min(100, float64(up)*100/float64(total)))
}

func bars(pts []metrics.Point, value func(metrics.Point) float64) []int {
	out := make([]int, len(pts))
	for i, pt := range pts {
		if pt.At.IsZero() {
			out[i] = -1
			continue
		}
		out[i] = int(math.Round(math.Max(0, math.Min(100, value(pt)))))
	}
	return out
}
