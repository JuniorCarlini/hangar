// Package alerts raises alerts and delivers them to the operator's channels
// (Telegram, e-mail, webhook), as docs/06 and docs/17 § 3.10 describe.
//
// Alerts come from two places: server rules evaluated by the Monitor
// (container down, restart loop, disk, memory, CPU) and security events
// taken from the audit log (login from a new IP, account locked, 2FA turned
// off, sudo actions, updates, lockdown). Security alerts cannot be turned
// off and reach every enabled channel.
//
// Every alert is stored (the panel's bell and history), deduplicated by key,
// and delivered in the background with retries. Messages are fixed
// templates with the variable parts escaped by each channel: nothing from
// the outside world is interpreted as markup.
package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/keyset"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Severity of an alert. Channels receive their minimum and above.
type Severity string

// Severities, lowest first.
const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Severities lists the valid severities, lowest first.
var Severities = []Severity{Info, Warning, Critical}

func (s Severity) rank() int {
	switch s {
	case Warning:
		return 1
	case Critical:
		return 2
	}
	return 0
}

// ParseSeverity validates a stored or submitted severity.
func ParseSeverity(s string) (Severity, bool) {
	for _, v := range Severities {
		if string(v) == s {
			return v, true
		}
	}
	return "", false
}

// Category says where an alert came from.
type Category string

// Categories.
const (
	Server   Category = "server"
	Security Category = "security"
)

// Event is something worth telling the operator about.
type Event struct {
	Kind     string
	Severity Severity
	Category Category
	// Key groups the events of one condition for deduplication; empty =
	// the kind itself.
	Key string
	// Params fill the message template (names, counts, addresses). Never
	// secrets.
	Params map[string]string
	// Resolved marks the "back to normal" notice of a server rule.
	Resolved bool
}

// Deduplication and limits.
const (
	// dedupWindow swallows repeats of a still-firing condition.
	dedupWindow    = 30 * time.Minute
	securityWindow = 10 * time.Minute
	// flapLimit firings of one key per flapWindow; more are swallowed.
	flapLimit  = 3
	flapWindow = time.Hour
	// channelBurst messages per channel per channelWindow; beyond that the
	// delivery is dropped (the alert stays in the panel).
	channelBurst  = 20
	channelWindow = 10 * time.Minute
	queueSize     = 256
	sendTimeout   = 15 * time.Second
)

// Options tunes the Service (tests point the channels at fake servers).
type Options struct {
	Now func() time.Time
	// TelegramAPI replaces https://api.telegram.org.
	TelegramAPI string
	// HTTPClient sends Telegram and webhook requests; nil builds one that
	// refuses private and loopback addresses (anti-SSRF, docs/17 #11).
	HTTPClient *http.Client
	// AllowInsecure lets tests use plain HTTP webhooks and SMTP without a
	// trusted certificate. Never set in production.
	AllowInsecure bool
	// SMTPRootCAs trusts a test SMTP server's certificate.
	SMTPTLS *TLSOverride
	// Backoff between delivery attempts; nil = 2 s, 10 s.
	Backoff []time.Duration
	// Locale renders messages sent to channels; empty = the default.
	Locale string
}

// Service stores alerts and delivers them.
type Service struct {
	db    *sql.DB
	q     *dbq.Queries
	box   *secrets.Box
	audit *audit.Logger
	log   *slog.Logger
	opt   Options

	mu      sync.Mutex
	queue   chan job
	events  chan audit.Entry
	pending sync.WaitGroup
}

// New creates the service. Without Start, deliveries happen synchronously
// inside Notify (the command line).
func New(db *sql.DB, box *secrets.Box, al *audit.Logger, log *slog.Logger, opt Options) *Service {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Backoff == nil {
		opt.Backoff = []time.Duration{2 * time.Second, 10 * time.Second}
	}
	if opt.Locale == "" {
		opt.Locale = i18n.Default
	}
	if opt.HTTPClient == nil {
		opt.HTTPClient = safeHTTPClient(opt.AllowInsecure)
	}
	return &Service{db: db, q: dbq.New(db), box: box, audit: al, log: log, opt: opt}
}

// Start runs the delivery worker and the audit observer until ctx ends.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	s.queue = make(chan job, queueSize)
	s.events = make(chan audit.Entry, queueSize)
	s.mu.Unlock()
	go s.deliverLoop(ctx)
	go s.observeLoop(ctx)
	// Old alerts and deliveries are pruned by the retention janitor
	// (internal/retention, docs/20).
}

// Wait blocks until queued deliveries are done (tests and shutdown).
func (s *Service) Wait() { s.pending.Wait() }

type job struct {
	alertID int64
	ch      dbq.AlertChannel
	ev      Event
	at      time.Time
}

// Notify records the event and sends it to the channels that want it. It
// returns the alert id (0 when it was a duplicate and only counted).
func (s *Service) Notify(ctx context.Context, ev Event) (int64, error) {
	if ev.Key == "" {
		ev.Key = ev.Kind
	}
	clean := make(map[string]string, len(ev.Params))
	for k, v := range ev.Params {
		clean[k] = cleanParam(v)
	}
	ev.Params = clean
	now := s.opt.Now()
	last, err := s.q.LastAlertByKey(ctx, ev.Key)
	hasLast := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("alerts: last by key: %w", err)
	}

	switch {
	case ev.Resolved:
		// Only a condition that was announced gets its "back to normal".
		if !hasLast || last.Resolved == 1 {
			return 0, nil
		}
	case hasLast && last.Resolved == 0 && now.Sub(time.Unix(last.CreatedAt, 0)) < window(ev):
		return 0, s.q.BumpAlertRepeat(ctx, dbq.BumpAlertRepeatParams{LastAt: now.Unix(), ID: last.ID})
	default:
		n, err := s.q.CountFiringSince(ctx, dbq.CountFiringSinceParams{DedupKey: ev.Key, CreatedAt: now.Add(-flapWindow).Unix()})
		if err != nil {
			return 0, err
		}
		if n >= flapLimit && hasLast {
			return 0, s.q.BumpAlertRepeat(ctx, dbq.BumpAlertRepeatParams{LastAt: now.Unix(), ID: last.ID})
		}
	}

	muted := ev.Category != Security && s.mutedAt(ctx, now)
	params, _ := json.Marshal(ev.Params)
	id, err := s.q.InsertAlert(ctx, dbq.InsertAlertParams{
		Kind: ev.Kind, Severity: string(ev.Severity), Category: string(ev.Category), DedupKey: ev.Key,
		ParamsJson: string(params), Resolved: boolInt(ev.Resolved), Muted: boolInt(muted),
		CreatedAt: now.Unix(), LastAt: now.Unix(),
	})
	if err != nil {
		return 0, fmt.Errorf("alerts: insert: %w", err)
	}
	if muted {
		return id, nil
	}

	chans, err := s.q.ListAlertChannels(ctx)
	if err != nil {
		return id, err
	}
	for _, ch := range chans {
		if ch.Enabled != 1 || !wants(ch, ev) {
			continue
		}
		s.enqueue(ctx, job{alertID: id, ch: ch, ev: ev, at: now})
	}
	return id, nil
}

// window is how long a repeat of a still-open condition is swallowed.
// Security events have no "resolved" notice, so theirs is shorter: a
// repeated sensitive action is told again after a few minutes.
func window(ev Event) time.Duration {
	if ev.Category == Security {
		return securityWindow
	}
	return dedupWindow
}

// wants reports whether the channel receives the event: security alerts go
// everywhere; the rest from the channel's minimum severity up.
func wants(ch dbq.AlertChannel, ev Event) bool {
	if ev.Category == Security {
		return true
	}
	min, _ := ParseSeverity(ch.MinSeverity)
	return ev.Severity.rank() >= min.rank()
}

func (s *Service) enqueue(ctx context.Context, j job) {
	s.mu.Lock()
	q := s.queue
	s.mu.Unlock()
	if q == nil {
		s.deliver(ctx, j)
		return
	}
	s.pending.Add(1)
	select {
	case q <- j:
	default:
		s.pending.Done()
		s.recordDelivery(ctx, j, "dropped", 0, "queue full")
	}
}

func (s *Service) deliverLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.queue:
			s.deliver(ctx, j)
			s.pending.Done()
		}
	}
}

// deliver sends one alert to one channel, retrying with backoff, and writes
// the outcome to the delivery log.
func (s *Service) deliver(ctx context.Context, j job) {
	ctx = context.WithoutCancel(ctx)
	since := s.opt.Now().Add(-channelWindow).Unix()
	if n, err := s.q.CountChannelDeliveriesSince(ctx, dbq.CountChannelDeliveriesSinceParams{
		ChannelID: sql.NullString{String: j.ch.ID, Valid: true}, CreatedAt: since,
	}); err == nil && n >= channelBurst {
		s.recordDelivery(ctx, j, "dropped", 0, "rate limited")
		return
	}
	snd, err := s.senderFor(j.ch)
	if err != nil {
		s.recordDelivery(ctx, j, "failed", 0, err.Error())
		return
	}
	msg := s.render(j.alertID, j.ev, j.at)
	var lastErr error
	attempts := 0
	for i := 0; i <= len(s.opt.Backoff); i++ {
		if i > 0 {
			time.Sleep(s.opt.Backoff[i-1])
		}
		attempts++
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		lastErr = snd.send(sctx, msg)
		cancel()
		if lastErr == nil {
			s.recordDelivery(ctx, j, "sent", attempts, "")
			return
		}
		var perm *permanentError
		if errors.As(lastErr, &perm) {
			break
		}
	}
	s.log.Warn("alert delivery failed", "channel", j.ch.ID, "kind", j.ev.Kind, "error", lastErr)
	s.recordDelivery(ctx, j, "failed", attempts, lastErr.Error())
}

func (s *Service) recordDelivery(ctx context.Context, j job, status string, attempts int, errText string) {
	kind := j.ev.Kind
	err := s.q.InsertAlertDelivery(context.WithoutCancel(ctx), dbq.InsertAlertDeliveryParams{
		AlertID:     sql.NullInt64{Int64: j.alertID, Valid: j.alertID > 0},
		ChannelID:   sql.NullString{String: j.ch.ID, Valid: true},
		ChannelName: j.ch.Name, ChannelKind: j.ch.Kind, Kind: kind, Status: status,
		Attempts: int64(attempts), Error: truncate(errText, 300), CreatedAt: s.opt.Now().Unix(),
	})
	if err != nil {
		s.log.Error("record alert delivery", "error", err)
	}
}

// Message is an alert rendered for the channels.
type Message struct {
	ID       int64
	Kind     string
	Severity Severity
	Category Category
	Resolved bool
	Title    string
	Text     string
	Params   map[string]string
	At       time.Time
}

// render builds the message in the channels' language.
func (s *Service) render(id int64, ev Event, at time.Time) Message {
	title, text := Texts(s.opt.Locale, ev.Kind, ev.Resolved, ev.Params)
	return Message{
		ID: id, Kind: ev.Kind, Severity: ev.Severity, Category: ev.Category, Resolved: ev.Resolved,
		Title: title, Text: text, Params: maps.Clone(ev.Params), At: at,
	}
}

// Texts returns an alert's title and body in the locale.
func Texts(locale, kind string, resolved bool, params map[string]string) (string, string) {
	args := make([]any, 0, len(params)*2)
	for k, v := range params {
		switch k {
		case "action": // stored as a key, shown as words
			v = i18n.Tl(locale, "alert.action."+v)
		case "role":
			v = i18n.Tl(locale, "role."+v)
		}
		if kind == "deploy_failed" {
			switch k {
			case "phase":
				v = i18n.Tl(locale, "deploy.phase."+v)
			case "trigger":
				v = i18n.Tl(locale, "deploy.trigger."+v)
			case "previous":
				v = i18n.Tl(locale, "alert.previous."+v)
			}
		}
		args = append(args, k, v)
	}
	title := i18n.Tl(locale, "alert.title."+kind, args...)
	if resolved {
		return i18n.Tl(locale, "alert.resolved_title", "title", title), i18n.Tl(locale, "alert.resolved_text")
	}
	return title, i18n.Tl(locale, "alert.text."+kind, args...)
}

const muteKey = "alerts.muted_until"

// MaxMute is the longest silence allowed: a forgotten mute must end.
const MaxMute = 24 * time.Hour

// Mute silences server alerts for d (0 unmutes). Security alerts are never
// muted. Muted alerts are still recorded and shown in the panel.
func (s *Service) Mute(ctx context.Context, a Actor, d time.Duration) error {
	if d < 0 || d > MaxMute {
		return i18n.E("alerts.error.mute")
	}
	v := "0"
	if d > 0 {
		v = fmt.Sprint(s.opt.Now().Add(d).Unix())
	}
	if err := s.q.SetSetting(ctx, dbq.SetSettingParams{Key: muteKey, ValueJson: v}); err != nil {
		return err
	}
	if s.audit != nil {
		_ = s.audit.Record(context.WithoutCancel(ctx), audit.Entry{
			ActorID: a.UserID, IP: a.IP, Action: "alerts.mute", Outcome: audit.OK,
			Summary: map[string]any{"minutes": int(d.Minutes())},
		})
	}
	return nil
}

// MutedUntil is when server alerts come back (zero = not muted).
func (s *Service) MutedUntil(ctx context.Context) time.Time {
	v, err := s.q.GetSetting(ctx, muteKey)
	if err != nil {
		return time.Time{}
	}
	var unix int64
	if json.Unmarshal([]byte(v), &unix) != nil || unix <= 0 {
		return time.Time{}
	}
	t := time.Unix(unix, 0)
	if !t.After(s.opt.Now()) {
		return time.Time{}
	}
	return t
}

func (s *Service) mutedAt(ctx context.Context, now time.Time) bool {
	return s.MutedUntil(ctx).After(now)
}

// Recent lists the newest alerts (security ones only for admins).
func (s *Service) Recent(ctx context.Context, withSecurity bool, limit int) ([]dbq.Alert, error) {
	return s.q.RecentAlerts(ctx, dbq.RecentAlertsParams{WithSecurity: boolInt(withSecurity), Lim: int64(limit)})
}

// Unread reports whether there is an alert newer than the user has seen.
func (s *Service) Unread(ctx context.Context, userID string, withSecurity bool) (bool, error) {
	latest, err := s.q.LatestAlertID(ctx, boolInt(withSecurity))
	if err != nil || latest == 0 {
		return false, err
	}
	seen, err := s.q.GetAlertSeen(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return latest > seen, err
}

// MarkSeen records that the user saw every alert up to now.
func (s *Service) MarkSeen(ctx context.Context, userID string, withSecurity bool) error {
	latest, err := s.q.LatestAlertID(ctx, boolInt(withSecurity))
	if err != nil {
		return err
	}
	return s.q.SetAlertSeen(ctx, dbq.SetAlertSeenParams{UserID: userID, LastID: latest})
}

// HistoryPage is one keyset page of the alerts (security ones only for
// admins), newest first.
func (s *Service) HistoryPage(ctx context.Context, withSecurity bool, req keyset.Request, size int) (keyset.Page[dbq.Alert], error) {
	sec := boolInt(withSecurity)
	return keyset.Fetch(req, size,
		func(k keyset.Key, lim int64) ([]dbq.Alert, error) {
			return s.q.AlertsOlder(ctx, dbq.AlertsOlderParams{WithSecurity: sec, BeforeID: k.At, Lim: lim})
		},
		func(k keyset.Key, lim int64) ([]dbq.Alert, error) {
			return s.q.AlertsNewer(ctx, dbq.AlertsNewerParams{WithSecurity: sec, AfterID: k.At, Lim: lim})
		},
		func(a dbq.Alert) keyset.Key { return keyset.Key{At: a.ID} })
}

// DeliveriesPage is one keyset page of the delivery attempts, newest first.
func (s *Service) DeliveriesPage(ctx context.Context, req keyset.Request, size int) (keyset.Page[dbq.AlertDelivery], error) {
	return keyset.Fetch(req, size,
		func(k keyset.Key, lim int64) ([]dbq.AlertDelivery, error) {
			return s.q.AlertDeliveriesOlder(ctx, dbq.AlertDeliveriesOlderParams{BeforeID: k.At, Lim: lim})
		},
		func(k keyset.Key, lim int64) ([]dbq.AlertDelivery, error) {
			return s.q.AlertDeliveriesNewer(ctx, dbq.AlertDeliveriesNewerParams{AfterID: k.At, Lim: lim})
		},
		func(d dbq.AlertDelivery) keyset.Key { return keyset.Key{At: d.ID} })
}

// Deliveries lists the newest delivery attempts.
func (s *Service) Deliveries(ctx context.Context, limit int) ([]dbq.AlertDelivery, error) {
	return s.q.RecentAlertDeliveries(ctx, int64(limit))
}

// cleanParam keeps a parameter on one short line: names come from users
// and the audit log, and a line break could fake a second message line (or,
// in e-mail, look like a header).
func cleanParam(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, v)
	if r := []rune(v); len(r) > 200 {
		v = string(r[:200]) + "…"
	}
	return v
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
