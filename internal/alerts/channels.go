package alerts

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Channel kinds.
const (
	KindTelegram = "telegram"
	KindEmail    = "email"
	KindWebhook  = "webhook"
)

// Kinds lists the channel kinds in display order.
var Kinds = []string{KindTelegram, KindEmail, KindWebhook}

// SMTP security modes. There is no plain mode: TLS is mandatory (docs/14).
const (
	SMTPStartTLS = "starttls"
	SMTPTLS      = "tls"
)

// Config is everything a channel needs. It is stored encrypted as a whole;
// only Channel.Target (a non-secret summary) is kept in clear.
type Config struct {
	// Telegram.
	BotToken string `json:"bot_token,omitempty"`
	ChatID   string `json:"chat_id,omitempty"`
	// E-mail.
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Security string   `json:"security,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	// Webhook. Discord and Slack put a token in the URL, so it is secret too.
	URL    string `json:"url,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// ErrChannelNotFound is returned for an unknown channel id.
var ErrChannelNotFound = &i18n.Error{Key: "alerts.error.channel_not_found"}

var (
	telegramTokenRE = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$`)
	telegramChatRE  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
	hostRE          = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
)

// Actor is who changes the channels, for the audit log.
type Actor struct {
	UserID string
	IP     string
}

// NewChannel is the form that creates a channel.
type NewChannel struct {
	Kind        string
	Name        string
	MinSeverity string
	Config      Config
}

// Validate checks the form and fills defaults (generated webhook secret,
// default SMTP port). It returns the non-secret target summary.
func (n *NewChannel) Validate(allowInsecure bool) (string, error) {
	n.Name = strings.Join(strings.Fields(n.Name), " ")
	if n.Name == "" || len([]rune(n.Name)) > 60 || strings.ContainsAny(n.Name, "<>") {
		return "", i18n.E("alerts.error.name")
	}
	if _, ok := ParseSeverity(n.MinSeverity); !ok {
		return "", i18n.E("alerts.error.severity")
	}
	c := &n.Config
	switch n.Kind {
	case KindTelegram:
		c.BotToken, c.ChatID = strings.TrimSpace(c.BotToken), strings.TrimSpace(c.ChatID)
		if !telegramTokenRE.MatchString(c.BotToken) {
			return "", i18n.E("alerts.error.bot_token")
		}
		if !telegramChatRE.MatchString(c.ChatID) {
			return "", i18n.E("alerts.error.chat_id")
		}
		*c = Config{BotToken: c.BotToken, ChatID: c.ChatID}
		return "chat " + c.ChatID, nil

	case KindEmail:
		c.Host = strings.ToLower(strings.TrimSpace(c.Host))
		if !hostRE.MatchString(c.Host) || len(c.Host) > 253 {
			return "", i18n.E("alerts.error.smtp_host")
		}
		if c.Security != SMTPStartTLS && c.Security != SMTPTLS {
			return "", i18n.E("alerts.error.smtp_security")
		}
		if c.Port == 0 {
			c.Port = 587
			if c.Security == SMTPTLS {
				c.Port = 465
			}
		}
		if c.Port < 1 || c.Port > 65535 {
			return "", i18n.E("alerts.error.smtp_port")
		}
		c.Username = strings.TrimSpace(c.Username)
		if strings.ContainsAny(c.Username, "\r\n") || len(c.Username) > 254 || len(c.Password) > 512 {
			return "", i18n.E("alerts.error.smtp_auth")
		}
		from, err := cleanAddress(c.From)
		if err != nil {
			return "", i18n.E("alerts.error.from")
		}
		c.From = from
		if len(c.To) == 0 || len(c.To) > 5 {
			return "", i18n.E("alerts.error.to")
		}
		for i, to := range c.To {
			a, err := cleanAddress(to)
			if err != nil {
				return "", i18n.E("alerts.error.to")
			}
			c.To[i] = a
		}
		*c = Config{Host: c.Host, Port: c.Port, Security: c.Security, Username: c.Username, Password: c.Password, From: c.From, To: c.To}
		return strings.Join(c.To, ", "), nil

	case KindWebhook:
		c.URL = strings.TrimSpace(c.URL)
		u, err := url.Parse(c.URL)
		if err != nil || u.Host == "" || u.User != nil || len(c.URL) > 2000 ||
			(u.Scheme != "https" && (!allowInsecure || u.Scheme != "http")) {
			return "", i18n.E("alerts.error.webhook_url")
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && !allowInsecure && !publicIP(ip) {
			return "", i18n.E("alerts.error.webhook_private")
		}
		c.Secret = strings.TrimSpace(c.Secret)
		if c.Secret == "" {
			c.Secret = newSecret()
		}
		if len(c.Secret) < 16 || len(c.Secret) > 256 {
			return "", i18n.E("alerts.error.webhook_secret")
		}
		*c = Config{URL: c.URL, Secret: c.Secret}
		return u.Hostname(), nil
	}
	return "", i18n.E("alerts.error.kind")
}

// cleanAddress accepts a bare e-mail address (no display name, no line
// breaks: nothing that could inject headers).
func cleanAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || strings.ContainsAny(s, "\r\n<>,;") || len(s) > 254 {
		return "", errors.New("invalid address")
	}
	return s, nil
}

func newSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func channelAD(id string) string { return "alert_channels|" + id + "|config_enc" }

// CreateChannel stores a new channel with its configuration encrypted.
func (s *Service) CreateChannel(ctx context.Context, a Actor, n NewChannel) (string, error) {
	target, err := n.Validate(s.opt.AllowInsecure)
	if err != nil {
		return "", err
	}
	id := ids.New("ach_")
	raw, err := json.Marshal(n.Config) //nolint:gosec // marshaled only to be encrypted right below
	if err != nil {
		return "", err
	}
	sealed, err := s.box.Seal(raw, channelAD(id))
	if err != nil {
		return "", err
	}
	now := s.opt.Now().Unix()
	if err := s.q.CreateAlertChannel(ctx, dbq.CreateAlertChannelParams{
		ID: id, Kind: n.Kind, Name: n.Name, Target: target, MinSeverity: n.MinSeverity, ConfigEnc: sealed,
		CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""}, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return "", fmt.Errorf("alerts: create channel: %w", err)
	}
	s.record(ctx, a, "alerts.channel.create", id, audit.OK, map[string]any{"kind": n.Kind, "name": n.Name, "min_severity": n.MinSeverity})
	return id, nil
}

// Channels lists the channels (secrets stay encrypted).
func (s *Service) Channels(ctx context.Context) ([]dbq.AlertChannel, error) {
	return s.q.ListAlertChannels(ctx)
}

func (s *Service) channel(ctx context.Context, id string) (dbq.AlertChannel, error) {
	ch, err := s.q.GetAlertChannel(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ch, ErrChannelNotFound
	}
	return ch, err
}

func (s *Service) config(ch dbq.AlertChannel) (Config, error) {
	raw, err := s.box.Open(ch.ConfigEnc, channelAD(ch.ID))
	if err != nil {
		return Config{}, fmt.Errorf("alerts: channel %s: %w", ch.ID, err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("alerts: channel %s: %w", ch.ID, err)
	}
	return c, nil
}

// RevealSecret returns the channel's secret in clear (bot token, SMTP
// password, webhook URL and signing secret). The route needs sudo; the
// reveal is audited as secret.reveal, which is itself a security alert.
func (s *Service) RevealSecret(ctx context.Context, a Actor, id string) (string, error) {
	ch, err := s.channel(ctx, id)
	if err != nil {
		return "", err
	}
	c, err := s.config(ch)
	if err != nil {
		return "", err
	}
	s.record(ctx, a, "secret.reveal", id, audit.OK, map[string]any{"channel": ch.Name, "kind": ch.Kind})
	switch ch.Kind {
	case KindTelegram:
		return c.BotToken, nil
	case KindEmail:
		return c.Password, nil
	}
	return c.URL + "\n" + c.Secret, nil
}

// DeleteChannel removes a channel.
func (s *Service) DeleteChannel(ctx context.Context, a Actor, id string) error {
	ch, err := s.channel(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.q.DeleteAlertChannel(ctx, id); err != nil {
		return err
	}
	s.record(ctx, a, "alerts.channel.delete", id, audit.OK, map[string]any{"channel": ch.Name, "kind": ch.Kind})
	return nil
}

// SetChannelEnabled pauses or resumes a channel.
func (s *Service) SetChannelEnabled(ctx context.Context, a Actor, id string, on bool) error {
	ch, err := s.channel(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.q.SetAlertChannelEnabled(ctx, dbq.SetAlertChannelEnabledParams{Enabled: boolInt(on), UpdatedAt: s.opt.Now().Unix(), ID: id}); err != nil {
		return err
	}
	s.record(ctx, a, "alerts.channel.toggle", id, audit.OK, map[string]any{"channel": ch.Name, "enabled": on})
	return nil
}

// TestChannel sends a test message right away (one attempt) and records it
// in the delivery log.
func (s *Service) TestChannel(ctx context.Context, a Actor, id string) error {
	ch, err := s.channel(ctx, id)
	if err != nil {
		return err
	}
	j := job{ch: ch, ev: Event{Kind: "test", Severity: Info, Category: Server}, at: s.opt.Now()}
	snd, err := s.senderFor(ch)
	if err == nil {
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		err = snd.send(sctx, s.render(0, j.ev, j.at))
		cancel()
	}
	if err != nil {
		s.recordDelivery(ctx, j, "failed", 1, err.Error())
		s.record(ctx, a, "alerts.channel.test", id, audit.Error, map[string]any{"channel": ch.Name})
		return i18n.E("alerts.error.test_failed", "error", err.Error())
	}
	s.recordDelivery(ctx, j, "sent", 1, "")
	s.record(ctx, a, "alerts.channel.test", id, audit.OK, map[string]any{"channel": ch.Name})
	return nil
}

func (s *Service) record(ctx context.Context, a Actor, action, target string, outcome audit.Outcome, summary map[string]any) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(context.WithoutCancel(ctx), audit.Entry{
		ActorID: a.UserID, IP: a.IP, Action: action, Outcome: outcome,
		TargetType: "alert_channel", TargetID: target, Summary: summary,
	})
}

// ParsePort reads the SMTP port field (empty = default).
func ParsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, i18n.E("alerts.error.smtp_port")
	}
	return p, nil
}

// ParseRecipients splits the "to" field on commas, semicolons and spaces.
func ParseRecipients(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}
