package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// TLSOverride trusts extra certificate authorities (test SMTP servers).
type TLSOverride struct{ RootCAs *x509.CertPool }

// sender delivers a rendered message to one channel.
type sender interface {
	send(ctx context.Context, m Message) error
}

// permanentError is a failure that retrying cannot fix (wrong token, chat
// not found, address refused).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(format string, args ...any) error {
	return &permanentError{err: fmt.Errorf(format, args...)}
}

func (s *Service) senderFor(ch dbq.AlertChannel) (sender, error) {
	c, err := s.config(ch)
	if err != nil {
		return nil, err
	}
	switch ch.Kind {
	case KindTelegram:
		api := s.opt.TelegramAPI
		if api == "" {
			api = "https://api.telegram.org"
		}
		return &telegram{api: strings.TrimRight(api, "/"), token: c.BotToken, chat: c.ChatID, client: s.opt.HTTPClient}, nil
	case KindEmail:
		var roots *x509.CertPool
		if s.opt.SMTPTLS != nil {
			roots = s.opt.SMTPTLS.RootCAs
		}
		return &email{cfg: c, roots: roots, allowInsecure: s.opt.AllowInsecure}, nil
	case KindWebhook:
		return &webhook{url: c.URL, secret: c.Secret, client: s.opt.HTTPClient}, nil
	}
	return nil, fmt.Errorf("unknown channel kind %q", ch.Kind)
}

// --- message text -------------------------------------------------------------

func mark(m Message) string {
	switch {
	case m.Resolved:
		return "🟢"
	case m.Severity == Critical:
		return "🔴"
	case m.Severity == Warning:
		return "🟠"
	}
	return "🔵"
}

// plainText is the message for Telegram and e-mail. It is plain text: no
// parse mode, no HTML, so a name with markup is shown as typed.
func plainText(m Message) string {
	return mark(m) + " " + m.Title + "\n" + m.Text + "\n\nHangar · " + m.At.Format("02/01/2006 15:04 MST")
}

// --- Telegram -----------------------------------------------------------------

type telegram struct {
	api, token, chat string
	client           *http.Client
}

func (t *telegram) send(ctx context.Context, m Message) error {
	body, _ := json.Marshal(map[string]any{
		"chat_id": t.chat, "text": plainText(m), "link_preview_options": map[string]bool{"is_disabled": true},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.api+"/bot"+t.token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		// The URL holds the bot token: never let it reach the log.
		return fmt.Errorf("telegram: %w", stripURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if resp.StatusCode == http.StatusOK && out.OK {
		return nil
	}
	desc := truncate(strings.ReplaceAll(out.Description, t.token, "[redacted]"), 200)
	if retryable(resp.StatusCode) {
		return fmt.Errorf("telegram: HTTP %d %s", resp.StatusCode, desc)
	}
	return permanent("telegram: HTTP %d %s", resp.StatusCode, desc)
}

// --- webhook ------------------------------------------------------------------

type webhook struct {
	url, secret string
	client      *http.Client
}

// WebhookPayload is the JSON body a webhook receives.
type WebhookPayload struct {
	ID       int64             `json:"id"`
	Kind     string            `json:"kind"`
	Severity Severity          `json:"severity"`
	Category Category          `json:"category"`
	Resolved bool              `json:"resolved"`
	Title    string            `json:"title"`
	Text     string            `json:"text"`
	Params   map[string]string `json:"params"`
	At       time.Time         `json:"at"`
}

// SignWebhook is the signature header value for a body sent at ts:
// "sha256=" + hex(HMAC-SHA256(secret, ts + "." + body)). The timestamp is
// signed too, so a receiver can refuse old replays.
func SignWebhook(secret string, ts int64, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(strconv.FormatInt(ts, 10)))
	h.Write([]byte("."))
	h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func (w *webhook) send(ctx context.Context, m Message) error {
	body, err := json.Marshal(WebhookPayload{
		ID: m.ID, Kind: m.Kind, Severity: m.Severity, Category: m.Category, Resolved: m.Resolved,
		Title: m.Title, Text: m.Text, Params: m.Params, At: m.At.UTC(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return permanent("webhook: invalid URL")
	}
	ts := time.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Hangar-Alerts")
	req.Header.Set("X-Hangar-Event", m.Kind)
	req.Header.Set("X-Hangar-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Hangar-Signature", SignWebhook(w.secret, ts, body))
	resp, err := w.client.Do(req)
	if err != nil {
		// Discord and Slack keep a token in the URL.
		return fmt.Errorf("webhook: %w", stripURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if retryable(resp.StatusCode) {
		return fmt.Errorf("webhook: HTTP %d", resp.StatusCode)
	}
	return permanent("webhook: HTTP %d", resp.StatusCode)
}

func retryable(status int) bool {
	return status >= 500 || status == http.StatusTooManyRequests || status == http.StatusRequestTimeout
}

// stripURL drops the URL from an HTTP client error, keeping the cause.
func stripURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// safeHTTPClient refuses to connect to private, loopback, link-local and
// other special addresses, checked on the address actually dialed (after
// DNS), so a name that resolves to the cloud metadata service is refused
// too (anti-SSRF and DNS rebinding, docs/17 #11). It never follows
// redirects and ignores proxy variables.
func safeHTTPClient(allowInsecure bool) *http.Client {
	dialer := safeDialer(allowInsecure)
	return &http.Client{
		Timeout: sendTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// safeDialer only connects to public addresses, checked after DNS. The
// e-mail channel uses it too: its host and port are free text, and without
// the check an admin could probe the server's internal network (or the
// cloud metadata service) and read the first line each service answers.
func safeDialer(allowInsecure bool) *net.Dialer {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !allowInsecure {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || !publicIP(ip) {
				return fmt.Errorf("address %s is not public", host)
			}
			return nil
		}
	}
	return dialer
}

var specialNets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 private space
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4 embeds an IPv4 address
	netip.MustParsePrefix("2001::/32"), // Teredo embeds one too
}

// publicIP reports whether ip is a normal internet address.
func publicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range specialNets {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// --- e-mail -------------------------------------------------------------------

type email struct {
	cfg           Config
	roots         *x509.CertPool
	allowInsecure bool // tests: a fake server on loopback
}

func (e *email) send(ctx context.Context, m Message) error {
	c := e.cfg
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, RootCAs: e.roots}
	nd := safeDialer(e.allowInsecure)
	var (
		conn net.Conn
		err  error
	)
	if c.Security == SMTPTLS {
		conn, err = (&tls.Dialer{NetDialer: nd, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = nd.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer func() { _ = cl.Close() }()
	if c.Security == SMTPStartTLS {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return permanent("smtp: server does not offer STARTTLS")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return permanent("smtp: auth: %v", err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return fmt.Errorf("smtp: from: %w", err)
	}
	for _, to := range c.To {
		if err := cl.Rcpt(to); err != nil {
			return fmt.Errorf("smtp: rcpt: %w", err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := w.Write(mailBody(c, m)); err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	return cl.Quit()
}

// mailBody builds the message. Every header value is either validated (the
// addresses) or encoded (the subject), so nothing can add headers.
func mailBody(c Config, m Message) []byte {
	var b bytes.Buffer
	subject := mark(m) + " Hangar · " + m.Title
	fmt.Fprintf(&b, "From: %s\r\n", c.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(c.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", m.At.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <hangar-%d-%d@%s>\r\n", m.ID, m.At.UnixNano(), domainOf(c.From))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(plainText(m), "\n", "\r\n")))
	_ = qp.Close()
	b.WriteString("\r\n")
	return b.Bytes()
}

func domainOf(addr string) string {
	if _, d, ok := strings.Cut(addr, "@"); ok {
		return d
	}
	return "hangar"
}
