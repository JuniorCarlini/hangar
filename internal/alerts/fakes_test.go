package alerts

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fake Telegram Bot API ----------------------------------------------------

type tgMessage struct {
	Token  string
	ChatID string
	Text   string
}

// fakeTelegram answers sendMessage like the Bot API: ok for the known token,
// 401 for any other, and 500 for the first `failures` calls.
type fakeTelegram struct {
	srv      *httptest.Server
	token    string
	failures int

	mu   sync.Mutex
	msgs []tgMessage
	hits int
}

func newFakeTelegram(t *testing.T, token string) *fakeTelegram {
	f := &fakeTelegram{token: token}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		tok, ok := strings.CutPrefix(r.URL.Path, "/bot")
		tok, method, _ := strings.Cut(tok, "/")
		if !ok || method != "sendMessage" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if f.failures > 0 {
			f.failures--
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`)
			return
		}
		if tok != f.token {
			w.WriteHeader(http.StatusUnauthorized)
			// The real API never echoes the token; a hostile proxy might.
			_, _ = io.WriteString(w, `{"ok":false,"error_code":401,"description":"Unauthorized `+tok+`"}`)
			return
		}
		var body struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.msgs = append(f.msgs, tgMessage{Token: tok, ChatID: body.ChatID, Text: body.Text})
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":1}}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTelegram) messages() []tgMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tgMessage(nil), f.msgs...)
}

// --- fake SMTP server ---------------------------------------------------------

type smtpMail struct {
	From string
	To   []string
	Data string
	User string
	Pass string
	TLS  bool
}

// fakeSMTP speaks enough SMTP for net/smtp: EHLO, STARTTLS, AUTH PLAIN,
// MAIL, RCPT, DATA, QUIT. With implicit, the whole connection is TLS (port
// 465 style); otherwise it offers STARTTLS (587 style) unless noTLS.
type fakeSMTP struct {
	ln       net.Listener
	tls      *tls.Config
	implicit bool
	noTLS    bool

	mu    sync.Mutex
	mails []smtpMail
}

func newFakeSMTP(t *testing.T, cert tls.Certificate, implicit, noTLS bool) *fakeSMTP {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicit {
		ln = tls.NewListener(ln, cfg)
	}
	f := &fakeSMTP{ln: ln, tls: cfg, implicit: implicit, noTLS: noTLS}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) received() []smtpMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]smtpMail(nil), f.mails...)
}

func (f *fakeSMTP) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	tp := textproto.NewConn(c)
	isTLS := f.implicit
	var m smtpMail
	reply := func(s string) { _ = tp.PrintfLine("%s", s) }
	reply("220 fake.smtp ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			reply("250-fake.smtp")
			if !isTLS && !f.noTLS {
				reply("250-STARTTLS")
			}
			reply("250-AUTH PLAIN")
			reply("250 8BITMIME")
		case "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(c, f.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, tp, isTLS = tc, textproto.NewConn(tc), true
		case "AUTH":
			_, b64, _ := strings.Cut(arg, " ")
			raw, _ := base64.StdEncoding.DecodeString(b64)
			parts := strings.Split(string(raw), "\x00")
			if len(parts) == 3 {
				m.User, m.Pass = parts[1], parts[2]
			}
			reply("235 2.7.0 Authentication successful")
		case "MAIL":
			m.From = angle(arg)
			reply("250 ok")
		case "RCPT":
			m.To = append(m.To, angle(arg))
			reply("250 ok")
		case "DATA":
			reply("354 end with .")
			lines, err := tp.ReadDotLines()
			if err != nil {
				return
			}
			m.Data, m.TLS = strings.Join(lines, "\n"), isTLS
			f.mu.Lock()
			f.mails = append(f.mails, m)
			f.mu.Unlock()
			m = smtpMail{}
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 not implemented")
		}
	}
}

// angle returns what is between < and > ("FROM:<a@b> BODY=8BITMIME").
func angle(s string) string {
	_, rest, _ := strings.Cut(s, "<")
	v, _, _ := strings.Cut(rest, ">")
	return v
}

// selfSigned makes a certificate for 127.0.0.1 and the pool that trusts it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake smtp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// --- webhook receiver -----------------------------------------------------------

type hookCall struct {
	Header  http.Header
	Body    []byte
	Payload WebhookPayload
}

func newHookReceiver(t *testing.T, status int) (*httptest.Server, func() []hookCall) {
	var mu sync.Mutex
	var calls []hookCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(bufio.NewReader(r.Body))
		var p WebhookPayload
		_ = json.Unmarshal(body, &p)
		mu.Lock()
		calls = append(calls, hookCall{Header: r.Header.Clone(), Body: body, Payload: p})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []hookCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]hookCall(nil), calls...)
	}
}
