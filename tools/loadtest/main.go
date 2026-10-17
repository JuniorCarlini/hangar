// Command loadtest drives a throwaway panel (tools/lab-panel.sh) with the
// mix of the security review: the main pages, /palette.json, the public status link
// (HTML, JSON, Prometheus) and the GitHub webhook endpoint with bad
// signatures. It samples hangard's RSS during and after the run, to see
// memory stay modest and come back down (no leak).
//
//	go run ./tools/loadtest -base http://127.0.0.1:PORT -pid PID \
//	  -email lab@hangar.test -password '...' -c 32 -d 60s
//
// Never point it at a real panel: it logs in, turns sudo on and creates a
// status link.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type result struct {
	name    string
	status  int
	latency time.Duration
	err     error
}

func main() {
	base := flag.String("base", "", "panel URL (http://127.0.0.1:PORT)")
	email := flag.String("email", "lab@hangar.test", "owner e-mail")
	password := flag.String("password", "", "owner password (account without 2FA)")
	pid := flag.Int("pid", 0, "hangard PID, for the RSS samples")
	ctr := flag.String("container", "", "or: the Docker container where hangard is PID 1 (Linux RSS)")
	conc := flag.Int("c", 32, "concurrent clients")
	dur := flag.Duration("d", 60*time.Second, "duration")
	settle := flag.Duration("settle", 30*time.Second, "idle time after the run before the last RSS sample")
	flag.Parse()
	if *base == "" || *password == "" {
		flag.Usage()
		os.Exit(2)
	}
	ctx := context.Background()
	rss := func(ctx context.Context) int { return rssOf(ctx, *pid, *ctr) }
	measured := *pid > 0 || *ctr != ""
	c, csrf, err := login(ctx, *base, *email, *password)
	if err != nil {
		fail("login: %v", err)
	}
	status, err := statusLink(ctx, c, *base, csrf, *password)
	if err != nil {
		fail("status link: %v", err)
	}

	type target struct {
		name string
		req  func(ctx context.Context) (*http.Request, error)
		// public requests go without the session.
		public bool
	}
	get := func(path string) func(ctx context.Context) (*http.Request, error) {
		return func(ctx context.Context) (*http.Request, error) {
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, *base+path, nil)
			if err == nil {
				r.Header.Set("Accept", "text/html")
			}
			return r, err
		}
	}
	targets := []target{
		{name: "GET /", req: get("/")},
		{name: "GET /ports", req: get("/ports")},
		{name: "GET /domains", req: get("/domains")},
		{name: "GET /updates", req: get("/updates")},
		{name: "GET /alerts", req: get("/alerts")},
		{name: "GET /backups", req: get("/backups")},
		{name: "GET /account", req: get("/account")},
		{name: "GET /palette.json", req: get("/palette.json")},
		{name: "GET /s/{token}", req: get(status), public: true},
		{name: "GET /s/{token}.json", req: get(status + ".json"), public: true},
		{name: "GET /s/{token}/metrics", req: get(status + "/metrics"), public: true},
		{name: "POST /hooks/git (bad signature)", public: true, req: func(ctx context.Context) (*http.Request, error) {
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, *base+"/hooks/git/"+randomHex(20), strings.NewReader(`{"ref":"refs/heads/main"}`))
			if err == nil {
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("X-GitHub-Event", "push")
				r.Header.Set("X-GitHub-Delivery", randomHex(16))
				r.Header.Set("X-Hub-Signature-256", "sha256="+randomHex(32))
			}
			return r, err
		}},
	}

	before := rss(ctx)
	results := make(chan result, 4096)
	var samples []int
	var smu sync.Mutex
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if v := rss(ctx); v > 0 {
					smu.Lock()
					samples = append(samples, v)
					smu.Unlock()
				}
			}
		}
	}()

	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	public := &http.Client{Timeout: 10 * time.Second, CheckRedirect: noRedirect}
	for w := range *conc {
		wg.Go(func() {
			for i := w; time.Now().Before(deadline); i++ {
				tg := targets[i%len(targets)]
				cl := c
				if tg.public {
					cl = public
				}
				req, err := tg.req(ctx)
				if err != nil {
					results <- result{name: tg.name, err: err}
					continue
				}
				start := time.Now()
				resp, err := cl.Do(req)
				r := result{name: tg.name, latency: time.Since(start), err: err}
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					r.status = resp.StatusCode
				}
				results <- r
			}
		})
	}
	agg := map[string]*stats{}
	done := make(chan struct{})
	go func() {
		for r := range results {
			s := agg[r.name]
			if s == nil {
				s = &stats{codes: map[int]int{}}
				agg[r.name] = s
			}
			s.add(r)
		}
		close(done)
	}()
	wg.Wait()
	close(results)
	<-done
	close(stop)
	peak := before
	for _, v := range samples {
		peak = max(peak, v)
	}
	fmt.Printf("load: %d clients, %s\n\n", *conc, *dur)
	fmt.Printf("%-34s %8s %8s %8s %8s %8s  %s\n", "endpoint", "req", "req/s", "p50", "p95", "p99", "status codes")
	total, errs := 0, 0
	names := make([]string, 0, len(agg))
	for n := range agg {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		s := agg[n]
		total += s.n
		errs += s.errs
		fmt.Printf("%-34s %8d %8.1f %8s %8s %8s  %s\n", n, s.n, float64(s.n)/dur.Seconds(),
			s.pct(50), s.pct(95), s.pct(99), s.codeString())
	}
	fmt.Printf("\ntotal %d requests (%.0f req/s), %d transport errors\n", total, float64(total)/dur.Seconds(), errs)
	if measured {
		time.Sleep(*settle)
		after := rss(ctx)
		fmt.Printf("hangard RSS: before %d MB, peak %d MB, %s after the run %d MB\n", before/1024, peak/1024, *settle, after/1024)
	}
}

type stats struct {
	n, errs int
	codes   map[int]int
	lat     []time.Duration
}

func (s *stats) add(r result) {
	s.n++
	if r.err != nil {
		s.errs++
		return
	}
	s.codes[r.status]++
	s.lat = append(s.lat, r.latency)
}

func (s *stats) pct(p int) string {
	if len(s.lat) == 0 {
		return "-"
	}
	slices.Sort(s.lat)
	i := min(len(s.lat)-1, len(s.lat)*p/100)
	return s.lat[i].Round(100 * time.Microsecond).String()
}

func (s *stats) codeString() string {
	keys := make([]int, 0, len(s.codes))
	for k := range s.codes {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d×%d", k, s.codes[k]))
	}
	return strings.Join(parts, " ")
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// login signs in through the form (no 2FA) and returns a client with the
// session and the session's CSRF token.
func login(ctx context.Context, base, email, password string) (*http.Client, string, error) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: secureJar{jar}, Timeout: 10 * time.Second, CheckRedirect: noRedirect}
	page, err := fetch(ctx, c, http.MethodGet, base+"/login", nil)
	if err != nil {
		return nil, "", err
	}
	tok := hidden(page, "csrf")
	form := url.Values{"email": {email}, "password": {password}, "csrf": {tok}}
	if _, err := fetch(ctx, c, http.MethodPost, base+"/login", form); err != nil {
		return nil, "", err
	}
	home, err := fetch(ctx, c, http.MethodGet, base+"/account", nil)
	if err != nil {
		return nil, "", err
	}
	csrf := hidden(home, "csrf")
	if csrf == "" {
		return nil, "", errors.New("no CSRF token after login (wrong password, or 2FA on?)")
	}
	return c, csrf, nil
}

// statusLink turns sudo on with the password and creates a link showing
// everything; it returns its path (/s/<token>).
func statusLink(ctx context.Context, c *http.Client, base, csrf, password string) (string, error) {
	if _, err := fetch(ctx, c, http.MethodPost, base+"/sudo", url.Values{"csrf": {csrf}, "code": {password}, "next": {"/status-links"}}); err != nil {
		return "", err
	}
	page, err := fetch(ctx, c, http.MethodGet, base+"/status-links", nil)
	if err != nil {
		return "", err
	}
	csrf = hidden(page, "csrf")
	body, err := fetch(ctx, c, http.MethodPost, base+"/status-links", url.Values{
		"csrf": {csrf}, "name": {"carga"}, "naming": {"hidden"}, "expiry": {"24h"},
	})
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`/s/([A-Za-z0-9_-]{20,})`).FindStringSubmatch(body)
	if m == nil {
		return "", errors.New("link not found in the answer")
	}
	return "/s/" + m[1], nil
}

func fetch(ctx context.Context, c *http.Client, method, u string, form url.Values) (string, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return "", err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return string(b), fmt.Errorf("%s %s: %d", method, u, resp.StatusCode)
	}
	return string(b), err
}

func hidden(page, name string) string {
	m := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		return ""
	}
	return m[1]
}

// secureJar keeps the panel's __Host- cookies over plain http on 127.0.0.1
// (Go's jar drops Secure cookies for http URLs).
type secureJar struct{ http.CookieJar }

func (j secureJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	s := *u
	s.Scheme = "https"
	j.CookieJar.SetCookies(&s, cookies)
}

func (j secureJar) Cookies(u *url.URL) []*http.Cookie {
	s := *u
	s.Scheme = "https"
	return j.CookieJar.Cookies(&s)
}

// rssOf is hangard's resident memory in KiB (0 when unknown): from ps for
// a local PID, from /proc/1/status inside a container.
func rssOf(ctx context.Context, pid int, container string) int {
	if container != "" {
		out, err := exec.CommandContext(ctx, "docker", "exec", container, "cat", "/proc/1/status").Output() //nolint:gosec // fixed binary, container name from the operator
		if err != nil {
			return 0
		}
		for _, ln := range strings.Split(string(out), "\n") {
			if f := strings.Fields(ln); len(f) >= 2 && f[0] == "VmRSS:" {
				v, _ := strconv.Atoi(f[1])
				return v
			}
		}
		return 0
	}
	if pid <= 0 {
		return 0
	}
	out, err := exec.CommandContext(ctx, "ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // fixed binary, numeric argument
	if err != nil {
		return 0
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(bytes.TrimSpace(out))))
	return v
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "loadtest: "+format+"\n", args...)
	os.Exit(1)
}
