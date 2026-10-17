//go:build integration

package chaos

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite" // read the panel's database from the test
)

const (
	email    = "caos@hangar.test"
	password = "pista-caos-Runway-2026!"
)

var hangardBin string

func TestMain(m *testing.M) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		fmt.Println("chaos: Docker unavailable, skipping")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "hangar-chaos-bin-")
	if err != nil {
		panic(err)
	}
	hangardBin = filepath.Join(dir, "hangard")
	build := exec.Command("go", "build", "-o", hangardBin, "github.com/JuniorCarlini/hangar/cmd/hangard")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// panel is a throwaway hangard with its own directory and port.
type panel struct {
	t      *testing.T
	dir    string
	config string
	port   int
	cmd    *exec.Cmd
	logf   *os.File
	c      *http.Client
	csrf   string
	dbh    *sql.DB
}

type panelOpts struct {
	dataDir    string // default dir/data
	dockerHost string // default: the machine's Docker
}

func newPanel(t *testing.T, o panelOpts) *panel {
	t.Helper()
	dir := t.TempDir()
	if o.dataDir == "" {
		o.dataDir = filepath.Join(dir, "data")
	}
	p := &panel{t: t, dir: dir, config: filepath.Join(dir, "hangar.toml"), port: freePort(t)}
	docker := ""
	if o.dockerHost != "" {
		docker = fmt.Sprintf("\n[docker]\nhost = %q\n", o.dockerHost)
	}
	cfg := fmt.Sprintf(`data_dir = %q
master_key_file = "master.key"

[panel]
listen = ["127.0.0.1:%d"]
hosts = ["127.0.0.1:%d"]

[update]
api_base = "http://127.0.0.1:9"

[scan]
enabled = false
osv_api = "http://127.0.0.1:9"

[alerts]
telegram_api = "http://127.0.0.1:9"
%s`, o.dataDir, p.port, p.port, docker)
	if err := os.WriteFile(p.config, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	create := exec.Command(hangardBin, "user", "create", "-config", p.config, "-email", email, "-role", "owner", "-no-2fa") //nolint:gosec // test binary
	create.Stdin = strings.NewReader(password + "\n" + password + "\n")
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("user create: %v\n%s", err, out)
	}
	var err error
	if p.logf, err = os.Create(filepath.Join(dir, "hangard.log")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.stop()
		_ = p.logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(p.logf.Name())
			t.Logf("hangard log:\n%s", tail(string(b), 4000))
		}
	})
	p.start()
	return p
}

func (p *panel) start() {
	p.t.Helper()
	p.cmd = exec.Command(hangardBin, "serve", "-config", p.config) //nolint:gosec // test binary
	p.cmd.Stdout, p.cmd.Stderr = p.logf, p.logf
	if err := p.cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.waitHealthy(15 * time.Second)
	p.login()
}

func (p *panel) waitHealthy(d time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		resp, err := http.Get(p.url("/healthz")) //nolint:noctx // test
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.t.Fatal("panel did not come up")
}

// kill is SIGKILL: no shutdown, no deferred cleanup, like an OOM kill or
// a power cut.
func (p *panel) kill() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		p.cmd = nil
	}
}

func (p *panel) stop() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = p.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
		p.cmd = nil
	}
}

func (p *panel) alive() bool {
	return p.cmd != nil && p.cmd.ProcessState == nil && p.cmd.Process.Signal(syscall.Signal(0)) == nil
}

func (p *panel) url(path string) string { return fmt.Sprintf("http://127.0.0.1:%d%s", p.port, path) }

func (p *panel) login() {
	p.t.Helper()
	jar, _ := cookiejar.New(nil)
	p.c = &http.Client{Jar: secureJar{jar}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, page := p.get("/login")
	tok := hidden(page, "csrf")
	if code, body := p.post("/login", url.Values{"email": {email}, "password": {password}, "csrf": {tok}}); code != http.StatusSeeOther {
		p.t.Fatalf("login: %d %s", code, tail(body, 300))
	}
	_, acc := p.get("/account")
	p.csrf = hidden(acc, "csrf")
	if p.csrf == "" {
		p.t.Fatal("no CSRF token after login")
	}
}

func (p *panel) get(path string) (int, string) {
	p.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, p.url(path), nil)
	req.Header.Set("Accept", "text/html")
	return p.do(req)
}

func (p *panel) post(path string, form url.Values) (int, string) {
	p.t.Helper()
	if form.Get("csrf") == "" && p.csrf != "" {
		form.Set("csrf", p.csrf)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, p.url(path), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	return p.do(req)
}

func (p *panel) do(req *http.Request) (int, string) {
	resp, err := p.c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (p *panel) db() *sql.DB {
	p.t.Helper()
	if p.dbh != nil {
		return p.dbh
	}
	db, err := sql.Open("sqlite", filepath.Join(p.dataDir(), "hangar.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { _ = db.Close() })
	p.dbh = db
	return db
}

func (p *panel) dataDir() string {
	b, _ := os.ReadFile(p.config)
	m := regexp.MustCompile(`data_dir = "([^"]+)"`).FindSubmatch(b)
	return string(m[1])
}

// project creates an e2e-cx-* project with an nginx service "web" and
// waits for its first deploy; Docker leftovers are removed at the end.
func (p *panel) project(name string) string {
	p.t.Helper()
	slug := "e2e-cx-" + name + "-" + randHex(3)
	p.t.Cleanup(func() { removeProject(slug) })
	if code, body := p.post("/projects", url.Values{"slug": {slug}, "name": {"Caos"}}); code != http.StatusSeeOther {
		p.t.Fatalf("create project: %d %s", code, tail(errorText(body), 300))
	}
	if code, body := p.post("/p/"+slug+"/services", url.Values{"slug": {"web"}, "image": {"nginx:1.29-alpine"}, "port": {"80"}, "memory_mb": {"64"}}); code != http.StatusSeeOther {
		p.t.Fatalf("create service: %d %s", code, tail(errorText(body), 300))
	}
	p.waitDeploy(slug, "live", 3*time.Minute)
	return slug
}

// lastDeploy returns the status and error of the service's newest deploy.
func (p *panel) lastDeploy(slug string) (status, errText string) {
	db := p.db()
	row := db.QueryRow(`SELECT d.status, coalesce(d.error, '') FROM deployments d
		JOIN services s ON s.id = d.service_id JOIN projects p ON p.id = s.project_id
		WHERE p.slug = ? AND s.slug = 'web' ORDER BY d.started_at DESC, d.rowid DESC LIMIT 1`, slug)
	_ = row.Scan(&status, &errText)
	return status, errText
}

func (p *panel) waitDeploy(slug, want string, d time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		st, e := p.lastDeploy(slug)
		if st == want {
			return
		}
		if st == "failed" && want != "failed" {
			p.t.Fatalf("deploy of %s failed: %s", slug, e)
		}
		time.Sleep(500 * time.Millisecond)
	}
	st, e := p.lastDeploy(slug)
	p.t.Fatalf("deploy of %s: status %q (%s), want %q", slug, st, e, want)
}

// --- Docker ---------------------------------------------------------------

func dockerOut(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput() //nolint:gosec // fixed binary, test arguments
	return strings.TrimSpace(string(out)), err
}

func containerState(name string) string {
	out, err := dockerOut("inspect", "-f", "{{.State.Status}}", name)
	if err != nil {
		return "absent"
	}
	return out
}

func waitContainer(t *testing.T, name, state string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if containerState(name) == state {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("container %s: %s, want %s", name, containerState(name), state)
}

func removeProject(slug string) {
	if !strings.HasPrefix(slug, "e2e-cx-") {
		return
	}
	ids, _ := dockerOut("ps", "-aq", "--filter", "label=hangar.project="+slug)
	if ids != "" {
		_, _ = dockerOut(append([]string{"rm", "-f", "-v"}, strings.Fields(ids)...)...)
	}
	vols, _ := dockerOut("volume", "ls", "-q", "--filter", "name=hangar_"+slug+"_")
	if vols != "" {
		_, _ = dockerOut(append([]string{"volume", "rm", "-f"}, strings.Fields(vols)...)...)
	}
	_, _ = dockerOut("network", "rm", "hangar_"+slug)
}

// --- small helpers ----------------------------------------------------------

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

func hidden(page, name string) string {
	m := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		return ""
	}
	return m[1]
}

func errorText(body string) string {
	m := regexp.MustCompile(`role="alert"[^>]*>(.*?)</div>`).FindStringSubmatch(body)
	if m == nil {
		return body
	}
	return regexp.MustCompile(`<[^>]+>`).ReplaceAllString(m[1], "")
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
