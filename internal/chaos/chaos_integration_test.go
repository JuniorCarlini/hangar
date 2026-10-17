//go:build integration

package chaos

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The panel dies (SIGKILL) while the pre-deploy command runs. The site
// keeps the old version, and after a restart the deploy is marked failed,
// the temporary container is gone and the next deploy works.
func TestKillPanelDuringPreDeploy(t *testing.T) {
	p := newPanel(t, panelOpts{})
	slug := p.project("pre")
	name := slug + "_web"
	svc := "/p/" + slug + "/s/web"
	if code, body := p.post(svc+"/deploy-settings", url.Values{"predeploy": {"sleep 120"}, "health_path": {""}}); code != http.StatusSeeOther {
		t.Fatalf("deploy settings: %d %s", code, errorText(body))
	}
	if code, _ := p.post(svc+"/deploy", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("deploy: %d", code)
	}
	waitContainer(t, name+"-predeploy", "running", time.Minute)

	p.kill()
	if st := containerState(name); st != "running" {
		t.Fatalf("site went down with the panel: %s", st)
	}

	p.start()
	if st, e := p.lastDeploy(slug); st != "failed" || !strings.Contains(e, "interrupted") {
		t.Fatalf("after restart the deploy is %q (%s), want failed/interrupted", st, e)
	}
	if st := containerState(name + "-predeploy"); st != "absent" {
		t.Errorf("pre-deploy container left behind: %s", st)
	}
	if st := containerState(name); st != "running" {
		t.Errorf("site after restart: %s", st)
	}
	// Deploys work again (a stuck "running" row used to refuse them).
	if code, body := p.post(svc+"/deploy-settings", url.Values{"predeploy": {""}, "health_path": {""}}); code != http.StatusSeeOther {
		t.Fatalf("deploy settings: %d %s", code, errorText(body))
	}
	if code, body := p.post(svc+"/deploy", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("deploy after recovery: %d %s", code, errorText(body))
	}
	p.waitDeploy(slug, "live", 2*time.Minute)
}

// The panel dies while the new container of a rolling deploy waits for its
// health check, both versions running side by side. After the restart the
// unconfirmed one is removed (it was receiving part of the traffic through
// the network alias) and the old one keeps serving.
func TestKillPanelDuringHealthCheck(t *testing.T) {
	p := newPanel(t, panelOpts{})
	slug := p.project("health")
	name := slug + "_web"
	svc := "/p/" + slug + "/s/web"
	if code, body := p.post(svc+"/deploy-settings", url.Values{"predeploy": {""}, "health_path": {"/nao-existe"}}); code != http.StatusSeeOther {
		t.Fatalf("deploy settings: %d %s", code, errorText(body))
	}
	oldID, _ := dockerOut("inspect", "-f", "{{.Id}}", name)
	if code, _ := p.post(svc+"/deploy", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("deploy: %d", code)
	}
	waitContainer(t, name+"-next", "running", time.Minute)

	p.kill()
	p.start()

	if st, _ := p.lastDeploy(slug); st != "failed" {
		t.Fatalf("after restart the deploy is %q, want failed", st)
	}
	if st := containerState(name + "-next"); st != "absent" {
		t.Errorf("unconfirmed container still running: %s", st)
	}
	if id, _ := dockerOut("inspect", "-f", "{{.Id}}", name); id != oldID || containerState(name) != "running" {
		t.Errorf("the old version should keep serving (id %s, state %s)", id, containerState(name))
	}
}

// A container stopped behind the panel's back (docker kill) is reported by
// the reconciler and can be started again from the panel.
func TestContainerKilledBehindThePanelsBack(t *testing.T) {
	p := newPanel(t, panelOpts{})
	slug := p.project("kill")
	name := slug + "_web"
	if _, err := dockerOut("kill", name); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(70 * time.Second)
	for {
		var n int
		_ = p.db().QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'service.drift' AND summary_json LIKE ?`, "%"+name+"%").Scan(&n)
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the reconciler did not report the stopped container")
		}
		time.Sleep(time.Second)
	}
	if code, _ := p.get("/p/" + slug + "/s/web"); code != http.StatusOK {
		t.Errorf("service page with the container stopped: %d", code)
	}
	if code, body := p.post("/p/"+slug+"/s/web/action", url.Values{"action": {"start"}}); code != http.StatusSeeOther {
		t.Fatalf("start: %d %s", code, errorText(body))
	}
	waitContainer(t, name, "running", 30*time.Second)
}

// Docker goes away (daemon restart, socket gone) while the panel runs: the
// pages still answer, actions fail with a message instead of hanging, and
// everything works again when Docker is back. Simulated with a proxy in
// front of the real socket, so the machine's Docker is never touched.
func TestDockerGoesAwayAndComesBack(t *testing.T) {
	real := dockerSocket(t)
	dir, err := os.MkdirTemp("/tmp", "cx") // unix socket paths must be short
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	px := startProxy(t, sock, real)
	p := newPanel(t, panelOpts{dockerHost: "unix://" + sock})
	slug := p.project("docker")
	svc := "/p/" + slug + "/s/web"

	px.close()
	for _, path := range []string{"/", svc, "/ports", "/p/" + slug} {
		start := time.Now()
		code, _ := p.get(path)
		if code == 0 || time.Since(start) > 20*time.Second {
			t.Errorf("GET %s without Docker: status %d after %s", path, code, time.Since(start))
		}
	}
	// The deploy starts in the background and ends failed, with the
	// reason, instead of hanging or staying "running".
	start := time.Now()
	if code, _ := p.post(svc+"/deploy", url.Values{}); code == 0 || time.Since(start) > 30*time.Second {
		t.Errorf("deploy without Docker: status %d after %s", code, time.Since(start))
	}
	p.waitDeploy(slug, "failed", time.Minute)
	if _, e := p.lastDeploy(slug); !strings.Contains(e, "docker") {
		t.Errorf("failed deploy without the reason: %q", e)
	}
	if !p.alive() {
		t.Fatal("panel died without Docker")
	}

	px = startProxy(t, sock, real)
	defer px.close()
	deadline := time.Now().Add(30 * time.Second)
	for {
		code, _ := p.post(svc+"/deploy", url.Values{})
		if code == http.StatusSeeOther {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deploy after Docker came back: %d", code)
		}
		time.Sleep(time.Second)
	}
	p.waitDeploy(slug, "live", 2*time.Minute)
}

// Another process holds the database locked (a stuck sqlite3 shell, a
// backup tool): writes wait busy_timeout and fail cleanly, reads keep
// working, and nothing is left broken when the lock goes away.
func TestDatabaseLocked(t *testing.T) {
	p := newPanel(t, panelOpts{})
	db := p.db()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	if code, _ := p.get("/"); code != http.StatusOK {
		t.Errorf("read with the database locked: %d", code)
	}
	start := time.Now()
	code, _ := p.post("/account/preferences", url.Values{"locale": {"pt-BR"}, "theme": {"dark"}})
	took := time.Since(start)
	if code == 0 || code == http.StatusSeeOther || took > 20*time.Second {
		t.Errorf("write with the database locked: status %d after %s, want an error after the busy timeout", code, took)
	}
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !p.alive() {
		t.Fatal("panel died with the database locked")
	}
	if code, _ := p.post("/account/preferences", url.Values{"locale": {"pt-BR"}, "theme": {"dark"}}); code != http.StatusSeeOther {
		t.Errorf("write after the lock: %d", code)
	}
	if out, err := exec.Command(hangardBin, "audit", "verify", "-config", p.config).CombinedOutput(); err != nil { //nolint:gosec // test binary
		t.Errorf("audit chain after the lock: %v %s", err, out)
	}
}

// A deploy log that is garbage (invalid UTF-8, huge, an unknown phase) or
// missing must not break the service page.
func TestBrokenDeployLog(t *testing.T) {
	p := newPanel(t, panelOpts{})
	slug := p.project("log")
	db := p.db()
	huge := strings.Repeat("\xff\xfe<script>alert(1)</script>\x1b[31m", 100_000)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE deployments SET log = ?, phase = 'nao-existe' WHERE service_id IN (SELECT s.id FROM services s JOIN projects p ON p.id = s.project_id WHERE p.slug = ?)`, []any{huge, slug}},
		{`UPDATE deployments SET log = '', phase = '' WHERE service_id IN (SELECT s.id FROM services s JOIN projects p ON p.id = s.project_id WHERE p.slug = ?)`, []any{slug}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
		code, body := p.get("/p/" + slug + "/s/web")
		if code != http.StatusOK {
			t.Fatalf("service page with a broken log: %d", code)
		}
		if strings.Contains(body, "<script>alert(1)") {
			t.Fatal("log rendered as HTML")
		}
	}
	// The builds directory and its logs gone (disk cleanup by hand).
	_ = os.RemoveAll(filepath.Join(p.dataDir(), "builds"))
	if code, body := p.post("/p/"+slug+"/s/web/deploy", url.Values{}); code != http.StatusSeeOther {
		t.Fatalf("deploy: %d %s", code, errorText(body))
	}
	p.waitDeploy(slug, "live", 2*time.Minute)
}

// The disk with the panel's data fills up: the panel keeps running and
// answering (errors, not a crash), and recovers when space comes back.
// macOS only (a RAM disk without root); on Linux it skips.
func TestDiskFull(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("needs hdiutil (macOS) for a small disk without root")
	}
	mount := ramDisk(t, 24) // MiB
	p := newPanel(t, panelOpts{dataDir: filepath.Join(mount, "data")})
	filler := filepath.Join(mount, "filler")
	fill(t, filler)

	// Enough writes to use up what SQLite had already allocated (the WAL).
	codes := map[int]int{}
	for range 300 {
		code, _ := p.post("/account/preferences", url.Values{"locale": {"pt-BR"}, "theme": {"light"}})
		codes[code]++
		code, _ = p.get("/")
		codes[code]++
	}
	if !p.alive() {
		t.Fatal("panel died with the disk full")
	}
	if codes[0] > 0 {
		t.Errorf("requests without an answer with the disk full: %v", codes)
	}
	t.Logf("answers with the disk full: %v", codes)
	if codes[http.StatusSeeOther] == 300 {
		t.Error("every write succeeded: the disk never filled up")
	}

	_ = os.Remove(filler)
	p.login()
	if code, _ := p.post("/account/preferences", url.Values{"locale": {"pt-BR"}, "theme": {"dark"}}); code != http.StatusSeeOther {
		t.Errorf("write after freeing space: %d", code)
	}
	p.stop()
	if out, err := exec.Command(hangardBin, "audit", "verify", "-config", p.config).CombinedOutput(); err != nil { //nolint:gosec // test binary
		t.Errorf("audit chain after the disk filled up: %v %s", err, out)
	}
}

// --- helpers ------------------------------------------------------------------

func dockerSocket(t *testing.T) string {
	t.Helper()
	host, _ := dockerOut("context", "inspect", "-f", "{{.Endpoints.docker.Host}}")
	if !strings.HasPrefix(host, "unix://") {
		host = "unix:///var/run/docker.sock"
	}
	path := strings.TrimPrefix(host, "unix://")
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	return path
}

// proxy forwards a unix socket to Docker's; close drops it and every open
// connection, as a daemon restart would.
type proxy struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startProxy(t *testing.T, sock, target string) *proxy {
	t.Helper()
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	px := &proxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("unix", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			px.mu.Lock()
			px.conns = append(px.conns, c, up)
			px.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
	return px
}

func (px *proxy) close() {
	_ = px.ln.Close()
	px.mu.Lock()
	defer px.mu.Unlock()
	for _, c := range px.conns {
		_ = c.Close()
	}
	px.conns = nil
}

// ramDisk attaches a small RAM disk and returns its mount point.
func ramDisk(t *testing.T, mib int) string {
	t.Helper()
	dev, err := exec.Command("hdiutil", "attach", "-nomount", "ram://"+strconv.Itoa(mib*2048)).Output()
	if err != nil {
		t.Skipf("hdiutil: %v", err)
	}
	d := strings.TrimSpace(string(dev))
	name := "hangarcx" + randHex(3)
	if out, err := exec.Command("diskutil", "erasevolume", "HFS+", name, d).CombinedOutput(); err != nil { //nolint:gosec // device from hdiutil
		_ = exec.Command("hdiutil", "detach", d).Run() //nolint:gosec // device from hdiutil
		t.Skipf("diskutil: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("hdiutil", "detach", "-force", d).Run() }) //nolint:gosec // device from hdiutil
	return "/Volumes/" + name
}

func fill(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	// Big blocks first, then smaller ones, down to the last byte.
	for size := 1 << 20; size >= 1; size /= 4 {
		buf := make([]byte, size)
		for {
			if _, err := f.Write(buf); err != nil {
				break // ENOSPC for this size
			}
		}
	}
	_ = f.Sync()
	if out, err := exec.Command("df", "-k", filepath.Dir(path)).Output(); err == nil { //nolint:gosec // test path
		t.Logf("after filling:\n%s", out)
	}
}
