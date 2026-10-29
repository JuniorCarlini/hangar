package web

import (
	"fmt"
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

var (
	olderLink = regexp.MustCompile(`href="([^"]+)" rel="next"`)
	newerLink = regexp.MustCompile(`href="([^"]+)" rel="prev"`)
)

// walk follows the "older" links from target and returns, per page, the
// markers found; it fails on a marker seen twice.
func (e *env) walk(t *testing.T, c *http.Cookie, target string, marker *regexp.Regexp) ([][]string, []string) {
	t.Helper()
	seen := map[string]bool{}
	var pages [][]string
	var bodies []string
	for range 50 {
		rec := e.do(req{method: "GET", target: target, cookies: []*http.Cookie{c}})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", target, rec.Code)
		}
		body := rec.Body.String()
		bodies = append(bodies, body)
		var page []string
		here := map[string]bool{}
		for _, m := range marker.FindAllStringSubmatch(body, -1) {
			if here[m[1]] {
				continue // the same row may name it twice (text and tip)
			}
			if seen[m[1]] {
				t.Fatalf("%s shows %s again", target, m[1])
			}
			seen[m[1]], here[m[1]] = true, true
			page = append(page, m[1])
		}
		pages = append(pages, page)
		next := olderLink.FindStringSubmatch(body)
		if next == nil {
			return pages, bodies
		}
		target = link(next[1])
	}
	t.Fatal("too many pages")
	return nil, nil
}

// link is the request a browser makes for an href: unescaped, without
// the fragment.
func link(href string) string {
	u, _, _ := strings.Cut(html.UnescapeString(href), "#")
	return u
}

func checkPages(t *testing.T, pages [][]string, total, size int) {
	t.Helper()
	want := (total + size - 1) / size
	if len(pages) != want {
		t.Fatalf("%d pages, want %d", len(pages), want)
	}
	n := 0
	for i, p := range pages {
		if i < len(pages)-1 && len(p) != size {
			t.Fatalf("page %d has %d rows, want %d", i+1, len(p), size)
		}
		n += len(p)
	}
	if n != total {
		t.Fatalf("%d rows over all pages, want %d", n, total)
	}
}

func TestDeployHistoryPages(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	c, _ := e.session(t, auth.RoleViewer)
	const total = deploysPerPage*2 + 3
	if _, err := e.st.DB.Exec(`DELETE FROM deployments`); err != nil { // the first deploy of labService
		t.Fatal(err)
	}
	for i := range total {
		// Same second for pairs: the id breaks the tie.
		if _, err := e.st.DB.Exec(`INSERT INTO deployments (id, service_id, status, image, env_hash, trigger, started_at) VALUES (?, ?, 'failed', ?, '', 'manual', ?)`,
			fmt.Sprintf("dep_t%03d", i), id, fmt.Sprintf("marker-img-%03d", i), 1_700_000_000+i/2); err != nil {
			t.Fatal(err)
		}
	}
	pages, bodies := e.walk(t, c, "/p/lab/s/web", regexp.MustCompile(`(marker-img-\d+)`))
	checkPages(t, pages, total, deploysPerPage)
	if pages[0][0] != fmt.Sprintf("marker-img-%03d", total-1) {
		t.Fatalf("first page starts at %s, want the newest", pages[0][0])
	}
	if newerLink.MatchString(bodies[0]) {
		t.Fatal("the first page has no newer link")
	}
	// "Newer" from the last page leads back to the one before it.
	back := link(newerLink.FindStringSubmatch(bodies[len(bodies)-1])[1])
	rec := e.do(req{method: "GET", target: back, cookies: []*http.Cookie{c}})
	if got := regexp.MustCompile(`marker-img-\d+`).FindAllString(rec.Body.String(), -1); fmt.Sprint(got) != fmt.Sprint(pages[len(pages)-2]) {
		t.Fatalf("newer page = %v, want %v", got, pages[len(pages)-2])
	}
}

func TestBackupHistoryPages(t *testing.T) {
	e := newEnv(t)
	c, _ := e.session(t, auth.RoleViewer)
	const total = runsPerPage + 7
	for i := range total {
		if _, err := e.st.DB.Exec(`INSERT INTO backup_runs (id, label, kind, trigger, status, started_at, finished_at) VALUES (?, ?, 'pg_dump', 'manual', 'ok', ?, ?)`,
			fmt.Sprintf("run_%03d", i), fmt.Sprintf("marker-run-%03d", i), 1_700_000_000+i, 1_700_000_000+i); err != nil {
			t.Fatal(err)
		}
	}
	pages, _ := e.walk(t, c, "/backups", regexp.MustCompile(`(marker-run-\d+)`))
	checkPages(t, pages, total, runsPerPage)
}

func TestAlertDeliveriesPage(t *testing.T) {
	e := newEnv(t)
	c, _ := e.session(t, auth.RoleAdmin)
	const total = deliveriesSize + 1
	for i := range total {
		if _, err := e.st.DB.Exec(`INSERT INTO alert_deliveries (channel_name, channel_kind, kind, status, created_at) VALUES (?, 'telegram', 'test', 'sent', ?)`,
			fmt.Sprintf("marker-ch-%03d", i), 1_700_000_000+i); err != nil {
			t.Fatal(err)
		}
	}
	pages, _ := e.walk(t, c, "/alerts?f=deliveries", regexp.MustCompile(`(marker-ch-\d+)`))
	checkPages(t, pages, total, deliveriesSize)
}

func TestDomainAsksPagesByFilter(t *testing.T) {
	e := newEnv(t)
	c, _ := e.session(t, auth.RoleViewer)
	const total = asksPerPage + 5
	for i := range total {
		decision := "deny"
		if i%2 == 0 {
			decision = "allow"
		}
		// Many share last_at: the primary key breaks the tie.
		if _, err := e.st.DB.Exec(`INSERT INTO tls_ask_log (hostname, decision, reason, hour, last_at) VALUES (?, ?, 'unknown', 1, ?)`,
			fmt.Sprintf("m%03d.example.com", i), decision, 1_700_000_000+i/10); err != nil {
			t.Fatal(err)
		}
	}
	marker := regexp.MustCompile(`>(m\d+\.example\.com)<`)
	pages, _ := e.walk(t, c, "/domains", marker)
	checkPages(t, pages, total, asksPerPage)
	denied, _ := e.walk(t, c, "/domains?f=deny", marker)
	checkPages(t, denied, total/2, asksPerPage)
}
