//go:build integration

package backup

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// A whole project in one file and back, on real Docker and MinIO: a
// PostgreSQL with an app role of its own (backed up to the destination
// first), a Redis by its recipe and a service with a volume (both backed up
// for the file), and an app that reaches the database through references.
// Restored as a new project with the kit: every service is there with its
// data, the app's references resolve to the copy's database, the app role
// logs in with its original password, and the domain stays off.
func TestProjectBackupAndRestore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E project"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateFromTemplate(ctx, e.who, e.project, "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	e.waitLive(t, ctx, "db")
	for _, q := range []string{
		`create role app_rw login password 'rw-senha'`,
		`create table pedidos (id serial primary key, valor int not null)`,
		`insert into pedidos (valor) select g from generate_series(1, 250) g`,
		`grant select, insert on pedidos to app_rw`,
	} {
		e.psql(t, ctx, "db", q)
	}
	s, _ := e.m.ref(ctx, e.project, "db")
	if _, err := e.m.backupDump(ctx, e.who, s, TriggerManual); err != nil {
		t.Fatalf("dump: %v", err)
	}
	// A row after the backup: the file carries the tested backup in the
	// destination, as it is (the service is not touched for it).
	e.psql(t, ctx, "db", "insert into pedidos (valor) values (999)")

	e.fromTemplate(t, ctx, "redis-queue", "queue")
	const cli = `export REDISCLI_AUTH="$REDIS_PASSWORD"; redis-cli --no-auth-warning `
	e.sh(t, ctx, "queue", `export REDISCLI_AUTH="$REDIS_PASSWORD"
for i in $(seq 1 120); do echo "SET job:$i payload-$i"; done | redis-cli --no-auth-warning --pipe >/dev/null
redis-cli --no-auth-warning ACL SETUSER worker on '>w0rker pw' '~job:*' '+@read' >/dev/null`)

	e.volumeService(t, ctx, "files")
	e.ash(t, ctx, "files", `printf 'olá, volume\n' > /data/nota.txt && mkdir -p /data/sub && ln -s ../nota.txt /data/sub/link`)

	web, err := e.pm.CreateService(ctx, e.who, e.project, projects.ServiceInput{Name: "web", Image: "nginx:1.31-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"DB_HOST": "${{db.HOST}}", "DB_URL": "${{db.DATABASE_URL}}", "QUEUE": "${{" + e.project + ".queue.HOST}}"} {
		if err := e.pm.SetEnv(ctx, e.who, web.ID, k, v, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.m.q.CreateDomain(ctx, dbq.CreateDomainParams{ID: "dom_e2e", ServiceID: web.ID, Hostname: e.project + ".example.com", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	if err := e.m.deployAndWait(ctx, e.who, svcRef{ID: web.ID, Project: e.project, Service: "web"}, "manual"); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()

	// The file.
	start := time.Now()
	if err := e.m.PrepareProjectDownload(ctx, e.who, e.project); err != nil {
		t.Fatal(err)
	}
	e.m.Wait()
	p, _ := e.pm.GetProject(ctx, e.project)
	d, ok := e.m.PendingProjectDownload(e.who.UserID, p.ID)
	if !ok || !d.Ready {
		t.Fatalf("project backup: %+v", d)
	}
	bundle, _, done, err := e.m.TakeDownload(ctx, e.who, d.Token)
	if err != nil {
		t.Fatal(err)
	}
	var zipped bytes.Buffer
	if err := bundle(&zipped); err != nil {
		t.Fatal(err)
	}
	done()
	files, _ := unzip(t, zipped.Bytes())
	man := manifestOf(t, files)
	if man.service("db").Source != SourceBackup || man.service("queue").Source != SourceNow || man.service("files").Source != SourceNow || man.service("web").Method != "" {
		t.Fatalf("manifest: %+v", man.Services)
	}
	t.Logf("project file: %d bytes in %s", zipped.Len(), time.Since(start).Round(time.Millisecond))

	// Back, as a new project, with the kit.
	start = time.Now()
	path, err := e.m.StageUpload(bytes.NewReader(zipped.Bytes()), int64(zipped.Len()))
	if err != nil {
		t.Fatal(err)
	}
	slug, err := e.m.StartProjectRestore(ctx, e.who, ProjectRestoreRequest{
		Name: e.project + "-copia", File: path, FileName: d.FileName, Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeProject(slug) })
	e.m.Wait()
	e.pm.Wait()
	np, _ := e.pm.GetProject(ctx, slug)
	r, ok := e.m.LatestProjectRestore(ctx, np.ID)
	if !ok || r.Status != "ok" {
		t.Fatalf("project restore: %+v", r)
	}
	t.Logf("restored as %s in %s: %+v", slug, time.Since(start).Round(time.Millisecond), r.Notes)
	// The app has no data: one that does not pass its deploy's probe is
	// noted, not a failed restore. (On a Mac with OrbStack the panel's
	// probe of a port on a project network made moments before can time
	// out while the container answers; the checks below go through the
	// container itself.)
	for _, n := range r.Notes.NotStarted {
		if !strings.HasPrefix(n, "web: ") {
			t.Fatalf("a service with data in NotStarted: %q", n)
		}
		t.Logf("noted: %s", n)
	}
	svcs, _ := e.pm.ListServices(ctx, np.ID)
	if len(svcs) != 4 {
		t.Fatalf("services of the copy: %d", len(svcs))
	}

	c := *e
	c.project = slug
	if n := c.psql(t, ctx, "db", "select count(*) || ':' || sum(valor) from pedidos"); n != "250:31375" {
		t.Fatalf("the copy's database holds %s, want the tested backup's 250 rows", n)
	}
	if out, err := c.asRole(ctx, "db", "app_rw", "rw-senha", `select count(*) from pedidos`); err != nil || out != "250" {
		t.Fatalf("app_rw with its original password: %q %v", out, err)
	}
	c.eventually(t, ctx, "queue", cli+"DBSIZE", "120")
	c.eventually(t, ctx, "queue", `redis-cli --no-auth-warning --user worker --pass 'w0rker pw' GET job:77`, "payload-77")
	if out := c.ash(t, ctx, "files", `cat /data/nota.txt; readlink /data/sub/link`); out != "olá, volume\n../nota.txt" {
		t.Fatalf("the copy's volume: %q", out)
	}
	if out := c.ash(t, ctx, "web", `printf '%s|%s|%s' "$DB_HOST" "$DB_URL" "$QUEUE"`); !strings.HasPrefix(out, slug+"_db|postgres://") ||
		!strings.Contains(out, "@"+slug+"_db:5432/") || !strings.HasSuffix(out, "|"+slug+"_queue") {
		t.Fatalf("the app's references must resolve to the copy: %q", out)
	}
	_, nweb, _ := e.pm.GetService(ctx, slug, "web")
	if doms, _ := e.pm.ListDomains(ctx, nweb.ID); len(doms) != 0 || len(r.Notes.Domains) != 1 {
		t.Fatalf("the domain must stay off and be listed: %v %+v", doms, r.Notes)
	}
	// The original is untouched: still its own data, with the row added
	// after the backup.
	if n := e.psql(t, ctx, "db", "select count(*) from pedidos"); n != "251" {
		t.Fatalf("the original holds %s rows", n)
	}
}

// ash runs a POSIX sh script in a service's container (an Alpine image
// has no bash) and returns its output.
func (e *realEnv) ash(t *testing.T, ctx context.Context, service, script string) string {
	t.Helper()
	var out bytes.Buffer
	if err := e.pm.Node().Exec(ctx, e.project, service, []string{"sh", "-c", script}, &out); err != nil {
		t.Fatalf("%s: %v\n%s", service, err, out.String())
	}
	return strings.TrimSpace(out.String())
}
