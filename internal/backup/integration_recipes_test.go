//go:build integration

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// sh runs a bash script in a service's container and returns its output.
func (e *realEnv) sh(t *testing.T, ctx context.Context, service, script string) string {
	t.Helper()
	out, err := e.trySh(ctx, service, script)
	if err != nil {
		t.Fatalf("%s: %v\n%s", service, err, out)
	}
	return out
}

func (e *realEnv) trySh(ctx context.Context, service, script string) (string, error) {
	var out bytes.Buffer
	err := e.pm.Node().Exec(ctx, e.project, service, []string{"bash", "-c", script}, &out)
	return strings.TrimSpace(out.String()), err
}

// eventually retries script until it prints want (a restored service may
// take a moment to accept its users).
func (e *realEnv) eventually(t *testing.T, ctx context.Context, service, script, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var out string
	var err error
	for time.Now().Before(deadline) {
		if out, err = e.trySh(ctx, service, script); err == nil && strings.Contains(out, want) {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s: want %q, got %q (%v)", service, want, out, err)
}

// waitHealthy waits for a service to be up and healthy.
func (e *realEnv) waitHealthy(t *testing.T, ctx context.Context, slug string) {
	t.Helper()
	e.pm.Wait()
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		if st, err := e.pm.Status(ctx, e.project, slug); err == nil && st.Running && (st.Health == "healthy" || st.Health == "") {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s did not get healthy", slug)
}

// fromTemplate creates a service from a template and waits for it.
func (e *realEnv) fromTemplate(t *testing.T, ctx context.Context, tpl, slug string) svcRef {
	t.Helper()
	if _, err := e.pm.CreateFromTemplate(ctx, e.who, e.project, tpl, slug, nil); err != nil {
		t.Fatal(err)
	}
	e.waitHealthy(t, ctx, slug)
	s, err := e.m.ref(ctx, e.project, slug)
	if err != nil {
		t.Fatal(err)
	}
	if s.Method != projects.BackupRecipe || s.Recipe == nil {
		t.Fatalf("%s is backed up as %q", tpl, s.Method)
	}
	return s
}

// recipeRun backs s up by its recipe and checks it was tested.
func (e *realEnv) recipeRun(t *testing.T, ctx context.Context, s svcRef) (string, RecipeCheck) {
	t.Helper()
	start := time.Now()
	runID, err := e.m.backupRecipe(ctx, e.who, s, TriggerManual)
	if err != nil {
		t.Fatalf("backup of %s: %v", s.Service, err)
	}
	run, _ := e.m.q.GetBackupRun(ctx, runID)
	var c RecipeCheck
	if err := json.Unmarshal([]byte(run.CheckJson), &c); err != nil || run.Verified != 1 || run.Status != "ok" {
		t.Fatalf("run: %+v (%v)", run, err)
	}
	if o, ok := archive.ParseKey(run.ObjectKey); !ok || o.Kind != archive.KindRecipe {
		t.Fatalf("key %q", run.ObjectKey)
	}
	t.Logf("%s: tested backup in %s, %d bytes (%d before compression), source %v, test copy %v",
		s.Service, time.Since(start).Round(time.Millisecond), run.SizeBytes, c.Bytes, c.Source, c.Restored)
	return run.ObjectKey, c
}

func (e *realEnv) restore(t *testing.T, ctx context.Context, s svcRef, key, dest, newService string) {
	t.Helper()
	start := time.Now()
	rid, err := e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: s.Service, Mode: ModeDump, Key: key, Destination: dest, NewService: newService,
		Confirm: s.Service, Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" {
		t.Fatalf("restore (%s): %+v", dest, r)
	}
	t.Logf("%s: restore into %s took %s", s.Service, dest, time.Since(start).Round(time.Millisecond))
}

func atLeast(t *testing.T, c map[string]int64, want map[string]int64) {
	t.Helper()
	for k, v := range want {
		if c[k] < v {
			t.Errorf("%s = %d, want at least %d (%v)", k, c[k], v, c)
		}
	}
}

// MariaDB, by its recipe: the databases with a user of the app's own and a
// role, backed up while running, tested in a throwaway server, restored
// into a new service and over the same one; the app logs in with its
// original password and reads the same data.
func TestMariaDBRecipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E MariaDB"); err != nil {
		t.Fatal(err)
	}
	s := e.fromTemplate(t, ctx, "mariadb", "maria")
	const root = `export MYSQL_PWD="$MARIADB_ROOT_PASSWORD"; mariadb -uroot -N -B -e `
	e.sh(t, ctx, "maria", root+`"
CREATE DATABASE shop CHARACTER SET utf8mb4;
USE shop;
CREATE TABLE shop.orders (id INT PRIMARY KEY AUTO_INCREMENT, total DECIMAL(10,2), note BLOB);
INSERT INTO shop.orders (total, note) SELECT seq, UNHEX('00FF10') FROM seq_1_to_1500;
CREATE VIEW shop.big AS SELECT * FROM shop.orders WHERE total > 1000;
CREATE ROLE reader; GRANT SELECT ON shop.* TO reader;
CREATE USER 'reporter'@'%' IDENTIFIED BY 'rep pw 1'; GRANT reader TO 'reporter'@'%'; SET DEFAULT ROLE reader FOR 'reporter'@'%';
CREATE USER 'writer'@'%' IDENTIFIED BY 'w\"r1t'; GRANT INSERT, SELECT ON shop.orders TO 'writer'@'%';
"`)
	e.sh(t, ctx, "maria", root+`"CREATE TABLE app.notes (id INT PRIMARY KEY, body TEXT); INSERT INTO app.notes VALUES (1, 'olá'), (2, 'mundo');"`)
	const asReporter = `MYSQL_PWD='rep pw 1' mariadb -ureporter -h127.0.0.1 -N -B -e "SELECT COUNT(*), SUM(total) FROM shop.orders"`
	const asWriter = `MYSQL_PWD='w"r1t' mariadb -uwriter -h127.0.0.1 -N -B -e "SELECT COUNT(*) FROM shop.orders"`
	const asApp = `MYSQL_PWD="$MARIADB_PASSWORD" mariadb -u"$MARIADB_USER" -h127.0.0.1 -N -B -e "SELECT GROUP_CONCAT(body ORDER BY id) FROM app.notes"`
	want := e.sh(t, ctx, "maria", asReporter)
	if !strings.HasPrefix(want, "1500\t") {
		t.Fatalf("seed: %q", want)
	}

	key, c := e.recipeRun(t, ctx, s)
	atLeast(t, c.Restored, map[string]int64{"databases": 2, "tables": 2, "rows": 1502, "users": 4})

	// A clone: the users log in with their original passwords.
	e.restore(t, ctx, s, key, DestNew, "maria-clone")
	e.waitHealthy(t, ctx, "maria-clone")
	e.eventually(t, ctx, "maria-clone", asReporter, want)
	e.eventually(t, ctx, "maria-clone", asWriter, "1500")
	e.eventually(t, ctx, "maria-clone", asApp, "olá,mundo")
	if out := e.sh(t, ctx, "maria-clone", root+`"SELECT HEX(note) FROM shop.orders WHERE id = 7; SELECT COUNT(*) FROM shop.big"`); !strings.Contains(out, "00FF10") || !strings.Contains(out, "500") {
		t.Fatalf("binary data or view lost: %q", out)
	}

	// Over the same service: what was deleted comes back, the users too.
	e.sh(t, ctx, "maria", root+`"DROP DATABASE shop; DROP USER 'reporter'@'%'; DELETE FROM app.notes"`)
	e.restore(t, ctx, s, key, DestOverwrite, "")
	e.waitHealthy(t, ctx, "maria")
	e.eventually(t, ctx, "maria", asReporter, want)
	e.eventually(t, ctx, "maria", asApp, "olá,mundo")
	runs, _ := e.m.ServiceRuns(ctx, s.ID, 10)
	if len(runs) < 2 || runs[0].Trigger != TriggerPreRestore || runs[0].Kind != archive.KindRecipe {
		t.Fatalf("overwriting must back up the current state first: %+v", runs)
	}
}

// mysqlTemplate is a MySQL 8 template with its recipe, for this test only
// (the catalog ships MariaDB): the format holds any database.
func mysqlTemplate(t *testing.T) *templates.Template {
	t.Helper()
	meta := `id = "mysql-it"
version = 1
category = "database"
main = "mysql"
name = { en = "MySQL", "pt-BR" = "MySQL" }
description = { en = "MySQL 8 (tests).", "pt-BR" = "MySQL 8 (testes)." }

[variables.password]
generate = "secret"

[variables.root_password]
generate = "secret"

[backup]
method = "recipe"
extension = "sql"
env = ["MYSQL_ROOT_PASSWORD"]
serve = ["docker-entrypoint.sh", "mysqld", "--innodb-buffer-pool-size=64M"]
ready = ["sh", "-c", 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqladmin -uroot -h127.0.0.1 --protocol=TCP --connect-timeout=2 ping']
dump = ["bash", "-c", '''
set -euo pipefail
export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
sql() { mysql -uroot -N -r -B "$@"; }
own="user IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', '')"
dbs=()
while IFS= read -r d; do dbs+=("$d"); done < <(sql -e "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') ORDER BY 1")
echo "-- Hangar: full backup of a MySQL server"
if [ "${#dbs[@]}" -gt 0 ]; then
  mysqldump -uroot --single-transaction --routines --events --triggers --hex-blob --add-drop-database --set-gtid-purged=OFF --max-allowed-packet=1G --databases "${dbs[@]}"
fi
accts=$(sql -e "SELECT CONCAT(QUOTE(u.user), '@', QUOTE(u.host)) FROM mysql.user u WHERE NOT ($own) ORDER BY (SELECT COUNT(*) FROM mysql.default_roles d WHERE d.USER = u.user AND d.HOST = u.host), 1")
while IFS= read -r acct; do
  [ -n "$acct" ] || continue
  echo "DROP USER IF EXISTS $acct;"
  printf '%s;\n' "$(sql -e "SET SESSION print_identified_with_as_hex = ON; SHOW CREATE USER $acct")"
done <<< "$accts"
# Grants on a table or routine that no longer exists stay in the server
# after a DROP but cannot be granted again: they are left out.
dangling=$(sql -e "SELECT CONCAT(' ON \@BT@', REPLACE(t.Db, '\@BT@', '\@BT@\@BT@'), '\@BT@.\@BT@', REPLACE(t.Table_name, '\@BT@', '\@BT@\@BT@'), '\@BT@ TO ') FROM mysql.tables_priv t WHERE NOT EXISTS (SELECT 1 FROM information_schema.tables i WHERE i.table_schema = t.Db AND i.table_name = t.Table_name) UNION SELECT CONCAT(' ON ', p.Routine_type, ' \@BT@', REPLACE(p.Db, '\@BT@', '\@BT@\@BT@'), '\@BT@.\@BT@', REPLACE(p.Routine_name, '\@BT@', '\@BT@\@BT@'), '\@BT@ TO ') FROM mysql.procs_priv p WHERE NOT EXISTS (SELECT 1 FROM information_schema.routines r WHERE r.routine_schema = p.Db AND r.routine_name = p.Routine_name AND r.routine_type = p.Routine_type)")
while IFS= read -r acct; do
  [ -n "$acct" ] || continue
  g=$(sql -e "SHOW GRANTS FOR $acct")
  if [ -n "$dangling" ]; then g=$(grep -vF -f <(printf '%s\n' "$dangling") <<< "$g" || true); fi
  [ -z "$g" ] || sed 's/$/;/' <<< "$g"
done <<< "$accts"
echo "FLUSH PRIVILEGES;"
''']
restore = ["bash", "-c", 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; exec mysql -uroot --binary-mode --max-allowed-packet=1G']
verify = ["bash", "-c", '''
set -euo pipefail
export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
sql() { mysql -uroot -N -r -B "$@"; }
own="user IN ('root', 'mysql.sys', 'mysql.session', 'mysql.infoschema', '')"
mine="table_type = 'BASE TABLE' AND table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')"
count=$(sql -e "SET SESSION group_concat_max_len = 1073741824; SELECT CONCAT('SELECT 0', IFNULL(GROUP_CONCAT(CONCAT(' + (SELECT COUNT(*) FROM \@BT@', REPLACE(table_schema, '\@BT@', '\@BT@\@BT@'), '\@BT@.\@BT@', REPLACE(table_name, '\@BT@', '\@BT@\@BT@'), '\@BT@)') SEPARATOR ''), '')) FROM information_schema.tables WHERE $mine")
echo "HANGAR-CHECK tables=$(sql -e "SELECT COUNT(*) FROM information_schema.tables WHERE $mine") rows=$(sql -e "$count") users=$(sql -e "SELECT COUNT(*) FROM mysql.user WHERE NOT ($own)")"
''']
`
	compose := `services:
  mysql:
    image: mysql:8.4
    command: ["mysqld", "--innodb-buffer-pool-size=128M"]
    environment:
      MYSQL_DATABASE: app
      MYSQL_USER: app
      MYSQL_PASSWORD: ${password}
      MYSQL_ROOT_PASSWORD: ${root_password}
    volumes:
      - data:/var/lib/mysql
    expose:
      - "3306"
    healthcheck:
      test: ["CMD-SHELL", "MYSQL_PWD=\"$$MYSQL_ROOT_PASSWORD\" mysqladmin -uroot -h127.0.0.1 ping"]
      interval: 5s
      timeout: 5s
      start_period: 60s
      retries: 20
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]
    deploy:
      resources:
        limits:
          memory: 768M
          cpus: "1.0"

volumes:
  data:
`
	// The verify script quotes names with backticks, which a Go raw
	// string cannot hold.
	meta = strings.ReplaceAll(meta, "@BT@", "`")
	tpl, err := templates.Parse("mysql-it", map[string][]byte{
		templates.FileMeta: []byte(meta), templates.FileCompose: []byte(compose),
		templates.FileLogo: []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

// MySQL 8: the same promise through a template that only Hangar's format
// describes (caching_sha2_password hashes travel as hex).
func TestMySQLRecipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	e.pm.SetTemplates(templates.NewRegistry(templates.Merge(templates.Builtin(), []*templates.Template{mysqlTemplate(t)})))
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E MySQL"); err != nil {
		t.Fatal(err)
	}
	s := e.fromTemplate(t, ctx, "mysql-it", "my")
	const root = `export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; mysql -uroot -N -B -e `
	e.sh(t, ctx, "my", root+`"
CREATE DATABASE shop;
CREATE TABLE shop.orders (id INT PRIMARY KEY AUTO_INCREMENT, total INT);
INSERT INTO shop.orders (total) WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 800) SELECT i FROM n;
CREATE ROLE 'reader'; GRANT SELECT ON shop.* TO 'reader';
CREATE USER 'reporter'@'%' IDENTIFIED BY 'rep pw 8' DEFAULT ROLE 'reader'; GRANT 'reader' TO 'reporter'@'%';
CREATE USER 'writer'@'%' IDENTIFIED BY 'wr1te pw'; GRANT INSERT, SELECT ON shop.orders TO 'writer'@'%';"`)
	const asReporter = `MYSQL_PWD='rep pw 8' mysql -ureporter -h127.0.0.1 -N -B -e "SELECT COUNT(*) FROM shop.orders"`
	const asApp = `MYSQL_PWD="$MYSQL_PASSWORD" mysql -uapp -h127.0.0.1 -N -B -e "SELECT 1"`
	if out := e.sh(t, ctx, "my", asReporter); out != "800" {
		t.Fatalf("seed: %q", out)
	}
	key, c := e.recipeRun(t, ctx, s)
	atLeast(t, c.Restored, map[string]int64{"tables": 1, "rows": 800, "users": 4})
	e.restore(t, ctx, s, key, DestNew, "my-clone")
	e.waitHealthy(t, ctx, "my-clone")
	e.eventually(t, ctx, "my-clone", asReporter, "800")
	e.eventually(t, ctx, "my-clone", asApp, "1")
	e.eventually(t, ctx, "my-clone", `MYSQL_PWD='wr1te pw' mysql -uwriter -h127.0.0.1 -N -B -e "SELECT COUNT(*) FROM shop.orders"`, "800")

	e.sh(t, ctx, "my", root+`"DROP DATABASE shop; DROP USER 'reporter'@'%'"`)
	e.restore(t, ctx, s, key, DestOverwrite, "")
	e.waitHealthy(t, ctx, "my")
	e.eventually(t, ctx, "my", asReporter, "800")
}

// MongoDB: the whole instance (admin's users and roles included) by
// mongodump; an app user of its own database logs into the clone with its
// original password.
func TestMongoDBRecipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E MongoDB"); err != nil {
		t.Fatal(err)
	}
	s := e.fromTemplate(t, ctx, "mongodb", "mongo")
	const asRoot = `mongosh --quiet mongodb://127.0.0.1:27017/admin --eval 'db.auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD); `
	e.sh(t, ctx, "mongo", asRoot+`
const shop = db.getSiblingDB("shop");
shop.orders.insertMany(Array.from({ length: 700 }, (_, i) => ({ n: i, tags: ["a", "b"], at: new Date() })));
shop.orders.createIndex({ n: 1 }, { unique: true });
shop.createRole({ role: "orderReader", privileges: [{ resource: { db: "shop", collection: "orders" }, actions: ["find"] }], roles: [] });
shop.createUser({ user: "reporter", pwd: "rep pw m", roles: ["orderReader"] });'`)
	const asReporter = `mongosh --quiet "mongodb://reporter:rep%20pw%20m@127.0.0.1:27017/shop?authSource=shop" --eval 'print(db.orders.countDocuments({}))'`
	const asApp = `mongosh --quiet mongodb://127.0.0.1:27017/admin --eval 'db.auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD); print("root " + db.getSiblingDB("shop").orders.getIndexes().length)'`
	if out := e.sh(t, ctx, "mongo", asReporter); out != "700" {
		t.Fatalf("seed: %q", out)
	}
	key, c := e.recipeRun(t, ctx, s)
	atLeast(t, c.Restored, map[string]int64{"collections": 1, "documents": 700, "users": 2, "roles": 1})

	e.restore(t, ctx, s, key, DestNew, "mongo-clone")
	e.waitHealthy(t, ctx, "mongo-clone")
	e.eventually(t, ctx, "mongo-clone", asReporter, "700")
	e.eventually(t, ctx, "mongo-clone", asApp, "root 2")

	e.sh(t, ctx, "mongo", asRoot+`db.getSiblingDB("shop").dropDatabase()'`)
	e.restore(t, ctx, s, key, DestOverwrite, "")
	e.waitHealthy(t, ctx, "mongo")
	e.eventually(t, ctx, "mongo", asReporter, "700")
}

// Redis (queues, with AOF): every key and an ACL user, with no restart; the
// user reads the clone's keys with its original password, and the clone
// keeps them across a restart (its own AOF).
func TestRedisRecipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E Redis"); err != nil {
		t.Fatal(err)
	}
	s := e.fromTemplate(t, ctx, "redis-queue", "queue")
	const cli = `export REDISCLI_AUTH="$REDIS_PASSWORD"; redis-cli --no-auth-warning `
	e.sh(t, ctx, "queue", `export REDISCLI_AUTH="$REDIS_PASSWORD"
for i in $(seq 1 400); do echo "SET job:$i payload-$i"; done | redis-cli --no-auth-warning --pipe >/dev/null
redis-cli --no-auth-warning RPUSH celery a b c >/dev/null
redis-cli --no-auth-warning ACL SETUSER worker on '>w0rker pw' '~job:*' '~celery' '+@read' '+@list' >/dev/null`)
	const asWorker = `redis-cli --no-auth-warning --user worker --pass 'w0rker pw' GET job:123; redis-cli --no-auth-warning --user worker --pass 'w0rker pw' LRANGE celery 0 -1 | tr '\n' ,`
	pid := e.sh(t, ctx, "queue", cli+`INFO server | sed -n 's/^process_id:\([0-9]*\).*/\1/p'`)
	key, c := e.recipeRun(t, ctx, s)
	atLeast(t, c.Restored, map[string]int64{"keys": 401, "users": 1})
	if after := e.sh(t, ctx, "queue", cli+`INFO server | sed -n 's/^process_id:\([0-9]*\).*/\1/p'`); after != pid {
		t.Fatalf("the backup restarted Redis: %s -> %s", pid, after)
	}

	e.restore(t, ctx, s, key, DestNew, "queue-clone")
	e.eventually(t, ctx, "queue-clone", asWorker, "payload-123\na,b,c,")
	if out := e.sh(t, ctx, "queue-clone", cli+"DBSIZE"); out != "401" {
		t.Fatalf("clone DBSIZE %q", out)
	}
	// The keys are the clone's own now: they survive its restart.
	if err := e.pm.Node().Restart(ctx, e.project, "queue-clone"); err != nil {
		t.Fatal(err)
	}
	e.eventually(t, ctx, "queue-clone", cli+"DBSIZE", "401")

	e.sh(t, ctx, "queue", cli+`DEL job:123 celery >/dev/null; `+cli+`ACL DELUSER worker`)
	e.restore(t, ctx, s, key, DestOverwrite, "")
	e.eventually(t, ctx, "queue", asWorker, "payload-123\na,b,c,")
}

// A database Hangar has no recipe for (a MariaDB from its image, no
// template) is backed up whole by the generic path: its volume, copied
// with the server stopped and started again. The clone opens with the
// same users and data.
func TestUnknownDatabaseStopCopy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E stop copy"); err != nil {
		t.Fatal(err)
	}
	svc, err := e.pm.CreateService(ctx, e.who, e.project, projects.ServiceInput{Name: "olddb", Image: "mariadb:12.3", MemoryMB: 512})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"MARIADB_ROOT_PASSWORD": "r00t pw", "MARIADB_DATABASE": "legacy", "MARIADB_USER": "legacy", "MARIADB_PASSWORD": "l3gacy"} {
		if err := e.pm.SetEnv(ctx, e.who, svc.ID, k, v, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.pm.AddServiceVolume(ctx, e.who, e.project, "olddb", "data", "/var/lib/mysql"); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	s, err := e.m.ref(ctx, e.project, "olddb")
	if err != nil {
		t.Fatal(err)
	}
	if s.Method != projects.BackupVolume || !s.Stop || s.hold() != ConsistencyStop {
		t.Fatalf("a database image without a recipe: method %q stop %v", s.Method, s.Stop)
	}
	if err := e.m.deployAndWait(ctx, e.who, s, "create"); err != nil {
		t.Fatal(err)
	}
	const asLegacy = `MYSQL_PWD=l3gacy mariadb -ulegacy -h127.0.0.1 -N -B -e "SELECT COUNT(*) FROM legacy.items"`
	e.eventually(t, ctx, "olddb", `MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb -uroot -N -B -e "USE legacy; CREATE TABLE IF NOT EXISTS legacy.items (id INT PRIMARY KEY); INSERT IGNORE INTO legacy.items SELECT seq FROM seq_1_to_250; SELECT 'seeded'"`, "seeded")
	e.eventually(t, ctx, "olddb", asLegacy, "250")

	start := time.Now()
	runID, err := e.m.backupVolume(ctx, e.who, s, TriggerManual, "")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	run, _ := e.m.q.GetBackupRun(ctx, runID)
	var c VolumeCheck
	if err := json.Unmarshal([]byte(run.CheckJson), &c); err != nil || run.Verified != 1 || c.Mode != ConsistencyStop || c.PauseMS <= 0 {
		t.Fatalf("run: %+v %+v", run, c)
	}
	t.Logf("olddb: stop copy in %s, down for %s (%d files, %d bytes)", time.Since(start).Round(time.Millisecond),
		time.Duration(c.PauseMS)*time.Millisecond, c.Files, c.Bytes)
	if !e.running(t, ctx, "olddb") {
		t.Fatal("the database must be running again after the copy")
	}
	back := time.Now()
	e.eventually(t, ctx, "olddb", asLegacy, "250")
	t.Logf("olddb: answering queries again %s after the backup returned", time.Since(back).Round(time.Millisecond))

	e.restore(t, ctx, s, run.ObjectKey, DestNew, "olddb-clone")
	e.eventually(t, ctx, "olddb-clone", asLegacy, "250")
	e.sh(t, ctx, "olddb", `MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb -uroot -e "DROP TABLE legacy.items"`)
	e.restore(t, ctx, s, run.ObjectKey, DestOverwrite, "")
	e.eventually(t, ctx, "olddb", asLegacy, "250")
}
