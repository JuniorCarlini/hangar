package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgroles"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// Run triggers.
const (
	TriggerSchedule   = "schedule"
	TriggerManual     = "manual"
	TriggerDownload   = "download"
	TriggerPreRestore = "pre_restore"
	TriggerWALStart   = "wal_start"
	TriggerChange     = "change"
)

// svcRef is a service being backed up.
type svcRef struct {
	ID       string
	Project  string
	Service  string
	Image    string
	Memory   int64
	DataPath string // where the data volume is mounted
	Volume   string // full Docker name of the data volume
	DBUser   string
	DBName   string
	// Method is how it is backed up: projects.BackupPGDump,
	// projects.BackupRecipe or projects.BackupVolume. Hangar picks it,
	// never the user (projects.BackupMethod).
	Method string
	// Template is the catalog template it was made from ("" for none).
	Template string
	// Recipe is its template's native backup (BackupRecipe).
	Recipe *templates.Recipe
	// Vols are the volumes it owns (BackupVolume and BackupRecipe).
	Vols []projects.OwnedVolume
	// Stop: a copy of its volumes is taken with it stopped (a database),
	// not paused.
	Stop bool
}

// kind is the kind of its full backups: a dump, a recipe's backup or a
// copy of its volumes.
func (s svcRef) kind() string {
	switch s.Method {
	case projects.BackupVolume:
		return archive.KindVolume
	case projects.BackupRecipe:
		return archive.KindRecipe
	}
	return archive.KindDump
}

// online reports whether its backup is taken from the running server (a
// dump), which then must be running; a copy of volumes is not.
func (s svcRef) online() bool { return s.Method != projects.BackupVolume }

// hold is how a copy of its volumes is kept consistent: stopped for a
// database (the only way that is safe for any of them), paused for the
// rest. Never a user's choice.
func (s svcRef) hold() string {
	if s.Stop {
		return ConsistencyStop
	}
	return ConsistencyPause
}

// meta is the object metadata of a service backup.
func (s svcRef) meta(kind string) map[string]string {
	switch kind {
	case archive.KindVolume:
		return map[string]string{"hangar-kind": kind, "hangar-service": s.label(), "hangar-image": s.Image}
	case archive.KindRecipe:
		return map[string]string{"hangar-kind": kind, "hangar-service": s.label(), "hangar-image": s.Image, "hangar-template": s.Template}
	}
	return map[string]string{
		"hangar-kind": kind, "hangar-service": s.label(), "hangar-image": s.Image,
		"hangar-db-user": s.DBUser, "hangar-db-name": s.DBName,
	}
}

func (s svcRef) label() string { return s.Project + "/" + s.Service }

// pgDumpCmd runs inside the service container; the credentials come from
// its own environment, never from a command line.
var pgDumpCmd = []string{"sh", "-c", `exec pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"`}

// verifyScript restores the dump into a throwaway PostgreSQL (same image,
// no network, scratch volume), the way a restore into a new service does,
// and counts what came back. It is a constant: nothing from the user
// reaches it. Its input is a line with the size of the roles script
// (pgroles ApplyScript, 0 for none), the script, then the dump.
//
// First the server's roles come back from the script, as they were
// (attributes, password hashes, memberships, settings), and it prints
// what PostgreSQL then has (HANGAR-SAVED, HANGAR-STATE), so the panel can
// check each role is as in the original. Then the dump is restored with
// its owners and permissions. Roles neither the script nor the image has
// (the original's own superuser) are not in a pg_dump, so a schema-only
// rehearsal finds, from PostgreSQL's own errors, each one the restore
// still needs and creates it (NOLOGIN, as the real restore does). It
// prints those (HANGAR-ROLE, hex), the dump's ACL, POLICY and DEFAULT ACL
// entries (HANGAR-ACL, hex) and the owners of its entries (HANGAR-OWNER,
// hex), so the panel can check that the real restore would find those
// same roles by reading the dump. Without a roles script (never, for a
// dump made now) owners are skipped as before.
const verifyScript = `set -eu
umask 077
read -r size
if [ "$size" -gt 0 ]; then dd bs=1 count="$size" of=/scratch/roles.sql 2>/dev/null; fi
cat > /scratch/dump
if command -v su-exec >/dev/null 2>&1; then AS="su-exec postgres"; else AS="gosu postgres"; fi
mkdir -p /scratch/pgdata /scratch/run
touch /scratch/roles.sql
chown postgres:postgres /scratch/pgdata /scratch/run /scratch/dump /scratch/roles.sql
$AS initdb -D /scratch/pgdata -U postgres --auth=trust -E UTF8 >/dev/null
$AS pg_ctl -D /scratch/pgdata -o "-c listen_addresses= -c unix_socket_directories=/scratch/run -c fsync=off -c lc_messages=C" -w -t 300 start >/dev/null
owner=--no-owner
if [ "$size" -gt 0 ]; then
  if [ "$(wc -c < /scratch/roles.sql)" -ne "$size" ]; then echo "the roles script arrived incomplete" >&2; exit 1; fi
  $AS psql -h /scratch/run -U postgres -d postgres -qAtX -v ON_ERROR_STOP=1 -v VERBOSITY=terse -f /scratch/roles.sql
  $AS psql -h /scratch/run -U postgres -d postgres -qAtX -v ON_ERROR_STOP=1 -f - <<'SQL'
` + pgroles.StateQuery + `
SQL
  owner=
  $AS pg_restore --schema-only -f - /scratch/dump | sed -n 's/^-- Name: .*; Owner: \(.*\)$/\1/p' | sort -u > /scratch/run/owners
  while IFS= read -r o; do printf 'HANGAR-OWNER %s\n' "$(printf '%s' "$o" | od -An -tx1 | tr -d ' \n')"; done < /scratch/run/owners
fi
$AS pg_restore -l /scratch/dump > /scratch/run/toc
tables=$(grep -c " TABLE DATA " /scratch/run/toc || true)
grep -E '^[0-9]+; [0-9]+ [0-9]+ (ACL|POLICY|DEFAULT ACL) ' /scratch/run/toc > /scratch/run/acl.list || true
chown postgres:postgres /scratch/run/acl.list
if [ -s /scratch/run/acl.list ]; then
  $AS pg_restore -L /scratch/run/acl.list -f /scratch/run/acl.sql /scratch/dump
  printf 'HANGAR-ACL %s\n' "$(od -An -tx1 /scratch/run/acl.sql | tr -d ' \n')"
fi
$AS createdb -h /scratch/run -U postgres hangar_roles
n=0
until $AS pg_restore -h /scratch/run -U postgres -d hangar_roles --schema-only $owner --single-transaction --exit-on-error /scratch/dump 2>/scratch/run/err; do
  role=$(sed -n 's/^.*ERROR:  role "\(.*\)" does not exist$/\1/p' /scratch/run/err | head -n 1)
  if [ -z "$role" ] || [ "$n" -ge 200 ]; then cat /scratch/run/err >&2; exit 1; fi
  printf 'CREATE ROLE :"r" NOLOGIN;\n' | $AS psql -h /scratch/run -U postgres -d postgres -qAtX -v ON_ERROR_STOP=1 -v r="$role" -f - >/dev/null
  printf 'HANGAR-ROLE %s\n' "$(printf '%s' "$role" | od -An -tx1 | tr -d ' \n')"
  n=$((n+1))
done
$AS dropdb -h /scratch/run -U postgres hangar_roles
$AS pg_restore -h /scratch/run -U postgres -d postgres $owner --exit-on-error /scratch/dump
counts=$($AS psql -h /scratch/run -U postgres -d postgres -AtX -v ON_ERROR_STOP=1 -c "select count(*), coalesce(sum((xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', schemaname, relname), false, true, '')))[1]::text::bigint), 0) from pg_stat_user_tables")
echo "HANGAR-CHECK tables=$tables restored=${counts%%|*} rows=${counts##*|}"
$AS pg_ctl -D /scratch/pgdata -m immediate stop >/dev/null
`

var (
	checkRE = regexp.MustCompile(`(?m)^HANGAR-CHECK tables=(\d+) restored=(\d+) rows=(\d+)\s*$`)
	aclRE   = regexp.MustCompile(`(?m)^HANGAR-ACL ([0-9a-f]*)\s*$`)
	roleRE  = regexp.MustCompile(`(?m)^HANGAR-ROLE ([0-9a-f]+)\s*$`)
	ownerRE = regexp.MustCompile(`(?m)^HANGAR-OWNER ([0-9a-f]+)\s*$`)
)

// Check is what the test restore found.
type Check struct {
	Tables   int64 `json:"tables"`   // tables with data in the dump
	Restored int64 `json:"restored"` // tables in the throwaway database
	Rows     int64 `json:"rows"`
	Bytes    int64 `json:"bytes"` // dump size before encryption
	// Saved are the server's roles the test restore recreated from the
	// roles saved with the dump, checked to be as in the original.
	Saved []string `json:"saved_roles,omitempty"`
	// Roles are the roles the dump refers to that neither a fresh
	// PostgreSQL nor the saved roles have: a restore creates them
	// without a password.
	Roles []string `json:"roles,omitempty"`
}

// parseCheck reads the test restore's output. g are the roles saved with
// the dump (nil: none).
func parseCheck(out string, g *pgroles.Globals) (Check, error) {
	m := checkRE.FindStringSubmatch(out)
	if m == nil {
		return Check{}, errors.New("the test restore did not report its counts")
	}
	var c Check
	c.Tables, _ = strconv.ParseInt(m[1], 10, 64)
	c.Restored, _ = strconv.ParseInt(m[2], 10, 64)
	c.Rows, _ = strconv.ParseInt(m[3], 10, 64)
	if c.Restored < c.Tables {
		return c, fmt.Errorf("the test restore has %d tables, the dump has %d", c.Restored, c.Tables)
	}
	if g != nil && len(g.Roles) > 0 {
		c.Saved = pgroles.ParseSaved(out)
		state, err := pgroles.ParseState(out)
		if err != nil {
			return c, err
		}
		if err := g.Check(c.Saved, state); err != nil {
			return c, err
		}
	}
	roles, err := checkRoles(out)
	c.Roles = roles
	return c, err
}

func hexLines(re *regexp.Regexp, out string) []string {
	var names []string
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		if b, err := hex.DecodeString(m[1]); err == nil {
			names = append(names, string(b))
		}
	}
	return names
}

// checkRoles compares the roles the test restore needed (PostgreSQL said
// which) with the ones a real restore finds by reading the dump's
// permissions and owners (pgroles): a role only the first knows would
// make the real restore fail, so the backup is not called tested.
func checkRoles(out string) ([]string, error) {
	needed := hexLines(roleRE, out)
	if len(needed) == 0 {
		return nil, nil
	}
	found := hexLines(ownerRE, out)
	if m := aclRE.FindStringSubmatch(out); m != nil {
		sql, err := hex.DecodeString(m[1])
		if err != nil {
			return needed, fmt.Errorf("the test restore sent unreadable permissions: %w", err)
		}
		acl, err := pgroles.FromScript(bytes.NewReader(sql))
		if err != nil {
			return needed, err
		}
		found = append(found, acl...)
	}
	var missing []string
	for _, r := range needed {
		if !slices.Contains(found, r) {
			missing = append(missing, strconv.Quote(r))
		}
	}
	if len(missing) > 0 {
		return needed, fmt.Errorf("the dump needs roles a restore would not create: %s", strings.Join(missing, ", "))
	}
	return needed, nil
}

type counter struct {
	n int64
}

func (c *counter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// sealedFile is an encrypted file being written to the staging dir.
type sealedFile struct {
	f    *os.File
	sha  hash.Hash
	size counter
}

func (s *sealedFile) hexSum() string { return hex.EncodeToString(s.sha.Sum(nil)) }

// sealBytes encrypts b into a new staging file.
func (m *Manager) sealBytes(rcpts []age.Recipient, pattern string, b []byte) (*sealedFile, error) {
	f, err := m.stagingFile(pattern)
	if err != nil {
		return nil, err
	}
	sf := &sealedFile{f: f, sha: sha256.New()}
	err = func() error {
		w, err := archive.Seal(io.MultiWriter(f, sf.sha, &sf.size), rcpts, false)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		return f.Sync()
	}()
	if err != nil {
		removeFile(f)
		return nil, err
	}
	return sf, nil
}

// pgRolesCmd prints the server's roles (pg_dumpall --roles-only: their
// attributes, password hashes, memberships and settings) under a line
// naming its bootstrap superuser (pgroles.BootstrapHeader). It runs in the
// service container as its superuser, like pg_dump.
var pgRolesCmd = []string{"sh", "-c", `set -eu
b=$(psql -AtX -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select encode(convert_to(rolname, 'UTF8'), 'hex') from pg_catalog.pg_authid where oid = 10")
printf '%s%s\n' '` + pgroles.BootstrapHeader + `' "$b"
exec pg_dumpall --roles-only -U "$POSTGRES_USER" -l "$POSTGRES_DB"`}

// captureRoles reads the roles of s's server (pgRolesCmd). The text holds
// password hashes: it only ever leaves memory encrypted.
func captureRoles(ctx context.Context, n node.Node, s svcRef) ([]byte, pgroles.Globals, error) {
	var buf bytes.Buffer
	if err := n.Exec(ctx, s.Project, s.Service, pgRolesCmd, &limitWriter{w: &buf, n: pgroles.MaxGlobals}); err != nil {
		return nil, pgroles.Globals{}, fmt.Errorf("pg_dumpall --roles-only: %w", err)
	}
	g, err := pgroles.ParseGlobals(buf.String())
	if err != nil {
		return nil, g, err
	}
	return buf.Bytes(), g, nil
}

// dumped is a dump and the roles of its server, encrypted in the staging
// dir, and what the test restore found.
type dumped struct {
	dump, roles *sealedFile
	check       Check
}

func (d *dumped) remove() {
	if d == nil {
		return
	}
	for _, sf := range []*sealedFile{d.dump, d.roles} {
		if sf != nil {
			removeFile(sf.f)
		}
	}
}

// dumpAndVerify saves the server's roles, runs pg_dump, feeds both to the
// test restore and, at the same time, encrypts the dump into a staging
// file. Plaintext only ever exists inside the database container, the
// throwaway one and this process's memory.
func (m *Manager) dumpAndVerify(ctx context.Context, s svcRef) (*dumped, error) {
	n, tk, err := m.tasker()
	if err != nil {
		return nil, err
	}
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return nil, err
	}
	rolesSQL, g, err := captureRoles(ctx, n, s)
	if err != nil {
		return nil, err
	}
	apply, err := g.ApplyScript()
	if err != nil {
		return nil, err
	}
	d := &dumped{}
	ok := false
	defer func() {
		if !ok {
			d.remove()
		}
	}()
	if d.roles, err = m.sealBytes(rcpts, "roles-*.age", rolesSQL); err != nil {
		return nil, err
	}
	f, err := m.stagingFile("dump-*.age")
	if err != nil {
		return nil, err
	}
	sf := &sealedFile{f: f, sha: sha256.New()}
	d.dump = sf
	sealer, err := archive.Seal(io.MultiWriter(f, sf.sha, &sf.size), rcpts, false)
	if err != nil {
		return nil, err
	}
	mem := max(s.Memory, 512<<20)
	pr, pw := io.Pipe()
	var taskOut bytes.Buffer
	taskErr := make(chan error, 1)
	go func() {
		err := tk.RunTask(ctx, node.TaskSpec{
			Image: s.Image, Cmd: []string{"sh", "-c", verifyScript}, Scratch: "/scratch",
			MemoryBytes: mem, NanoCPUs: 1e9, PidsLimit: 256,
		}, pr, &taskOut)
		_ = pr.CloseWithError(errors.Join(err, errors.New("test restore ended")))
		taskErr <- err
	}()
	var plain counter
	// The roles script first (its size on a line of its own), then the
	// dump as pg_dump writes it.
	_, derr := io.WriteString(pw, strconv.Itoa(len(apply))+"\n"+apply)
	if derr == nil {
		derr = n.Exec(ctx, s.Project, s.Service, pgDumpCmd, io.MultiWriter(pw, sealer, &plain))
	}
	_ = pw.Close()
	terr := <-taskErr
	switch {
	case derr != nil && terr != nil && !strings.Contains(derr.Error(), "test restore ended"):
		return nil, fmt.Errorf("pg_dump: %w", derr)
	case terr != nil:
		// PostgreSQL may quote a statement of the roles script.
		return nil, fmt.Errorf("test restore: %s", g.Redact(terr.Error()))
	case derr != nil:
		return nil, fmt.Errorf("pg_dump: %w", derr)
	}
	d.check, err = parseCheck(taskOut.String(), &g)
	if err != nil {
		return nil, errors.New(g.Redact(err.Error()))
	}
	d.check.Bytes = plain.n
	if err := sealer.Close(); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	ok = true
	return d, nil
}

// class picks the retention folder of a scheduled dump: the first
// successful one of the month goes to mensal/, of the week to semanal/,
// the rest to diario/. Manual and pre-restore dumps are daily.
func (m *Manager) class(ctx context.Context, label, kind, trigger string) string {
	if trigger != TriggerSchedule {
		return archive.ClassDaily
	}
	now := m.now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if n, err := m.q.CountOKRunsInClassSince(ctx, dbq.CountOKRunsInClassSinceParams{Label: label, Kind: kind, Class: archive.ClassMonthly, StartedAt: month.Unix()}); err == nil && n == 0 {
		return archive.ClassMonthly
	}
	wd := (int(now.Weekday()) + 6) % 7 // Monday = 0
	week := time.Date(now.Year(), now.Month(), now.Day()-wd, 0, 0, 0, 0, time.UTC)
	nm, _ := m.q.CountOKRunsInClassSince(ctx, dbq.CountOKRunsInClassSinceParams{Label: label, Kind: kind, Class: archive.ClassMonthly, StartedAt: week.Unix()})
	nw, _ := m.q.CountOKRunsInClassSince(ctx, dbq.CountOKRunsInClassSinceParams{Label: label, Kind: kind, Class: archive.ClassWeekly, StartedAt: week.Unix()})
	if nm+nw == 0 {
		return archive.ClassWeekly
	}
	return archive.ClassDaily
}

// sizeWarning flags a backup that shrank or grew strangely compared with
// the previous good one (docs/09: deleted data, or data encrypted by
// ransomware).
func sizeWarning(prev dbq.BackupRun, size int64, rows int64) string {
	if prev.ID == "" || prev.SizeBytes <= 0 {
		return ""
	}
	switch {
	case size*2 < prev.SizeBytes:
		return "shrank"
	case size > prev.SizeBytes*3 && size-prev.SizeBytes > 10<<20:
		return "grew"
	}
	var pc Check
	if json.Unmarshal([]byte(prev.CheckJson), &pc) == nil && pc.Rows > 1000 && rows*2 < pc.Rows {
		return "rows_dropped"
	}
	return ""
}

// startRun records a run in progress.
func (m *Manager) startRun(ctx context.Context, a Actor, serviceID, label, kind, trigger, class string) (string, error) {
	id := ids.New("bkp_")
	err := m.q.CreateBackupRun(ctx, dbq.CreateBackupRunParams{
		ID: id, ServiceID: nullStr(serviceID), Label: label, Kind: kind, Trigger: trigger, Class: class,
		CreatedBy: nullStr(a.UserID), StartedAt: m.now().Unix(),
	})
	return id, err
}

type runResult struct {
	key      string
	size     int64
	sha      string
	verified bool
	check    any
	uploads  []upload
	warning  string
}

func (m *Manager) finishRun(ctx context.Context, id string, res runResult, err error) {
	status, errText := "ok", sql.NullString{}
	if err != nil {
		status = "failed"
		errText = sql.NullString{String: truncate(err.Error(), 2000), Valid: true}
	}
	cj, _ := json.Marshal(res.check)
	if res.check == nil {
		cj = []byte("{}")
	}
	uj, _ := json.Marshal(res.uploads)
	if res.uploads == nil {
		uj = []byte("[]")
	}
	verified := int64(0)
	if res.verified {
		verified = 1
	}
	if ferr := m.q.FinishBackupRun(context.WithoutCancel(ctx), dbq.FinishBackupRunParams{
		Status: status, ObjectKey: res.key, SizeBytes: res.size, Sha256: res.sha, Verified: verified,
		CheckJson: string(cj), UploadsJson: string(uj), Warning: res.warning, Error: errText,
		FinishedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: id,
	}); ferr != nil {
		m.log.Error("record backup end", "run", id, "error", ferr)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// backupDump is a full logical backup: dump, test restore, encrypt,
// upload to every destination, check each copy.
func (m *Manager) backupDump(ctx context.Context, a Actor, s svcRef, trigger string) (string, error) {
	unlock := m.lock(s.label())
	defer unlock()
	ts, err := m.targets(ctx)
	if err != nil {
		return "", err
	}
	class := m.class(ctx, s.label(), archive.KindDump, trigger)
	runID, err := m.startRun(ctx, a, s.ID, s.label(), archive.KindDump, trigger, class)
	if err != nil {
		return "", err
	}
	res := runResult{}
	err = func() error {
		d, err := m.dumpAndVerify(ctx, s)
		if err != nil {
			return err
		}
		defer d.remove()
		sf, check := d.dump, d.check
		res.verified, res.check, res.size, res.sha = true, check, sf.size.n, sf.hexSum()
		prev, _ := m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: s.label(), Kind: archive.KindDump})
		res.warning = sizeWarning(prev, res.size, check.Rows)
		key := archive.DumpKey(class, s.Project, s.Service, m.now())
		// The roles go first: a dump in the bucket always has its roles
		// next to it (only dumps made before them lack them).
		if _, err := m.sendFile(ctx, ts, archive.RolesKey(key), archive.FolderOf(class), d.roles.f, d.roles.size.n, d.roles.hexSum(), s.meta(archive.KindRoles)); err != nil {
			return fmt.Errorf("roles: %w", err)
		}
		res.key = key
		res.uploads, err = m.sendFile(ctx, ts, res.key, archive.FolderOf(class), sf.f, res.size, res.sha, s.meta(archive.KindDump))
		return err
	}()
	m.finishRun(ctx, runID, res, err)
	m.record(ctx, a, "backup.run", "service", s.ID, outcomeOf(err), map[string]any{
		"service": s.label(), "kind": archive.KindDump, "trigger": trigger, "run": runID, "size": res.size, "warning": res.warning,
	})
	if err != nil {
		m.log.Warn("backup failed", "service", s.label(), "kind", archive.KindDump, "error", err)
	}
	return runID, err
}
