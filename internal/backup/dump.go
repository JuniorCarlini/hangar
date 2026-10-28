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

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgroles"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
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
}

// meta is the object metadata of a service backup.
func (s svcRef) meta(kind string) map[string]string {
	return map[string]string{
		"hangar-kind": kind, "hangar-service": s.label(), "hangar-image": s.Image,
		"hangar-db-user": s.DBUser, "hangar-db-name": s.DBName,
	}
}

func (s svcRef) label() string { return s.Project + "/" + s.Service }

// pgDumpCmd runs inside the service container; the credentials come from
// its own environment, never from a command line.
var pgDumpCmd = []string{"sh", "-c", `exec pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"`}

// verifyScript restores the dump read from stdin into a throwaway
// PostgreSQL (same image, no network, scratch volume) and counts what came
// back. It is a constant: nothing from the user reaches it.
//
// The dump is restored with its permissions, as a real restore does. The
// roles they name are not in a pg_dump, so a schema-only rehearsal finds,
// from PostgreSQL's own errors, each role the restore needs and creates it
// (NOLOGIN, as the real restore does) before the real attempt. It prints
// the roles it had to create (HANGAR-ROLE, hex) and the dump's ACL, POLICY
// and DEFAULT ACL entries (HANGAR-ACL, hex), so the panel can check that
// the real restore would find those same roles by reading the dump.
const verifyScript = `set -eu
umask 077
cat > /scratch/dump
if command -v su-exec >/dev/null 2>&1; then AS="su-exec postgres"; else AS="gosu postgres"; fi
mkdir -p /scratch/pgdata /scratch/run
chown postgres:postgres /scratch/pgdata /scratch/run /scratch/dump
$AS initdb -D /scratch/pgdata -U postgres --auth=trust -E UTF8 >/dev/null
$AS pg_ctl -D /scratch/pgdata -o "-c listen_addresses= -c unix_socket_directories=/scratch/run -c fsync=off -c lc_messages=C" -w -t 300 start >/dev/null
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
until $AS pg_restore -h /scratch/run -U postgres -d hangar_roles --schema-only --no-owner --single-transaction --exit-on-error /scratch/dump 2>/scratch/run/err; do
  role=$(sed -n 's/^.*ERROR:  role "\(.*\)" does not exist$/\1/p' /scratch/run/err | head -n 1)
  if [ -z "$role" ] || [ "$n" -ge 200 ]; then cat /scratch/run/err >&2; exit 1; fi
  printf 'CREATE ROLE :"r" NOLOGIN;\n' | $AS psql -h /scratch/run -U postgres -d postgres -qAtX -v ON_ERROR_STOP=1 -v r="$role" -f - >/dev/null
  printf 'HANGAR-ROLE %s\n' "$(printf '%s' "$role" | od -An -tx1 | tr -d ' \n')"
  n=$((n+1))
done
$AS dropdb -h /scratch/run -U postgres hangar_roles
$AS pg_restore -h /scratch/run -U postgres -d postgres --no-owner --exit-on-error /scratch/dump
counts=$($AS psql -h /scratch/run -U postgres -d postgres -AtX -v ON_ERROR_STOP=1 -c "select count(*), coalesce(sum((xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', schemaname, relname), false, true, '')))[1]::text::bigint), 0) from pg_stat_user_tables")
echo "HANGAR-CHECK tables=$tables restored=${counts%%|*} rows=${counts##*|}"
$AS pg_ctl -D /scratch/pgdata -m immediate stop >/dev/null
`

var (
	checkRE = regexp.MustCompile(`(?m)^HANGAR-CHECK tables=(\d+) restored=(\d+) rows=(\d+)\s*$`)
	aclRE   = regexp.MustCompile(`(?m)^HANGAR-ACL ([0-9a-f]*)\s*$`)
	roleRE  = regexp.MustCompile(`(?m)^HANGAR-ROLE ([0-9a-f]+)\s*$`)
)

// Check is what the test restore found.
type Check struct {
	Tables   int64 `json:"tables"`   // tables with data in the dump
	Restored int64 `json:"restored"` // tables in the throwaway database
	Rows     int64 `json:"rows"`
	Bytes    int64 `json:"bytes"` // dump size before encryption
	// Roles are the roles the dump refers to that a fresh PostgreSQL
	// lacks: a restore creates them without a password.
	Roles []string `json:"roles,omitempty"`
}

func parseCheck(out string) (Check, error) {
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
	roles, err := checkRoles(out)
	c.Roles = roles
	return c, err
}

// checkRoles compares the roles the test restore needed (PostgreSQL said
// which) with the ones a real restore finds by reading the dump's
// permissions (pgroles): a role only the first knows would make the real
// restore fail, so the backup is not called tested.
func checkRoles(out string) ([]string, error) {
	var needed []string
	for _, m := range roleRE.FindAllStringSubmatch(out, -1) {
		if b, err := hex.DecodeString(m[1]); err == nil {
			needed = append(needed, string(b))
		}
	}
	if len(needed) == 0 {
		return nil, nil
	}
	var found []string
	if m := aclRE.FindStringSubmatch(out); m != nil {
		sql, err := hex.DecodeString(m[1])
		if err != nil {
			return needed, fmt.Errorf("the test restore sent unreadable permissions: %w", err)
		}
		if found, err = pgroles.FromScript(bytes.NewReader(sql)); err != nil {
			return needed, err
		}
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

// dumpAndVerify runs pg_dump, feeds the stream to the test restore and,
// at the same time, encrypts it into a staging file. Plaintext only ever
// exists inside the database container and the throwaway one.
func (m *Manager) dumpAndVerify(ctx context.Context, s svcRef) (*sealedFile, Check, error) {
	n, tk, err := m.tasker()
	if err != nil {
		return nil, Check{}, err
	}
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return nil, Check{}, err
	}
	f, err := m.stagingFile("dump-*.age")
	if err != nil {
		return nil, Check{}, err
	}
	sf := &sealedFile{f: f, sha: sha256.New()}
	ok := false
	defer func() {
		if !ok {
			removeFile(f)
		}
	}()
	sealer, err := archive.Seal(io.MultiWriter(f, sf.sha, &sf.size), rcpts, false)
	if err != nil {
		return nil, Check{}, err
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
	derr := n.Exec(ctx, s.Project, s.Service, pgDumpCmd, io.MultiWriter(pw, sealer, &plain))
	_ = pw.Close()
	terr := <-taskErr
	switch {
	case derr != nil && terr != nil && !strings.Contains(derr.Error(), "test restore ended"):
		return nil, Check{}, fmt.Errorf("pg_dump: %w", derr)
	case terr != nil:
		return nil, Check{}, fmt.Errorf("test restore: %w", terr)
	case derr != nil:
		return nil, Check{}, fmt.Errorf("pg_dump: %w", derr)
	}
	check, err := parseCheck(taskOut.String())
	if err != nil {
		return nil, check, err
	}
	check.Bytes = plain.n
	if err := sealer.Close(); err != nil {
		return nil, check, err
	}
	if err := f.Sync(); err != nil {
		return nil, check, err
	}
	ok = true
	return sf, check, nil
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
		sf, check, err := m.dumpAndVerify(ctx, s)
		if err != nil {
			return err
		}
		defer removeFile(sf.f)
		res.verified, res.check, res.size, res.sha = true, check, sf.size.n, sf.hexSum()
		prev, _ := m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: s.label(), Kind: archive.KindDump})
		res.warning = sizeWarning(prev, res.size, check.Rows)
		res.key = archive.DumpKey(class, s.Project, s.Service, m.now())
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
