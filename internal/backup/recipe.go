package backup

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
)

// Backups by a template's own recipe (docs/09, templates.Recipe): the
// template says how to dump its whole service (data, users, passwords,
// permissions) and how to load that into an empty instance; Hangar runs
// it like pg_dump. The dump runs in the service's container and streams
// through this process, which compresses and encrypts it into the staging
// dir and, at the same time, feeds it to a throwaway container of the
// service's image where an empty instance is started and the backup is
// restored into it. It is called tested only when that restore worked
// and the instance holds what the original holds (the recipe's verify on
// both). Plaintext never lands on disk, and the service keeps running.

// recipeTestScript runs in the throwaway container: it starts an empty
// instance in the background (serve), waits until it accepts the restore
// (ready, up to 10 minutes), says so on a line of its own, restores the
// backup read from standard input (restore) and prints what the instance
// then holds (verify). Each command is the template's, quoted (shellJoin):
// nothing a user types reaches it.
const recipeTestScript = `set -u
log=/tmp/hangar-serve.log
( exec @SERVE@ ) </dev/null >"$log" 2>&1 &
pid=$!
n=0
until ( @READY@ ) </dev/null >/dev/null 2>&1; do
  if ! kill -0 "$pid" 2>/dev/null; then echo "the empty instance did not start:" >&2; tail -n 15 "$log" >&2; exit 1; fi
  n=$((n+1))
  if [ "$n" -ge 600 ]; then echo "the empty instance was not ready in 10 minutes:" >&2; tail -n 15 "$log" >&2; exit 1; fi
  sleep 1
done
echo HANGAR-READY
if ! ( @RESTORE@ ) >&2; then
  echo "the restore into the empty instance failed" >&2
  cat >/dev/null
  exit 1
fi
cat >/dev/null
@VERIFY@
`

// shellJoin quotes args for sh: each in single quotes.
func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

// testScript is recipeTestScript for r.
func testScript(r *templates.Recipe) string {
	verify := "echo HANGAR-CHECK restored=1"
	if len(r.Verify) > 0 {
		verify = "( " + shellJoin(r.Verify) + " ) </dev/null"
	}
	return strings.NewReplacer(
		"@SERVE@", shellJoin(r.Serve), "@READY@", shellJoin(r.Ready),
		"@RESTORE@", shellJoin(r.Restore), "@VERIFY@", verify,
	).Replace(recipeTestScript)
}

// fingerprintRE is a verify line: HANGAR-CHECK name=number ...
var fingerprintRE = regexp.MustCompile(`(?m)^HANGAR-CHECK((?: [a-z][a-z0-9_]{0,31}=[0-9]{1,19})+)\s*$`)

// parseFingerprint reads the last HANGAR-CHECK line of out.
func parseFingerprint(out string) (map[string]int64, bool) {
	all := fingerprintRE.FindAllStringSubmatch(out, -1)
	if len(all) == 0 {
		return nil, false
	}
	fp := map[string]int64{}
	for _, f := range strings.Fields(all[len(all)-1][1]) {
		k, v, _ := strings.Cut(f, "=")
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, false
		}
		fp[k] = n
	}
	return fp, true
}

// RecipeCheck is what the test of a recipe's backup found
// (backup_runs.check_json).
type RecipeCheck struct {
	// Source is what the recipe's verify counted in the service just
	// before the dump; Restored, in the throwaway instance the backup
	// was restored into.
	Source   map[string]int64 `json:"source,omitempty"`
	Restored map[string]int64 `json:"restored"`
	// Bytes is the backup's size before compression.
	Bytes int64 `json:"bytes"`
}

// compare refuses a test copy that lost what the original had: a count
// the original has that the copy lacks, or that is zero in the copy and
// not in the original (a restore that loaded nothing). Counts may differ
// otherwise: the service kept working during the dump.
func (c RecipeCheck) compare() error {
	if len(c.Restored) == 0 {
		return errors.New("the test restore did not report what it holds")
	}
	var lost []string
	for k, v := range c.Source {
		got, ok := c.Restored[k]
		if !ok || (v > 0 && got == 0) {
			lost = append(lost, fmt.Sprintf("%s %d -> %d", k, v, got))
		}
	}
	if len(lost) > 0 {
		sort.Strings(lost)
		return fmt.Errorf("the test restore lost what the service holds: %s", strings.Join(lost, ", "))
	}
	return nil
}

// Counts lists the counts of the test copy in name order, for the UI.
func (c RecipeCheck) Counts() []Count {
	out := make([]Count, 0, len(c.Restored))
	for k, v := range c.Restored {
		out = append(out, Count{Name: k, N: v})
	}
	slices.SortFunc(out, func(a, b Count) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Count is one number of a recipe's verify.
type Count struct {
	Name string
	N    int64
}

// secretRE finds what a database may quote back in an error: a password
// or its hash in a CREATE USER, GRANT or SET PASSWORD.
var secretRE = regexp.MustCompile(`(?i)((?:password|identified(?: with \S+)?(?: by| as| via \S+ using))\s*(?:\(\s*)?)('(?:[^'\\]|\\.|'')*'|"(?:[^"\\]|\\.)*"|0x[0-9a-f]+|\*[0-9a-f]{40})`)

// redactSecrets hides passwords and hashes in s (errors and logs).
func redactSecrets(s string) string { return secretRE.ReplaceAllString(s, "$1'…'") }

// recipeEnv are the service's variables the throwaway instance gets (the
// recipe's env, by name). Their values never reach a log.
func (m *Manager) recipeEnv(ctx context.Context, s svcRef) (map[string]string, error) {
	if len(s.Recipe.Env) == 0 {
		return nil, nil
	}
	vars, err := m.projects.ListEnvValues(ctx, s.ID)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, v := range vars {
		if slices.Contains(s.Recipe.Env, v.Key) {
			env[v.Key] = v.Value
		}
	}
	return env, nil
}

// scratchPath is where the throwaway instance keeps its data: the path of
// the service's first volume (so the image's VOLUME is a scratch volume
// that goes away with it), else /scratch.
func (s svcRef) scratchPath() string {
	if len(s.Vols) > 0 {
		return s.Vols[0].Path
	}
	return "/scratch"
}

// verifyService runs the recipe's verify in the service; nil when it has
// none or it failed (the test then only checks the copy is not empty).
func (m *Manager) verifyService(ctx context.Context, n node.Node, s svcRef) map[string]int64 {
	if len(s.Recipe.Verify) == 0 {
		return nil
	}
	out := &tailBuffer{max: 16 << 10}
	if err := n.Exec(ctx, s.Project, s.Service, s.Recipe.Verify, out); err != nil {
		m.log.Warn("count what the service holds before its backup", "service", s.label(), "error", redactSecrets(err.Error()))
		return nil
	}
	fp, _ := parseFingerprint(out.String())
	return fp
}

// dumpAndTest runs s's recipe: the throwaway instance first (the dump
// waits for it, so a slow start never holds the service's dump open), then
// the dump in the service, streamed to sink and to the test restore at
// once. sink is the caller's.
func (m *Manager) dumpAndTest(ctx context.Context, s svcRef, sink io.Writer) (RecipeCheck, error) {
	var c RecipeCheck
	if s.Recipe == nil {
		return c, ErrUnsupported
	}
	n, tk, err := m.tasker()
	if err != nil {
		return c, err
	}
	env, err := m.recipeEnv(ctx, s)
	if err != nil {
		return c, err
	}
	c.Source = m.verifyService(ctx, n, s)
	image := s.Recipe.Image
	if image == "" {
		image = s.Image
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	t := startTask(ctx, tk, node.TaskSpec{
		Image: image, Cmd: []string{"sh", "-c", testScript(s.Recipe)}, Env: env, Scratch: s.scratchPath(),
		MemoryBytes: max(s.Memory, 512<<20), NanoCPUs: 2e9, PidsLimit: 512,
	})
	if _, err := t.line("HANGAR-READY"); err != nil {
		return c, fmt.Errorf("test instance: %s", redactSecrets(errors.Join(err, t.stop(cancel)).Error()))
	}
	var plain counter
	derr := n.Exec(ctx, s.Project, s.Service, s.Recipe.Dump, io.MultiWriter(t.in, sink, &plain))
	_ = t.in.CloseWithError(derr)
	out := &tailBuffer{max: 16 << 10}
	_, _ = io.Copy(out, t.out)
	terr := <-t.done
	switch {
	case derr != nil && terr == nil:
		return c, fmt.Errorf("dump: %s", redactSecrets(derr.Error()))
	case terr != nil && derr != nil && !errors.Is(derr, errTaskEnded):
		return c, fmt.Errorf("dump: %s; test restore: %s", redactSecrets(derr.Error()), redactSecrets(terr.Error()))
	case terr != nil:
		return c, fmt.Errorf("test restore: %s", redactSecrets(terr.Error()))
	}
	c.Bytes = plain.n
	if plain.n == 0 {
		return c, errors.New("the dump wrote nothing")
	}
	fp, ok := parseFingerprint(out.String())
	if !ok {
		return c, fmt.Errorf("the test restore did not report what it holds: %q", truncate(strings.TrimSpace(out.String()), 300))
	}
	c.Restored = fp
	return c, c.compare()
}

// archiveRecipe makes a tested, encrypted backup of s by its recipe in a
// staging file.
func (m *Manager) archiveRecipe(ctx context.Context, s svcRef) (*sealedFile, RecipeCheck, error) {
	var c RecipeCheck
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return nil, c, err
	}
	if err := m.checkRoom(s); err != nil {
		return nil, c, err
	}
	f, err := m.stagingFile("native-*.age")
	if err != nil {
		return nil, c, err
	}
	sf := &sealedFile{f: f, sha: sha256.New()}
	ok := false
	defer func() {
		if !ok {
			removeFile(f)
		}
	}()
	sealer, err := archive.Seal(io.MultiWriter(&roomWriter{w: f, dir: m.opt.StagingDir}, sf.sha, &sf.size), rcpts, true)
	if err != nil {
		return nil, c, err
	}
	if c, err = m.dumpAndTest(ctx, s, sealer); err != nil {
		return nil, c, err
	}
	if err := sealer.Close(); err != nil {
		return nil, c, err
	}
	if err := f.Sync(); err != nil {
		return nil, c, err
	}
	ok = true
	return sf, c, nil
}

// backupRecipe is a full backup of s by its template's recipe: dump, test
// restore, encrypt, upload to every destination, check each copy. The
// service keeps running.
func (m *Manager) backupRecipe(ctx context.Context, a Actor, s svcRef, trigger string) (string, error) {
	unlock := m.lock(s.label())
	defer unlock()
	ts, err := m.targets(ctx)
	if err != nil {
		return "", err
	}
	class := m.class(ctx, s.label(), archive.KindRecipe, trigger)
	runID, err := m.startRun(ctx, a, s.ID, s.label(), archive.KindRecipe, trigger, class)
	if err != nil {
		return "", err
	}
	res := runResult{}
	err = func() error {
		sf, check, err := m.archiveRecipe(ctx, s)
		res.check = check
		if err != nil {
			return err
		}
		defer removeFile(sf.f)
		res.verified, res.size, res.sha = true, sf.size.n, sf.hexSum()
		prev, _ := m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: s.label(), Kind: archive.KindRecipe})
		res.warning = sizeWarning(prev, res.size, 0)
		res.key = archive.RecipeKey(class, s.Project, s.Service, m.now())
		res.uploads, err = m.sendFile(ctx, ts, res.key, archive.FolderOf(class), sf.f, res.size, res.sha, s.meta(archive.KindRecipe))
		return err
	}()
	m.finishRun(ctx, runID, res, err)
	m.record(ctx, a, "backup.run", "service", s.ID, outcomeOf(err), map[string]any{
		"service": s.label(), "kind": archive.KindRecipe, "trigger": trigger, "run": runID, "size": res.size, "warning": res.warning,
	})
	if err != nil {
		m.log.Warn("backup failed", "service", s.label(), "kind", archive.KindRecipe, "error", err)
	}
	return runID, err
}

// --- restore ---------------------------------------------------------------------

// waitRecipeReady waits until t accepts a restore (the recipe's ready).
func (m *Manager) waitRecipeReady(ctx context.Context, t svcRef, timeout time.Duration) error {
	n, _, err := m.tasker()
	if err != nil {
		return err
	}
	deadline := m.now().Add(timeout)
	for {
		if err := n.Exec(ctx, t.Project, t.Service, t.Recipe.Ready, io.Discard); err == nil {
			return nil
		}
		if m.now().After(deadline) {
			return errors.New("the service did not accept the restore in time")
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

// restoreRecipe loads the backup key into t, a running instance with no
// data of its own (a new service, or t after emptyAndStart), with the
// recipe's restore, and logs what t then holds.
func (m *Manager) restoreRecipe(ctx context.Context, id string, t svcRef, key string, ids []age.Identity) error {
	n, tk, err := m.tasker()
	if err != nil {
		return err
	}
	if t.Recipe == nil {
		return ErrUnsupported
	}
	m.step(ctx, id, "restore")
	if err := m.waitRecipeReady(ctx, t, 5*time.Minute); err != nil {
		return err
	}
	rc, _, err := m.fetch(ctx, key)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	plain, err := archive.Open(rc, ids, archive.LimitsFor(key))
	if err != nil {
		return err
	}
	defer func() { _ = plain.Close() }()
	if err := tk.ExecIO(ctx, t.Project, t.Service, t.Recipe.Restore, plain, io.Discard); err != nil {
		return fmt.Errorf("restore: %s", redactSecrets(err.Error()))
	}
	if fp := m.verifyService(ctx, n, t); fp != nil {
		m.log.Info("service restored", "service", t.label(), "holds", fp)
	}
	m.step(ctx, id, "done")
	return nil
}

// wipeScript empties each volume named (mounted under /v).
const wipeScript = `set -eu
cd /v
for v in "$@"; do find "$v" -mindepth 1 -delete; done
`

// emptyAndStart turns t into an empty instance: everything that uses its
// volumes stops, the volumes are emptied, and t is deployed again (its
// image sets up a new, empty server from the service's variables) with
// the others started after it. changed says the volumes were touched.
func (m *Manager) emptyAndStart(ctx context.Context, a Actor, id string, t svcRef) (changed bool, err error) {
	n, tk, err := m.tasker()
	if err != nil {
		return false, err
	}
	m.step(ctx, id, "stop_service")
	var stopped []string
	for _, u := range t.volumeUsers() {
		if st, err := m.projects.Status(ctx, t.Project, u); err == nil && st.Running {
			if err := n.Stop(ctx, t.Project, u); err != nil {
				return false, fmt.Errorf("stop %s: %w", u, err)
			}
			stopped = append(stopped, u)
		}
	}
	defer func() {
		bg := context.WithoutCancel(ctx)
		for _, u := range stopped {
			if u != t.Service {
				_ = n.Start(bg, t.Project, u)
			}
		}
	}()
	if names := t.volNames(); len(names) > 0 {
		changed = true
		if err := tk.RunTask(ctx, volumeSpec(t, wipeScript, false, names, nil), nil, io.Discard); err != nil {
			return true, fmt.Errorf("empty the volumes: %w", err)
		}
	}
	m.step(ctx, id, "deploy")
	return changed, m.deployAndWait(ctx, a, t, "restore")
}

// runRecipeRestore is runRestore for a service backed up by its recipe.
// Into a new service: a copy of it (its variables, so the same root
// password) is created with the original's disk sizes, deployed empty,
// then the backup is loaded. Overwriting first backs up the current
// state, then empties the service and loads the backup; if that fails
// once the service was touched, the backup made just before goes back
// the same way.
func (m *Manager) runRecipeRestore(ctx context.Context, a Actor, id string, s svcRef, req RestoreRequest) (err error) {
	if req.Destination == DestOverwrite {
		m.step(ctx, id, "pre_backup")
		runID, err := m.backupRecipe(ctx, a, s, TriggerPreRestore)
		if err != nil {
			return fmt.Errorf("backup of the current state failed, nothing was changed: %w", err)
		}
		pre, err := m.q.GetBackupRun(ctx, runID)
		if err != nil {
			return err
		}
		replace := func(key string) (bool, error) {
			changed, err := m.emptyAndStart(ctx, a, id, s)
			if err != nil {
				return changed, err
			}
			return true, m.restoreRecipe(ctx, id, s, key, req.Identities)
		}
		changed, rerr := replace(req.Key)
		if rerr == nil || !changed {
			return rerr
		}
		m.step(ctx, id, "rollback")
		if _, berr := replace(pre.ObjectKey); berr != nil {
			return fmt.Errorf("%w; putting back the backup made just before (%s) also failed: %w", rerr, pre.ObjectKey, berr)
		}
		return fmt.Errorf("%w; the service is back as it was before the restore", rerr)
	}
	m.step(ctx, id, "create")
	c, err := m.projects.CloneService(ctx, a, s.Project, s.Service, req.NewService)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			m.dropNewService(ctx, a, id, s, c.Slug)
		}
	}()
	m.copyLimits(ctx, a, s, c.Slug)
	t, err := m.ref(ctx, s.Project, c.Slug)
	if err != nil {
		return err
	}
	m.step(ctx, id, "deploy")
	if err := m.deployAndWait(ctx, a, t, "create"); err != nil {
		return err
	}
	return m.restoreRecipe(ctx, id, t, req.Key, req.Identities)
}

// recoverRecipe brings back s, just deployed empty on a new server, from
// its newest recipe backup made up to at.
func (m *Manager) recoverRecipe(ctx context.Context, s svcRef, at time.Time, ids []age.Identity) error {
	points, err := m.Dumps(ctx, s.Project, s.Service)
	if err != nil {
		return err
	}
	for _, p := range points { // newest first
		if o, ok := archive.ParseKey(p.Key); ok && o.Kind == archive.KindRecipe && !p.LastModified.After(at) && m.vouched(ctx, p.Key) {
			return m.restoreRecipe(ctx, "", s, p.Key, ids)
		}
	}
	return errNoVolumeBackup
}

// tailBuffer keeps the last max bytes written to it and never refuses a
// write, so whoever writes is never blocked.
type tailBuffer struct {
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = append(t.b[:0], t.b[len(t.b)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.b) }

// recipeCheckOf reads a run's check (nil for another kind).
func recipeCheckOf(r dbq.BackupRun) *RecipeCheck {
	if r.Kind != archive.KindRecipe {
		return nil
	}
	var c RecipeCheck
	if json.Unmarshal([]byte(r.CheckJson), &c) != nil {
		return nil
	}
	return &c
}
