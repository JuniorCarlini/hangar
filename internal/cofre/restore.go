package cofre

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgroles"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// DefaultImage is used when a backup does not say which image made it.
// It receives the decrypted dump, so it is pinned by digest (the
// multi-arch index of the tag beside it). To update: docker buildx
// imagetools inspect postgres:18-alpine.
const DefaultImage = "postgres:18-alpine@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5"

// dataMount is where the template mounts the data volume (PGDATA lives
// under it, as set by the image).
const dataMount = "/var/lib/postgresql"

// RestoreOptions is restore-local.
type RestoreOptions struct {
	Project, Service string
	// At is the moment to go back to (zero: the newest available).
	At time.Time
	// Dump restores the newest pg_dump (before At) instead of WAL.
	Dump bool
	Port int
}

// Restored says where the database came up.
type Restored struct {
	Container string
	Volume    string
	Image     string
	Port      int
	User      string
	DB        string
	Password  string // only for dump restores (a fresh cluster)
	Mode      string // "pitr" or "dump"
	Key       string // base or dump used
	Target    time.Time
	ToEnd     bool
	// Saved are the roles a dump restore recreated from the roles saved
	// with it, as they were (same passwords).
	Saved []string
	// Roles are the roles a dump restore created without a password.
	Roles []string
}

func randSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ParseService accepts "project/service" and "project_service".
func ParseService(s string) (string, string, error) {
	for _, sep := range []string{"/", "_"} {
		if p, svc, ok := strings.Cut(s, sep); ok && p != "" && svc != "" {
			return p, svc, nil
		}
	}
	return "", "", fmt.Errorf("service %q: use project/service", s)
}

// hardened are the docker run flags of every container hangar-cofre puts
// a backup in. The data and the configuration come from the app, which
// owns its database's superuser (COPY ... TO PROGRAM, functions that run
// during a restore): whatever it planted runs inside the container, so the
// container gets only the capabilities the image's entrypoint needs to
// hand the data directory to the postgres user, no privilege escalation
// and a bound on processes. While a backup is restored the container also
// has no network at all (restoreFlags); only the finished database is
// published, on 127.0.0.1.
var hardened = []string{
	"--cap-drop", "ALL",
	"--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
	"--cap-add", "SETUID", "--cap-add", "SETGID",
	"--security-opt", "no-new-privileges",
	"--pids-limit", "512",
}

// restoreFlags are hardened plus no network: what a container gets while
// the backup's own commands and functions may run in it.
func restoreFlags() []string {
	return append([]string{"--network", "none"}, hardened...)
}

// RestoreLocal brings a backup up in the local Docker: point-in-time from
// a base backup and WAL when there is one (unless Dump), else the newest
// pg_dump. The backup is restored with no network (the app's settings
// that run commands neutralized for a point in time); only then, when Port
// is set, the database is started again listening on 127.0.0.1:Port.
func (v *Vault) RestoreLocal(ctx context.Context, o RestoreOptions) (Restored, error) {
	if len(v.ids) == 0 {
		return Restored{}, errors.New("no recovery kit loaded")
	}
	at := o.At
	if at.IsZero() {
		at = v.now()
	}
	if !o.Dump {
		objs, err := v.Src.List(ctx, archive.WALPrefix(o.Project, o.Service))
		if err != nil {
			return Restored{}, err
		}
		plan, err := archive.PlanRecovery(objs, at)
		switch {
		case err == nil:
			return v.restorePITR(ctx, o, plan)
		case !errors.Is(err, archive.ErrNoBase):
			return Restored{}, err
		}
		v.tr("cofre.no_wal_using_dump")
	}
	key, err := v.latestDump(ctx, o.Project, o.Service, at)
	if err != nil {
		return Restored{}, err
	}
	r, err := v.startDump(ctx, key, "hangar-cofre-"+o.Project+"-"+o.Service+"-"+randSuffix(), o.Port)
	if err != nil {
		return r, err
	}
	r.Target = at
	return r, nil
}

func (v *Vault) latestDump(ctx context.Context, project, service string, before time.Time) (string, error) {
	// The time in the name is when the dump was made; a synced copy's file
	// time only approximates the upload.
	var best archive.Object
	for _, folder := range []string{"diario", "semanal", "mensal"} {
		objs, err := v.Src.List(ctx, folder+"/"+project+"/"+service+"/")
		if err != nil {
			return "", err
		}
		for _, l := range objs {
			if p, ok := archive.ParseKey(l.Key); ok && p.Kind == archive.KindDump && !p.Time.After(before) && p.Time.After(best.Time) {
				best = p
			}
		}
	}
	if best.Key == "" {
		return "", fmt.Errorf("no pg_dump of %s/%s before %s", project, service, before.Format(time.RFC3339))
	}
	return best.Key, nil
}

// officialPostgres matches the Docker Official PostgreSQL images, the only
// ones hangar-cofre runs on a backup's word alone.
var officialPostgres = regexp.MustCompile(`^(docker\.io/)?(library/)?postgres:[0-9]+(\.[0-9]+)*(-(alpine[0-9.]*|bookworm|bullseye|trixie))?$`)

// image picks the image that will receive the decrypted backup. The
// backup's metadata names the image that made it, but metadata is not
// covered by the encryption: whoever can write the bucket (the server's own
// credential, if the server is broken into) could name an image of theirs
// and read the backup the moment it is restored here. So the metadata is
// only advice: the operator's -image wins, an official postgres image is
// accepted, anything else is refused with the flag that trusts it.
func (v *Vault) image(meta map[string]string) (string, error) {
	if v.Image != "" {
		return v.Image, nil
	}
	m := meta["hangar-image"]
	switch {
	case m == "":
		return DefaultImage, nil
	case officialPostgres.MatchString(m):
		return m, nil
	}
	return "", i18n.E("cofre.error.untrusted_image", "image", m)
}

func metaOr(meta map[string]string, key, def string) string {
	if v := meta[key]; v != "" {
		return v
	}
	return def
}

// opener adapts the source for archive.WriteRecoveryTar.
func (v *Vault) opener(ctx context.Context) archive.Opener {
	return func(key string) (io.ReadCloser, error) {
		rc, _, err := v.Src.Open(ctx, key)
		return rc, err
	}
}

func (v *Vault) restorePITR(ctx context.Context, o RestoreOptions, plan archive.Plan) (Restored, error) {
	rc, meta, err := v.Src.Open(ctx, plan.Base.Key)
	if err != nil {
		return Restored{}, err
	}
	_ = rc.Close()
	img, err := v.image(meta)
	if err != nil {
		return Restored{}, err
	}
	r := Restored{
		Mode: "pitr", Key: plan.Base.Key, Target: plan.Target, ToEnd: plan.ToEnd, Port: o.Port,
		Image: img, User: metaOr(meta, "hangar-db-user", "postgres"), DB: metaOr(meta, "hangar-db-name", "postgres"),
	}
	suffix := randSuffix()
	r.Volume = "hangar-cofre-" + o.Project + "-" + o.Service + "-" + suffix
	r.Container = r.Volume
	if err := v.Docker(ctx, nil, nil, "volume", "create", "--label", "hangar.cofre=true", r.Volume); err != nil {
		return r, err
	}
	v.tr("cofre.staging", "base", plan.Base.Key, "wal", len(plan.WAL))
	pr, pw := io.Pipe()
	go func() { _ = pw.CloseWithError(archive.WriteLocalRecoveryTar(pw, plan, v.opener(ctx), v.ids)) }()
	stage := append(append([]string{"run", "--rm", "-i"}, restoreFlags()...), "-v", r.Volume+":"+dataMount, "--entrypoint", "sh", r.Image, "-c", archive.StageScript)
	err = v.Docker(ctx, pr, nil, stage...)
	_ = pr.CloseWithError(err)
	if err != nil {
		return r, err
	}
	// Recovery replays the WAL with no network: a command the app's
	// configuration still managed to run would reach nothing.
	run := append(append([]string{"run", "-d", "--name", r.Container, "--label", "hangar.cofre=true"}, restoreFlags()...), "-v", r.Volume+":"+dataMount, r.Image)
	if err := v.Docker(ctx, nil, nil, run...); err != nil {
		return r, err
	}
	v.tr("cofre.recovering")
	if err := v.waitSQL(ctx, r, "select pg_is_in_recovery()", "f", time.Hour); err != nil {
		return r, err
	}
	_ = v.Docker(ctx, nil, nil, "exec", r.Container, "sh", "-c", `rm -rf "$PGDATA/`+archive.RestoreWALDir+`" "$PGDATA.before-restore"`)
	return r, v.publish(ctx, r, nil)
}

// publish starts the restored database again, on the same volume, now
// listening on 127.0.0.1:r.Port, once nothing of the backup is being
// restored any more. With no port it stays as it is, with no network.
func (v *Vault) publish(ctx context.Context, r Restored, env []string) error {
	if r.Port <= 0 {
		return nil
	}
	if err := v.Docker(ctx, nil, nil, "stop", "-t", "60", r.Container); err != nil {
		return err
	}
	if err := v.Docker(ctx, nil, nil, "rm", r.Container); err != nil {
		return err
	}
	args := append([]string{"run", "-d", "--name", r.Container, "--label", "hangar.cofre=true"}, hardened...)
	args = append(append(args, env...), "-v", r.Volume+":"+dataMount, "-p", "127.0.0.1:"+strconv.Itoa(r.Port)+":5432", r.Image)
	if err := v.Docker(ctx, nil, nil, args...); err != nil {
		return err
	}
	return v.waitSQL(ctx, r, "select 1", "1", 5*time.Minute)
}

// startDump starts a fresh PostgreSQL and restores a pg_dump into it, as
// the panel restores into a new service: the roles saved with the dump
// first (as they were, same passwords), then the data with its owners and
// permissions, then the database's settings and GRANTs. A dump saved
// without its roles restores as before (roles without a password, no
// owners).
func (v *Vault) startDump(ctx context.Context, key, name string, port int) (Restored, error) {
	rc, meta, err := v.Src.Open(ctx, key)
	if err != nil {
		return Restored{}, err
	}
	defer func() { _ = rc.Close() }()
	img, err := v.image(meta)
	if err != nil {
		return Restored{}, err
	}
	g, saved, err := v.loadRoles(ctx, key)
	if err != nil {
		return Restored{}, err
	}
	r := Restored{
		Mode: "dump", Key: key, Container: name, Volume: name, Port: port, Password: randSuffix() + randSuffix(),
		Image: img, User: metaOr(meta, "hangar-db-user", "postgres"), DB: metaOr(meta, "hangar-db-name", "postgres"),
	}
	if err := v.Docker(ctx, nil, nil, "volume", "create", "--label", "hangar.cofre=true", r.Volume); err != nil {
		return Restored{}, err
	}
	env := []string{"-e", "POSTGRES_USER=" + r.User, "-e", "POSTGRES_DB=" + r.DB, "-e", "POSTGRES_PASSWORD=" + r.Password}
	// The dump is restored as the superuser (owners, roles, the database's
	// settings need it), so its functions run with the superuser's
	// power while it loads: no network until it is in.
	args := append(append([]string{"run", "-d", "--name", name, "--label", "hangar.cofre=true"}, restoreFlags()...), env...)
	if err := v.Docker(ctx, nil, nil, append(args, "-v", r.Volume+":"+dataMount, r.Image)...); err != nil {
		return r, err
	}
	// The image's first start runs a temporary server on the socket only;
	// the real one answers "select 1" over TCP inside the container.
	if err := v.waitSQL(ctx, r, "select 1", "1", 5*time.Minute); err != nil {
		return r, err
	}
	if saved {
		if r.Saved, err = v.applyRoles(ctx, r, g); err != nil {
			return r, err
		}
	}
	schema, err := v.createRoles(ctx, key, r, saved)
	r.Roles = schema.Roles
	if err != nil {
		return r, err
	}
	plain, err := archive.Open(rc, v.ids, archive.DefaultLimits)
	if err != nil {
		return r, err
	}
	defer func() { _ = plain.Close() }()
	v.tr("cofre.restoring_dump", "key", key)
	restore := []string{"exec", "-i", name, "pg_restore", "-U", r.User, "-d", r.DB, "--exit-on-error"}
	if !saved {
		restore = append(restore, "--no-owner")
	}
	if err := v.Docker(ctx, plain, nil, restore...); err != nil {
		return r, err
	}
	if script := pgroles.DatabaseScript(schema.Database); saved && script != "" {
		if err := v.Docker(ctx, strings.NewReader(script), nil, "exec", "-i", name, "psql", "-qAtX", "-v", "ON_ERROR_STOP=1",
			"-v", "VERBOSITY=terse", "-v", pgroles.DatabaseVar+"="+r.DB, "-U", r.User, "-d", r.DB, "-f", "-"); err != nil {
			return r, fmt.Errorf("apply the database settings: %w", err)
		}
	}
	return r, v.publish(ctx, r, env)
}

// isNotFound reports an object or file that does not exist.
func isNotFound(err error) bool {
	return s3.IsNotFound(err) || errors.Is(err, fs.ErrNotExist)
}

// loadRoles reads the roles saved with the dump key (archive.RolesKey).
// ok is false when there are none (a dump made before they were saved).
func (v *Vault) loadRoles(ctx context.Context, key string) (pgroles.Globals, bool, error) {
	var g pgroles.Globals
	rk := archive.RolesKey(key)
	if rk == "" {
		return g, false, nil
	}
	rc, _, err := v.Src.Open(ctx, rk)
	if isNotFound(err) {
		return g, false, nil
	}
	if err != nil {
		return g, false, fmt.Errorf("read the roles of the backup: %w", err)
	}
	defer func() { _ = rc.Close() }()
	raw, err := readRoles(rc, v.ids)
	if err != nil {
		return g, false, err
	}
	g, err = pgroles.ParseGlobals(string(raw))
	return g, err == nil, err
}

// readRoles decrypts a roles file.
func readRoles(r io.Reader, ids []age.Identity) ([]byte, error) {
	plain, err := archive.Open(r, ids, archive.DefaultLimits)
	if err != nil {
		return nil, err
	}
	defer func() { _ = plain.Close() }()
	raw, err := io.ReadAll(io.LimitReader(plain, pgroles.MaxGlobals+1))
	if err == nil && len(raw) > pgroles.MaxGlobals {
		err = errors.New("the roles of the backup are too large")
	}
	return raw, err
}

// applyRoles recreates the saved roles the fresh PostgreSQL lacks, as
// they were (pgroles ApplyScript). Password hashes stay out of errors.
func (v *Vault) applyRoles(ctx context.Context, r Restored, g pgroles.Globals) ([]string, error) {
	script, err := g.ApplyScript()
	if err != nil || script == "" {
		return nil, err
	}
	var out bytes.Buffer
	if err := v.Docker(ctx, strings.NewReader(script), &out, "exec", "-i", r.Container, "psql", "-qAtX", "-v", "ON_ERROR_STOP=1",
		"-v", "VERBOSITY=terse", "-U", r.User, "-d", r.DB, "-f", "-"); err != nil {
		return nil, errors.New("recreate the roles of the backup: " + g.Redact(err.Error()))
	}
	return pgroles.ParseSaved(out.String()), nil
}

// createRoles creates in the fresh PostgreSQL the roles the dump's
// permissions (and, with owners, its owners) name that it still lacks,
// without a password, so the GRANTs, policies and ownership restore as
// they were (as the panel does). It returns them in Schema.Roles, with the
// database-level statements when owners is set.
func (v *Vault) createRoles(ctx context.Context, key string, r Restored, owners bool) (pgroles.Schema, error) {
	var none pgroles.Schema
	rc, _, err := v.Src.Open(ctx, key)
	if err != nil {
		return none, err
	}
	defer func() { _ = rc.Close() }()
	plain, err := archive.Open(rc, v.ids, archive.DefaultLimits)
	if err != nil {
		return none, err
	}
	defer func() { _ = plain.Close() }()
	create := ""
	if owners {
		create = "--create "
	}
	var schemaSQL bytes.Buffer
	if err := v.Docker(ctx, plain, &schemaSQL, "exec", "-i", r.Container, "sh", "-c", `pg_restore `+create+`--schema-only -f - ; s=$?; cat >/dev/null; exit $s`); err != nil {
		return none, fmt.Errorf("read the roles of the dump: %w", err)
	}
	schema, err := pgroles.ReadSchema(&schemaSQL, owners)
	if err != nil {
		return none, err
	}
	out := pgroles.Schema{Database: schema.Database}
	script, err := pgroles.CreateScript(schema.Roles)
	if err != nil || script == "" {
		return out, err
	}
	var res bytes.Buffer
	if err := v.Docker(ctx, strings.NewReader(script), &res, "exec", "-i", r.Container, "psql", "-qAtX", "-v", "ON_ERROR_STOP=1", "-U", r.User, "-d", r.DB, "-f", "-"); err != nil {
		return out, fmt.Errorf("create the roles of the dump: %w", err)
	}
	out.Roles = pgroles.ParseCreated(res.String())
	return out, nil
}

// waitSQL waits until query answers want inside the container.
func (v *Vault) waitSQL(ctx context.Context, r Restored, query, want string, timeout time.Duration) error {
	deadline := v.now().Add(timeout)
	for {
		var out bytes.Buffer
		err := v.Docker(ctx, nil, &out, "exec", r.Container, "psql", "-h", "127.0.0.1", "-AtX", "-U", r.User, "-d", r.DB, "-c", query)
		if err == nil && strings.TrimSpace(out.String()) == want {
			return nil
		}
		if v.now().After(deadline) {
			return fmt.Errorf("the database did not come up in time: %w", errors.Join(err, errors.New("timeout")))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// Remove deletes a container and volume made by restore-local or test.
func (v *Vault) Remove(ctx context.Context, r Restored) {
	if r.Container != "" {
		_ = v.Docker(context.WithoutCancel(ctx), nil, nil, "rm", "-f", "-v", r.Container)
	}
	if r.Volume != "" {
		_ = v.Docker(context.WithoutCancel(ctx), nil, nil, "volume", "rm", "-f", r.Volume)
	}
}

// --- the monthly drill -------------------------------------------------------------

// countQuery counts tables and rows of the restored database.
const countQuery = `select count(*) || '|' || coalesce(sum((xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', schemaname, relname), false, true, '')))[1]::text::bigint), 0) from pg_stat_user_tables`

// Result is one line of the drill.
type Result struct {
	Label  string
	Key    string
	OK     bool
	Tables int64
	Rows   int64
	Took   time.Duration
	Err    error
}

// Test is `hangar-cofre test` (docs/09 "simulado mensal"): the newest
// pg_dump of each service (or of only) is decrypted with the kit and
// restored into a throwaway local PostgreSQL, and the newest panel backup
// is decrypted and checked. Everything it starts is removed at the end.
func (v *Vault) Test(ctx context.Context, only string) ([]Result, error) {
	if len(v.ids) == 0 {
		return nil, errors.New("no recovery kit loaded")
	}
	objs, err := v.Src.List(ctx, "")
	if err != nil {
		return nil, err
	}
	newest := map[string]archive.Object{}
	var panel archive.Object
	for _, l := range objs {
		o, ok := archive.ParseKey(l.Key)
		if !ok {
			continue
		}
		switch o.Kind {
		case archive.KindDump:
			label := o.Project + "/" + o.Service
			if only != "" && only != label {
				continue
			}
			if o.Time.After(newest[label].Time) {
				newest[label] = o
			}
		case archive.KindPanel:
			if o.Time.After(panel.Time) {
				panel = o
			}
		}
	}
	labels := make([]string, 0, len(newest))
	for l := range newest {
		labels = append(labels, l)
	}
	sortStrings(labels)
	var out []Result
	for _, label := range labels {
		out = append(out, v.testDump(ctx, label, newest[label].Key))
	}
	if panel.Key != "" && only == "" {
		out = append(out, v.testPanel(ctx, panel.Key))
	}
	if len(out) == 0 {
		return nil, errors.New("no backup found to test")
	}
	return out, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (v *Vault) testDump(ctx context.Context, label, key string) Result {
	start := v.now()
	res := Result{Label: label, Key: key}
	v.tr("cofre.testing", "label", label, "key", key)
	r, err := v.startDump(ctx, key, "hangar-cofre-test-"+randSuffix(), 0)
	defer v.Remove(ctx, r)
	if err == nil {
		var out bytes.Buffer
		err = v.Docker(ctx, nil, &out, "exec", r.Container, "psql", "-h", "127.0.0.1", "-AtX", "-U", r.User, "-d", r.DB, "-c", countQuery)
		if err == nil {
			t, rows, _ := strings.Cut(strings.TrimSpace(out.String()), "|")
			res.Tables, _ = strconv.ParseInt(t, 10, 64)
			res.Rows, _ = strconv.ParseInt(rows, 10, 64)
		}
	}
	res.OK, res.Err, res.Took = err == nil, err, v.now().Sub(start)
	return res
}

// testPanel decrypts the panel backup and checks it holds a SQLite
// database, the master key and the manifest.
func (v *Vault) testPanel(ctx context.Context, key string) Result {
	start := v.now()
	res := Result{Label: "painel", Key: key}
	err := func() error {
		rc, _, err := v.Src.Open(ctx, key)
		if err != nil {
			return err
		}
		defer func() { _ = rc.Close() }()
		plain, err := archive.Open(rc, v.ids, archive.DefaultLimits)
		if err != nil {
			return err
		}
		defer func() { _ = plain.Close() }()
		tr := tar.NewReader(plain)
		found := map[string]bool{}
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			head := make([]byte, 16)
			n, _ := io.ReadFull(tr, head)
			switch h.Name {
			case "hangar.db":
				found[h.Name] = bytes.HasPrefix(head[:n], []byte("SQLite format 3"))
				res.Rows = h.Size
			case "master.key":
				found[h.Name] = h.Size == 32
			case "manifest.json":
				found[h.Name] = true
			}
			res.Tables++
		}
		for _, name := range []string{"manifest.json", "hangar.db", "master.key"} {
			if !found[name] {
				return fmt.Errorf("%s missing or damaged", name)
			}
		}
		return nil
	}()
	res.OK, res.Err, res.Took = err == nil, err, v.now().Sub(start)
	return res
}
