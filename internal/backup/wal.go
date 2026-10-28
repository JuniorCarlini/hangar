package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgwal"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// walBatch caps how many WAL files one pass sends, so one busy database
// does not starve the others.
const walBatch = 32

// maxWALFile bounds what is read from the outbox (segments are 16 MiB by
// default; clusters may use up to 1 GiB, which this refuses).
const maxWALFile = archive.MaxWALFile

// archiverState reads pg_stat_archiver: archive_mode and whether
// archive_command is failing.
var archiverQuery = []string{"sh", "-c", `exec psql -AtX -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select current_setting('archive_mode'), failed_count, coalesce(extract(epoch from last_failed_time)::bigint, 0), coalesce(extract(epoch from last_archived_time)::bigint, 0) from pg_stat_archiver"`}

// WAL problems shown in the UI (wal_status.last_error keeps these codes or
// an upload error).
const (
	WALRestartNeeded = "restart_needed"
	WALArchiveFails  = "archive_failing"
)

// shipWAL moves finished WAL files from the service's outbox to every
// destination, oldest first, and deletes each one from the outbox only
// after all destinations confirmed it.
func (m *Manager) shipWAL(ctx context.Context, s svcRef) error {
	n, _, err := m.tasker()
	if err != nil {
		return err
	}
	status := dbq.UpsertWALStatusParams{ServiceID: s.ID, CheckedAt: m.now().Unix()}
	if old, err := m.q.GetWALStatus(ctx, s.ID); err == nil {
		status.LastArchivedWal, status.LastArchivedAt = old.LastArchivedWal, old.LastArchivedAt
	}
	defer func() { _ = m.q.UpsertWALStatus(context.WithoutCancel(ctx), status) }()

	var st bytes.Buffer
	if err := n.Exec(ctx, s.Project, s.Service, archiverQuery, &st); err != nil {
		status.LastError = "psql: " + truncate(err.Error(), 300)
		return err
	}
	fields := strings.Split(strings.TrimSpace(st.String()), "|")
	if len(fields) == 4 && fields[0] != "on" {
		status.LastError = WALRestartNeeded
		return nil
	}
	if len(fields) == 4 && atoi(fields[2]) > atoi(fields[3]) {
		status.LastError = WALArchiveFails
	}

	dir := pgwal.Quote(pgwal.Outbox(s.DataPath))
	var ls bytes.Buffer
	if err := n.Exec(ctx, s.Project, s.Service, []string{"sh", "-c", "[ -d " + dir + " ] || exit 0; cd " + dir + " && ls -1"}, &ls); err != nil {
		status.LastError = "ls: " + truncate(err.Error(), 300)
		return err
	}
	var names []string
	for _, name := range strings.Fields(ls.String()) {
		if archive.WALNameRE.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	now := m.now()
	m.walMu.Lock()
	for _, name := range names {
		if _, ok := m.walSeen[s.ID+"/"+name]; !ok {
			m.walSeen[s.ID+"/"+name] = now
		}
	}
	m.walMu.Unlock()
	status.Pending = int64(len(names))
	if len(names) > 0 {
		status.OldestPendingAt = sql.NullInt64{Int64: m.firstSeen(s.ID, names[0]).Unix(), Valid: true}
	}
	if len(names) == 0 {
		return nil
	}
	ts, err := m.targets(ctx)
	if err != nil {
		return err
	}
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return err
	}
	for i, name := range names {
		if i >= walBatch {
			break
		}
		var raw bytes.Buffer
		if err := n.Exec(ctx, s.Project, s.Service, []string{"cat", dir + "/" + name}, &limitWriter{w: &raw, n: maxWALFile}); err != nil {
			status.LastError = "read " + name + ": " + truncate(err.Error(), 300)
			return err
		}
		var sealed bytes.Buffer
		w, err := archive.Seal(&sealed, rcpts, true)
		if err != nil {
			return err
		}
		if _, err := w.Write(raw.Bytes()); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		sum := sha256.Sum256(sealed.Bytes())
		key := archive.WALKey(s.Project, s.Service, name)
		if _, err := m.sendFile(ctx, ts, key, "wal", bytes.NewReader(sealed.Bytes()), int64(sealed.Len()), hex.EncodeToString(sum[:]),
			s.meta(archive.KindWAL)); err != nil {
			status.LastError = "upload " + name + ": " + truncate(err.Error(), 300)
			return err
		}
		if err := n.Exec(ctx, s.Project, s.Service, []string{"rm", "-f", dir + "/" + name}, io.Discard); err != nil {
			status.LastError = "remove " + name + ": " + truncate(err.Error(), 300)
			return err
		}
		m.walMu.Lock()
		delete(m.walSeen, s.ID+"/"+name)
		m.walMu.Unlock()
		status.LastArchivedWal = name
		status.LastArchivedAt = sql.NullInt64{Int64: m.now().Unix(), Valid: true}
		status.Pending--
		if status.Pending > 0 && i+1 < len(names) {
			status.OldestPendingAt = sql.NullInt64{Int64: m.firstSeen(s.ID, names[i+1]).Unix(), Valid: true}
		} else {
			status.OldestPendingAt = sql.NullInt64{}
		}
	}
	if status.LastError != WALArchiveFails {
		status.LastError = ""
	}
	return nil
}

func atoi(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func (m *Manager) firstSeen(serviceID, name string) time.Time {
	m.walMu.Lock()
	defer m.walMu.Unlock()
	if t, ok := m.walSeen[serviceID+"/"+name]; ok {
		return t
	}
	return m.now()
}

type limitWriter struct {
	w io.Writer
	n int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, errors.New("larger than expected")
	}
	l.n -= int64(len(p))
	return l.w.Write(p)
}

// pgBaseCmd streams a base backup (tar) from inside the container. -X none:
// the WAL it needs comes from the archive, which is the point.
var pgBaseCmd = []string{"sh", "-c", `exec pg_basebackup -U "$POSTGRES_USER" -D - -Ft -X none -c fast --no-manifest -w`}

// backupBase takes a base backup: the starting point that WAL is replayed
// on for a point-in-time restore.
func (m *Manager) backupBase(ctx context.Context, a Actor, s svcRef, trigger string) (string, error) {
	unlock := m.lock(s.label())
	defer unlock()
	n, _, err := m.tasker()
	if err != nil {
		return "", err
	}
	ts, err := m.targets(ctx)
	if err != nil {
		return "", err
	}
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return "", err
	}
	runID, err := m.startRun(ctx, a, s.ID, s.label(), archive.KindBase, trigger, "")
	if err != nil {
		return "", err
	}
	res := runResult{}
	err = func() error {
		f, err := m.stagingFile("base-*.age")
		if err != nil {
			return err
		}
		defer removeFile(f)
		sf := &sealedFile{f: f, sha: sha256.New()}
		sealer, err := archive.Seal(io.MultiWriter(f, sf.sha, &sf.size), rcpts, true)
		if err != nil {
			return err
		}
		pr, pw := io.Pipe()
		infoc := make(chan archive.BaseInfo, 1)
		errc := make(chan error, 1)
		go func() {
			info, err := archive.CheckBase(pr, sealer)
			_ = pr.CloseWithError(err)
			infoc <- info
			errc <- err
		}()
		eerr := n.Exec(ctx, s.Project, s.Service, pgBaseCmd, pw)
		_ = pw.CloseWithError(eerr)
		info, cerr := <-infoc, <-errc
		if cerr != nil && (eerr == nil || !errors.Is(cerr, eerr)) {
			return cerr // the stream itself is wrong (unsafe path, not a data directory)
		}
		if eerr != nil {
			return fmt.Errorf("pg_basebackup: %w", eerr)
		}
		if err := sealer.Close(); err != nil {
			return err
		}
		res.verified, res.check, res.size, res.sha = true, map[string]any{"files": info.Files, "start_wal": info.StartSegment}, sf.size.n, sf.hexSum()
		res.key = archive.BaseKey(s.Project, s.Service, m.now(), info.StartSegment)
		res.uploads, err = m.sendFile(ctx, ts, res.key, "wal", f, res.size, res.sha, s.meta(archive.KindBase))
		return err
	}()
	m.finishRun(ctx, runID, res, err)
	m.record(ctx, a, "backup.run", "service", s.ID, outcomeOf(err), map[string]any{
		"service": s.label(), "kind": archive.KindBase, "trigger": trigger, "run": runID, "size": res.size,
	})
	if err != nil {
		m.log.Warn("backup failed", "service", s.label(), "kind", archive.KindBase, "error", err)
	}
	return runID, err
}

// archivingActive reports whether the running server has archive_mode on
// (WAL was turned on and the database was redeployed since).
func (m *Manager) archivingActive(ctx context.Context, s svcRef) bool {
	n, _, err := m.tasker()
	if err != nil {
		return false
	}
	var out bytes.Buffer
	if err := n.Exec(ctx, s.Project, s.Service, archiverQuery, &out); err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(out.String()), "on|")
}
