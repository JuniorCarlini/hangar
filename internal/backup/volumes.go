package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/volumes"
)

// Backups of volumes (docs/09): for services without a dump of their own
// (pg_dump or a template's recipe), a copy of the files of the volumes
// they own, Hangar disks included (a disk is a Docker volume bound into
// its image). The copy is GNU tar run in a throwaway container that mounts
// the volumes read-only, so owners, permissions, symlinks, hard links,
// ACLs and user.* attributes come out as they are, without the panel
// (which runs unprivileged) reading them.
//
// The services that write to the volumes are held for the copy, the way
// Hangar picks (svcRef.hold): a database is stopped (it shuts down
// cleanly, so its files are whole) and started again; anything else is
// paused (its processes freeze, nothing is written) and goes on where it
// was.
//
// The hold is kept short with two passes, as rsync-based backups do. The
// helper first copies the volumes live into a scratch volume of its own
// (tar piped into tar, with a GNU tar snapshot file); then, with the
// services held, a second, incremental pass brings over only what changed
// meanwhile (files whose content, owner, mode or links changed, new ones,
// and the removal of the ones gone), and counts what the volumes hold.
// The services go on right after that count: the tar that becomes the
// backup is read from the scratch copy, which nothing writes to. When the
// server's disk cannot hold the scratch copy, the copy is taken in one
// pass, all of it with the services held, as before.
//
// The tar streams through this process, which encrypts it (zstd, then
// age) into the staging dir and, at the same time, feeds it to a second
// throwaway container that reads it back with GNU tar: a copy is called
// tested only when what that container counted (entries, bytes, SHA-256
// of the stream) matches what this process saw and what the volumes held
// while the services were held. Plaintext never lands on disk outside
// the scratch volume (removed with the helper), and the server never
// needs to decrypt to test, as with dumps.

// VolumeHelperImage runs the copy and the restore of volumes: GNU tar
// with ACL and extended-attribute support, findutils, bash. It runs as
// root inside the container (to read and restore every owner), with no
// network and only the default capabilities.
//
// It is pinned by digest (the multi-arch index of the tag beside it): it
// runs as root with every volume writable and is pulled on each run, so a
// retagged or compromised upstream image must not reach it silently. To
// update: docker buildx imagetools inspect debian:13-slim.
const VolumeHelperImage = "debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4"

// tarFlags are the options both ends agree on: the POSIX format (pax
// records carry ACLs and attributes), owners as numbers (the container's
// /etc/passwd means nothing to the app's files), sparse files kept sparse.
// security.* attributes (SELinux labels, file capabilities) are left out:
// restoring them needs privileges no helper has.
const tarFlags = `--numeric-owner --acls --xattrs --xattrs-include='user.*'`

// stageDir is where the copy helper mounts its scratch volume.
const stageDir = "/stage"

// stageReserve is what the scratch copy leaves free on the disk it is on
// (tests raise it to take the one-pass way).
var stageReserve = stagingReserve

// volumeCopyScript runs in /v, where each volume is mounted read-only
// under its name; the names come as arguments, never into the script.
//
// With HANGAR_STAGE set (a scratch volume), it first copies the volumes
// live into it when its disk has room for them twice (the scratch copy,
// and the encrypted copy the panel writes, maybe to the same disk) plus
// HANGAR_RESERVE. It then writes its ready line, which says how it will
// copy: "HANGAR-READY staged" or "HANGAR-READY direct" (with why, and the
// numbers), and waits for "go" (the services are held by then). Staged,
// it brings the scratch copy up to date (only what changed), counts what
// the volumes hold and writes that line (the services can go on from
// there), then the tar of the scratch copy. Direct, it counts and writes
// the tar of the volumes themselves. Sockets are skipped (tar cannot keep
// them). With HANGAR_LIVE=1, tar's "file changed as we read it" (exit 1)
// is accepted.
const volumeCopyScript = `set -euo pipefail
cd /v
pack() { tar --create --file=- --format=posix --sparse --one-file-system ` + tarFlags + ` "$@"; }
unpack() { tar --extract --file=- --listed-incremental=/dev/null --preserve-permissions --same-owner ` + tarFlags + ` -C "$HANGAR_STAGE/d"; }
how="direct"
if [ -n "${HANGAR_STAGE:-}" ]; then
  # The volumes are live here: a file gone between listing and reading
  # makes du complain (and exit 1), not wrong.
  used=$( { du -sxcB1 -- "$@" 2>/dev/null || true; } | tail -n1 | cut -f1)
  free=$(df -B1 --output=avail "$HANGAR_STAGE" | tail -n1 | tr -d ' ')
  need=$((2 * used + ${HANGAR_RESERVE:-0}))
  if [ "$free" -lt "$need" ]; then
    how="direct reason=no_room used=$used free=$free need=$need"
  else
    mkdir "$HANGAR_STAGE/d"
    rcs=(0 0)
    pack --listed-incremental="$HANGAR_STAGE/snar" -- "$@" | unpack || rcs=("${PIPESTATUS[@]}")
    if [ "${rcs[0]}" -le 1 ] && [ "${rcs[1]}" -eq 0 ]; then
      how="staged used=$used free=$free"
    else
      rm -rf "$HANGAR_STAGE/d" "$HANGAR_STAGE/snar"
      how="direct reason=stage_failed used=$used free=$free need=$need"
    fi
  fi
fi
echo "HANGAR-READY $how"
IFS= read -r go
[ "$go" = go ] || exit 3
if [ "${how%% *}" = staged ]; then
  pack --listed-incremental="$HANGAR_STAGE/snar" -- "$@" | unpack
fi
entries=$(find "$@" -xdev ! -type s -printf . | wc -c)
bytes=$(find "$@" -xdev -type f -printf '%D:%i %s\n' | sort -u -k1,1 | awk '{s+=$2} END {printf "%d", s}')
echo "HANGAR-SOURCE entries=$entries bytes=$bytes"
if [ "${how%% *}" = staged ]; then
  cd "$HANGAR_STAGE/d"
  pack -- "$@"
  exit 0
fi
rc=0
pack -- "$@" || rc=$?
if [ "$rc" -eq 1 ] && [ "${HANGAR_LIVE:-0}" = 1 ]; then rc=0; fi
exit "$rc"
`

// volumeVerifyScript reads the copy from standard input with GNU tar,
// the way a restore does (every file's content goes through tar, to
// nowhere), and reports how many entries it listed, how many bytes of
// content it gave and the SHA-256 of what it received. It writes a line
// when it is ready.
const volumeVerifyScript = `set -euo pipefail
mkfifo /tmp/hangar-sum
sha256sum < /tmp/hangar-sum > /tmp/hangar-sum.txt &
echo HANGAR-READY
entries=$( { tee /tmp/hangar-sum | { rc=0; tar --extract --file=- --to-stdout --verbose --index-file=/dev/fd/3 ` + tarFlags + ` | wc -c > /tmp/hangar-bytes || rc=$?; cat > /dev/null; exit "$rc"; }; } 3>&1 | wc -l )
wait
echo "HANGAR-VERIFY entries=$entries bytes=$(cat /tmp/hangar-bytes) sha256=$(cut -d' ' -f1 /tmp/hangar-sum.txt)"
`

// volumeRestoreScript empties each volume named (mounted read-write under
// /v), extracts the copy from standard input as root (owners, modes,
// ACLs, attributes, the volume folder's own included) and counts what
// the volumes then hold, as volumeCopyScript did.
const volumeRestoreScript = `set -euo pipefail
cd /v
for v in "$@"; do find "$v" -mindepth 1 -delete; done
tar --extract --file=- --preserve-permissions --same-owner ` + tarFlags + ` -- "$@"
cat > /dev/null
entries=$(find "$@" -xdev ! -type s -printf . | wc -c)
bytes=$(find "$@" -xdev -type f -printf '%D:%i %s\n' | sort -u -k1,1 | awk '{s+=$2} END {printf "%d", s}')
echo "HANGAR-RESTORED entries=$entries bytes=$bytes"
`

var (
	readyRE    = regexp.MustCompile(`^HANGAR-READY(?: (staged|direct)(?: reason=(\w+))?(?: used=(\d+))?(?: free=(\d+))?(?: need=(\d+))?)?\s*$`)
	sourceRE   = regexp.MustCompile(`^HANGAR-SOURCE entries=(\d+) bytes=(\d+)\s*$`)
	verifyRE   = regexp.MustCompile(`(?m)^HANGAR-VERIFY entries=(\d+) bytes=(\d+) sha256=([0-9a-f]{64})\s*$`)
	restoredRE = regexp.MustCompile(`(?m)^HANGAR-RESTORED entries=(\d+) bytes=(\d+)\s*$`)
)

// VolumeCheck is what a copy of volumes found (backup_runs.check_json).
type VolumeCheck struct {
	// Files are the entries of the copy (files, folders, links, FIFOs).
	Files int64 `json:"files"`
	// Bytes is the size of the files' contents.
	Bytes   int64                `json:"bytes"`
	Volumes []archive.VolumeStat `json:"volumes"`
	// Mode is how it was kept consistent (ConsistencyPause or
	// ConsistencyStop); "" when no service using the volumes was running.
	Mode string `json:"mode"`
	// Paused are the services paused (or stopped) for the copy, and for
	// how long, from the pause (or the stop) to their going on again.
	Paused  []string `json:"paused,omitempty"`
	PauseMS int64    `json:"pause_ms,omitempty"`
	// TarBytes is the size of the tar before compression.
	TarBytes int64 `json:"tar_bytes"`
	// Staged: the copy was taken in two passes (live, then only what
	// changed with the services held), so the hold lasted only the
	// second one.
	Staged bool `json:"staged,omitempty"`
}

// maxPause is the longest a service stays paused (or stopped) for a
// copy: past it, the services go on and the backup fails, saying to copy
// live or at a quieter time.
var maxPause = 30 * time.Minute

// stagingReserve is what a copy leaves free on the server's disk: the
// staging dir is on it, and a full disk takes everything down.
const stagingReserve int64 = 1 << 30

var (
	errTaskEnded = errors.New("helper ended")
	errPauseLong = errors.New("the copy took longer than the pause allows")
)

// liveTask is a helper container being fed and read while it runs.
type liveTask struct {
	in   *io.PipeWriter
	outR *io.PipeReader
	out  *bufio.Reader
	done chan error
}

func startTask(ctx context.Context, tk node.Tasker, spec node.TaskSpec) *liveTask {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	t := &liveTask{in: inW, outR: outR, out: bufio.NewReaderSize(outR, 64<<10), done: make(chan error, 1)}
	go func() {
		err := tk.RunTask(ctx, spec, inR, outW)
		_ = outW.CloseWithError(err) // nil: the reader sees EOF
		_ = inR.CloseWithError(errors.Join(err, errTaskEnded))
		t.done <- err
	}()
	return t
}

// line reads one line of the helper's output and checks it starts with
// want.
func (t *liveTask) line(want string) (string, error) {
	s, err := t.out.ReadString('\n')
	if err != nil {
		return s, err
	}
	if !strings.HasPrefix(s, want) {
		return s, fmt.Errorf("the helper said %q instead of %s", strings.TrimSpace(s), want)
	}
	return s, nil
}

// stop ends the helper (an error elsewhere) and waits for it.
func (t *liveTask) stop(cancel context.CancelFunc) error {
	cancel()
	_ = t.in.CloseWithError(errTaskEnded)
	_ = t.outR.CloseWithError(errTaskEnded)
	return <-t.done
}

func volumeSpec(s svcRef, cmd string, readOnly bool, names []string, env map[string]string) node.TaskSpec {
	spec := node.TaskSpec{
		Image: VolumeHelperImage, Cmd: append([]string{"bash", "-c", cmd, "hangar"}, names...), Env: env,
		MemoryBytes: 256 << 20, NanoCPUs: 1e9, PidsLimit: 64,
	}
	for _, v := range s.Vols {
		if slices.Contains(names, v.Name) {
			spec.Mounts = append(spec.Mounts, node.TaskMount{Volume: v.Docker, Path: "/v/" + v.Name, ReadOnly: readOnly})
		}
	}
	return spec
}

func (s svcRef) volNames() []string {
	out := make([]string, 0, len(s.Vols))
	for _, v := range s.Vols {
		out = append(out, v.Name)
	}
	return out
}

// volumeUsers are the services that mount s's volumes: s first, then the
// ones that share them.
func (s svcRef) volumeUsers() []string {
	out := []string{s.Service}
	for _, v := range s.Vols {
		for _, u := range v.Users {
			if !slices.Contains(out, u) {
				out = append(out, u)
			}
		}
	}
	return out
}

// hold pauses (or stops) the running users of s's volumes and returns
// what it did and how to undo it. Undo is safe to call more than once.
func (m *Manager) hold(ctx context.Context, s svcRef, mode string) (held []string, undo func(), err error) {
	undo = func() {}
	if mode == ConsistencyLive {
		return nil, undo, nil
	}
	n, _, err := m.tasker()
	if err != nil {
		return nil, undo, err
	}
	p, canPause := n.(node.Pauser)
	if mode == ConsistencyPause && !canPause {
		return nil, undo, ErrNoDocker
	}
	var unhold []func()
	release := func(names []string) {
		bg := context.WithoutCancel(ctx)
		defer func() {
			for _, f := range unhold {
				f()
			}
		}()
		for _, u := range names {
			var err error
			if mode == ConsistencyPause {
				err = p.Unpause(bg, s.Project, u)
			} else {
				err = n.Start(bg, s.Project, u)
			}
			if err != nil {
				m.log.Error("resume a service after the copy of its volumes", "service", s.Project+"/"+u, "mode", mode, "error", err)
			}
		}
	}
	for _, u := range s.volumeUsers() {
		st, err := m.projects.Status(ctx, s.Project, u)
		if err != nil || !st.Running {
			continue
		}
		// Marked before the pause, so the reconciler never sees it paused
		// unmarked.
		unhold = append(unhold, m.projects.Hold(s.Project, u))
		if mode == ConsistencyPause {
			err = p.Pause(ctx, s.Project, u)
		} else {
			err = n.Stop(ctx, s.Project, u)
		}
		if err != nil {
			release(held)
			return nil, func() {}, fmt.Errorf("%s %s: %w", mode, u, err)
		}
		held = append(held, u)
	}
	var once sync.Once
	return held, func() { once.Do(func() { release(held) }) }, nil
}

// freeSpace is the room left on the filesystem of path (tests swap it).
var freeSpace = func(path string) (int64, bool) {
	_, _, avail, err := volumes.Statfs(path)
	if err != nil {
		return 0, false
	}
	return int64(min(avail, 1<<62)), true //nolint:gosec // bounded
}

func gbText(b int64) string { return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30)) }

// checkRoom refuses a copy the staging dir cannot hold: the volumes'
// last measured size (a compressed copy is not bigger) plus what must
// stay free on the server.
func (m *Manager) checkRoom(s svcRef) error {
	var used int64
	for _, v := range s.Vols {
		used += max(v.Used, 0)
	}
	free, ok := freeSpace(m.opt.StagingDir)
	if !ok {
		return nil
	}
	if free < used+stagingReserve {
		return i18n.E("backup.error.no_room", "need", gbText(used+stagingReserve), "free", gbText(free))
	}
	return nil
}

// roomWriter stops a copy before it fills the server's disk: the volumes
// may have grown since they were measured.
type roomWriter struct {
	w     io.Writer
	dir   string
	since int64
}

func (r *roomWriter) Write(p []byte) (int, error) {
	r.since += int64(len(p))
	if r.since >= 256<<20 {
		r.since = 0
		if free, ok := freeSpace(r.dir); ok && free < stagingReserve {
			return 0, i18n.E("backup.error.disk_full", "free", gbText(free))
		}
	}
	return r.w.Write(p)
}

// copied is a copy of volumes, encrypted in the staging dir (nil file
// when it went to a writer instead).
type copied struct {
	file  *sealedFile
	check VolumeCheck
}

func (c *copied) remove() {
	if c != nil && c.file != nil {
		removeFile(c.file.f)
	}
}

// copyVolumes copies s's volumes, kept consistent as mode says, and
// streams the tar to sink as it comes. With verify, a second helper
// reads it back meanwhile and the counts must all match. It returns the
// check; the caller owns sink.
func (m *Manager) copyVolumes(ctx context.Context, s svcRef, mode string, sink io.Writer, verify bool) (VolumeCheck, error) {
	var c VolumeCheck
	_, tk, err := m.tasker()
	if err != nil {
		return c, err
	}
	names := s.volNames()
	if len(names) == 0 {
		return c, ErrUnsupported
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	env := map[string]string{}
	if mode == ConsistencyLive {
		env["HANGAR_LIVE"] = "1"
	}
	spec := volumeSpec(s, volumeCopyScript, true, names, env)
	if mode != ConsistencyLive {
		// Room for the live first pass (see volumeCopyScript).
		spec.Scratch = stageDir
		env["HANGAR_STAGE"] = stageDir
		env["HANGAR_RESERVE"] = strconv.FormatInt(stageReserve, 10)
	}
	stop := func(t *liveTask) error { return t.stop(func() { cancel(errTaskEnded) }) }
	src := startTask(ctx, tk, spec)
	ready, err := src.line("HANGAR-READY")
	if err != nil {
		return c, fmt.Errorf("copy of the volumes: %w", errors.Join(err, stop(src)))
	}
	if rm := readyRE.FindStringSubmatch(strings.TrimSpace(ready)); rm != nil {
		c.Staged = rm[1] == "staged"
		if rm[2] != "" {
			// Not fatal: the copy is still whole, the services are only
			// held for all of it.
			m.log.Warn("volumes copied in one pass, with the services held for all of it", "service", s.label(), "reason", rm[2],
				"used", rm[3], "free", rm[4], "need", rm[5])
		}
	}
	var ver *liveTask
	if verify {
		ver = startTask(ctx, tk, node.TaskSpec{
			Image: VolumeHelperImage, Cmd: []string{"bash", "-c", volumeVerifyScript},
			MemoryBytes: 256 << 20, NanoCPUs: 1e9, PidsLimit: 64,
		})
		if _, err := ver.line("HANGAR-READY"); err != nil {
			return c, fmt.Errorf("test of the copy: %w", errors.Join(err, stop(ver), stop(src)))
		}
	}
	stopAll := func(err error) error {
		errs := []error{err, stop(src)}
		if ver != nil {
			errs = append(errs, stop(ver))
		}
		return errors.Join(errs...)
	}

	// Both helpers are up (and the live first pass is done): from here to
	// the count of a staged copy, or to the end of a direct tar, the
	// services wait, so that span is all the pause (or the stop) lasts.
	start := m.now()
	held, resume, err := m.hold(ctx, s, mode)
	if err != nil {
		return c, stopAll(err)
	}
	defer resume()
	if len(held) > 0 {
		c.Mode, c.Paused = mode, held
	} else if mode == ConsistencyLive {
		c.Mode = mode
	}
	timer := time.AfterFunc(maxPause, func() {
		if len(held) > 0 {
			resume()
			cancel(errPauseLong)
		}
	})
	defer timer.Stop()

	// Once the volumes are copied (staged: brought up to date in the
	// scratch copy; direct: the tar is over or failed), the services go
	// on right away, while the rest is read, encrypted and tested.
	var ended sync.Once
	end := func() {
		ended.Do(func() {
			timer.Stop()
			resume()
			if len(held) > 0 {
				c.PauseMS = m.now().Sub(start).Milliseconds()
				m.log.Info("volumes copied", "service", s.label(), "mode", mode, "staged", c.Staged, "paused", held, "pause", m.now().Sub(start).Round(time.Millisecond))
			}
		})
	}

	if _, err := io.WriteString(src.in, "go\n"); err != nil {
		resume()
		return c, stopAll(err)
	}
	_ = src.in.Close()
	line, err := src.line("HANGAR-SOURCE")
	if err != nil {
		resume()
		return c, stopAll(fmt.Errorf("copy of the volumes: %w", err))
	}
	sm := sourceRE.FindStringSubmatch(strings.TrimSpace(line))
	if sm == nil {
		resume()
		return c, stopAll(fmt.Errorf("copy of the volumes: unreadable count %q", strings.TrimSpace(line)))
	}
	if c.Staged {
		// The scratch copy is up to date and counted: nothing the
		// services do now changes the backup.
		end()
	}

	type scanned struct {
		m   archive.VolumeManifest
		err error
	}
	scanR, scanW := io.Pipe()
	scanDone := make(chan scanned, 1)
	go func() {
		man, err := archive.ScanVolumes(scanR, names, archive.VolumeTarLimits)
		_ = scanR.CloseWithError(err)
		scanDone <- scanned{man, err}
	}()
	plainSum := sha256.New()
	var plain counter
	outs := []io.Writer{sink, scanW, plainSum, &plain}
	if ver != nil {
		outs = append(outs, ver.in)
	}
	cerr := relay(io.MultiWriter(outs...), src.out, end)
	end()
	_ = scanW.CloseWithError(cerr)
	if ver != nil {
		_ = ver.in.CloseWithError(cerr)
	}
	if cerr != nil {
		if cause := context.Cause(ctx); errors.Is(cause, errPauseLong) {
			cerr = i18n.E("backup.error.pause_long", "minutes", int(maxPause/time.Minute))
		}
		<-scanDone
		return c, stopAll(fmt.Errorf("copy of the volumes: %w", cerr))
	}
	srcErr := <-src.done
	sc := <-scanDone
	var verOut string
	var verErr error
	if ver != nil {
		b, _ := io.ReadAll(ver.out)
		verOut = string(b)
		verErr = <-ver.done
	}
	switch {
	case srcErr != nil:
		return c, fmt.Errorf("copy of the volumes: %w", srcErr)
	case sc.err != nil:
		return c, fmt.Errorf("copy of the volumes: %w", sc.err)
	case verErr != nil:
		return c, fmt.Errorf("test of the copy: %w", verErr)
	}
	c.Files, c.Bytes, c.Volumes, c.TarBytes = sc.m.Entries, sc.m.Bytes, sc.m.Volumes, plain.n
	srcEntries, _ := strconv.ParseInt(sm[1], 10, 64)
	srcBytes, _ := strconv.ParseInt(sm[2], 10, 64)
	// Copied live, files may come and go during the copy: what the
	// volumes held at its start is no measure then.
	if mode != ConsistencyLive && (srcEntries != c.Files || srcBytes != c.Bytes) {
		return c, fmt.Errorf("the copy has %d entries and %d bytes, the volumes had %d and %d", c.Files, c.Bytes, srcEntries, srcBytes)
	}
	if ver != nil {
		vm := verifyRE.FindStringSubmatch(verOut)
		if vm == nil {
			return c, fmt.Errorf("the test of the copy did not report its counts: %q", truncate(strings.TrimSpace(verOut), 300))
		}
		ve, _ := strconv.ParseInt(vm[1], 10, 64)
		vb, _ := strconv.ParseInt(vm[2], 10, 64)
		switch {
		case ve != c.Files || vb != c.Bytes:
			return c, fmt.Errorf("the test of the copy read %d entries and %d bytes, the copy has %d and %d", ve, vb, c.Files, c.Bytes)
		case vm[3] != hex.EncodeToString(plainSum.Sum(nil)):
			return c, errors.New("the test of the copy read different bytes than were encrypted")
		}
	}
	return c, nil
}

// relayChunk and relayDepth bound what relay holds: 64 MiB.
const (
	relayChunk = 1 << 20
	relayDepth = 64
)

// relay copies r to w through a buffer read on its own goroutine, so r
// (the copy helper's output) is drained as fast as it comes while w
// (compression, encryption, the test) works behind it: the services wait
// for the tar, not for what is done with it. eof is called as soon as r
// ends. relay returns once w took everything, or on the first error.
func relay(w io.Writer, r io.Reader, eof func()) error {
	chunks := make(chan []byte, relayDepth)
	free := make(chan []byte, relayDepth+1)
	stop := make(chan struct{})
	rerr := make(chan error, 1)
	go func() {
		defer close(chunks)
		for {
			var buf []byte
			select {
			case buf = <-free:
			default:
				buf = make([]byte, relayChunk)
			}
			n, err := io.ReadFull(r, buf)
			if n > 0 {
				select {
				case chunks <- buf[:n]:
				case <-stop:
					rerr <- nil
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					err = nil
				}
				if err == nil {
					eof()
				}
				rerr <- err
				return
			}
		}
	}()
	var werr error
	for buf := range chunks {
		if werr == nil {
			if _, werr = w.Write(buf); werr != nil {
				close(stop)
			}
		}
		select {
		case free <- buf[:cap(buf)]:
		default:
		}
	}
	if err := <-rerr; werr == nil {
		werr = err
	}
	return werr
}

// archiveVolumes copies s's volumes, tested, into an encrypted staging
// file.
func (m *Manager) archiveVolumes(ctx context.Context, s svcRef, mode string) (*copied, error) {
	rcpts, err := m.recipients(ctx)
	if err != nil {
		return nil, err
	}
	if err := m.checkRoom(s); err != nil {
		return nil, err
	}
	f, err := m.stagingFile("volumes-*.age")
	if err != nil {
		return nil, err
	}
	out := &copied{file: &sealedFile{f: f, sha: sha256.New()}}
	ok := false
	defer func() {
		if !ok {
			out.remove()
		}
	}()
	sf := out.file
	sealer, err := archive.Seal(io.MultiWriter(&roomWriter{w: f, dir: m.opt.StagingDir}, sf.sha, &sf.size), rcpts, true)
	if err != nil {
		return nil, err
	}
	if out.check, err = m.copyVolumes(ctx, s, mode, sealer, true); err != nil {
		return nil, err
	}
	if err := sealer.Close(); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	ok = true
	return out, nil
}

// volumeWarning is sizeWarning for a copy of volumes: it also flags a
// copy that lost more than half of the files.
func volumeWarning(prev dbq.BackupRun, size, files int64) string {
	if w := sizeWarning(prev, size, 0); w != "" {
		return w
	}
	var pc VolumeCheck
	if prev.ID != "" && json.Unmarshal([]byte(prev.CheckJson), &pc) == nil && pc.Files > 1000 && files*2 < pc.Files {
		return "files_dropped"
	}
	return ""
}

// backupVolume is a full backup of s's volumes: copy (kept consistent as
// mode says, "" for the way Hangar picks for s), test, encrypt, upload to
// every destination, check each copy.
func (m *Manager) backupVolume(ctx context.Context, a Actor, s svcRef, trigger, mode string) (string, error) {
	unlock := m.lock(s.label())
	defer unlock()
	ts, err := m.targets(ctx)
	if err != nil {
		return "", err
	}
	if mode == "" {
		mode = s.hold()
	}
	class := m.class(ctx, s.label(), archive.KindVolume, trigger)
	runID, err := m.startRun(ctx, a, s.ID, s.label(), archive.KindVolume, trigger, class)
	if err != nil {
		return "", err
	}
	res := runResult{}
	err = func() error {
		v, err := m.archiveVolumes(ctx, s, mode)
		if err != nil {
			return err
		}
		defer v.remove()
		sf := v.file
		res.verified, res.check, res.size, res.sha = true, v.check, sf.size.n, sf.hexSum()
		prev, _ := m.q.LastOKBackupRun(ctx, dbq.LastOKBackupRunParams{Label: s.label(), Kind: archive.KindVolume})
		res.warning = volumeWarning(prev, res.size, v.check.Files)
		res.key = archive.VolumesKey(class, s.Project, s.Service, m.now())
		meta := s.meta(archive.KindVolume)
		meta["hangar-volumes"] = archive.VolumeManifest{Volumes: v.check.Volumes}.Meta()
		res.uploads, err = m.sendFile(ctx, ts, res.key, archive.FolderOf(class), sf.f, res.size, res.sha, meta)
		return err
	}()
	m.finishRun(ctx, runID, res, err)
	m.record(ctx, a, "backup.run", "service", s.ID, outcomeOf(err), map[string]any{
		"service": s.label(), "kind": archive.KindVolume, "trigger": trigger, "run": runID, "size": res.size, "warning": res.warning, "mode": mode,
	})
	if err != nil {
		m.log.Warn("backup failed", "service", s.label(), "kind", archive.KindVolume, "error", err)
	}
	return runID, err
}

// backupService runs the full backup s's method calls for.
func (m *Manager) backupService(ctx context.Context, a Actor, s svcRef, trigger string) (string, error) {
	switch s.Method {
	case projects.BackupVolume:
		return m.backupVolume(ctx, a, s, trigger, "")
	case projects.BackupRecipe:
		return m.backupRecipe(ctx, a, s, trigger)
	}
	return m.backupDump(ctx, a, s, trigger)
}

// --- restore ---------------------------------------------------------------------

// volumeHeadroom is what a disk must keep free above a restored copy.
const volumeHeadroom = 64 << 20

// checkVolumesFit refuses a restore into t of a copy (as its metadata
// describes it) that has a volume t lacks or that its disk cannot hold.
func checkVolumesFit(t svcRef, man archive.VolumeManifest) error {
	for _, st := range man.Volumes {
		i := slices.IndexFunc(t.Vols, func(v projects.OwnedVolume) bool { return v.Name == st.Name })
		if i < 0 {
			return i18n.E("backup.error.volume_missing", "volume", st.Name, "service", t.Service)
		}
		if lim := t.Vols[i].Limit; lim > 0 && st.Need+volumeHeadroom > lim {
			return i18n.E("backup.error.volume_too_big", "volume", st.Name, "need", gbText(st.Need+volumeHeadroom), "limit", gbText(lim))
		}
	}
	return nil
}

// restoreVolumes replaces the files of t's volumes with the copy key:
// the services that use them stop, each volume in the copy is emptied
// and filled from it (a volume of t not in the copy is left alone), the
// result is counted against the copy, and the services start again. The
// copy is checked entry by entry (archive.ScanVolumes) as it streams in;
// a bad one stops the restore.
func (m *Manager) restoreVolumes(ctx context.Context, a Actor, id string, t svcRef, key string, ids []age.Identity) (changed bool, err error) {
	n, tk, err := m.tasker()
	if err != nil {
		return false, err
	}
	rc, info, err := m.fetch(ctx, key)
	if err != nil {
		return false, err
	}
	defer func() { _ = rc.Close() }()
	man, ok := archive.ParseVolumeMeta(info.Metadata["hangar-volumes"])
	if !ok {
		return false, errors.New("the copy does not say which volumes it holds")
	}
	if err := checkVolumesFit(t, man); err != nil {
		return false, err
	}
	plain, err := archive.Open(rc, ids, archive.VolumeLimits)
	if err != nil {
		return false, err
	}
	defer func() { _ = plain.Close() }()

	m.step(ctx, id, "stop_service")
	// Everything that writes to the volumes stops; what was running
	// starts again at the end, whatever happens.
	var stopped []string
	for _, u := range t.volumeUsers() {
		if st, err := m.projects.Status(ctx, t.Project, u); err == nil && st.Running {
			unhold := m.projects.Hold(t.Project, u)
			defer unhold()
			if err := n.Stop(ctx, t.Project, u); err != nil {
				return false, fmt.Errorf("stop %s: %w", u, err)
			}
			stopped = append(stopped, u)
		}
	}
	started := false
	defer func() {
		if started {
			return
		}
		bg := context.WithoutCancel(ctx)
		for _, u := range stopped {
			_ = n.Start(bg, t.Project, u)
		}
	}()

	m.step(ctx, id, "copy")
	names := man.Names()
	type scanned struct {
		m   archive.VolumeManifest
		err error
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	scanR, scanW := io.Pipe()
	scanDone := make(chan scanned, 1)
	go func() {
		got, err := archive.ScanVolumes(scanR, names, archive.VolumeTarLimits)
		_ = scanR.CloseWithError(err)
		if err != nil {
			// A bad entry stops the extraction now, not at the end.
			cancel()
		}
		scanDone <- scanned{got, err}
	}()
	inR, inW := io.Pipe()
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		_, err := io.Copy(io.MultiWriter(inW, scanW), plain)
		_ = scanW.CloseWithError(err)
		_ = inW.CloseWithError(err)
	}()
	var out strings.Builder
	terr := tk.RunTask(cctx, volumeSpec(t, volumeRestoreScript, false, names, nil), inR, &limitWriter{w: &out, n: 4 << 10})
	_ = inR.CloseWithError(errors.Join(terr, errTaskEnded))
	sc := <-scanDone
	<-fed
	switch {
	case sc.err != nil && !errors.Is(sc.err, errTaskEnded):
		return true, fmt.Errorf("the copy was refused: %w", sc.err)
	case terr != nil:
		return true, fmt.Errorf("restore the volumes: %w", terr)
	case sc.err != nil:
		return true, fmt.Errorf("restore the volumes: %w", sc.err)
	}
	rm := restoredRE.FindStringSubmatch(out.String())
	if rm == nil {
		return true, errors.New("the restore did not report what the volumes hold")
	}
	re, _ := strconv.ParseInt(rm[1], 10, 64)
	rb, _ := strconv.ParseInt(rm[2], 10, 64)
	if re != sc.m.Entries || rb != sc.m.Bytes {
		return true, fmt.Errorf("the volumes hold %d entries and %d bytes after the restore, the copy has %d and %d", re, rb, sc.m.Entries, sc.m.Bytes)
	}

	m.step(ctx, id, "start")
	started = true
	var errs []error
	for _, u := range stopped {
		if u == t.Service {
			continue
		}
		if err := n.Start(ctx, t.Project, u); err != nil {
			errs = append(errs, fmt.Errorf("start %s: %w", u, err))
		}
	}
	// The service itself comes back through a deploy, which waits for it
	// to be healthy on the restored files.
	if slices.Contains(stopped, t.Service) {
		if err := m.deployAndWait(ctx, a, t, "restore"); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return true, err
	}
	m.step(ctx, id, "done")
	return true, nil
}

// runVolumeRestore is runRestore for a service backed up as volumes.
// Overwriting first copies the current state; if the restore then fails
// once the volumes were touched, that copy goes back in. Into a new
// service, the copy gets the original's disk sizes, is deployed (so its
// volumes exist), then filled.
func (m *Manager) runVolumeRestore(ctx context.Context, a Actor, id string, s svcRef, req RestoreRequest) (err error) {
	if req.Destination == DestOverwrite {
		m.step(ctx, id, "pre_backup")
		runID, err := m.backupVolume(ctx, a, s, TriggerPreRestore, "")
		if err != nil {
			return fmt.Errorf("backup of the current state failed, nothing was changed: %w", err)
		}
		pre, err := m.q.GetBackupRun(ctx, runID)
		if err != nil {
			return err
		}
		changed, rerr := m.restoreVolumes(ctx, a, id, s, req.Key, req.Identities)
		if rerr == nil || !changed {
			return rerr
		}
		m.step(ctx, id, "rollback")
		if _, berr := m.restoreVolumes(ctx, a, id, s, pre.ObjectKey, req.Identities); berr != nil {
			return fmt.Errorf("%w; putting back the copy made just before (%s) also failed: %w", rerr, pre.ObjectKey, berr)
		}
		return fmt.Errorf("%w; the volumes are back as they were before the restore", rerr)
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
	// Read again: the disks exist now, with their sizes.
	if t, err = m.ref(ctx, s.Project, c.Slug); err != nil {
		return err
	}
	_, err = m.restoreVolumes(ctx, a, id, t, req.Key, req.Identities)
	return err
}

// copyLimits gives the new service slug the disk sizes of s's volumes,
// before its first deploy creates them. Without volume limits on this
// server (or when one fails) the volume is plain: it holds the copy
// anyway, on the server's disk.
func (m *Manager) copyLimits(ctx context.Context, a Actor, s svcRef, slug string) {
	for _, v := range s.Vols {
		if v.Limit <= 0 {
			continue
		}
		if err := m.projects.SetVolumeLimit(ctx, a, s.Project, slug, v.Name, v.Limit); err != nil {
			m.log.Warn("give the restored copy its disk size", "service", s.Project+"/"+slug, "volume", v.Name, "error", err)
		}
	}
}

// errNoVolumeBackup: the bucket has no copy of a service's volumes.
var errNoVolumeBackup = errors.New("no backup of these volumes in the destinations")

// recoverVolumes brings back s's volumes on a server where it was just
// deployed with empty ones: the newest copy made up to at.
func (m *Manager) recoverVolumes(ctx context.Context, a Actor, s svcRef, at time.Time, ids []age.Identity) error {
	points, err := m.Dumps(ctx, s.Project, s.Service)
	if err != nil {
		return err
	}
	for _, p := range points { // newest first
		if o, ok := archive.ParseKey(p.Key); ok && o.Kind == archive.KindVolume && !p.LastModified.After(at) {
			_, err := m.restoreVolumes(ctx, a, "", s, p.Key, ids)
			return err
		}
	}
	return errNoVolumeBackup
}
