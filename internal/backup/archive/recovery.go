package archive

import (
	"archive/tar"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
)

// Opener opens an encrypted object by key (from a bucket or a local copy).
type Opener func(key string) (io.ReadCloser, error)

// MaxWALFile bounds a WAL file read into memory (segments are 16 MiB by
// default).
const MaxWALFile = 64 << 20

// WriteRecoveryTar writes a ready-to-start PostgreSQL data directory as a
// tar: the base backup (checked entry by entry), the WAL files to replay
// under RestoreWALDir, the recovery settings appended to
// postgresql.auto.conf and recovery.signal. The panel extracts it into an
// empty PGDATA of the service's own volume.
func WriteRecoveryTar(w io.Writer, plan Plan, open Opener, ids []age.Identity) error {
	return writeRecoveryTar(w, plan, open, ids, RecoverySettings(plan))
}

// WriteLocalRecoveryTar is WriteRecoveryTar for a data directory that
// starts outside the server, on the operator's computer (hangar-cofre
// restore-local): LocalOverrides come last in postgresql.auto.conf.
func WriteLocalRecoveryTar(w io.Writer, plan Plan, open Opener, ids []age.Identity) error {
	return writeRecoveryTar(w, plan, open, ids, RecoverySettings(plan)+LocalOverrides)
}

// LocalOverrides neutralize, in a data directory restored on the
// operator's computer, every setting that makes PostgreSQL run a command
// or load code: the app owns its database's superuser, so it can put
// anything in postgresql.conf and postgresql.auto.conf (ALTER SYSTEM, or
// writing the files), and a base backup carries both. The last value of a
// setting wins, and postgresql.auto.conf is read last, so these lines,
// appended at its very end, override whatever came before. Archiving is
// off, which also keeps archive_library from loading. Every name exists
// since PostgreSQL 12 (an unknown one would stop the server).
const LocalOverrides = `
# Added by hangar-cofre: nothing the app configured runs on this computer.
archive_mode = 'off'
archive_command = ''
archive_cleanup_command = ''
recovery_end_command = ''
ssl_passphrase_command = ''
primary_conninfo = ''
primary_slot_name = ''
shared_preload_libraries = ''
local_preload_libraries = ''
session_preload_libraries = ''
dynamic_library_path = '$libdir'
jit = 'off'
`

func writeRecoveryTar(w io.Writer, plan Plan, open Opener, ids []age.Identity, settings string) error {
	tw := tar.NewWriter(w)
	rc, err := open(plan.Base.Key)
	if err != nil {
		return err
	}
	base, err := Open(rc, ids, DefaultLimits)
	if err != nil {
		_ = rc.Close()
		return err
	}
	sawConf := false
	err = CopyTar(tw, tar.NewReader(base), DefaultTarLimits, func(name string, body io.Reader) ([]byte, bool, error) {
		if name != "postgresql.auto.conf" {
			return nil, false, nil
		}
		sawConf = true
		b, err := io.ReadAll(io.LimitReader(body, 1<<20))
		// A last line without its newline would swallow the first of ours.
		return append(append(b, '\n'), settings...), true, err
	})
	_ = base.Close()
	_ = rc.Close()
	if err != nil {
		return err
	}
	if !sawConf {
		if err := writeEntry(tw, "postgresql.auto.conf", []byte(settings)); err != nil {
			return err
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: RestoreWALDir + "/", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: time.Now()}); err != nil {
		return err
	}
	for _, l := range plan.WAL {
		o, _ := ParseKey(l.Key)
		b, err := ReadSealed(open, l.Key, ids, MaxWALFile)
		if err != nil {
			return fmt.Errorf("WAL %s: %w", o.Name, err)
		}
		if err := writeEntry(tw, RestoreWALDir+"/"+o.Name, b); err != nil {
			return err
		}
	}
	if err := writeEntry(tw, "recovery.signal", nil); err != nil {
		return err
	}
	return tw.Close()
}

func writeEntry(tw *tar.Writer, name string, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// ReadSealed opens a small encrypted object fully into memory.
func ReadSealed(open Opener, key string, ids []age.Identity, limit int64) ([]byte, error) {
	rc, err := open(key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	plain, err := Open(rc, ids, Limits{MaxBytes: limit})
	if err != nil {
		return nil, err
	}
	defer func() { _ = plain.Close() }()
	return io.ReadAll(plain)
}

// StageScript replaces PGDATA (from the image's environment) with the tar
// read from stdin, keeping what was there aside in PGDATA.before-restore
// until the restore is proven. It runs as root inside the PostgreSQL image
// with the data volume mounted.
const StageScript = `set -eu
parent=$(dirname "$PGDATA")
mkdir -p "$parent"
rm -rf "$PGDATA.before-restore"
if [ -d "$PGDATA" ]; then mv "$PGDATA" "$PGDATA.before-restore"; fi
mkdir -p "$PGDATA"
cd "$PGDATA"
tar -x -f -
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"
`
