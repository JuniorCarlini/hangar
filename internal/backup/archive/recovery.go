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
// postgresql.auto.conf and recovery.signal. Both the panel and
// hangar-cofre restore-local extract it into an empty PGDATA.
func WriteRecoveryTar(w io.Writer, plan Plan, open Opener, ids []age.Identity) error {
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
	settings := RecoverySettings(plan)
	sawConf := false
	err = CopyTar(tw, tar.NewReader(base), DefaultTarLimits, func(name string, body io.Reader) ([]byte, bool, error) {
		if name != "postgresql.auto.conf" {
			return nil, false, nil
		}
		sawConf = true
		b, err := io.ReadAll(io.LimitReader(body, 1<<20))
		return append(b, settings...), true, err
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
