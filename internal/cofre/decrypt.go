package cofre

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/pgroles"
)

// Written is a file decrypt wrote.
type Written struct {
	Path string
	Size int64
}

// maxBundleFiles bounds the members of a downloaded bundle.
const maxBundleFiles = 16

// DecryptBackup decrypts what the operator has: a .age file, a pg_dump
// together with the roles saved next to it (archive.RolesKey), or a .zip
// downloaded from the panel. Roles come out as pg_dumpall's SQL plus a
// script that recreates only the roles a server lacks
// (archive.ExtRolesRestore). out is the file (or, for a .zip, the folder)
// to write; empty picks a name next to in.
func (v *Vault) DecryptBackup(in, out string) ([]Written, error) {
	if strings.HasSuffix(in, archive.ExtBundle) {
		if out == "" {
			out = strings.TrimSuffix(in, archive.ExtBundle)
		}
		return v.decryptBundle(in, out)
	}
	if out == "" {
		out = DecryptedName(in)
	}
	n, err := v.DecryptFile(in, out)
	if err != nil {
		return nil, err
	}
	done := []Written{{out, n}}
	switch {
	case strings.HasSuffix(in, archive.ExtRoles):
		w, err := writeRestoreScript(out, strings.TrimSuffix(out, archive.ExtRolesSQL)+archive.ExtRolesRestore)
		return append(done, w...), err
	case strings.HasSuffix(in, archive.ExtDump):
		roles := archive.RolesKey(in)
		if _, err := os.Stat(roles); errors.Is(err, fs.ErrNotExist) {
			return done, nil // a dump made before roles were saved
		}
		base, _ := strings.CutSuffix(out, ".dump")
		w, err := v.DecryptBackup(roles, base+archive.ExtRolesSQL)
		return append(done, w...), err
	}
	return done, nil
}

// writeRestoreScript writes, next to a decrypted roles file, the script
// that recreates only the missing roles.
func writeRestoreScript(rolesPath, dest string) ([]Written, error) {
	raw, err := os.ReadFile(rolesPath) //nolint:gosec // the file just written
	if err != nil {
		return nil, err
	}
	script, err := pgroles.RestoreScript(raw)
	if err != nil {
		return nil, err
	}
	if err := writeNew(dest, strings.NewReader(string(script))); err != nil {
		return nil, err
	}
	return []Written{{dest, int64(len(script))}}, nil
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, r io.Reader) error {
	o, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // a path the operator named
	if err != nil {
		return err
	}
	_, cerr := io.Copy(o, r)
	if err := o.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		_ = os.Remove(path)
	}
	return cerr
}

// decryptBundle unpacks a .zip from the panel into dir, decrypting its
// .age files.
func (v *Vault) decryptBundle(in, dir string) ([]Written, error) {
	zr, err := zip.OpenReader(in)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	if len(zr.File) > maxBundleFiles {
		return nil, fmt.Errorf("%s: not a Hangar backup (%d files)", in, len(zr.File))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var done []Written
	for _, zf := range zr.File {
		name := zf.Name
		if name != filepath.Base(name) || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			return done, fmt.Errorf("%s: unexpected file %q", in, name)
		}
		rc, err := zf.Open()
		if err != nil {
			return done, err
		}
		dest := filepath.Join(dir, name) //nolint:gosec // name is a bare file name, checked above
		if strings.HasSuffix(name, ".age") {
			dest = filepath.Join(dir, DecryptedName(name))
			plain, err := archive.Open(rc, v.ids, archive.LimitsFor(name))
			if err != nil {
				_ = rc.Close()
				return done, err
			}
			err = writeNew(dest, plain)
			_ = plain.Close()
			_ = rc.Close()
			if err != nil {
				return done, err
			}
		} else {
			err = writeNew(dest, rc)
			_ = rc.Close()
			if err != nil {
				return done, err
			}
		}
		info, _ := os.Stat(dest)
		var size int64
		if info != nil {
			size = info.Size()
		}
		done = append(done, Written{dest, size})
		if strings.HasSuffix(name, archive.ExtRoles) {
			w, err := writeRestoreScript(dest, strings.TrimSuffix(dest, archive.ExtRolesSQL)+archive.ExtRolesRestore)
			done = append(done, w...)
			if err != nil {
				return done, err
			}
		}
	}
	return done, nil
}
