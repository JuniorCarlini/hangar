// Package hostperms puts back the owner and mode of the files the panel needs
// to start. Run as root before every start of hangard (ExecStartPre=+) and
// before an update, so a file left root:root by a manual edit (sudo cp, sudo
// mv) heals itself instead of taking the panel down until someone logs in by
// SSH.
package hostperms

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Want is the owner and mode one path must have. Owner "" is root.
type Want struct {
	Path string
	// Owner and Group: "" is root, "hangar" is the service user.
	Owner, Group string
	Mode         fs.FileMode
	Dir          bool
	// Optional: a missing path is fine (the GitHub token file).
	Optional bool
}

// Plan lists what the panel's files must look like (the same as install.sh
// sets them up).
func Plan(configFile, configDir, masterKey, tokenFile, dataDir string) []Want {
	w := []Want{
		{Path: configDir, Group: "hangar", Mode: 0o750, Dir: true},
		{Path: configFile, Group: "hangar", Mode: 0o640},
		{Path: masterKey, Owner: "hangar", Group: "hangar", Mode: 0o400},
		{Path: dataDir, Owner: "hangar", Group: "hangar", Mode: 0o700, Dir: true},
	}
	if tokenFile != "" {
		w = append(w, Want{Path: tokenFile, Owner: "hangar", Group: "hangar", Mode: 0o400, Optional: true})
	}
	return w
}

// Lookup resolves user and group names to ids.
type Lookup func(name string) (uid, gid int, err error)

// SystemLookup reads /etc/passwd and /etc/group ("" is root).
func SystemLookup(name string) (int, int, error) {
	if name == "" {
		return 0, 0, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// Fix makes every path in plan match it and returns what it changed. A
// symlink is never followed nor touched (it could point anywhere), and a
// path of the wrong kind (a directory where a file belongs) is an error
// left for a person: changing it could hide what happened.
func Fix(plan []Want, lookup Lookup) ([]string, error) {
	var changed []string
	var errs []error
	for _, w := range plan {
		if w.Path == "" {
			continue
		}
		st, err := os.Lstat(w.Path)
		if errors.Is(err, fs.ErrNotExist) {
			if !w.Optional {
				errs = append(errs, fmt.Errorf("%s is missing", w.Path))
			}
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			errs = append(errs, fmt.Errorf("%s is a symlink; not touched", w.Path))
			continue
		}
		if st.IsDir() != w.Dir {
			errs = append(errs, fmt.Errorf("%s is not a %s", w.Path, kind(w.Dir)))
			continue
		}
		uid, _, err := lookup(w.Owner)
		if err != nil {
			errs = append(errs, fmt.Errorf("user %q: %w", w.Owner, err))
			continue
		}
		_, gid, err := lookup(w.Group)
		if err != nil {
			errs = append(errs, fmt.Errorf("group %q: %w", w.Group, err))
			continue
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if int(sys.Uid) != uid || int(sys.Gid) != gid {
			if err := os.Lchown(w.Path, uid, gid); err != nil {
				errs = append(errs, err)
				continue
			}
			changed = append(changed, fmt.Sprintf("%s owner %d:%d -> %d:%d", w.Path, sys.Uid, sys.Gid, uid, gid))
		}
		if st.Mode().Perm() != w.Mode {
			if err := os.Chmod(w.Path, w.Mode); err != nil {
				errs = append(errs, err)
				continue
			}
			changed = append(changed, fmt.Sprintf("%s mode %o -> %o", w.Path, st.Mode().Perm(), w.Mode))
		}
	}
	return changed, errors.Join(errs...)
}

func kind(dir bool) string {
	if dir {
		return "directory"
	}
	return "file"
}
