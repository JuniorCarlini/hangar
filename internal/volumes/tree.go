//go:build unix

package volumes

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Walks here never follow symbolic links: the files belong to the apps
// and root only looks at them.

func statOf(path string) fs.FileInfo {
	fi, err := os.Lstat(path)
	if err != nil || !fi.IsDir() {
		return nil
	}
	return fi
}

// clearDir empties dir (a fresh image's folder, or the new plain volume a
// copy goes to) without removing it.
func clearDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// copyAttrs gives dst the owner and mode of src (cp copies what is inside).
func copyAttrs(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no file owner on this system")
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(dst, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	return syscall.Chmod(dst, uint32(st.Mode)&0o7777) //nolint:unconvert // the mode's type differs per OS
}

// entry is what a copy must keep of a file.
type entry struct {
	mode     fs.FileMode
	uid, gid uint32
	size     int64
	link     string
}

func entryOf(path string, fi fs.FileInfo) (entry, error) {
	e := entry{mode: fi.Mode() & (fs.ModeType | fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.uid, e.gid = st.Uid, st.Gid
	}
	switch {
	case fi.Mode().IsRegular():
		e.size = fi.Size()
	case fi.Mode()&fs.ModeSymlink != 0:
		l, err := os.Readlink(path)
		if err != nil {
			return e, err
		}
		e.link = l
	}
	return e, nil
}

// tree lists every entry under root by relative path.
func tree(root string) (map[string]entry, error) {
	out := map[string]entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e, err := entryOf(p, fi)
		if err != nil {
			return err
		}
		out[rel] = e
		return nil
	})
	return out, err
}

// verifyCopy checks dst holds exactly src's entries, with the same type,
// mode, owner, size and link target.
func verifyCopy(src, dst string) error {
	a, err := tree(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	b, err := tree(dst)
	if err != nil {
		return fmt.Errorf("read the copy: %w", err)
	}
	for rel, want := range a {
		got, ok := b[rel]
		switch {
		case !ok:
			return fmt.Errorf("copy check: %s is missing", rel)
		case got.mode != want.mode:
			return fmt.Errorf("copy check: %s has mode %v, want %v", rel, got.mode, want.mode)
		case got.uid != want.uid || got.gid != want.gid:
			return fmt.Errorf("copy check: %s belongs to %d:%d, want %d:%d", rel, got.uid, got.gid, want.uid, want.gid)
		case got.size != want.size:
			return fmt.Errorf("copy check: %s has %d bytes, want %d", rel, got.size, want.size)
		case got.link != want.link:
			return fmt.Errorf("copy check: link %s points to %q, want %q", rel, got.link, want.link)
		}
	}
	if len(b) != len(a) {
		return fmt.Errorf("copy check: %d entries in the copy, %d in the source", len(b), len(a))
	}
	return nil
}

// allocated is the disk space the files under root take (blocks really
// used: holes in sparse files are free).
func allocated(root string) (uint64, error) {
	var n uint64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
			n += uint64(st.Blocks) * 512 //nolint:gosec // checked positive
		}
		return nil
	})
	return n, err
}

// statfs is the filesystem holding path, as df shows it: used, size
// (used + available) and available bytes.
func statfs(path string) (used, total, avail uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec,unconvert // block size is positive; its type differs per OS
	all := uint64(st.Blocks) * bs
	free := uint64(st.Bfree) * bs
	avail = uint64(st.Bavail) * bs
	if free > all {
		return 0, all, avail, nil
	}
	used = all - free
	return used, used + avail, avail, nil
}

// Statfs is statfs for the panel (the free space of the server's disk, a
// limited volume's usage).
func Statfs(path string) (used, total, avail uint64, err error) { return statfs(path) }

// SameDevice reports whether a and b are on the same filesystem (the panel
// checks a limited volume's mount point is really a mount in its view).
func SameDevice(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return true
	}
	sa, ok1 := fa.Sys().(*syscall.Stat_t)
	sb, ok2 := fb.Sys().(*syscall.Stat_t)
	return !ok1 || !ok2 || sa.Dev == sb.Dev
}
