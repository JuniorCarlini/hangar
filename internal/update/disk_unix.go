//go:build unix

package update

import "syscall"

// freeSpace is the bytes an unprivileged user can still write on the
// filesystem holding path. The root reserve is left out on purpose: the new
// version's pre-migration copy is written by the hangar user.
func freeSpace(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil //nolint:gosec,unconvert // block size is positive; its type differs per OS
}
