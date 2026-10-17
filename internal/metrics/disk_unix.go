//go:build unix

package metrics

import "syscall"

// diskUsage is used and total bytes of the filesystem holding path, as df
// shows them: the size is used + available, root's reserve left out.
func diskUsage(path string) (used, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bs := uint64(st.Bsize) //nolint:gosec,unconvert // block size is positive; its type differs per OS
	all := uint64(st.Blocks) * bs
	free := uint64(st.Bfree) * bs
	avail := uint64(st.Bavail) * bs
	if free > all {
		return 0, all
	}
	used = all - free
	return used, used + avail
}
