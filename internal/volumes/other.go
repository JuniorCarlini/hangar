//go:build !unix

package volumes

import "errors"

// Statfs is not available off Unix: limits need Linux.
func Statfs(string) (used, total, avail uint64, err error) {
	return 0, 0, 0, errors.New("not supported on this system")
}

// SameDevice cannot tell off Unix.
func SameDevice(string, string) bool { return true }
