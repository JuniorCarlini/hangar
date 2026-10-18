//go:build !unix

package update

import "math"

// freeSpace is not measured off unix; the check always passes there.
func freeSpace(string) (uint64, error) { return math.MaxUint64, nil }
