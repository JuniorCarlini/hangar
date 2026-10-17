//go:build !unix

package metrics

func diskUsage(string) (used, total uint64) { return 0, 0 }
