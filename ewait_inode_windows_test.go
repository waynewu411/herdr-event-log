//go:build windows

package main

import "testing"

// inode is a no-op on Windows. herdr-ewait.sh requires bash and these tests are
// skipped there (requireEwaitTools), so this exists only to keep the test binary
// building.
func inode(t *testing.T, path string) uint64 {
	t.Helper()
	t.Skip("inode not meaningful on Windows")
	return 0
}
