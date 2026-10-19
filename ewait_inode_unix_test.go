//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

// inode returns path's inode number, used to prove --sync's replace is a real atomic
// rename (new inode) rather than an in-place edit (same inode).
func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		t.Skip("inode not available via syscall.Stat_t on this platform")
	}
	return st.Ino
}
