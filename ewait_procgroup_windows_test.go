//go:build windows

package main

import "os/exec"

// setNewProcessGroup is a no-op on Windows. herdr-ewait.sh requires bash and these
// tests are skipped there (requireEwaitTools), so this exists only to keep the test
// binary building.
func setNewProcessGroup(cmd *exec.Cmd) {}

// killProcessGroup falls back to killing just the direct child on Windows; never
// actually exercised, since the tests that call it are skipped there.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
