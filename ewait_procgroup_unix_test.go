//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// setNewProcessGroup configures cmd so it and any children it spawns (the script's own
// `sleep`, and the herdr stub it invokes) run in a new process group, letting
// killProcessGroup below kill all of them together instead of only the direct bash child.
func setNewProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills cmd's entire process group. A plain Process.Kill() only kills
// the direct bash child; an orphaned `sleep "$POLL"` (or a herdr stub call) then keeps
// the subprocess's stdout/stderr pipes open, which blocks cmd.Wait() for however long
// that child has left to run — turning a hung script into a slow test failure instead of
// a fast one.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
