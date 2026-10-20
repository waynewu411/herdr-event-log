//go:build !windows

package main

// TestSync_SIGINT_CleansUpAndExitsNonZero is unix-only (sending a real SIGINT
// via syscall is meaningless on Windows, and these tests are already skipped
// there via requireEwaitTools).

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSync_SIGINT_CleansUpAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// A curl stub that blocks long enough for the test to deliver SIGINT while
	// cmd_sync is inside the fetch step, after its cleanup trap is armed.
	stubDir := t.TempDir()
	writeExec(t, filepath.Join(stubDir, "curl"), "#!/usr/bin/env bash\nsleep 30\n")

	env := testHookEnv(t, "HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	proc := startEwaitAt(t, scriptPath, []string{"--sync", headSHA}, env)
	time.Sleep(700 * time.Millisecond) // let it reach the (trap-armed) fetch step

	if !hasTempScriptFile(t, dir) {
		t.Fatalf("expected a .herdr-ewait.sh.tmp.* file to exist before SIGINT (trap not yet armed?)")
	}

	// A plain Process.Signal() targets only bash's own PID — bash defers running a
	// trap until its current FOREGROUND CHILD (curl, here) returns, exactly like a
	// real terminal's Ctrl-C needs to reach the whole foreground process group to
	// interrupt a blocking child at all. setNewProcessGroup already made bash (and
	// everything it spawns) its own group, at its own pid — signal that group.
	if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT to process group: %v", err)
	}

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 130 {
		t.Fatalf("exit = %d, want 130 (128+SIGINT) after cleanup; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}

	if hasTempScriptFile(t, dir) {
		t.Errorf("leftover .herdr-ewait.sh.tmp.* file after SIGINT cleanup")
	}
}

func hasTempScriptFile(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".herdr-ewait.sh.tmp.") {
			return true
		}
	}
	return false
}
