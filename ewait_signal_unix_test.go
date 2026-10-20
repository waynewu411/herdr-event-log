//go:build !windows

package main

// TestSync_SIGINT_CleansUpAndExitsNonZero is unix-only (sending a real SIGINT
// via syscall is meaningless on Windows, and these tests are already skipped
// there via requireEwaitTools).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestWaitMode_SIGTERM_StopsQuickly_NotDeferredByPoll:
// installing the vendoring INT/TERM traps unconditionally at script scope
// regressed ordinary wait-mode runs — a trap is only ever acted on BETWEEN
// foreground commands, so with one installed, SIGTERM is deferred until the
// current `sleep "$POLL"`/`herdr agent get` call finishes (measured: up to a
// full --poll interval, here 60s, instead of immediately). Wait mode must now
// install no trap at all and behave exactly as before vendoring was added:
// SIGTERM kills bash itself within a couple of seconds, not up to --poll.
//
// This deliberately signals ONLY bash's own pid (not the whole process group
// via -pid, the way the --sync signal tests do): that matches how a real
// supervisor/process manager tracking a single child pid delivers SIGTERM,
// and is exactly the scenario that exposed the regression — if the blocking
// `sleep "$POLL"` child were ALSO signaled (a process-group-wide kill), it
// would die immediately and mask the deferred-trap bug entirely.
//
// Liveness is checked by polling kill(pid, 0) directly, NOT by waiting on
// proc.wait()/cmd.Wait(): cmd.Wait() also blocks until the Stdout/Stderr
// io-copy goroutines see EOF, and since bash's own SIGTERM (sent to only its
// pid) leaves the still-running `sleep "$POLL"` child alive as an orphan that
// inherited the SAME stdout/stderr pipe, that orphan keeps the pipe open —
// and cmd.Wait() blocked — for the rest of its sleep, regardless of how
// quickly bash itself actually died (the same caveat killProcessGroup's own
// doc comment describes for exactly this reason). kill(pid, 0) only asks
// "does this specific pid still exist", independent of any lingering
// child/pipe, so it isolates bash's own death precisely.
func TestWaitMode_SIGTERM_StopsQuickly_NotDeferredByPoll(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)

	proc := startEwait(t, []string{
		"--targets", "w9:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "3600",
		"--poll", "60",
		"--safety-net", "60",
	}, stubConfig{alwaysWorking: "w9:p1"})
	defer killProcessGroup(proc.cmd) // reap the orphaned `sleep 60` either way

	time.Sleep(700 * time.Millisecond) // let it get into its poll loop first

	pid := proc.cmd.Process.Pid
	if err := proc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second) // well under --poll's 60s; the bug made this take ~60s
	for {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return // bash itself is gone — success
		}
		if time.Now().After(deadline) {
			t.Fatalf("bash (pid %d) still alive 3s after SIGTERM — a trap is deferring it until the current poll/herdr-call finishes", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

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

// TestSync_SIGTERM_CleansUpAndExitsNonZero: SIGTERM must stop a sync in
// progress exactly like SIGINT does (128+signal, cleanup), and — since this
// signal lands during the fetch step, before either atomic mv — the original
// script file must be left completely untouched, not just "no leftover temp
// file".
func TestSync_SIGTERM_CleansUpAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	stubDir := t.TempDir()
	writeExec(t, filepath.Join(stubDir, "curl"), "#!/usr/bin/env bash\nsleep 30\n")

	env := testHookEnv(t, "HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	origScript, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}

	proc := startEwaitAt(t, scriptPath, []string{"--sync", headSHA}, env)
	time.Sleep(700 * time.Millisecond) // let it reach the (trap-armed) fetch step

	if !hasTempScriptFile(t, dir) {
		t.Fatalf("expected a .herdr-ewait.sh.tmp.* file to exist before SIGTERM (trap not yet armed?)")
	}

	if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to process group: %v", err)
	}

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 143 {
		t.Fatalf("exit = %d, want 143 (128+SIGTERM) after cleanup; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}

	if hasTempScriptFile(t, dir) {
		t.Errorf("leftover .herdr-ewait.sh.tmp.* file after SIGTERM cleanup")
	}
	gotScript, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotScript) != string(origScript) {
		t.Errorf("script file content changed even though SIGTERM arrived before any mv — nothing should have been installed")
	}
}

// TestSync_SIGTERM_DuringAncestryCheck_LeavesNoScratchDir: the ancestry
// scratch dir created by verify_sha_on_upstream must be registered for cleanup
// too, not just check-source's/sync's own temp files — a SIGTERM delivered
// while `git fetch` is still running inside the ancestry check must not leak
// a herdr-ewait.verify-ancestry.* directory.
func TestSync_SIGTERM_DuringAncestryCheck_LeavesNoScratchDir(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found in PATH")
	}
	stubDir := t.TempDir()
	// Passthrough to the real git for everything except a "fetch" invocation
	// (verify_sha_on_upstream's long-running ancestry step), which blocks long
	// enough for the test to deliver SIGTERM while the scratch dir still exists.
	script := "#!/usr/bin/env bash\n" +
		"for a in \"$@\"; do\n" +
		"  [ \"$a\" = \"fetch\" ] && sleep 30\n" +
		"done\n" +
		"exec '" + realGit + "' \"$@\"\n"
	writeExec(t, filepath.Join(stubDir, "git"), script)

	tmpDir := t.TempDir()
	env := testHookEnv(t, "HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase)
	for i, kv := range env {
		switch {
		case strings.HasPrefix(kv, "PATH="):
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		case strings.HasPrefix(kv, "TMPDIR="):
			env[i] = "TMPDIR=" + tmpDir
		}
	}

	proc := startEwaitAt(t, scriptPath, []string{"--sync", headSHA}, env)

	deadline := time.Now().Add(5 * time.Second)
	var sawScratch bool
	for time.Now().Before(deadline) {
		if hasAncestryScratchDir(t, tmpDir) {
			sawScratch = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sawScratch {
		proc.wait(t, 2*time.Second)
		t.Fatalf("ancestry scratch dir never appeared under %s", tmpDir)
	}

	if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to process group: %v", err)
	}

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 143 {
		t.Fatalf("exit = %d, want 143 (128+SIGTERM) after cleanup; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if hasAncestryScratchDir(t, tmpDir) {
		t.Errorf("leftover herdr-ewait.verify-ancestry.* scratch dir after SIGTERM cleanup")
	}
}

func hasAncestryScratchDir(t *testing.T, tmpDir string) bool {
	t.Helper()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "herdr-ewait.verify-ancestry.") {
			return true
		}
	}
	return false
}
