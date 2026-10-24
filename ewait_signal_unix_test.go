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
	// cmd_sync is inside the fetch step, after its cleanup trap is armed. The
	// marker, written immediately before the stub's own sleep, lets the test
	// wait (bounded) for the fetch step to actually be running instead of
	// relying on a fixed wall-clock delay — a fixed delay either wastes time
	// when the machine is fast or, under load, fires before the ancestry
	// check (a real `git fetch` against the local fake remote) and the
	// tmp_script mktemp have actually completed, which previously failed
	// this test outright at the hasTempScriptFile check below.
	stubDir := t.TempDir()
	fetchStartedMarker := filepath.Join(stubDir, "fetch-started")
	writeExec(t, filepath.Join(stubDir, "curl"), "#!/usr/bin/env bash\n: > '"+fetchStartedMarker+"'\nsleep 30\n")

	env := testHookEnv(t, "HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase)
	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
	}

	proc := startEwaitAt(t, scriptPath, []string{"--sync", headSHA}, env)

	markerDeadline := time.Now().Add(5 * time.Second)
	var sawFetchStarted bool
	for time.Now().Before(markerDeadline) {
		if _, err := os.Stat(fetchStartedMarker); err == nil {
			sawFetchStarted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawFetchStarted {
		proc.wait(t, 2*time.Second)
		t.Fatalf("fetch-started marker never appeared at %s", fetchStartedMarker)
	}

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
	// Marker written immediately before the stub's own sleep, so the test can
	// wait (bounded) for the fetch step to actually be running instead of
	// relying on a fixed wall-clock delay — a fixed delay either wastes time
	// when the machine is fast or, under load, fires before the ancestry
	// check (a real `git fetch` against the local fake remote) and the
	// tmp_script mktemp have actually completed, which previously failed
	// this test outright at the hasTempScriptFile check below.
	fetchStartedMarker := filepath.Join(stubDir, "fetch-started")
	writeExec(t, filepath.Join(stubDir, "curl"), "#!/usr/bin/env bash\n: > '"+fetchStartedMarker+"'\nsleep 30\n")

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

	markerDeadline := time.Now().Add(5 * time.Second)
	var sawFetchStarted bool
	for time.Now().Before(markerDeadline) {
		if _, err := os.Stat(fetchStartedMarker); err == nil {
			sawFetchStarted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawFetchStarted {
		proc.wait(t, 2*time.Second)
		t.Fatalf("fetch-started marker never appeared at %s", fetchStartedMarker)
	}

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

// TestCheckSource_SIGTERM_CleansUpAndExitsNonZero: proves
// cmd_check_source ALSO installs the vendoring traps (not just cmd_sync) —
// a SIGTERM delivered while --check-source is blocked in its own fetch step
// must stop it (128+signal) and leave no herdr-ewait.check-source.* temp
// file behind, the same guarantee TestSync_SIGTERM_CleansUpAndExitsNonZero
// already proves for --sync.
func TestCheckSource_SIGTERM_CleansUpAndExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	// Marker written immediately before the stub's own sleep, so the test
	// can wait (bounded) for the fetch step to actually be running instead
	// of relying on a fixed wall-clock delay — see
	// TestSync_SIGTERM_CleansUpAndExitsNonZero's comment for why a fixed
	// delay is unreliable under load.
	stubDir := t.TempDir()
	fetchStartedMarker := filepath.Join(stubDir, "fetch-started")
	writeExec(t, filepath.Join(stubDir, "curl"), "#!/usr/bin/env bash\n: > '"+fetchStartedMarker+"'\nsleep 30\n")

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

	proc := startEwaitAt(t, scriptPath, []string{"--check-source"}, env)

	markerDeadline := time.Now().Add(5 * time.Second)
	var sawFetchStarted bool
	for time.Now().Before(markerDeadline) {
		if _, err := os.Stat(fetchStartedMarker); err == nil {
			sawFetchStarted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawFetchStarted {
		proc.wait(t, 2*time.Second)
		t.Fatalf("fetch-started marker never appeared at %s", fetchStartedMarker)
	}

	if !hasCheckSourceTempFile(t, tmpDir) {
		t.Fatalf("expected a herdr-ewait.check-source.* temp file to exist before SIGTERM (trap not yet armed?)")
	}

	if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to process group: %v", err)
	}

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 143 {
		t.Fatalf("exit = %d, want 143 (128+SIGTERM) after cleanup; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if hasCheckSourceTempFile(t, tmpDir) {
		t.Errorf("leftover herdr-ewait.check-source.* temp file after SIGTERM cleanup")
	}
}

func hasCheckSourceTempFile(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "herdr-ewait.check-source.") {
			return true
		}
	}
	return false
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
	// The marker file, written immediately before `sleep 30`, lets the test
	// wait for the sleep to actually be running (not just about to be started)
	// before sending SIGTERM: sending it too early — e.g. while the "init"
	// step that precedes "fetch" is still the foreground command, or in the
	// narrow window between the stub process forking and `sleep` itself
	// starting — can leave bash deferring the TERM trap until that still-
	// running foreground command finishes, which for `sleep 30` is far
	// longer than this test's 10s wait.
	fetchStartedMarker := filepath.Join(stubDir, "fetch-started")
	script := "#!/usr/bin/env bash\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"fetch\" ]; then\n" +
		"    : > '" + fetchStartedMarker + "'\n" +
		"    sleep 30\n" +
		"  fi\n" +
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

	markerDeadline := time.Now().Add(5 * time.Second)
	var sawFetchStarted bool
	for time.Now().Before(markerDeadline) {
		if _, err := os.Stat(fetchStartedMarker); err == nil {
			sawFetchStarted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawFetchStarted {
		proc.wait(t, 2*time.Second)
		t.Fatalf("fetch-started marker never appeared at %s", fetchStartedMarker)
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

// TestSync_SIGTERM_Stress_NoLeftoverTempFiles is a general robustness SMOKE
// TEST, not a deterministic test of the mktemp-to-_register_cleanup gap: it
// sends SIGTERM at a spread of small (millisecond-scale) delays from
// process start, which lands somewhere during the default-branch checks,
// "init", or mid-sleep during the stubbed "fetch" — all comfortably outside
// the actual gap, which is two adjacent bash statements wide (nanoseconds,
// not milliseconds). It does NOT reliably land inside that gap and does
// NOT, on its own, prove the glob-sweep backstop or the $$-scoped mktemp
// templates are doing anything — deleting either (verified: removing
// _cleanup_all's $$ glob-sweep block, or removing $$ from every mktemp
// template) still leaves this test green, because it was never exercising
// that specific race to begin with.
// See TestSync_SIGTERM_DuringScratchDirCreation_LeavesNoLeftovers and
// TestSync_SIGTERM_DuringTmpScriptCreation_LeavesNoLeftovers below for
// deterministic coverage of the actual gap, via a stubbed `mktemp` that
// holds the race window open long enough to signal into reliably. This
// test still has standalone value as a broad, unstructured sanity check
// across the whole flow (bounded runtime: every trial's fake git stub
// sleeps during "fetch" far longer than any delay tried here, so --sync
// never reaches the install phase, and so never mutates the real
// script/sidecar, in any trial).
func TestSync_SIGTERM_Stress_NoLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)

	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found in PATH")
	}

	delays := []time.Duration{
		0,
		5 * time.Millisecond,
		15 * time.Millisecond,
		30 * time.Millisecond,
		50 * time.Millisecond,
		75 * time.Millisecond,
		100 * time.Millisecond,
		150 * time.Millisecond,
		250 * time.Millisecond,
		400 * time.Millisecond,
	}

	for _, delay := range delays {
		t.Run(delay.String(), func(t *testing.T) {
			writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

			stubDir := t.TempDir()
			script := "#!/usr/bin/env bash\n" +
				"for a in \"$@\"; do\n" +
				"  [ \"$a\" = \"fetch\" ] && sleep 5\n" +
				"done\n" +
				"exec '" + realGit + "' \"$@\"\n"
			writeExec(t, filepath.Join(stubDir, "git"), script)

			tmpDir := t.TempDir()
			env := testHookEnv(t, "HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase)
			for j, kv := range env {
				switch {
				case strings.HasPrefix(kv, "PATH="):
					env[j] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
				case strings.HasPrefix(kv, "TMPDIR="):
					env[j] = "TMPDIR=" + tmpDir
				}
			}

			proc := startEwaitAt(t, scriptPath, []string{"--sync", headSHA}, env)
			time.Sleep(delay)
			if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGTERM); err != nil {
				t.Fatalf("send SIGTERM to process group: %v", err)
			}
			proc.wait(t, 10*time.Second)

			assertNoLeftoverVendoringTempFiles(t, tmpDir, dir)
		})
	}
}

// TestSync_SIGTERM_DuringScratchDirCreation_LeavesNoLeftovers deterministically
// reproduces the mktemp-to-_register_cleanup gap by stubbing `mktemp` itself
// (not a downstream git/curl call): the stub runs the REAL mktemp — so the
// scratch directory is genuinely created on disk, exactly as it would be
// for real — then writes a marker and sleeps. Because `scratch="$(mktemp
// -d ...)"` is a command substitution, that assignment (and therefore the
// following `_register_cleanup "$scratch"` line) cannot complete until the
// stub itself exits — so for as long as the stub sleeps, the real,
// on-disk scratch directory is guaranteed to be completely unregistered.
// This holds the actual race window open for seconds instead of the two
// adjacent bash statements (nanoseconds) it normally spans, so the test
// can land a signal inside it reliably via a bounded marker-wait, rather
// than hoping an externally-timed SIGTERM happens to land there (which
// TestSync_SIGTERM_Stress_NoLeftoverTempFiles above does not reliably do).
// No git repo is created at dir, so --sync's default-branch check is
// skipped entirely (no .git found walking up from dir) and the flow goes
// straight to verify_sha_on_upstream.
func TestSync_SIGTERM_DuringScratchDirCreation_LeavesNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, strings.Repeat("a", 40))

	realMktemp, err := exec.LookPath("mktemp")
	if err != nil {
		t.Skip("mktemp not found in PATH")
	}
	stubDir := t.TempDir()
	marker := filepath.Join(stubDir, "mktemp-called")
	// Only the scratch-dir (verify-ancestry) template is slowed; anything
	// else passes through with its real output and no delay.
	script := "#!/usr/bin/env bash\n" +
		"out=\"$('" + realMktemp + "' \"$@\")\"\n" +
		"case \"$*\" in\n" +
		"  *herdr-ewait.verify-ancestry*)\n" +
		"    : > '" + marker + "'\n" +
		"    sleep 30\n" +
		"    ;;\n" +
		"esac\n" +
		"printf '%s\\n' \"$out\"\n"
	writeExec(t, filepath.Join(stubDir, "mktemp"), script)

	tmpDir := t.TempDir()
	env := deadHookEnv(t)
	for i, kv := range env {
		switch {
		case strings.HasPrefix(kv, "PATH="):
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		case strings.HasPrefix(kv, "TMPDIR="):
			env[i] = "TMPDIR=" + tmpDir
		}
	}

	proc := startEwaitAt(t, scriptPath, []string{"--sync", strings.Repeat("b", 40)}, env)

	markerDeadline := time.Now().Add(5 * time.Second)
	var sawMarker bool
	for time.Now().Before(markerDeadline) {
		if _, err := os.Stat(marker); err == nil {
			sawMarker = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawMarker {
		proc.wait(t, 2*time.Second)
		t.Fatalf("mktemp stub's marker never appeared at %s", marker)
	}

	if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to process group: %v", err)
	}

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 143 {
		t.Fatalf("exit = %d, want 143 (128+SIGTERM) after cleanup; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	assertNoLeftoverVendoringTempFiles(t, tmpDir, dir)
}

// TestSync_SIGTERM_DuringTmpScriptCreation_LeavesNoLeftovers is the same
// deterministic technique as the test above, applied to the OTHER
// mktemp-to-_register_cleanup gap this round's fix covers: tmp_script, in
// the sync target directory. Here the ancestry check runs for real (a
// genuine `git fetch`/`merge-base` against setupFakeRemote's local bare
// repo, which completes quickly and is not itself stubbed), so the flow
// reaches cmd_sync's `tmp_script="$(mktemp ...)"` line before the signal —
// exercising the $$-scoped glob sweep's OTHER branch (_CLEANUP_DIR, not
// TMPDIR).
func TestSync_SIGTERM_DuringTmpScriptCreation_LeavesNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	scriptPath := copyScriptToDir(t, dir)
	remoteBase, _, headSHA := setupFakeRemote(t, fakeRepo)
	writeSidecar(t, dir, fakeRepo, fakeScriptRelPath, headSHA)

	realMktemp, err := exec.LookPath("mktemp")
	if err != nil {
		t.Skip("mktemp not found in PATH")
	}
	stubDir := t.TempDir()
	marker := filepath.Join(stubDir, "mktemp-called")
	script := "#!/usr/bin/env bash\n" +
		"out=\"$('" + realMktemp + "' \"$@\")\"\n" +
		"case \"$*\" in\n" +
		"  *.herdr-ewait.sh.tmp.*)\n" +
		"    : > '" + marker + "'\n" +
		"    sleep 30\n" +
		"    ;;\n" +
		"esac\n" +
		"printf '%s\\n' \"$out\"\n"
	writeExec(t, filepath.Join(stubDir, "mktemp"), script)

	env := testHookEnv(t, "HERDR_EWAIT_REMOTE_BASE_URL="+remoteBase)
	var tmpDirUsed string
	for i, kv := range env {
		switch {
		case strings.HasPrefix(kv, "PATH="):
			env[i] = "PATH=" + stubDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		case strings.HasPrefix(kv, "TMPDIR="):
			tmpDirUsed = strings.TrimPrefix(kv, "TMPDIR=")
		}
	}

	proc := startEwaitAt(t, scriptPath, []string{"--sync", headSHA}, env)

	markerDeadline := time.Now().Add(5 * time.Second)
	var sawMarker bool
	for time.Now().Before(markerDeadline) {
		if _, err := os.Stat(marker); err == nil {
			sawMarker = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawMarker {
		proc.wait(t, 2*time.Second)
		t.Fatalf("mktemp stub's marker never appeared at %s", marker)
	}

	if err := syscall.Kill(-proc.cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to process group: %v", err)
	}

	res := proc.wait(t, 10*time.Second)
	if res.exitCode != 143 {
		t.Fatalf("exit = %d, want 143 (128+SIGTERM) after cleanup; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	assertNoLeftoverVendoringTempFiles(t, tmpDirUsed, dir)
}

// assertNoLeftoverVendoringTempFiles scans tmpDir (TMPDIR, for
// verify_sha_on_upstream's scratch dir and --check-source's own temp files)
// and workDir (the synced-into directory, for tmp_script/sidecar_tmp) for
// any file/dir matching one of the script's known vendoring-temp-file
// prefixes.
func assertNoLeftoverVendoringTempFiles(t *testing.T, tmpDir, workDir string) {
	t.Helper()
	tmpPrefixes := []string{
		"herdr-ewait.verify-ancestry.",
		"herdr-ewait.check-source.",
		"herdr-ewait.check-source-latest.",
	}
	if entries, err := os.ReadDir(tmpDir); err == nil {
		for _, e := range entries {
			for _, pfx := range tmpPrefixes {
				if strings.HasPrefix(e.Name(), pfx) {
					t.Errorf("leftover %s under TMPDIR (%s) after SIGTERM", e.Name(), tmpDir)
				}
			}
		}
	}
	workPrefixes := []string{".herdr-ewait.sh.tmp.", ".herdr-ewait.source.tmp."}
	if entries, err := os.ReadDir(workDir); err == nil {
		for _, e := range entries {
			for _, pfx := range workPrefixes {
				if strings.HasPrefix(e.Name(), pfx) {
					t.Errorf("leftover %s under %s after SIGTERM", e.Name(), workDir)
				}
			}
		}
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
