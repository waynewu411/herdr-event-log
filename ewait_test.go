package main

// TestEwait_* exercises scripts/herdr-ewait.sh as a real subprocess, against a
// fake `herdr` stub on PATH — see issue #9 and its round-1 review. No live
// Herdr session is required.
//
// The stub (herdrStubScript below) implements only `herdr agent get <target>`:
//   - a target in $HERDR_STUB_UNRESOLVABLE (comma-separated) fails with a
//     realistic agent_not_found error JSON on stdout, exit 1 (simulates an
//     unresolvable --targets entry: unknown name, or herdr down);
//   - a target in $HERDR_STUB_ALWAYS_WORKING (comma-separated) always reports
//     agent_status "working" with pane_id == the target itself (simulates a
//     target that never reaches a terminal state, for the overall-timeout
//     path, or a resolvable-but-idle target for diagnostic-only checks);
//   - the target in $HERDR_STUB_NOT_YET_DETECTED fails with the SAME
//     agent_not_found error for its first $HERDR_STUB_DETECT_AFTER calls (a
//     pane that exists but whose agent herdr hasn't classified yet), then
//     falls through to the counter-based branch below, using the target
//     itself as the resolved pane_id;
//   - a target found in $HERDR_STUB_MAP ("name1=pane1;name2=pane2") resolves
//     to the mapped pane id and reports "working" forever — no counter, used
//     to check multi-target resolution/diagnostics without needing a hit;
//   - any other target increments a shared counter file and reports pane_id =
//     $HERDR_STUB_PANE_ID with agent_status "working" while the counter is <=
//     $HERDR_STUB_FLIP_AT, then "done" after that. This lets a test control
//     exactly which call (startup resolution, check-first, a later safety-net
//     sweep, or a log-triggered verify) first observes the terminal state,
//     without depending on real wall-clock timing.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const herdrStubScript = `#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != "agent" ] || [ "$2" != "get" ]; then
  exit 1
fi
target="$3"

unresolvable=",${HERDR_STUB_UNRESOLVABLE:-},"
case "$unresolvable" in
  *",$target,"*)
    printf '{"error":{"code":"agent_not_found","message":"agent target %s not found"},"id":"cli:agent:get"}\n' "$target"
    exit 1
    ;;
esac

always_working=",${HERDR_STUB_ALWAYS_WORKING:-},"
case "$always_working" in
  *",$target,"*)
    printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"working"}\n' "$target"
    exit 0
    ;;
esac

not_yet_detected="${HERDR_STUB_NOT_YET_DETECTED:-}"
if [ -n "$not_yet_detected" ] && [ "$target" = "$not_yet_detected" ]; then
  detect_after="${HERDR_STUB_DETECT_AFTER:?missing}"
  detect_counter_file="${HERDR_STUB_DETECT_COUNTER_FILE:?missing}"
  dn=0
  if [ -f "$detect_counter_file" ]; then
    dn="$(cat "$detect_counter_file")"
  fi
  dn=$((dn+1))
  printf '%s' "$dn" > "$detect_counter_file"
  if [ "$dn" -le "$detect_after" ]; then
    printf '{"error":{"code":"agent_not_found","message":"agent target %s not found"},"id":"cli:agent:get"}\n' "$target"
    exit 1
  fi
  # detected now: fall through to the counter-based branch below, using the
  # target itself as the canonical pane_id (it already looks like one).
fi

map="${HERDR_STUB_MAP:-}"
if [ -n "$map" ]; then
  mapped="$(printf '%s' "$map" | tr ';' '\n' | grep -F "${target}=" | head -n1 | sed 's/^[^=]*=//')"
  if [ -n "$mapped" ]; then
    printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"working"}\n' "$mapped"
    exit 0
  fi
fi

counter_file="${HERDR_STUB_COUNTER_FILE:?missing}"
flip_at="${HERDR_STUB_FLIP_AT:?missing}"
pane_id="${HERDR_STUB_PANE_ID:?missing}"
n=0
if [ -f "$counter_file" ]; then
  n="$(cat "$counter_file")"
fi
n=$((n+1))
printf '%s' "$n" > "$counter_file"
status="working"
if [ "$n" -gt "$flip_at" ]; then
  status="done"
fi
printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"%s"}\n' "$pane_id" "$status"
`

// stubConfig configures the fake herdr for one test run. Zero value is valid
// (no target will ever match a special case, and the default-case branch is
// simply never reached if the script never calls herdr).
type stubConfig struct {
	unresolvable      string // comma-separated targets -> agent_not_found error, exit 1
	alwaysWorking     string // comma-separated targets -> identity pane_id, "working" forever
	notYetDetected    string // single target -> agent_not_found for detectAfter calls, then falls through
	detectAfter       int
	detectCounterFile string
	mapEntries        string // "name1=pane1;name2=pane2" -> mapped pane_id, "working" forever
	paneID            string
	flipAt            int
	counterFile       string
	omitHerdr         bool // if true, herdr is absent from PATH entirely
}

func (c stubConfig) env() []string {
	env := os.Environ()
	set := func(k, v string) { env = append(env, k+"="+v) }
	if c.unresolvable != "" {
		set("HERDR_STUB_UNRESOLVABLE", c.unresolvable)
	}
	if c.alwaysWorking != "" {
		set("HERDR_STUB_ALWAYS_WORKING", c.alwaysWorking)
	}
	if c.notYetDetected != "" {
		set("HERDR_STUB_NOT_YET_DETECTED", c.notYetDetected)
		set("HERDR_STUB_DETECT_AFTER", strconv.Itoa(c.detectAfter))
		set("HERDR_STUB_DETECT_COUNTER_FILE", c.detectCounterFile)
	}
	if c.mapEntries != "" {
		set("HERDR_STUB_MAP", c.mapEntries)
	}
	if c.paneID != "" {
		set("HERDR_STUB_PANE_ID", c.paneID)
		set("HERDR_STUB_FLIP_AT", strconv.Itoa(c.flipAt))
		set("HERDR_STUB_COUNTER_FILE", c.counterFile)
	}
	return env
}

func requireEwaitTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("herdr-ewait.sh requires bash/grep/sed, not available on windows")
	}
	for _, tool := range []string{"bash", "grep", "sed", "tail", "wc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH: %v", tool, err)
		}
	}
}

func ewaitScriptPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("scripts", "herdr-ewait.sh"))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("herdr-ewait.sh not found at %s: %v", path, err)
	}
	return path
}

func writeHerdrStub(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "herdr")
	if err := os.WriteFile(path, []byte(herdrStubScript), 0o755); err != nil {
		t.Fatalf("write herdr stub: %v", err)
	}
}

// minimalToolsPath builds a PATH containing only the directories that hold
// the core tools herdr-ewait.sh itself needs (bash/grep/sed/tail/wc), with no
// herdr stub added — used to simulate "herdr is not installed at all"
// (L5/#9 review) without accidentally picking up a real herdr binary that
// might happen to be on this machine's normal PATH.
func minimalToolsPath(t *testing.T) string {
	t.Helper()
	tools := []string{"bash", "grep", "sed", "tail", "wc", "cat", "date", "head"}
	dirSet := map[string]bool{}
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not found in PATH: %v", tool, err)
		}
		dirSet[filepath.Dir(p)] = true
	}
	var dirs []string
	for d := range dirSet {
		dirs = append(dirs, d)
	}
	path := strings.Join(dirs, string(os.PathListSeparator))

	check := exec.Command("env", "-i", "PATH="+path, "sh", "-c", "command -v herdr")
	if err := check.Run(); err == nil {
		t.Skip("a real herdr binary is colocated with core shell tools on this machine; skipping the herdr-unreachable test")
	}
	return path
}

type ewaitResult struct {
	stdout   string
	stderr   string
	exitCode int
}

type ewaitProcess struct {
	cmd    *exec.Cmd
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	done   chan error
}

// startEwait launches herdr-ewait.sh as a subprocess with the fake herdr
// stub prepended to PATH (or, with stub.omitHerdr, no herdr on PATH at all).
// The caller must eventually call wait().
func startEwait(t *testing.T, args []string, stub stubConfig) *ewaitProcess {
	t.Helper()
	requireEwaitTools(t)

	scriptPath := ewaitScriptPath(t)

	var pathEnv string
	if stub.omitHerdr {
		pathEnv = minimalToolsPath(t)
	} else {
		stubDir := t.TempDir()
		writeHerdrStub(t, stubDir)
		pathEnv = stubDir + string(os.PathListSeparator) + os.Getenv("PATH")
	}

	cmd := exec.Command("bash", append([]string{scriptPath}, args...)...)
	cmd.Env = append(stub.env(), "PATH="+pathEnv)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start herdr-ewait.sh: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return &ewaitProcess{cmd: cmd, stdout: &stdout, stderr: &stderr, done: done}
}

func (p *ewaitProcess) wait(t *testing.T, timeout time.Duration) ewaitResult {
	t.Helper()
	select {
	case err := <-p.done:
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				t.Fatalf("herdr-ewait.sh did not run: %v (stderr: %s)", err, p.stderr.String())
			}
		}
		return ewaitResult{stdout: p.stdout.String(), stderr: p.stderr.String(), exitCode: code}
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Fatalf("herdr-ewait.sh did not exit within %s (stdout: %q, stderr: %q)", timeout, p.stdout.String(), p.stderr.String())
		return ewaitResult{}
	}
}

func runEwait(t *testing.T, args []string, stub stubConfig, timeout time.Duration) ewaitResult {
	t.Helper()
	return startEwait(t, args, stub).wait(t, timeout)
}

// waitForFileToExist polls for path to appear. Used to synchronize with the
// script's own cursor-file write (it writes the fresh cursor immediately
// after check-first), so a test can append log bytes only once the script
// has actually snapshotted its starting cursor — appending any earlier would
// race the snapshot and silently fold the new bytes into "no new bytes".
func waitForFileToExist(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to exist", path)
}

func appendLine(t *testing.T, path string, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open %s for append: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("append line: %v", err)
	}
}

func newEwaitFiles(t *testing.T) (logPath, cursorPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "events.log")
	cursorPath = filepath.Join(dir, "cursor")
	if err := os.WriteFile(logPath, []byte(""), 0o644); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	return logPath, cursorPath
}

// readCounter reads the stub's call-counter file and returns its integer
// value, used to prove exactly which call (resolve / check-first / verify /
// safety-net sweep) produced a given outcome.
func readCounter(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read counter file %s: %v", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse counter file %s = %q: %v", path, data, err)
	}
	return n
}

// --- target resolution -------------------------------------------------

func TestEwait_NameResolvesToPaneID_LogHitStillDetected(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	counterFile := filepath.Join(t.TempDir(), "counter")
	stub := stubConfig{
		paneID:      "w9:p1",
		flipAt:      2, // call1=resolve(by name), call2=check-first(by pane id) -> working; call3=verify-on-log-hit -> done
		counterFile: counterFile,
	}

	args := []string{
		"--targets", "agent-alice", // a name, not a pane id
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		// L4 fix (#9 review): safety-net/overall-timeout generous enough that only the
		// log path (not a safety-net sweep) can plausibly produce the hit within the
		// test's wait budget — see the counter assertion below for direct proof.
		"--safety-net", "60",
		"--overall-timeout", "60",
	}

	p := startEwait(t, args, stub)
	waitForFileToExist(t, cursorPath, 5*time.Second)
	appendLine(t, logPath, `{"ts":"2026-10-18T00:00:00Z","pane_id":"w9:p1","agent_status":"done","workspace_id":"w9","agent":"claude"}`)

	res := p.wait(t, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w9:p1"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	// M1 fix: the hit line also carries the ORIGINAL --targets entry back, so a
	// name-based caller can map a hit to its own bookkeeping without a probe of its own.
	if !strings.Contains(res.stdout, `"target":"agent-alice"`) {
		t.Fatalf(`stdout missing "target":"agent-alice"; got: %q`, res.stdout)
	}
	if !strings.Contains(res.stderr, "w9:p1") {
		t.Fatalf("startup line should report the resolved pane id, not the name; stderr: %q", res.stderr)
	}
	if n := readCounter(t, counterFile); n != 3 {
		t.Fatalf("counter = %d, want exactly 3 (resolve, check-first, verify) — a safety-net sweep must not have run", n)
	}
}

func TestEwait_UnresolvableTarget_ExitsWithDedicatedCode(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{unresolvable: "ghost-target"}

	args := []string{
		"--targets", "ghost-target",
		"--log", logPath,
		"--cursor-file", cursorPath,
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 6 {
		t.Fatalf("exit code = %d, want 6; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "ghost-target") {
		t.Fatalf("stderr should name the unresolvable target; got: %q", res.stderr)
	}
	// L3 fix: herdr's own error code must be surfaced, not discarded, so the caller can
	// tell "fix my target" (agent_not_found) apart from other failure modes.
	if !strings.Contains(res.stderr, "agent_not_found") {
		t.Fatalf("stderr should surface herdr's error code; got: %q", res.stderr)
	}
	if _, err := os.Stat(cursorPath); err == nil {
		t.Fatalf("an unresolvable target must never start a waiter: cursor file should not have been created")
	}
}

func TestEwait_SecondOfTwoTargets_Unresolvable_ExitsWithDedicatedCode(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		alwaysWorking: "good-pane", // the first target resolves fine
		unresolvable:  "bad-name",  // the second does not
	}

	args := []string{
		"--targets", "good-pane,bad-name",
		"--log", logPath,
		"--cursor-file", cursorPath,
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 6 {
		t.Fatalf("exit code = %d, want 6; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "bad-name") {
		t.Fatalf("stderr should name the unresolvable second target; got: %q", res.stderr)
	}
	if _, err := os.Stat(cursorPath); err == nil {
		t.Fatalf("one unresolvable target must stop the whole waiter before it starts")
	}
}

func TestEwait_HerdrUnreachable_ExitsWithDedicatedCode(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{omitHerdr: true}

	args := []string{
		"--targets", "some-agent-name", // name-shaped, not pane-id-shaped: no H1 fallback applies
		"--log", logPath,
		"--cursor-file", cursorPath,
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 6 {
		t.Fatalf("exit code = %d, want 6; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("herdr missing from PATH must not leak anything to stdout; got: %q", res.stdout)
	}
}

// --- H1: a pane id whose agent herdr hasn't classified yet must keep waiting ---

func TestEwait_PaneIDNotYetDetected_KeepsWaitingAndStillHits(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	detectCounterFile := filepath.Join(t.TempDir(), "detect-counter")
	mainCounterFile := filepath.Join(t.TempDir(), "main-counter")
	stub := stubConfig{
		notYetDetected:    "w1:p9", // pane-id-shaped: herdr's first response is agent_not_found
		detectAfter:       1,       // only the resolve call (call #1) gets agent_not_found
		detectCounterFile: detectCounterFile,
		paneID:            "w1:p9", // identity: once "detected", herdr reports this pane id
		flipAt:            1,       // call2 (check-first) -> working; call3 (verify) -> done
		counterFile:       mainCounterFile,
	}

	args := []string{
		"--targets", "w1:p9", // already a pane id, per the H1 scenario (not a name)
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "60",
		"--overall-timeout", "60",
	}

	p := startEwait(t, args, stub)
	waitForFileToExist(t, cursorPath, 5*time.Second)
	appendLine(t, logPath, `{"ts":"2026-10-18T00:00:00Z","pane_id":"w1:p9","agent_status":"done","workspace_id":"w1","agent":"claude"}`)

	res := p.wait(t, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (must keep waiting on agent_not_found for a pane-id target, not exit 6); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w1:p9"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "agent_not_found") {
		t.Fatalf("stderr should explain the detection-lag warning; got: %q", res.stderr)
	}
}

// --- L2: an empty --targets entry is skipped, not a fatal resolution failure ---

func TestEwait_EmptyTargetsEntry_SkippedNotExit6(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{alwaysWorking: "w6:p1"}

	args := []string{
		"--targets", "w6:p1,,", // trailing/doubled commas leave empty entries
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "1",
		"--overall-timeout", "2",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	// The real (non-empty) target never reaches a terminal state, so this must end via
	// overall timeout (exit 2) — proving the empty entries were silently dropped rather
	// than tripping exit 6 or a usage error.
	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestEwait_AllEmptyTargetsEntries_UsageError(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)

	args := []string{
		"--targets", " , ,",
		"--log", logPath,
		"--cursor-file", cursorPath,
	}

	res := runEwait(t, args, stubConfig{}, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit code = %d, want 4 (usage error); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
}

// --- M1: the startup diagnostic lists every target's name=pane_id mapping ---

func TestEwait_TwoResolvableTargets_DiagnosticListsBothMappings(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{mapEntries: "alice=w7:p3;bob=w8:p1"}

	args := []string{
		"--targets", "alice,bob",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "1",
		"--overall-timeout", "2",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	for _, want := range []string{"alice=w7:p3", "bob=w8:p1"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("diagnostic should list %q; stderr: %q", want, res.stderr)
		}
	}
}

// --- H2: an explicit short --overall-timeout with default poll/safety-net stays valid ---

func TestEwait_ShortOverallTimeoutAlone_StaysValid(t *testing.T) {
	cases := []struct {
		name           string
		overallTimeout string
	}{
		{"overall-timeout 30 alone", "30"},
		{"overall-timeout 3 alone", "3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath, cursorPath := newEwaitFiles(t)
			stub := stubConfig{
				paneID:      "w2:p1",
				flipAt:      0, // every call reports "done" -> hits on check-first, before any sleep
				counterFile: filepath.Join(t.TempDir(), "counter"),
			}
			args := []string{
				"--targets", "w2:p1",
				"--log", logPath,
				"--cursor-file", cursorPath,
				"--overall-timeout", tc.overallTimeout,
				// --poll/--safety-net deliberately omitted: their unchanged defaults
				// (5/60) exceed this --overall-timeout, which must be clamped down
				// rather than rejected (#9 review, H1 regression).
			}

			res := runEwait(t, args, stub, 10*time.Second)

			if res.exitCode != 0 {
				t.Fatalf("exit code = %d, want 0 (must not be a usage error); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
			}
		})
	}
}

func TestEwait_ShortOverallTimeoutAlone_ClampsSafetyNetAndPoll(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	// alwaysWorking never reaches a terminal state, so this run ends via overall timeout
	// — deliberately not relying on a log-hit race, since --poll ends up clamped equal to
	// --overall-timeout here (3s/3s), leaving no slack for a second loop iteration.
	stub := stubConfig{alwaysWorking: "w2:p9"}
	args := []string{
		"--targets", "w2:p9",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "3", // --poll/--safety-net omitted: must clamp to fit this
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	for _, want := range []string{"poll=3s", "safety-net=3s", "overall-timeout=3s"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("startup line should show clamped %q; stderr: %q", want, res.stderr)
		}
	}
}

// --- interval validation -------------------------------------------------

func TestEwait_IntervalValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"poll non-numeric", []string{"--poll", "abc"}},
		{"poll zero", []string{"--poll", "0"}},
		{"safety-net negative", []string{"--safety-net", "-5"}},
		{"overall-timeout non-numeric", []string{"--overall-timeout", "1m"}},
		{"poll greater than safety-net", []string{"--poll", "20", "--safety-net", "10"}},
		{"safety-net greater than overall-timeout", []string{"--safety-net", "120", "--overall-timeout", "60"}},
		{"poll exceeds ceiling", []string{"--poll", "10000"}},
		{"safety-net exceeds ceiling", []string{"--safety-net", "10000", "--overall-timeout", "20000"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath, cursorPath := newEwaitFiles(t)
			args := append([]string{
				"--targets", "w1:p1",
				"--log", logPath,
				"--cursor-file", cursorPath,
			}, tc.args...)

			res := runEwait(t, args, stubConfig{}, 10*time.Second)

			if res.exitCode != 4 {
				t.Fatalf("exit code = %d, want 4 (usage error); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
			}
		})
	}
}

func TestEwait_PollExceedsCeiling_MentionsMilliseconds(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "10000",
		"--safety-net", "10000",
		"--overall-timeout", "20000",
	}

	res := runEwait(t, args, stubConfig{}, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit code = %d, want 4; stderr: %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "millisecond") {
		t.Fatalf("ceiling error should call out the millisecond-vs-second mistake; stderr: %q", res.stderr)
	}
}

// --- existing behaviour, unchanged ----------------------------------------

func TestEwait_CheckFirstHit(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w1:p1",
		flipAt:      0, // every call reports "done"
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "5",
		"--overall-timeout", "10",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w1:p1"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, `"target":"w1:p1"`) {
		t.Fatalf(`a pane-id caller should see "target" equal to its own pane_id; got: %q`, res.stdout)
	}
}

func TestEwait_LogHit(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	counterFile := filepath.Join(t.TempDir(), "counter")
	stub := stubConfig{
		paneID:      "w3:p2",
		flipAt:      2, // call1=resolve, call2=check-first -> working; call3=verify-on-log-hit -> done
		counterFile: counterFile,
	}
	args := []string{
		"--targets", "w3:p2",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		// L4 fix (#9 review): generous enough that only the log path can plausibly
		// produce the hit — the counter assertion below proves it directly.
		"--safety-net", "60",
		"--overall-timeout", "60",
	}

	p := startEwait(t, args, stub)
	waitForFileToExist(t, cursorPath, 5*time.Second)
	appendLine(t, logPath, `{"ts":"2026-10-18T00:00:00Z","pane_id":"w3:p2","agent_status":"done","workspace_id":"w3","agent":"claude"}`)

	res := p.wait(t, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w3:p2"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	for _, want := range []string{"w3:p2", "poll=1s", "safety-net=60s", "overall-timeout=60s", "cursor=0"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("startup line missing %q; stderr: %q", want, res.stderr)
		}
	}
	if n := readCounter(t, counterFile); n != 3 {
		t.Fatalf("counter = %d, want exactly 3 (resolve, check-first, verify) — a safety-net sweep must not have run", n)
	}
}

func TestEwait_SafetyNetHit(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w4:p1",
		flipAt:      2, // call1=resolve, call2=check-first -> working; call3=safety-net sweep -> done
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}
	args := []string{
		"--targets", "w4:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "1",
		"--overall-timeout", "10",
	}

	// Deliberately never append anything to the log: only the safety-net
	// sweep (not the log pre-filter) can observe the eventual "done".
	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w4:p1"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
}

func TestEwait_OverallTimeout(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{alwaysWorking: "w5:p1"}
	args := []string{
		"--targets", "w5:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "1",
		"--overall-timeout", "2",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("overall timeout must not print a hit line; stdout: %q", res.stdout)
	}
}
