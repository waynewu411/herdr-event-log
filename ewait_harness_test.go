package main

// Test harness for ewait_test.go: a fake `herdr` CLI stub and the subprocess
// plumbing to run scripts/herdr-ewait.sh against it. Split out from
// ewait_test.go (which holds the actual TestEwait_* functions) to keep each
// file under this repo's ~800-line guideline — see issue #9's round-2 review
// (N4).
//
// The stub (herdrStubScript below) is deliberately shaped to match REAL
// herdr (0.8.2), verified live and read-only against this machine before
// writing it (issue #9's round-2 review, H1/M1): herdr writes its SUCCESS
// JSON to stdout and its ERROR JSON to STDERR, both on exit 1. Round 1's
// stub put error JSON on stdout, which is why round 1's H1 fix (keep
// waiting on a pane-id target that returns agent_not_found) silently never
// fired against real herdr — the script's resolve step discarded stderr,
// so `$code` was always empty — while the fake tests still passed, because
// they were asserting against the stub's (wrong) stdout-based error.
//
// Round-3 review (#9, N3) re-checked the "server_not_running" stream claim
// specifically, since N3 asserted it should be on stdout: re-verified live
// on this machine (herdr 0.8.2) with explicit file redirection — stdout was
// 0 bytes, stderr carried the full 162-byte error JSON, for both an unknown
// agent and a dead socket. The stub's choice (stderr) is correct as-is; see
// the round-3 report for the exact commands and byte counts.
//
// The stub implements `herdr agent get <target>` and `herdr pane get
// <target>`:
//   - if $HERDR_STUB_SERVER_DOWN is set, EVERY call (either subcommand,
//     any target) fails with the real "server_not_running" shape on
//     stderr, exit 1 — simulating a dead herdr socket;
//   - a target in $HERDR_STUB_WEIRD_SHAPE (comma-separated) succeeds (exit
//     0) with an agent_status but NO recognizable pane_id field — an
//     unexpected/renamed response shape, not a failure herdr itself
//     reported (round-3 review, L2);
//   - `pane get`: a target in $HERDR_STUB_PANE_NOT_FOUND (comma-separated)
//     fails with "pane_not_found" on stderr, exit 1; any other target
//     succeeds with a pane_info response carrying its own pane_id (the
//     pane "exists", regardless of whether it has a classified agent);
//   - `agent get`: a target in $HERDR_STUB_UNRESOLVABLE (comma-separated)
//     fails with "agent_not_found" on stderr, exit 1 (an unresolvable
//     --targets entry: unknown name, or a pane with no agent);
//   - a target in $HERDR_STUB_ALWAYS_WORKING (comma-separated) always
//     succeeds with agent_status "working" and pane_id == the target
//     itself (a target that never reaches a terminal state, for the
//     overall-timeout path, or a resolvable-but-idle target for
//     diagnostic-only checks);
//   - the target in $HERDR_STUB_NOT_YET_DETECTED fails with the SAME
//     "agent_not_found" (on stderr) for its first $HERDR_STUB_DETECT_AFTER
//     calls, then falls through to the counter-based branch below, using
//     the target itself as the resolved pane_id — a pane that exists but
//     whose agent herdr hasn't classified yet;
//   - a target found in $HERDR_STUB_MAP ("name1=pane1;name2=pane2") — matched
//     by EXACT name OR mapped pane id, never a substring (round-4 review,
//     L2: a plain `grep -F "${target}="` both missed every post-resolution
//     probe of the mapped pane id, since only the name side of the "="
//     ever appeared verbatim on the left, and could false-match a target
//     whose name is a suffix of another entry's, e.g. "alice" against a
//     "malice=..." line) — resolves to/reports the mapped pane id with
//     "working" forever, for either form. No counter, used to check
//     multi-target resolution/diagnostics without needing a hit;
//   - $HERDR_STUB_MOVED_NAME simulates a mid-wait `herdr pane move`: its
//     first call (the startup resolve) reports $HERDR_STUB_MOVED_OLD_PANE
//     with agent_status "working"; every call after that reports
//     $HERDR_STUB_MOVED_NEW_PANE instead. $HERDR_STUB_MOVED_OLD_PANE's OWN
//     first call (check-first, using the resolved id) reports "working";
//     every call after that fails with agent_not_found on stderr — as if
//     the old pane_id stopped resolving once the pane moved.
//     $HERDR_STUB_MOVED_NEW_PANE always reports "done" (round-3 review, L5);
//   - any other target increments a shared counter file and reports
//     pane_id = $HERDR_STUB_PANE_ID with agent_status "working" while the
//     counter is <= $HERDR_STUB_FLIP_AT, then "done" after that. This lets
//     a test control exactly which call (startup resolution, check-first,
//     a later safety-net sweep, or a log-triggered verify) first observes
//     the terminal state, without depending on real wall-clock timing.

import (
	"bytes"
	"encoding/json"
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
cmd="${1:-}"
sub="${2:-}"
target="${3:-}"

if [ -n "${HERDR_STUB_SERVER_DOWN:-}" ]; then
  printf '{"id":"cli:%s:%s","error":{"code":"server_not_running","message":"no herdr server is running"}}\n' "$cmd" "$sub" >&2
  exit 1
fi

if [ "$cmd" = "pane" ] && [ "$sub" = "get" ]; then
  pane_not_found=",${HERDR_STUB_PANE_NOT_FOUND:-},"
  case "$pane_not_found" in
    *",$target,"*)
      printf '{"error":{"code":"pane_not_found","message":"pane %s not found"},"id":"cli:pane:get"}\n' "$target" >&2
      exit 1
      ;;
  esac
  printf '{"id":"cli:pane:get","result":{"pane":{"pane_id":"%s"},"type":"pane_info"}}\n' "$target"
  exit 0
fi

if [ "$cmd" != "agent" ] || [ "$sub" != "get" ]; then
  exit 1
fi

weird_shape=",${HERDR_STUB_WEIRD_SHAPE:-},"
case "$weird_shape" in
  *",$target,"*)
    printf '{"id":"cli:agent:get","agent_status":"done","pane":"%s"}\n' "$target"
    exit 0
    ;;
esac

unresolvable=",${HERDR_STUB_UNRESOLVABLE:-},"
case "$unresolvable" in
  *",$target,"*)
    printf '{"error":{"code":"agent_not_found","message":"agent target %s not found"},"id":"cli:agent:get"}\n' "$target" >&2
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
    printf '{"error":{"code":"agent_not_found","message":"agent target %s not found"},"id":"cli:agent:get"}\n' "$target" >&2
    exit 1
  fi
  # detected now: fall through to the counter-based branch below, using the
  # target itself as the canonical pane_id (it already looks like one).
fi

map="${HERDR_STUB_MAP:-}"
if [ -n "$map" ]; then
  old_ifs="$IFS"
  IFS=';'
  for entry in $map; do
    name="${entry%%=*}"
    pane="${entry#*=}"
    if [ "$target" = "$name" ] || [ "$target" = "$pane" ]; then
      IFS="$old_ifs"
      printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"working"}\n' "$pane"
      exit 0
    fi
  done
  IFS="$old_ifs"
fi

moved_name="${HERDR_STUB_MOVED_NAME:-}"
if [ -n "$moved_name" ] && [ "$target" = "$moved_name" ]; then
  cf="${HERDR_STUB_MOVED_NAME_COUNTER_FILE:?missing}"
  n=0
  if [ -f "$cf" ]; then n="$(cat "$cf")"; fi
  n=$((n+1)); printf '%s' "$n" > "$cf"
  if [ "$n" -eq 1 ]; then
    printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"working"}\n' "${HERDR_STUB_MOVED_OLD_PANE:?missing}"
  else
    printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"working"}\n' "${HERDR_STUB_MOVED_NEW_PANE:?missing}"
  fi
  exit 0
fi

moved_old="${HERDR_STUB_MOVED_OLD_PANE:-}"
if [ -n "$moved_old" ] && [ "$target" = "$moved_old" ]; then
  cf="${HERDR_STUB_MOVED_OLD_COUNTER_FILE:?missing}"
  n=0
  if [ -f "$cf" ]; then n="$(cat "$cf")"; fi
  n=$((n+1)); printf '%s' "$n" > "$cf"
  if [ "$n" -eq 1 ]; then
    printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"working"}\n' "$target"
    exit 0
  fi
  printf '{"error":{"code":"agent_not_found","message":"agent target %s not found"},"id":"cli:agent:get"}\n' "$target" >&2
  exit 1
fi

moved_new="${HERDR_STUB_MOVED_NEW_PANE:-}"
if [ -n "$moved_new" ] && [ "$target" = "$moved_new" ]; then
  printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"done"}\n' "$target"
  exit 0
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
	unresolvable         string // comma-separated targets -> agent_not_found error, exit 1
	alwaysWorking        string // comma-separated targets -> identity pane_id, "working" forever
	notYetDetected       string // single target -> agent_not_found for detectAfter calls, then falls through
	detectAfter          int
	detectCounterFile    string
	mapEntries           string // "name1=pane1;name2=pane2" -> mapped pane_id, "working" forever
	paneID               string
	flipAt               int
	counterFile          string
	omitHerdr            bool   // if true, herdr is absent from PATH entirely
	serverDown           bool   // if true, every herdr call fails with server_not_running
	paneNotFound         string // comma-separated targets -> `herdr pane get` fails with pane_not_found
	weirdShape           string // comma-separated targets -> success (exit 0) with no pane_id field
	movedName            string // name whose resolution changes pane_id after its first call
	movedOldPane         string
	movedNewPane         string
	movedNameCounterFile string
	movedOldCounterFile  string
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
	if c.serverDown {
		set("HERDR_STUB_SERVER_DOWN", "1")
	}
	if c.paneNotFound != "" {
		set("HERDR_STUB_PANE_NOT_FOUND", c.paneNotFound)
	}
	if c.weirdShape != "" {
		set("HERDR_STUB_WEIRD_SHAPE", c.weirdShape)
	}
	if c.movedName != "" {
		set("HERDR_STUB_MOVED_NAME", c.movedName)
		set("HERDR_STUB_MOVED_OLD_PANE", c.movedOldPane)
		set("HERDR_STUB_MOVED_NEW_PANE", c.movedNewPane)
		set("HERDR_STUB_MOVED_NAME_COUNTER_FILE", c.movedNameCounterFile)
		set("HERDR_STUB_MOVED_OLD_COUNTER_FILE", c.movedOldCounterFile)
	}
	return env
}

func requireEwaitTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("herdr-ewait.sh requires bash/grep/sed, not available on windows")
	}
	for _, tool := range []string{"bash", "grep", "sed", "tail", "wc", "tr", "sleep"} {
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

// runHerdrStub invokes the fake `herdr` binary directly (not via
// herdr-ewait.sh) — used to unit-test the stub's own branches, such as
// HERDR_STUB_MAP's name/pane-id matching (round-4 review, L2), in isolation
// from the script under test.
func runHerdrStub(t *testing.T, stub stubConfig, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	writeHerdrStub(t, dir)
	cmd := exec.Command(filepath.Join(dir, "herdr"), args...)
	cmd.Env = stub.env()
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run herdr stub: %v", err)
		}
	}
	return out.String(), errBuf.String(), code
}

// minimalToolsPath builds a PATH containing only the directories that hold
// the core tools herdr-ewait.sh itself needs, with no herdr stub added —
// used to simulate "herdr is not installed at all" without accidentally
// picking up a real herdr binary that might happen to be on this machine's
// normal PATH. The list must cover every external tool the script invokes —
// round-3 review (N6) found `tr` and `sleep` missing: harmless on a machine
// where every tool shares one directory (e.g. /usr/bin), but on a split
// layout the herdr-unreachable test would exit 127 from inside a command
// substitution instead of the intended 6.
func minimalToolsPath(t *testing.T) string {
	t.Helper()
	tools := []string{"bash", "grep", "sed", "tail", "wc", "cat", "date", "head", "tr", "sleep"}
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
// script's own cursor-file write, so a test can append log bytes only once
// the script has actually snapshotted its starting cursor — appending any
// earlier would race the snapshot and silently fold the new bytes into "no
// new bytes".
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

// assertSingleJSONLine fails the test unless stdout is exactly one line that
// parses as valid JSON (round-3 review, N4: every hit-test assertion so far
// used strings.Contains on fragments, so a stray comma or quote introduced
// while editing emit_hit/the stall printfs would have passed every one of
// them).
func assertSingleJSONLine(t *testing.T, stdout string) {
	t.Helper()
	trimmed := strings.TrimRight(stdout, "\n")
	if n := strings.Count(trimmed, "\n"); n != 0 {
		t.Fatalf("stdout must be exactly one line, found %d newlines in: %q", n, stdout)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		t.Fatalf("stdout is not valid JSON: %v; got: %q", err, stdout)
	}
}
