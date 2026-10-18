package main

// TestEwait_* exercises scripts/herdr-ewait.sh as a real subprocess, against a
// fake `herdr` stub on PATH — see issue #9. No live Herdr session is required.
//
// The stub (herdrStubScript below) implements only `herdr agent get <target>`:
//   - a target equal to $HERDR_STUB_UNRESOLVABLE makes the call fail (simulates
//     an unresolvable --targets entry);
//   - a target equal to $HERDR_STUB_ALWAYS_WORKING always reports agent_status
//     "working" with pane_id == the target itself (simulates a target that
//     never reaches a terminal state, for the overall-timeout path);
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
unresolvable="${HERDR_STUB_UNRESOLVABLE:-}"
always_working="${HERDR_STUB_ALWAYS_WORKING:-}"
if [ -n "$unresolvable" ] && [ "$target" = "$unresolvable" ]; then
  exit 1
fi
if [ -n "$always_working" ] && [ "$target" = "$always_working" ]; then
  printf '{"id":"cli:agent:get","pane_id":"%s","agent_status":"working"}\n' "$target"
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
// (no target will ever match unresolvable/alwaysWorking, and the default-case
// branch is simply never reached if the script never calls herdr).
type stubConfig struct {
	unresolvable  string
	alwaysWorking string
	paneID        string
	flipAt        int
	counterFile   string
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
// stub prepended to PATH. The caller must eventually call wait().
func startEwait(t *testing.T, args []string, stub stubConfig) *ewaitProcess {
	t.Helper()
	requireEwaitTools(t)

	scriptPath := ewaitScriptPath(t)
	stubDir := t.TempDir()
	writeHerdrStub(t, stubDir)

	cmd := exec.Command("bash", append([]string{scriptPath}, args...)...)
	cmd.Env = append(stub.env(), "PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))

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

// --- target resolution -------------------------------------------------

func TestEwait_NameResolvesToPaneID_LogHitStillDetected(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w9:p1",
		flipAt:      2, // call1=resolve(by name), call2=check-first(by pane id) -> working; call3=verify-on-log-hit -> done
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}

	args := []string{
		"--targets", "agent-alice", // a name, not a pane id
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "10",
		"--overall-timeout", "15",
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
	if !strings.Contains(res.stderr, "w9:p1") {
		t.Fatalf("startup line should report the resolved pane id, not the name; stderr: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "agent-alice") {
		t.Fatalf("startup line should report the resolved pane id, not the original name; stderr: %q", res.stderr)
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
	if _, err := os.Stat(cursorPath); err == nil {
		t.Fatalf("an unresolvable target must never start a waiter: cursor file should not have been created")
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
}

func TestEwait_LogHit(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w3:p2",
		flipAt:      2, // call1=resolve, call2=check-first -> working; call3=verify-on-log-hit -> done
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}
	args := []string{
		"--targets", "w3:p2",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "10",
		"--overall-timeout", "15",
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
	for _, want := range []string{"w3:p2", "poll=1s", "safety-net=10s", "overall-timeout=15s", "cursor=0"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("startup line missing %q; stderr: %q", want, res.stderr)
		}
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
