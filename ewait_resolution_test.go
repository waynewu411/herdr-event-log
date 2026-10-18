package main

// TestEwait_* (target-resolution focus) exercises scripts/herdr-ewait.sh as a
// real subprocess against the fake `herdr` stub defined in
// ewait_harness_test.go — see issue #9 and its round-1/round-2/round-3
// reviews. No live Herdr session is required. Split out from ewait_test.go
// (which holds the interval-validation and existing-behavior tests) to keep
// each file under this repo's ~800-line guideline (round-2 review, N4).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
		// safety-net/overall-timeout generous enough that only the log path (not a
		// safety-net sweep) can plausibly produce the hit within the test's wait budget
		// — see the counter assertion below for direct proof.
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
	// L3 fix, re-verified post H1 fix (round 2): herdr's own error code — now read from
	// REAL herdr's error stream (stderr), not stdout — must be surfaced, not discarded,
	// so the caller can tell "fix my target" (agent_not_found) apart from other failures.
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
		"--targets", "some-agent-name", // name-shaped, not pane-id-shaped: no H1/M2 fallback applies
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
	// L1 fix (#9 round-3 review): a non-JSON failure has no "code" to surface, but the
	// message must still say SOMETHING concrete about what herdr/the shell actually
	// printed, not just the old generic three-way guess.
	if !strings.Contains(res.stderr, "herdr said") {
		t.Fatalf("stderr should surface the raw herdr/shell failure text for a non-JSON error; got: %q", res.stderr)
	}
}

// --- M1 (round 2): "server down" — herdr present but its socket is dead ---

func TestEwait_ServerDown_ExitsWithDedicatedCode(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"name target", "some-agent-name"},
		{"pane-id target", "w1:p9"}, // pane-id-shaped: must NOT trigger the H1/M2 "keep waiting" fallback
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath, cursorPath := newEwaitFiles(t)
			stub := stubConfig{serverDown: true}

			args := []string{
				"--targets", tc.target,
				"--log", logPath,
				"--cursor-file", cursorPath,
			}

			res := runEwait(t, args, stub, 10*time.Second)

			if res.exitCode != 6 {
				t.Fatalf("exit code = %d, want 6; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
			}
			if !strings.Contains(res.stderr, "server_not_running") {
				t.Fatalf("stderr should surface herdr's server_not_running code; got: %q", res.stderr)
			}
		})
	}
}

// --- H1 (round 2): a pane id whose agent herdr hasn't classified yet must keep waiting ---

func TestEwait_PaneIDNotYetDetected_KeepsWaitingAndStillHits(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	detectCounterFile := filepath.Join(t.TempDir(), "detect-counter")
	mainCounterFile := filepath.Join(t.TempDir(), "main-counter")
	stub := stubConfig{
		notYetDetected:    "w1:p9", // pane-id-shaped: herdr's first response is agent_not_found (on stderr)
		detectAfter:       1,       // only the resolve call (call #1) gets agent_not_found
		detectCounterFile: detectCounterFile,
		paneID:            "w1:p9", // identity: once "detected", herdr reports this pane id
		flipAt:            1,       // call2 (check-first) -> working; call3 (verify) -> done
		counterFile:       mainCounterFile,
		// HERDR_STUB_PANE_NOT_FOUND left unset: the stub's default `pane get` response
		// for ANY target (including this one) reports the pane as existing — exactly the
		// M2 check this test must pass through before the H1 fallback can apply.
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
		t.Fatalf("exit code = %d, want 0 (must keep waiting on agent_not_found for an existing pane, not exit 6); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w1:p9"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "agent_not_found") {
		t.Fatalf("stderr should explain the detection-lag warning; got: %q", res.stderr)
	}
}

// --- M2 (round 2): a nonexistent (typo'd) pane id must still exit 6, not wait forever ---

func TestEwait_NonexistentPaneID_ExitsWithDedicatedCode(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		unresolvable: "w9999:p9999", // agent_not_found on `agent get`
		paneNotFound: "w9999:p9999", // AND `pane get` confirms the pane itself doesn't exist
	}

	args := []string{
		"--targets", "w9999:p9999",
		"--log", logPath,
		"--cursor-file", cursorPath,
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 6 {
		t.Fatalf("exit code = %d, want 6 (a typo'd pane id must never be waited out for the full --overall-timeout); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "w9999:p9999") {
		t.Fatalf("stderr should name the nonexistent target; got: %q", res.stderr)
	}
	if !strings.Contains(res.stderr, "pane_not_found") {
		t.Fatalf("stderr should surface herdr's pane_not_found code, distinguishing this from H1's detection-lag case; got: %q", res.stderr)
	}
	if _, err := os.Stat(cursorPath); err == nil {
		t.Fatalf("a nonexistent pane id must never start a waiter: cursor file should not have been created")
	}
}

// --- L5 (round 3): a mid-wait `herdr pane move` must not silently strand a name target ---

func TestEwait_NameTargetMovedMidWait_SafetyNetReresolvesAndHits(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		movedName:            "deliverer",
		movedOldPane:         "w2F:pA",
		movedNewPane:         "w9Z:pZ",
		movedNameCounterFile: filepath.Join(t.TempDir(), "moved-name-counter"),
		movedOldCounterFile:  filepath.Join(t.TempDir(), "moved-old-counter"),
	}

	args := []string{
		"--targets", "deliverer", // a name, not a pane id
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "1",
		"--overall-timeout", "10",
	}

	// Never append anything to the log: only the safety-net sweep's re-resolve of the
	// ORIGINAL name (not the log pre-filter, which only ever knows the stale old pane_id)
	// can observe the move and the eventual hit on the new pane_id.
	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (a mid-wait pane move must not strand a name target for the full --overall-timeout); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w9Z:pZ"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, `"target":"deliverer"`) {
		t.Fatalf(`hit line should still carry the original name as "target"; got: %q`, res.stdout)
	}
	if !strings.Contains(res.stderr, "deliverer") || !strings.Contains(res.stderr, "w9Z:pZ") {
		t.Fatalf("stderr should note the re-resolution from the original name to the new pane_id; got: %q", res.stderr)
	}
}

// --- L2 (round 3): a herdr success response with an unexpected shape must not fail-closed on a pane-id caller ---

func TestEwait_UnexpectedSuccessShape_PaneID_KeepsWaitingAndStillHits(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{weirdShape: "w1:p1"} // pane-id-shaped: nothing to resolve either way

	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "2",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	// The stub's weird-shape response always carries "agent_status":"done", which the
	// script's shape-agnostic grep still finds even though "pane_id" itself didn't parse
	// — so this should hit on check-first (exit 0), not exit 6 and not wait out the timeout.
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (an unexpected success shape on a pane-id target must not fail-closed); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w1:p1"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "unexpected response shape") {
		t.Fatalf("stderr should explain the unexpected-shape warning; got: %q", res.stderr)
	}
}

func TestEwait_UnexpectedSuccessShape_Name_ExitsWithDedicatedCode(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{weirdShape: "some-agent-name"} // name: no safe fallback identity

	args := []string{
		"--targets", "some-agent-name",
		"--log", logPath,
		"--cursor-file", cursorPath,
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 6 {
		t.Fatalf("exit code = %d, want 6; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "unexpected response shape") {
		t.Fatalf("stderr should say the response shape was the problem, not blame an unknown target; got: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "unknown target, pane gone, or herdr unreachable") {
		t.Fatalf("stderr should not use the generic unresolvable-target message here (herdr DID succeed); got: %q", res.stderr)
	}
}

// --- round-2 L2: an empty --targets entry is skipped, not a fatal resolution failure ---

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

// --- N2 (round 2): the startup diagnostic prints even when check-first hits immediately ---

func TestEwait_DiagnosticPrintedEvenOnImmediateHit(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w1:p1",
		flipAt:      0, // every call reports "done" -> hits on check-first
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", res.exitCode, res.stderr)
	}
	for _, want := range []string{"targets=w1:p1=w1:p1", "stall-after=0s"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("startup diagnostic missing %q even though the run hit immediately; stderr: %q", want, res.stderr)
		}
	}
}

// N5 fix (#9 round-3 review): --stall-after was the one interval the normalization step
// missed — "--stall-after 007" used to print "stall-after=007s" in the diagnostic even
// though --poll/--safety-net/--overall-timeout were all already normalized to "7s".
func TestEwait_StallAfterNormalizedInDiagnostic(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w1:p1",
		flipAt:      0, // hits on check-first, before any sleep
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "007",
		"--safety-net", "007",
		"--overall-timeout", "7",
		"--stall-after", "007",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "stall-after=7s") {
		t.Fatalf(`diagnostic should show normalized "stall-after=7s", not "stall-after=007s"; stderr: %q`, res.stderr)
	}
	if strings.Contains(res.stderr, "stall-after=007s") {
		t.Fatalf("diagnostic still shows the unnormalized stall-after value; stderr: %q", res.stderr)
	}
}
