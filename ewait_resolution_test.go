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

// L3 fix (#9 round-5 review): the non-JSON-failure flavor of the same ride-it-out
// behavior — herdr entirely absent from PATH, not just its socket being down — for a
// pane-id-shaped target.
func TestEwait_HerdrUnreachable_PaneIDTarget_RidesOutInsteadOfExit6(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{omitHerdr: true}

	args := []string{
		"--targets", "w1:p9",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "2",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode == 6 {
		t.Fatalf("exit code = 6 (a pane-id caller must ride out herdr being entirely absent at startup, as main did); stderr: %q", res.stderr)
	}
	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2 (herdr never appears in this stub, so it should simply time out, not fail closed); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
}

// --- M1 (round 2): "server down" — herdr present but its socket is dead ---
// A NAME target still has no identity to fall back on, so it still exits 6.

func TestEwait_ServerDown_NameTarget_ExitsWithDedicatedCode(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{serverDown: true}

	args := []string{
		"--targets", "some-agent-name",
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
}

// L3 fix (#9 round-5 review): on `main`, a pane-id caller had nothing to resolve and so
// rode out a transient herdr outage at startup for free (every probe is unconditionally
// tolerant, `|| true`). Resolution introduced a NEW hard failure for this exact case —
// exit 6 on herdr simply being down for a moment — that main never had. Issue 9 never
// asked to fail closed on "herdr itself is temporarily unreachable" for a target that
// already IS a pane id; only a genuinely bad target (an unresolvable name, or a pane id
// confirmed via `herdr pane get` not to exist) should exit 6.
func TestEwait_ServerDown_PaneIDTarget_RidesOutInsteadOfExit6(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{serverDown: true} // never recovers in this stub config

	args := []string{
		"--targets", "w1:p9",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "2",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode == 6 {
		t.Fatalf("exit code = 6 (a pane-id caller must ride out a herdr outage at startup, as main did); stderr: %q", res.stderr)
	}
	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2 (herdr never recovers in this stub, so it should simply time out, not fail closed); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
}

// The actual point of riding it out: once herdr comes back, the wait succeeds, exactly
// like main would have.
func TestEwait_ServerDown_PaneIDTarget_RecoversAndHits(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		serverDownForCalls:    2, // resolution + check-first both see the outage
		serverDownCounterFile: filepath.Join(t.TempDir(), "server-down-counter"),
		paneID:                "w1:p9",
		flipAt:                0, // "done" as soon as herdr recovers
		counterFile:           filepath.Join(t.TempDir(), "counter"),
	}

	args := []string{
		"--targets", "w1:p9",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "1",
		"--overall-timeout", "10",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (once herdr recovers, the wait must still succeed); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w1:p9"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
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

// L1 fix (#9 round-5 review): the L5 re-resolution above only runs inside the safety-net
// sweep. The STALL sweep (rule 6) probed the stale pane_id directly and counted every
// empty response toward "unreachable for a full window" — so a mid-wait pane move could
// trip a false exit 5 ("may no longer exist") if the --stall-after window elapsed before
// the next safety-net tick, even though the agent is alive under its new pane_id. Using a
// --stall-after shorter than --safety-net deliberately lets the stall sweep observe the
// stale pane_id first; the fix must re-resolve there too before counting the miss.
func TestEwait_StallSweep_MovedNameTarget_NoFalseExitFive_ThenHits(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		movedName:            "deliverer",
		movedOldPane:         "w2F:pA",
		movedNewPane:         "w9Z:pZ",
		movedNameCounterFile: filepath.Join(t.TempDir(), "moved-name-counter"),
		movedOldCounterFile:  filepath.Join(t.TempDir(), "moved-old-counter"),
	}

	args := []string{
		"--targets", "deliverer",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "4",
		"--stall-after", "1",
		"--overall-timeout", "10",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode == 5 {
		t.Fatalf("exit 5 (false stall/unreachable) on a target that only moved; stdout: %q stderr: %q", res.stdout, res.stderr)
	}
	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (the stall sweep must not strand a moved name target); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w9Z:pZ"`) {
		t.Fatalf("expected an eventual hit on the new pane_id; stdout: %q", res.stdout)
	}
}

// L4 fix (#9 round-5 review): neither exit-5 stall line had a test exercising it — the
// hit line gets assertSingleJSONLine precisely because fragment matching would miss a
// stray quote/comma in a printf, and the two stall printfs were edited in this PR (the
// "target" field was added, then its position fixed in round 4) with nothing covering
// either. This also pins whatever decision L1 made: re-resolving the NAME does not
// prevent a genuinely dead pane (not merely moved) from still reporting a real stall.
//
// Uses the existing movedOldPane/movedNewPane stub mechanism, but with BOTH set to the
// SAME pane_id — "deliverer" always resolves to that one pane_id (never actually moves),
// so reresolve_if_stale correctly finds nothing to update and falls through, and the
// pane's own probe genuinely, permanently fails after its first call.
func TestEwait_StallSweep_UnreachableTarget_ExitsFiveWithValidJSON(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		movedName:            "deliverer",
		movedOldPane:         "w2F:pA",
		movedNewPane:         "w2F:pA", // same pane_id: this target never actually moves
		movedNameCounterFile: filepath.Join(t.TempDir(), "moved-name-counter"),
		movedOldCounterFile:  filepath.Join(t.TempDir(), "moved-old-counter"),
	}

	args := []string{
		"--targets", "deliverer",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "300", // must not fire before the stall sweep does
		"--stall-after", "2",
		"--overall-timeout", "600",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 5 {
		t.Fatalf("exit code = %d, want 5; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"detection_content_seq":null`) {
		t.Fatalf(`expected "detection_content_seq":null (a genuine probe outage, not a seq-based stall); stdout: %q`, res.stdout)
	}
	if !strings.Contains(res.stdout, `"target":"deliverer"`) {
		t.Fatalf(`stall line should carry the original name as "target"; got: %q`, res.stdout)
	}
	assertSingleJSONLine(t, res.stdout)
}

// The other exit-5 shape: content unchanged across two bracketing ticks while still
// `working` (not a probe outage at all — detection_content_seq is present and stable).
func TestEwait_StallSweep_WorkingUnchanged_ExitsFiveWithValidJSON(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		alwaysWorking: "w1:p1",
		contentSeq:    "42", // constant across every call: never "moves"
	}

	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "1",
		"--safety-net", "300",
		"--stall-after", "1",
		"--overall-timeout", "600",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 5 {
		t.Fatalf("exit code = %d, want 5; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"detection_content_seq":42`) || !strings.Contains(res.stdout, `"agent_status":"working"`) {
		t.Fatalf("unexpected stdout: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, `"target":"w1:p1"`) {
		t.Fatalf(`stall line should carry "target"; got: %q`, res.stdout)
	}
	assertSingleJSONLine(t, res.stdout)
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

// See ewait_diagnostics_test.go for: HERDR_STUB_MAP stub-fidelity tests (round-4, L2),
// stub success-shape nesting tests (round-5, N2), cursor-file tests (round-5, L2), and
// the startup-diagnostic tests (round-2 N2, round-3 N5).
