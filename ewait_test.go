package main

// TestEwait_* exercises scripts/herdr-ewait.sh as a real subprocess against
// the fake `herdr` stub defined in ewait_harness_test.go — see issue #9 and
// its round-1/round-2 reviews. No live Herdr session is required.

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
				// rather than rejected.
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

// --- L1 (round 2): the ordering error tells the caller the cheapest repair ---

func TestEwait_OrderingError_MentionsClampHint(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"poll greater than safety-net", []string{"--poll", "20", "--safety-net", "10"}},
		{"safety-net greater than overall-timeout", []string{"--safety-net", "120", "--overall-timeout", "60"}},
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
				t.Fatalf("exit code = %d, want 4; stderr: %q", res.exitCode, res.stderr)
			}
			if !strings.Contains(res.stderr, "omit") {
				t.Errorf("ordering error should hint at omitting the flag to use the automatic clamp; stderr: %q", res.stderr)
			}
		})
	}
}

// Explicitly passing the README's example flags, then shortening only
// --overall-timeout, is a genuine ordering violation (L1, round 2): the
// clamp only ever applies to an OMITTED flag, by design, so this must still
// be a usage error — documented here so the behaviour is pinned, not just
// asserted away as a regression.
func TestEwait_ExplicitDefaultsWithShortTimeout_IsUsageError(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "30",
		"--poll", "5",
		"--safety-net", "60",
	}

	res := runEwait(t, args, stubConfig{}, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit code = %d, want 4; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
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
		// L2 fix (#9 round-2 review): with --safety-net left at its default (60), a bare
		// --poll 10000 was rejected by the poll>safety-net ORDERING check before ever
		// reaching the ceiling check, so this case didn't actually exercise the ceiling.
		// Satisfy ordering (all three equal) so only the ceiling can reject it.
		{"poll exceeds ceiling", []string{"--poll", "301", "--safety-net", "301", "--overall-timeout", "301"}},
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
			if res.stdout != "" {
				t.Fatalf("a usage error must never print anything to stdout; got: %q", res.stdout)
			}
		})
	}
}

// L2 fix (#9 round-2 review): the ceiling's own boundary — exactly 300s — must be
// accepted, not just values far past it.
func TestEwait_IntervalBoundary_300IsAccepted(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w2:p2",
		flipAt:      0, // hits on check-first, before any sleep
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}
	args := []string{
		"--targets", "w2:p2",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--poll", "300",
		"--safety-net", "300",
		"--overall-timeout", "300",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (300s is the ceiling, not past it); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
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
		// generous enough that only the log path can plausibly produce the hit — the
		// counter assertion below proves it directly.
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
	for _, want := range []string{"w3:p2", "poll=1s", "safety-net=60s", "overall-timeout=60s", "stall-after=0s", "cursor=0"} {
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
