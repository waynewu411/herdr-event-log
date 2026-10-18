package main

// TestEwait_* (interval-validation and existing-behavior focus) exercises
// scripts/herdr-ewait.sh as a real subprocess against the fake `herdr` stub
// defined in ewait_harness_test.go — see issue #9 and its round-1/round-2/
// round-3 reviews. No live Herdr session is required. Target-resolution
// tests (H1/M1/M2/L1/L2 and friends) live in ewait_resolution_test.go
// instead, to keep each file under this repo's ~800-line guideline.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

// L3 fix (#9 round-3 review): the millisecond hint must fire even when only ONE of
// --poll/--safety-net is passed (the other left at its default) — previously the
// ordering check (poll>safety-net, or safety-net>overall-timeout) caught these first,
// with a message that doesn't describe what the caller actually did.
func TestEwait_CeilingAlone_MentionsMilliseconds(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"poll alone", []string{"--poll", "10000"}},
		{"safety-net alone", []string{"--safety-net", "30000"}},
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
			if !strings.Contains(res.stderr, "millisecond") {
				t.Fatalf("ceiling error should call out the millisecond-vs-second mistake even with only one flag set; stderr: %q", res.stderr)
			}
		})
	}
}

// L4 fix (#9 round-3 review): --overall-timeout itself needs a ceiling too — issue 9's
// own exact mistake (2400000, ~28 days) survives validation when --poll/--safety-net are
// both omitted, since only they had a ceiling before this fix.
func TestEwait_OverallTimeoutCeiling_MentionsMilliseconds(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "2400000",
	}

	res := runEwait(t, args, stubConfig{}, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit code = %d, want 4; stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "millisecond") {
		t.Fatalf("overall-timeout ceiling error should call out the millisecond-vs-second mistake; stderr: %q", res.stderr)
	}
}

// --- N2 (round 3): --overall-timeout 0 is a pre-existing "probe once" idiom ---

func TestEwait_OverallTimeoutZero_ProbesOnceThenExits2(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	// alwaysWorking never reaches a terminal state, so check-first does not hit and the
	// main loop's very first ELAPSED>=OVERALL_TIMEOUT(0) check must fire immediately.
	stub := stubConfig{alwaysWorking: "w1:p1"}
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "0",
		// --poll/--safety-net deliberately omitted: on `main`, nothing validated them,
		// and they were never used either, since the loop body never runs.
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2 (probe once via check-first, then give up immediately); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	// Confirms --poll/--safety-net kept their UNCLAMPED defaults (5/60) rather than
	// being clamped down to 0, which would otherwise fail their own > 0 validation.
	for _, want := range []string{"poll=5s", "safety-net=60s", "overall-timeout=0s"} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("startup line missing %q; stderr: %q", want, res.stderr)
		}
	}
}

func TestEwait_OverallTimeoutZero_NegativeIsStillRejected(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "-1",
	}

	res := runEwait(t, args, stubConfig{}, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit code = %d, want 4 (only 0 is special-cased, not negative); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
}

func TestEwait_OverallTimeoutZero_ExplicitOversizedPollStillCeilings(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", cursorPath,
		"--overall-timeout", "0",
		"--poll", "10000",
	}

	res := runEwait(t, args, stubConfig{}, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit code = %d, want 4 (an explicit oversized --poll must still ceiling-error even with --overall-timeout 0); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
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
	assertSingleJSONLine(t, res.stdout)
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
	assertSingleJSONLine(t, res.stdout)
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
