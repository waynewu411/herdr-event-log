package main

// Stub-fidelity tests (HERDR_STUB_MAP matching, success-shape nesting) and startup
// diagnostic / cursor-file tests for scripts/herdr-ewait.sh. Split out from
// ewait_resolution_test.go to keep each file under this repo's ~800-line guideline
// (round-2 review, N4) — see ewait_harness_test.go for the shared stub/subprocess
// plumbing both files use.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- L2 (round 4): the HERDR_STUB_MAP branch must answer for the mapped pane id too
// (every post-resolution probe uses it, not the name), and must match by exact name or
// pane id — never a substring — or TestEwait_TwoResolvableTargets_DiagnosticListsBothMappings
// above silently runs in a "every probe after resolution fails" world instead of the
// "two healthy, working-forever targets" one its name claims. ---

func TestHerdrStub_MapAnswersForBothNameAndMappedPaneID(t *testing.T) {
	requireEwaitTools(t)
	stub := stubConfig{mapEntries: "alice=w7:p3;bob=w8:p1"}

	for _, target := range []string{"alice", "w7:p3"} {
		stdout, stderr, code := runHerdrStub(t, stub, "agent", "get", target)
		if code != 0 {
			t.Fatalf("agent get %q: exit %d, want 0; stdout: %q stderr: %q", target, code, stdout, stderr)
		}
		if !strings.Contains(stdout, `"pane_id":"w7:p3"`) || !strings.Contains(stdout, `"agent_status":"working"`) {
			t.Fatalf("agent get %q: unexpected stdout: %q", target, stdout)
		}
	}
}

func TestHerdrStub_MapLookupDoesNotSubstringMatch(t *testing.T) {
	requireEwaitTools(t)
	// "alice" is not a key in this map, but is a suffix of "malice" — a substring
	// lookup (grep -F "alice=") would wrongly match the "malice=..." line.
	stub := stubConfig{mapEntries: "malice=w9:p9;bob=w8:p1"}

	_, stderr, code := runHerdrStub(t, stub, "agent", "get", "alice")
	if code == 0 {
		t.Fatalf("agent get %q unexpectedly succeeded against an unrelated map entry it is a substring of; stderr: %q", "alice", stderr)
	}
}

// N2 fix (#9 round-5 review): real herdr 0.8.2 nests a success response under
// result.agent (agent get) / result.pane (pane get) — verified read-only against this
// machine's live herdr: `herdr agent get <pane>` -> {"id":"cli:agent:get","result":
// {"agent":{...,"pane_id":"...",...},"type":"agent_info"}}; `herdr pane get <pane>` ->
// {"id":"cli:pane:get","result":{"pane":{...,"agent_status":"...",...,"pane_id":"...",
// ...},"type":"pane_info"}}, including "agent_status":"unknown" for a real agent-less
// pane. The stub's success shapes were flat at top level — harmless today, since the
// script's own greps are shape-agnostic, but a false claim of fidelity in this file's
// own header comment.
func TestHerdrStub_AgentGetSuccess_NestsUnderResultAgent(t *testing.T) {
	requireEwaitTools(t)
	stub := stubConfig{alwaysWorking: "w1:p1"}

	stdout, stderr, code := runHerdrStub(t, stub, "agent", "get", "w1:p1")
	if code != 0 {
		t.Fatalf("agent get: exit %d, want 0; stderr: %q", code, stderr)
	}
	var parsed struct {
		Result struct {
			Agent map[string]any `json:"agent"`
			Type  string         `json:"type"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v; got: %q", err, stdout)
	}
	if parsed.Result.Agent == nil || parsed.Result.Agent["pane_id"] != "w1:p1" {
		t.Fatalf(`expected result.agent.pane_id == "w1:p1"; got: %q`, stdout)
	}
	if parsed.Result.Type != "agent_info" {
		t.Fatalf(`expected result.type == "agent_info"; got: %q`, stdout)
	}
}

func TestHerdrStub_PaneGetSuccess_NestsUnderResultPane(t *testing.T) {
	requireEwaitTools(t)
	stub := stubConfig{}

	stdout, stderr, code := runHerdrStub(t, stub, "pane", "get", "w1:p1")
	if code != 0 {
		t.Fatalf("pane get: exit %d, want 0; stderr: %q", code, stderr)
	}
	var parsed struct {
		Result struct {
			Pane map[string]any `json:"pane"`
			Type string         `json:"type"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v; got: %q", err, stdout)
	}
	if parsed.Result.Pane == nil || parsed.Result.Pane["pane_id"] != "w1:p1" {
		t.Fatalf(`expected result.pane.pane_id == "w1:p1"; got: %q`, stdout)
	}
	if parsed.Result.Type != "pane_info" {
		t.Fatalf(`expected result.type == "pane_info"; got: %q`, stdout)
	}
	// N2 fix: real herdr's pane get always carries agent_status (e.g. "unknown" for an
	// agent-less pane), which the stub previously omitted entirely.
	if _, ok := parsed.Result.Pane["agent_status"]; !ok {
		t.Fatalf(`expected result.pane.agent_status to be present; got: %q`, stdout)
	}
}

// --- L2 (round 5): moving the cursor PERSIST ahead of check-first (for the diagnostic,
// N1/round-3) must not turn a previously-successful immediate hit into a raw, undocumented
// exit 1 when --cursor-file is not writable. On `main` the cursor file was written only
// AFTER check-first, so a target that was already terminal got its hit JSON regardless of
// whether the cursor path was any good; the write is restored to that position here (the
// CURSOR *value* is still computed earlier, so the startup diagnostic can still show it).

func TestEwait_UnwritableCursorFile_ImmediateHitStillSucceeds(t *testing.T) {
	logPath, _ := newEwaitFiles(t)
	badCursorPath := filepath.Join(t.TempDir(), "no-such-dir", "cursor")
	stub := stubConfig{
		paneID:      "w1:p1",
		flipAt:      0, // check-first hits immediately
		counterFile: filepath.Join(t.TempDir(), "counter"),
	}
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", badCursorPath,
		"--overall-timeout", "5",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (an immediate hit must not be lost to an unwritable cursor file); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, `"pane_id":"w1:p1"`) || !strings.Contains(res.stdout, `"verified_state":"done"`) {
		t.Fatalf("expected a hit line on stdout; stdout: %q", res.stdout)
	}
	if _, err := os.Stat(badCursorPath); err == nil {
		t.Fatalf("cursor file should never have been created under the nonexistent directory")
	}
}

// Matches `main`: an immediate hit via check-first never creates a cursor file at all
// (not merely "doesn't crash if it can't") — this also means the README/header caveat
// about a cursor file now appearing on an immediate hit no longer applies.
func TestEwait_ImmediateHit_CursorFileNotCreated(t *testing.T) {
	logPath, cursorPath := newEwaitFiles(t)
	stub := stubConfig{
		paneID:      "w1:p1",
		flipAt:      0,
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
	if _, err := os.Stat(cursorPath); err == nil {
		t.Fatalf("cursor file should not be created on an immediate check-first hit, matching main")
	}
}

func TestEwait_UnwritableCursorFile_NonImmediateRun_ExitsFourNotRawError(t *testing.T) {
	logPath, _ := newEwaitFiles(t)
	badCursorPath := filepath.Join(t.TempDir(), "no-such-dir", "cursor")
	// alwaysWorking never reaches a terminal state, so check-first does not hit and the
	// script must actually try to persist the cursor before entering the main loop.
	stub := stubConfig{alwaysWorking: "w1:p1"}
	args := []string{
		"--targets", "w1:p1",
		"--log", logPath,
		"--cursor-file", badCursorPath,
		"--overall-timeout", "5",
	}

	res := runEwait(t, args, stub, 10*time.Second)

	if res.exitCode != 4 {
		t.Fatalf("exit code = %d, want 4 (a documented usage error, not a raw bash crash); stdout: %q stderr: %q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "cursor") {
		t.Fatalf("error should name the cursor file as the problem; stderr: %q", res.stderr)
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
