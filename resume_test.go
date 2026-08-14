package main

// TestCursorResumeRecipe validates the exact byte-offset cursor/resume
// recipe documented in README.md — not the hook itself. It synthesizes a
// log file, simulates a gap by appending lines while nothing is "watching"
// (no tail running), then resumes from a saved cursor exactly as the
// recipe prescribes and asserts nothing from the gap was missed. It
// requires no live Herdr session.

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func requireUnixTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("cursor-resume recipe uses tail/grep/wc, not available on windows")
	}
	for _, tool := range []string{"tail", "grep", "wc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH: %v", tool, err)
		}
	}
}

// wcDashC runs the exact `wc -c < path` snapshot step from the README
// recipe and returns the byte count.
func wcDashC(t *testing.T, path string) int64 {
	t.Helper()
	out, err := exec.Command("bash", "-c", `wc -c < "`+path+`"`).Output()
	if err != nil {
		t.Fatalf("wc -c: %v", err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Fatalf("parse wc -c output %q: %v", out, err)
	}
	return n
}

func appendLines(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open %s for append: %v", path, err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatalf("append line: %v", err)
		}
	}
}

// runResumeRecipe runs the documented `tail -c +$((CURSOR+1)) -f events.log
// | grep --line-buffered -m1 pattern` recipe and returns the matched line.
// grep exits on its own after the first match; tail (follow mode) never
// exits on its own, so it is run and killed independently instead of
// waiting on a single shell pipeline (which would block forever on tail).
func runResumeRecipe(t *testing.T, logPath string, cursor int64, pattern string, timeout time.Duration) string {
	t.Helper()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	tailCmd := exec.Command("tail", "-c", "+"+strconv.FormatInt(cursor+1, 10), "-f", logPath)
	tailCmd.Stdout = pw
	if err := tailCmd.Start(); err != nil {
		t.Fatalf("start tail: %v", err)
	}
	defer func() {
		_ = tailCmd.Process.Kill()
		_ = tailCmd.Wait()
	}()
	_ = pw.Close() // our copy; tail holds its own duplicated fd

	grepCmd := exec.Command("grep", "--line-buffered", "-m1", pattern)
	grepCmd.Stdin = pr
	var out bytes.Buffer
	grepCmd.Stdout = &out
	if err := grepCmd.Start(); err != nil {
		t.Fatalf("start grep: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- grepCmd.Wait() }()

	select {
	case err := <-done:
		_ = pr.Close()
		if err != nil {
			t.Fatalf("grep exited with error: %v (output so far: %q)", err, out.String())
		}
	case <-time.After(timeout):
		_ = grepCmd.Process.Kill()
		_ = pr.Close()
		t.Fatalf("timed out after %s waiting for the resume recipe to catch the gap event", timeout)
	}

	return strings.TrimRight(out.String(), "\n")
}

func TestCursorResumeRecipe_CatchesEventsAcrossAGap(t *testing.T) {
	requireUnixTools(t)

	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")

	// Pre-existing history for an unrelated pane, as if the log already
	// had activity before we ever started caring about w2:p9.
	preexisting := []string{
		`{"ts":"2026-08-14T01:00:00.000Z","pane_id":"w1:p1","agent_status":"working","workspace_id":"w1","agent":"claude"}`,
		`{"ts":"2026-08-14T01:00:01.000Z","pane_id":"w1:p1","agent_status":"idle","workspace_id":"w1","agent":"claude"}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(preexisting, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("seed log: %v", err)
	}

	// Snapshot the cursor BEFORE we start caring about w2:p9 — per the
	// README recipe, this must happen before the pane we care about is
	// even dispatched, to avoid a race.
	cursor := wcDashC(t, logPath)

	// Simulate the gap: events land on the log while nothing is tailing —
	// this mirrors a reader going off to do something else entirely
	// before it resumes.
	gap := []string{
		`{"ts":"2026-08-14T01:00:02.000Z","pane_id":"w2:p9","agent_status":"working","workspace_id":"w2","agent":"claude"}`,
		`{"ts":"2026-08-14T01:00:03.000Z","pane_id":"w2:p9","agent_status":"done","workspace_id":"w2","agent":"claude"}`,
	}
	appendLines(t, logPath, gap)

	// Resume from the saved cursor using the exact recipe from README.md.
	matched := runResumeRecipe(t, logPath, cursor, `"pane_id":"w2:p9"`, 10*time.Second)
	if !strings.Contains(matched, `"pane_id":"w2:p9"`) {
		t.Fatalf("resume did not catch the gap event, got: %q", matched)
	}
	if matched != gap[0] {
		t.Fatalf("resume matched %q, want the first gap event %q", matched, gap[0])
	}

	// Confirm nothing from the gap was lost: a full catch-up read from the
	// same cursor must contain BOTH gap events, and none of the
	// pre-existing history (which was before the cursor).
	full := readFromOffset(t, logPath, cursor)
	for _, want := range gap {
		if !strings.Contains(full, want) {
			t.Errorf("full catch-up missing gap event %q; got: %q", want, full)
		}
	}
	for _, unwanted := range preexisting {
		if strings.Contains(full, unwanted) {
			t.Errorf("full catch-up unexpectedly included pre-cursor history %q", unwanted)
		}
	}
}

// readFromOffset reads a file starting at the given byte offset, the same
// slice of the file the README's `tail -c +$((CURSOR+1))` step reads.
func readFromOffset(t *testing.T, path string, offset int64) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	r := bufio.NewReader(f)
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}
