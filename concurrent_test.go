package main

// TestConcurrentHookInvocations_RealProcesses verifies the O_APPEND +
// single-write() atomicity assumption the design relies on (see main.go's
// package comment). It spawns real, independent OS processes running the
// built hook binary — not goroutines. Goroutines only exercise
// same-process concurrency, which `go test -race` already covers and isn't
// the actual risk: every real hook invocation is a separate process with
// no shared memory, so the only thing that can protect the log file from
// interleaved/truncated writes is the OS-level guarantee for small
// O_APPEND writes, not anything in-process. This test spawns the
// goroutines only to launch and wait on the child processes concurrently;
// the concurrent writers under test are the child processes themselves.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentHookInvocations_RealProcesses(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not found in PATH")
	}

	// Build a real hook binary to exec repeatedly, same as herdr-plugin.toml
	// would invoke it.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "hook-under-test")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build hook binary: %v\n%s", err, out)
	}

	stateDir := t.TempDir()
	const n = 50

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			event := fmt.Sprintf(`{"pane_id":"w1:p%d","agent_status":"working","workspace_id":"w1","agent":"claude"}`, i)
			cmd := exec.Command(binPath)
			cmd.Env = append(os.Environ(),
				stateDirEnv+"="+stateDir,
				eventEnv+"="+event,
				socketEnv+"="+testSocketPath,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				errs[i] = fmt.Errorf("invocation %d failed: %w (output: %s)", i, err, out)
			}
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	logPath := filepath.Join(stateDir, logFileName(testSocketPath))
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	lines := splitNonEmptyLines(string(data))
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d — some writes were lost or merged into others: %q", len(lines), n, data)
	}

	seenPaneIDs := make(map[string]bool, n)
	for i, line := range lines {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d is not valid JSON (truncated or interleaved write): %q: %v", i, line, err)
		}
		paneID, _ := m["pane_id"].(string)
		if !strings.HasPrefix(paneID, "w1:p") {
			t.Fatalf("line %d has unexpected pane_id %q, full line: %q", i, paneID, line)
		}
		if seenPaneIDs[paneID] {
			t.Fatalf("pane_id %q appears more than once — a write was duplicated or two writes merged", paneID)
		}
		seenPaneIDs[paneID] = true
	}
	if len(seenPaneIDs) != n {
		t.Fatalf("got %d distinct pane_ids, want %d", len(seenPaneIDs), n)
	}
}
