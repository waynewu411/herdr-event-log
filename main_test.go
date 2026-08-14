package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 8, 14, 1, 31, 13, 614000000, time.UTC)

const testSocketPath = "/Users/test/.config/herdr/herdr.sock"

func readLastLine(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := splitNonEmptyLines(string(data))
	if len(lines) == 0 {
		t.Fatalf("no lines in %s", path)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("unmarshal last line %q: %v", lines[len(lines)-1], err)
	}
	return m
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func TestBuildLine_WellFormedFlatEvent(t *testing.T) {
	raw := `{"pane_id":"w3:p2","agent_status":"idle","workspace_id":"w3","agent":"claude"}`
	got, err := buildLine(raw, fixedTime)
	if err != nil {
		t.Fatalf("buildLine returned error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, got)
	}

	want := map[string]interface{}{
		"ts":           "2026-08-14T01:31:13.614Z",
		"pane_id":      "w3:p2",
		"agent_status": "idle",
		"workspace_id": "w3",
		"agent":        "claude",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("field %q = %v, want %v", k, m[k], v)
		}
	}
}

func TestBuildLine_WrappedInDataEnvelope(t *testing.T) {
	raw := `{"type":"pane.agent_status_changed","data":{"pane_id":"w1:p4","agent_status":"blocked","workspace_id":"w1","agent":"reviewer"}}`
	got, err := buildLine(raw, fixedTime)
	if err != nil {
		t.Fatalf("buildLine returned error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if m["pane_id"] != "w1:p4" {
		t.Errorf("pane_id = %v, want w1:p4", m["pane_id"])
	}
	if m["agent_status"] != "blocked" {
		t.Errorf("agent_status = %v, want blocked", m["agent_status"])
	}
}

func TestBuildLine_MissingAgentEncodesNull(t *testing.T) {
	raw := `{"pane_id":"w3:p2","agent_status":"idle","workspace_id":"w3"}`
	got, err := buildLine(raw, fixedTime)
	if err != nil {
		t.Fatalf("buildLine returned error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	agentVal, present := m["agent"]
	if !present {
		t.Fatalf("agent key missing entirely, want present with null value")
	}
	if agentVal != nil {
		t.Errorf("agent = %v, want null", agentVal)
	}
}

func TestBuildLine_MalformedJSON(t *testing.T) {
	_, err := buildLine("{not valid json", fixedTime)
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestLogFileName_StableForSameInput(t *testing.T) {
	a := logFileName(testSocketPath)
	b := logFileName(testSocketPath)
	if a != b {
		t.Errorf("logFileName(%q) is not stable: got %q then %q", testSocketPath, a, b)
	}
}

func TestLogFileName_DifferentForDifferentInput(t *testing.T) {
	a := logFileName("/Users/test/.config/herdr/herdr.sock")
	b := logFileName("/Users/test/.config/herdr/herdr-2.sock")
	if a == b {
		t.Errorf("logFileName produced the same name for two different socket paths: %q", a)
	}
}

func TestLogFileName_MatchesDocumentedFormat(t *testing.T) {
	name := logFileName(testSocketPath)
	if !strings.HasPrefix(name, "events-") || !strings.HasSuffix(name, ".log") {
		t.Fatalf("logFileName = %q, want events-<hash>.log", name)
	}
	hash := strings.TrimSuffix(strings.TrimPrefix(name, "events-"), ".log")
	if len(hash) != 16 {
		t.Fatalf("hash portion of %q has length %d, want 16", name, len(hash))
	}

	sum := sha256.Sum256([]byte(testSocketPath))
	want := hex.EncodeToString(sum[:])[:16]
	if hash != want {
		t.Fatalf("hash = %q, want %q (sha256 hex, first 16 chars, matching README's documented algorithm)", hash, want)
	}
}

func TestRun_Success(t *testing.T) {
	dir := t.TempDir()
	raw := `{"pane_id":"w3:p2","agent_status":"idle","workspace_id":"w3","agent":"claude"}`

	if err := run(dir, raw, testSocketPath, fixedTime); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	m := readLastLine(t, filepath.Join(dir, logFileName(testSocketPath)))
	if m["pane_id"] != "w3:p2" || m["agent_status"] != "idle" {
		t.Errorf("unexpected written line: %v", m)
	}
}

func TestRun_AppendsRatherThanOverwrites(t *testing.T) {
	dir := t.TempDir()
	first := `{"pane_id":"w1:p1","agent_status":"working","workspace_id":"w1","agent":"a"}`
	second := `{"pane_id":"w1:p1","agent_status":"idle","workspace_id":"w1","agent":"a"}`

	if err := run(dir, first, testSocketPath, fixedTime); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := run(dir, second, testSocketPath, fixedTime.Add(time.Second)); err != nil {
		t.Fatalf("second run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, logFileName(testSocketPath)))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := splitNonEmptyLines(string(data))
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), data)
	}
}

func TestRun_MissingStateDir(t *testing.T) {
	raw := `{"pane_id":"w3:p2","agent_status":"idle","workspace_id":"w3","agent":"claude"}`
	err := run("", raw, testSocketPath, fixedTime)
	if err == nil {
		t.Fatal("expected an error when HERDR_PLUGIN_STATE_DIR is empty, got nil")
	}
}

func TestRun_StateDirDoesNotExist(t *testing.T) {
	raw := `{"pane_id":"w3:p2","agent_status":"idle","workspace_id":"w3","agent":"claude"}`
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	err := run(missing, raw, testSocketPath, fixedTime)
	if err == nil {
		t.Fatal("expected an error when the state dir does not exist, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(missing, logFileName(testSocketPath))); statErr == nil {
		t.Fatal("log file should not have been created")
	}
}

func TestRun_MissingEventJSON(t *testing.T) {
	dir := t.TempDir()
	err := run(dir, "", testSocketPath, fixedTime)
	if err == nil {
		t.Fatal("expected an error when HERDR_PLUGIN_EVENT_JSON is empty, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(dir, logFileName(testSocketPath))); statErr == nil {
		t.Fatal("log file should not have been created on a missing event payload")
	}
}

func TestRun_MalformedEventJSONNoPartialWrite(t *testing.T) {
	dir := t.TempDir()
	err := run(dir, "{not valid json", testSocketPath, fixedTime)
	if err == nil {
		t.Fatal("expected an error for malformed HERDR_PLUGIN_EVENT_JSON, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(dir, logFileName(testSocketPath))); statErr == nil {
		t.Fatal("log file should not have been created on malformed JSON — no partial write")
	}
}

func TestRun_MissingSocketPath(t *testing.T) {
	dir := t.TempDir()
	raw := `{"pane_id":"w3:p2","agent_status":"idle","workspace_id":"w3","agent":"claude"}`
	err := run(dir, raw, "", fixedTime)
	if err == nil {
		t.Fatal("expected an error when HERDR_SOCKET_PATH is empty, got nil")
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("no file should have been created without a socket path to derive a filename from, found: %v", entries)
	}
}
