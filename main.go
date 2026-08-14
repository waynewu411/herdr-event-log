// Command hook is the Herdr event hook — invoked automatically by the Herdr
// server once per matching event (see herdr-plugin.toml). No daemon, no
// persistent process: this binary starts, appends one line, and exits.
//
// Intentionally dumb: no filtering, no pane_id scoping, no parent/child
// registry. Every matching event gets appended unconditionally. All
// filtering responsibility belongs to readers (see README's tail/grep
// recipe) — this keeps the write side free of routing bugs and lets any
// reader, at any depth of the agent hierarchy, watch any pane_id it knows
// about without registering anything here first.
//
// Writes are small (well under PIPE_BUF), so concurrent hook invocations
// appending at once stay safe: POSIX guarantees O_APPEND writes below that
// size don't interleave.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	stateDirEnv = "HERDR_PLUGIN_STATE_DIR"
	eventEnv    = "HERDR_PLUGIN_EVENT_JSON"
	socketEnv   = "HERDR_SOCKET_PATH"

	logFilePrefix  = "events-"
	logFileSuffix  = ".log"
	logFileHashLen = 16
)

// logFileName derives the per-Herdr-instance log filename from
// $HERDR_SOCKET_PATH: sha256(socketPath), hex-encoded, truncated to the
// first 16 characters of the digest. See README for the exact algorithm —
// a reader with its own $HERDR_SOCKET_PATH can independently derive the
// same filename with no coordination.
func logFileName(socketPath string) string {
	sum := sha256.Sum256([]byte(socketPath))
	return logFilePrefix + hex.EncodeToString(sum[:])[:logFileHashLen] + logFileSuffix
}

// logLine is the shape of one appended log line. PaneID/AgentStatus/
// WorkspaceID are omitted entirely when absent from the event payload
// (mirroring JSON.stringify dropping undefined-valued properties in the
// original Node hook); Agent is always present, encoding as null when
// absent, since a missing map key naturally yields a nil interface{}.
type logLine struct {
	TS          string      `json:"ts"`
	PaneID      interface{} `json:"pane_id,omitempty"`
	AgentStatus interface{} `json:"agent_status,omitempty"`
	WorkspaceID interface{} `json:"workspace_id,omitempty"`
	Agent       interface{} `json:"agent"`
}

// buildLine parses the raw HERDR_PLUGIN_EVENT_JSON payload and returns the
// JSON line to append (without a trailing newline). It returns an error if
// the payload isn't valid JSON; it never panics on unexpected shapes.
func buildLine(raw string, now time.Time) ([]byte, error) {
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", eventEnv, err)
	}

	// PaneAgentStatusChangedEvent per `herdr api schema --json`: required
	// { pane_id, workspace_id, agent_status }; optional { agent,
	// display_agent, title, state_labels }. Fields may arrive nested under
	// "data" or flat at the top level.
	data := envelope
	if d, ok := envelope["data"].(map[string]interface{}); ok {
		data = d
	}

	line := logLine{
		TS:          now.UTC().Format("2006-01-02T15:04:05.000Z"),
		PaneID:      data["pane_id"],
		AgentStatus: data["agent_status"],
		WorkspaceID: data["workspace_id"],
		Agent:       data["agent"],
	}
	return json.Marshal(line)
}

// run performs the whole hook: validate env, build the log line, append it.
// It writes nothing unless the line was built successfully, so a failure
// never leaves a partial or corrupt line in the log file.
func run(stateDir, raw, socketPath string, now time.Time) error {
	if stateDir == "" {
		return fmt.Errorf("%s is not set — refusing to write anywhere else", stateDirEnv)
	}
	if raw == "" {
		return fmt.Errorf("%s is not set", eventEnv)
	}
	if socketPath == "" {
		return fmt.Errorf("%s is not set — refusing to derive a log filename", socketEnv)
	}

	line, err := buildLine(raw, now)
	if err != nil {
		return err
	}

	fileName := logFileName(socketPath)
	f, err := os.OpenFile(filepath.Join(stateDir, fileName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", fileName, err)
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("failed to write %s: %w", fileName, err)
	}
	return nil
}

func main() {
	if err := run(os.Getenv(stateDirEnv), os.Getenv(eventEnv), os.Getenv(socketEnv), time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
