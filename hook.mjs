#!/usr/bin/env node
// Herdr event hook — invoked automatically by the Herdr server once per
// matching event (see herdr-plugin.toml). No daemon, no persistent process:
// this process starts, appends one line, and exits.
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

import { appendFileSync } from "node:fs";
import { join } from "node:path";

const stateDir = process.env.HERDR_PLUGIN_STATE_DIR;
if (!stateDir) {
  console.error("HERDR_PLUGIN_STATE_DIR is not set — refusing to write anywhere else");
  process.exit(1);
}

const raw = process.env.HERDR_PLUGIN_EVENT_JSON;
if (!raw) {
  console.error("HERDR_PLUGIN_EVENT_JSON is not set");
  process.exit(1);
}

let event;
try {
  event = JSON.parse(raw);
} catch (error) {
  console.error("Failed to parse HERDR_PLUGIN_EVENT_JSON:", error.message);
  process.exit(1);
}

// PaneAgentStatusChangedEvent per `herdr api schema --json`:
// required { pane_id, workspace_id, agent_status }; optional { agent,
// display_agent, title, state_labels }.
const data = event.data ?? event;
const line = {
  ts: new Date().toISOString(),
  pane_id: data.pane_id,
  agent_status: data.agent_status,
  workspace_id: data.workspace_id,
  agent: data.agent ?? null,
};

appendFileSync(join(stateDir, "events.log"), `${JSON.stringify(line)}\n`);
