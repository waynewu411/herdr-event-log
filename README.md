# herdr-event-log

A minimal [Herdr](https://herdr.dev) plugin that logs every pane agent-status
change to a durable, append-only file. No daemon, no filtering, no
parent/child registry — just one JSON line per event, so any reader at any
depth can grep for the `pane_id` it cares about and resume safely across gaps.

## Why

An orchestrating agent (e.g. a `deliverer` watching a child, or a grandchild,
agent in another pane) needs to know when that pane's agent status changes
(`blocked`/`idle`/`done`/...), without polling `herdr agent get`/`agent wait`
in a tight loop and without hand-managing a persistent watcher process.

Herdr's own socket API (`events.subscribe`) gives you a live event stream,
but no history — if you're not connected when an event fires, it's gone.
This plugin trades that immediacy for durability: the Herdr server itself
invokes the hook on every matching event for the life of the session, so the
log always has a full history you can resume from at any offset.

## Install

From this repo's checkout:

```bash
herdr plugin link <path-to-this-repo>
herdr plugin enable waynewu411.herdr-event-log
```

`link` registers the plugin manifest (`herdr-plugin.toml`) with the current
Herdr session; `enable` turns it on. Both are per Herdr session/socket — run
them again for any other session instance you want covered.

Once enabled, Herdr invokes `hook.mjs` automatically on every
`pane.agent_status_changed` event, for the life of that session. There is
nothing to start, supervise, or restart.

## Log format

One JSON object per line, appended to `$HERDR_PLUGIN_STATE_DIR/events.log`:

```json
{"ts":"2026-08-14T02:13:04.512Z","pane_id":"w3:p2","agent_status":"idle","workspace_id":"w3","agent":"tester"}
```

| Field          | Type           | Meaning                                             |
|----------------|----------------|------------------------------------------------------|
| `ts`           | string (ISO)   | Time the hook observed the event                     |
| `pane_id`      | string         | Pane the status change occurred in                    |
| `agent_status` | string         | New agent status (`idle`, `working`, `blocked`, `done`, `unknown`) |
| `workspace_id` | string         | Workspace containing the pane                         |
| `agent`        | string \| null | Agent name, if any, at the time of the event          |

The hook does zero filtering: every matching event for the whole session gets
appended, regardless of which pane it's for. Filtering is entirely a reader's
job — this is deliberate, so any reader at any depth of an agent hierarchy
can watch any `pane_id` it knows about (including a grandchild's) without
registering anything anywhere first.

## Reading the log: cursor-based tail/resume

Because the log is durable and append-only, a reader can maintain its own
persisted byte-offset cursor and never miss an event, even across an
arbitrarily long gap where it isn't tailing at all:

```bash
# snapshot cursor BEFORE you start caring about a pane_id (avoids a race)
CURSOR=$(wc -c < "$HERDR_PLUGIN_STATE_DIR/events.log")
# wait: tail from the cursor, grep for what you care about, exits on first match
tail -c +$((CURSOR+1)) -f "$HERDR_PLUGIN_STATE_DIR/events.log" | grep --line-buffered -m1 '"pane_id":"<target>"'
# after the wait returns (or if you go off and do something else entirely first),
# re-snapshot before your next wait so you never lose anything in between
CURSOR=$(wc -c < "$HERDR_PLUGIN_STATE_DIR/events.log")
```

Chain a second `grep` if you also need to match on `agent_status`. Snapshot
the cursor *before* dispatching/starting the child pane you're about to
watch, not after — otherwise a status change that fires in between is lost.

This is the same byte-offset cursor approach used by
[`joelhooks/herdr-pings`](https://github.com/joelhooks/herdr-pings), arrived
at independently — a sign it's the right pattern for this problem, not a
novel risk.

## Non-goal: active push

This plugin is passive/log-only. It does not, and will not, write text or
Enter into a target pane to wake it up.

Actively pushing into a pane (e.g. `herdr agent prompt`) was tested
separately: buffered text+Enter do get delivered once the target frees up —
delivery isn't lost or corrupted — but it lands interleaved with whatever the
target was already doing, which can distract or derail its current turn.
That's a real risk for a hook that fires unconditionally on every matching
event, so it stays out of this plugin. If a caller wants to actively wake a
specific pane, that's a separate, deliberately narrow action taken by the
caller itself: confirm the target is actually idle with `agent get` first,
then `agent prompt` — never automated unconditionally inside this hook.
