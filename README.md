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

The hook is a Go binary, built from `main.go`. The binary itself is **not
committed** — it's platform-specific and would silently go stale relative to
its source if it were checked in, so it's always built fresh from source
instead. `.gitignore` excludes it.

From this repo's checkout:

```bash
herdr plugin link <path-to-this-repo>
make build
herdr plugin enable waynewu411.herdr-event-log
```

`link` registers the plugin manifest (`herdr-plugin.toml`) with the current
Herdr session; `enable` turns it on. Both are per Herdr session/socket — run
them again for any other session instance you want covered. `make build`
must be re-run after pulling any change to `main.go` — `herdr-plugin.toml`
points at the built `./hook` binary, not the Go source, so a stale binary
silently keeps running old behavior otherwise.

Once enabled, Herdr invokes `./hook` automatically on every
`pane.agent_status_changed` event, for the life of that session. There is
nothing to start, supervise, or restart.

## Plugin manifest

This repo's current `herdr-plugin.toml`, verbatim:

```toml
id = "waynewu411.herdr-event-log"
name = "Herdr Event Log"
version = "0.1.0"
min_herdr_version = "0.7.0"

[[events]]
on = "pane.agent_status_changed"
command = ["./hook"]
```

`[[events]]` is TOML's array-of-tables syntax — each `[[events]]` block is
one hook registration, and `on` inside it is a single string, not an array
(verified against
[`RawPluginManifestEventHook`](https://github.com/herdrdev/herdr/blob/main/src/app/api/plugins/manifest.rs#L64-L69)
in Herdr's own source: `on: String`, not `Vec<String>`). The array-ness
lives entirely in the outer `[[events]]` repetition, not in `on` itself.

If this plugin ever grows to log more than `pane.agent_status_changed` (see
[Why](#why) — the manifest is deliberately scoped broadly for exactly this
reason), that means **another `[[events]]` block**, not a list value on
`on`:

```toml
[[events]]
on = "pane.agent_status_changed"
command = ["./hook"]

[[events]]
on = "some.other_event_type"
command = ["./hook"]
```

Not `on = ["pane.agent_status_changed", "some.other_event_type"]` — that
shape doesn't exist in the manifest schema.

## Log file: one per Herdr instance

The hook writes to a log file scoped to the specific Herdr session/socket it
was invoked for, not a single fixed `events.log` shared by every session on
the machine:

```
$HERDR_PLUGIN_STATE_DIR/events-<hash>.log
```

`<hash>` is derived from `$HERDR_SOCKET_PATH`: **SHA-256 of the socket path
string, hex-encoded, truncated to the first 16 characters of the digest.**
That's the whole algorithm — no coordination or registration needed to
compute it. Any reader that also has `$HERDR_SOCKET_PATH` set (i.e. is
itself running inside the same Herdr session) can derive the exact same
filename independently:

```bash
LOG_HASH=$(printf '%s' "$HERDR_SOCKET_PATH" | { command -v sha256sum >/dev/null 2>&1 && sha256sum || shasum -a 256; } | cut -c1-16)
LOGFILE="$HERDR_PLUGIN_STATE_DIR/events-${LOG_HASH}.log"
```

(`sha256sum` is used when available — typical on Linux — falling back to
`shasum -a 256`, typical on macOS; both print the hex digest first, so
`cut -c1-16` takes the same 16 characters either way.)

`$HERDR_SOCKET_PATH` is what identifies the running Herdr instance for this
purpose — it has a stable 1:1 correspondence with the session. (This is
unrelated to `herdr-client.sock`, a separate terminal-rendering-protocol
socket that has nothing to do with plugin state.)

## Log format

One JSON object per line, appended to the per-instance log file above:

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
# derive the per-instance log filename (see "Log file" above)
LOG_HASH=$(printf '%s' "$HERDR_SOCKET_PATH" | { command -v sha256sum >/dev/null 2>&1 && sha256sum || shasum -a 256; } | cut -c1-16)
LOGFILE="$HERDR_PLUGIN_STATE_DIR/events-${LOG_HASH}.log"

# snapshot cursor BEFORE you start caring about a pane_id (avoids a race)
CURSOR=$(wc -c < "$LOGFILE")
# wait: tail from the cursor, grep for what you care about, exits on first match
tail -c +$((CURSOR+1)) -f "$LOGFILE" | grep --line-buffered -m1 '"pane_id":"<target>"'
# after the wait returns (or if you go off and do something else entirely first),
# re-snapshot before your next wait so you never lose anything in between
CURSOR=$(wc -c < "$LOGFILE")
```

Chain a second `grep` if you also need to match on `agent_status`. Snapshot
the cursor *before* dispatching/starting the child pane you're about to
watch, not after — otherwise a status change that fires in between is lost.

This is the same byte-offset cursor approach used by
[`joelhooks/herdr-pings`](https://github.com/joelhooks/herdr-pings), arrived
at independently — a sign it's the right pattern for this problem, not a
novel risk.

## Ready-made waiter: `scripts/herdr-ewait.sh`

This repo also ships `scripts/herdr-ewait.sh`, a hardened event-log consumer
for orchestration code. It replaces hand-rolled `tail -f`/`sleep` loops with a
cursor-based bounded reader plus live `herdr agent get` verification:

```bash
scripts/herdr-ewait.sh \
  --targets "w3:p2,w4:p1" \
  --states "blocked|done|idle" \
  --log "$LOGFILE" \
  --cursor-file "/tmp/herdr-ewait.cursor" \
  --overall-timeout 3600 \
  --poll 5 \
  --safety-net 60
```

- `--targets` is a comma-separated list of `pane_id`s to watch.
- `--states` is a `|`-separated regex of statuses to accept; the default is
  `blocked|done|idle`.
- `--log` is the per-instance event log described above.
- `--cursor-file` persists the byte cursor across calls.
- `--overall-timeout`, `--poll`, and `--safety-net` tune the total wait, the
  bounded read interval, and the periodic verification sweep.

On success stdout is exactly one compact JSON line:

```json
{"pane_id":"w3:p2","verified_state":"done","ts":"2026-08-15T00:00:00Z"}
```

Exit codes are `0` for a verified hit, `2` for overall timeout, `3` when the
log is missing/unreadable at start (the caller can fall back to the degraded
`herdr agent wait` path), and `4` for a usage error.

Log matches are wake-up signals, not truth: every candidate hit and every
periodic safety-net sweep is re-checked against `herdr agent get`, so a stale
log line cannot produce a false success. A fresh waiter starts its cursor at
the current log size, so it never replays old history.

## Development

```bash
make build   # build the hook binary (go build -o hook .)
make test    # unit tests + the automated cursor-resume test (go test -race ./...)
make vet     # go vet ./...
make fmt     # checks gofmt compliance; run `gofmt -w .` yourself to fix
make clean   # remove the built binary
```

`make test` covers:

- the hook's own logic (well-formed events, the log-filename hash
  derivation, graceful failure on missing/malformed
  `HERDR_PLUGIN_EVENT_JSON`, a missing `HERDR_PLUGIN_STATE_DIR`, or a
  missing `HERDR_SOCKET_PATH`);
- the cursor-resume recipe above — synthesizes a log file, simulates a gap,
  and asserts the exact `tail`/`grep` recipe documented here catches
  everything across it;
- the `O_APPEND` + single-`write()` atomicity assumption the design relies
  on — spawns many real child OS processes (not goroutines) that all
  invoke the built hook binary concurrently against the same log file, then
  asserts every line is present, valid JSON, and not merged/truncated.

None of this requires a live Herdr session. A GitHub Actions workflow
(`.github/workflows/test.yml`) runs `make fmt`, `make vet`, `make build`, and
`make test` on every pull request and on push to `main`.

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
