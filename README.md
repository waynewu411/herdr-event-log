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

## Bundled wait helper: `scripts/herdr-ewait.sh`

This repo also ships `scripts/herdr-ewait.sh`, a hardened event-log consumer
for orchestration code. It replaces hand-rolled `tail -f`/`sleep` loops with a
cursor-based bounded reader plus live `herdr agent get` verification. This
repo is the single source of truth for the script — see the "Vendoring"
section below for how a copy vendored into another repo (e.g.
`edbayside/edbright-portal-core`) stays pinned and verified against it:

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

- `--targets` is a comma-separated list of targets to watch. Each entry is
  either a `pane_id` or a unique live agent name — whatever `herdr agent get`
  itself accepts (it does **not** accept a bare label) — and is resolved to
  its canonical `pane_id` once, at startup, before any waiting begins (the
  log only ever carries `pane_id`, never a name, so this is what makes a name
  target work with the log-detection path at all). A NAME that genuinely
  can't be resolved — unknown, or herdr itself unreachable — exits
  immediately with code `6` rather than starting a waiter that can never
  match (a name has no fallback identity, so there's nothing else it can
  do). A `pane_id` that does not exist (confirmed with `herdr pane get`, not
  just assumed) also exits `6`, but herdr itself being only *temporarily*
  unreachable does not: a `pane_id` target already is the identity the rest
  of the script needs, exactly like on `main` before any of this existed,
  so it is kept as-is with a warning and the wait proceeds — only a
  genuinely confirmed-gone pane fails closed. An empty entry (from a doubled
  or trailing comma) is dropped instead, not resolved; a `--targets` value
  with no non-empty entries left is a usage error, exit `4`. A `pane_id`
  that **does** exist but whose agent herdr hasn't classified yet
  (`agent_not_found` with the pane itself confirmed present — the normal
  race right after dispatching a fresh pane) is kept as-is and the script
  keeps waiting, not rejected.
  The hit/stall JSON also carries this original entry back as `"target"`,
  alongside the resolved `"pane_id"`.
- A *name* target's resolved `pane_id` can go stale mid-wait — e.g. `herdr
  pane move` gives the pane a new, workspace-qualified `pane_id` and the old
  one stops resolving. Both the safety-net sweep (the `--safety-net` ticks)
  and the stall sweep (the `--stall-after` ticks, if enabled) detect this
  themselves: on any tick whose live probe of the current `pane_id` comes
  back completely empty, each re-resolves the *original* name and, if that
  now points at a different `pane_id`, switches to it (with a note on
  stderr) instead of stranding the wait on a dead pane for the rest of
  `--overall-timeout` — or, for the stall sweep specifically, instead of
  misreporting the move itself as a suspected stall. A `pane_id` target
  given directly is never re-resolved — there is no name to fall back on.
- `--states` is a `|`-separated regex of statuses to accept; the default is
  `blocked|done|idle`.
- `--log` is the per-instance event log described above.
- `--cursor-file` persists the byte cursor across calls.
- `--overall-timeout`, `--poll`, and `--safety-net` are all in **seconds**
  (never milliseconds) and tune the total wait, the bounded read interval,
  and the periodic verification sweep. All three must be a whole number —
  this is a deliberate, intentional behaviour change from `main` (where
  e.g. `--poll 0.5` worked, since nothing validated it at all): issue 9's
  own `--poll > --safety-net` / `--safety-net > --overall-timeout` ordering
  checks below are bash integer comparisons, so a fractional value is
  rejected rather than silently truncated or mishandled. `--poll`/
  `--safety-net` must be a positive integer `<= 300s` — a value past that
  (e.g. `10000`) almost
  always means milliseconds were passed by mistake, and is a usage error,
  checked **before** the ordering rule below so it fires regardless of what
  the other flags happen to be. `--overall-timeout` must be `0` (see below)
  or a positive integer; past `86400s` (24h) it only **warns** on stderr
  (not a usage error — issue 9 scoped the hard ceiling to `--poll`/
  `--safety-net` only, and a multi-day supervision wait is plausible) and
  keeps running with the value as given.
  `--poll` must not exceed `--safety-net`, which must not exceed
  `--overall-timeout` (skipped entirely when `--overall-timeout` is `0`,
  since nothing in that case ever uses them — see below). These
  ordering/ceiling checks only bind a flag you actually pass: an **omitted**
  `--poll`/`--safety-net` is clamped down to fit an explicit, nonzero
  `--overall-timeout` instead of being rejected, so e.g.
  `--overall-timeout 30` alone stays valid exactly as before this validation
  existed. **This only applies to an omitted flag** — the example above
  passes all three explicitly, so shortening just `--overall-timeout` in a
  copy of it (without also dropping `--poll`/`--safety-net`) is a genuine
  ordering violation, not something the clamp repairs; the error message
  says so. `--overall-timeout 0` is a special, pre-existing case: "probe
  once (check-first), then give up immediately" (exit `2`) — it predates all
  of this validation and keeps working exactly as before. Any other
  violation is a usage error (exit `4`).

On startup, once targets are resolved, the script prints one diagnostic line
to stderr — **before** check-first, so it prints even on a run that hits
immediately. Only the diagnostic moved earlier; a fresh cursor file is still
written only **after** check-first, exactly as on `main` — so an immediate
hit is reported with exit `0` even if `--cursor-file` turns out to be
unwritable, and (round-5 review, L2) no cursor file is created at all on a
run that hits immediately, same as before this diagnostic existed. The line
shows each target as `original=resolved` (e.g.
`alice=w7:p3`), `--states`, `--poll`/`--safety-net`/`--overall-timeout`/
`--stall-after` in seconds (after any clamping above), and the starting
cursor — so a misconfigured waiter is visible in the caller's own output
immediately, not only as unexplained silence hours later.

On success stdout is exactly one compact JSON line:

```json
{"pane_id":"w3:p2","verified_state":"done","ts":"2026-08-15T00:00:00Z","target":"w3:p2"}
```

`"target"` is the original `--targets` entry this `"pane_id"` was resolved
from — equal to `"pane_id"` itself for a caller that already passed a
`pane_id`. It is appended after every pre-existing field rather than
inserted among them, so it is strictly additive for a consumer matching
on the fields that predate it. (Two `--targets` entries that resolve to the same pane — a
duplicate, or a name alongside its own `pane_id` — are each probed
independently every tick, not deduplicated; a hit reports whichever entry's
turn came first.)

Exit codes: `0` for a verified hit, `2` for overall timeout, `3` when the log
is missing/unreadable at start (the caller can fall back to the degraded
`herdr agent wait` path), `4` for a usage error (bad flags, invalid
`--states`, an invalid/out-of-range `--poll`/`--safety-net`/
`--overall-timeout`, a `--targets` with no non-empty entries left after
dropping doubled/trailing commas, a `--targets` value containing a newline/CR,
a `--targets` entry starting with `-`, a `--targets` entry containing a `"` or
`\`, or an unwritable `--cursor-file` once a run actually needs to persist one
— never for a run whose first check already hits), `5` for a suspected stall
(only with `--stall-after` set), and `6` when a `--targets` entry could not be
resolved to a `pane_id` (an unresolvable NAME, a nonexistent `pane_id`, or
herdr unreachable for a NAME specifically — a `pane_id` target rides out herdr
being merely *temporarily* unreachable instead, exactly as `main` did, since
there's nothing to resolve either way; not a `pane_id` that exists but whose
agent simply hasn't been classified yet, and not an empty entry, which is
dropped rather than resolved). The exit-`6` message includes herdr's own error
code when one was returned (e.g. `agent_not_found`, `pane_not_found`,
`server_not_running`); for a non-JSON failure (herdr absent entirely, a
shell-level error) it instead quotes whatever text was actually printed,
rather than a generic guess. If herdr instead returns **success** with a
response that just doesn't contain a recognizable `pane_id` (an unexpected or
future-renamed shape, not a failure herdr itself reported), a `pane_id` target
is kept as-is with a warning — the same posture as the detection-lag case
above — while a name target still exits `6`, with a message that says the
response shape was the problem, not the target.

Log matches are wake-up signals, not truth: every candidate hit and every
periodic safety-net sweep is re-checked against `herdr agent get`, so a stale
log line cannot produce a false success. A fresh invocation starts its cursor
at the current log size, so it never replays old history.

### Vendoring: `--check-source` / `--sync`

This repo is the single source of truth for `scripts/herdr-ewait.sh` — the
script's text names no repo, so a copy vendored elsewhere (e.g.
into `edbayside/edbright-portal-core`) can be byte-identical. A vendored copy
carries a sidecar file next to it, `herdr-ewait.source`:

```
# key=value, '#' starts a comment
repo=waynewu411/herdr-event-log
path=scripts/herdr-ewait.sh
sha=<40-hex commit sha>
```

No sidecar means this copy **is** the source; a sidecar that exists but isn't
a regular file (a directory, a dangling symlink) is an error, not "no
sidecar", and so is a symlinked `herdr-ewait.sh` itself (both commands refuse
it, the same rule as `--sync`'s symlink refusal). Sidecar fields are
validated strictly (attacker-controllable if the sidecar is edited, duplicate
or unknown keys are rejected too) before ever reaching a URL. Both commands
are standalone, herdr-free, and read none of the wait-mode flags. Before
trusting any pinned/explicit sha, both commands confirm it is actually
reachable from the named repo's upstream default branch (a throwaway local
`git fetch` + `merge-base --is-ancestor`) — a sha alone proves nothing, since
GitHub's raw-content endpoint also serves fork-network commits under the
upstream path. Every git call runs with all `GIT_*` env vars scrubbed,
`GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, and a low-speed abort
(so a dubious-ownership/corrupt-repo/stalled-connection case fails closed
rather than silently skipping the check or hanging); `curl` carries
`--connect-timeout`/`--max-time`/`--max-filesize` and is protocol-restricted.
A sidecar can only vouch for itself, though — a look-alike fork could ship
one naming itself as the upstream repo — so both commands also accept
`--expect-repo owner/name` and `--expect-path path`, checked against the
sidecar's own `repo=`/`path=` (strictly validated with the same format rules
as the sidecar fields themselves); a consumer's CI should pass
`--expect-vendored --expect-repo <owner/name> --expect-path <path>` together
to assert it is looking at a genuinely vendored copy of the expected file
from the expected repo, not merely trusting whatever the sidecar on disk
claims.

- `herdr-ewait.sh --check-source [--latest] [--expect-vendored] [--expect-repo owner/name] [--expect-path path]` —
  read-only, writes nothing. Fetches the pinned raw content and compares its
  sha256 against this script's own bytes. Exit `0` for a match (or no
  sidecar at all, unless `--expect-vendored` is given — see below), `7` for
  a drift (both hashes printed), `8` when the fetch/hash/ancestry step
  itself fails, the sidecar is irregular/malformed/invalid, this copy's own
  path fails to resolve to a regular readable file, this copy is a symlink,
  or an `--expect-repo`/`--expect-path` value is invalid or doesn't match the
  sidecar (fails closed, never reported as a match). `--latest` also
  resolves the pinned repo's default-branch head and, only if the **file's
  content** at that head actually differs (not just the commit), exits `9`
  with a stderr notice — a commit-only move with unchanged content is exit
  `0`. `--expect-vendored` turns "no sidecar" from a clean exit `0` into a
  distinct exit `13`, so a consumer's CI can assert it's looking at a
  genuinely vendored (not accidentally source) copy.
- `herdr-ewait.sh --sync <sha|main> [--expect-repo owner/name] [--expect-path path]` —
  explicit update; never commits or pushes. `--expect-repo`/`--expect-path`
  are checked the same way as `--check-source`'s, before any download.
  Resolves `main` to the named repo's resolved default-branch head,
  downloads the file to a temp file in the same directory, and requires it
  to pass `bash -n` **and** look like a genuine `herdr-ewait.sh` — non-empty,
  under a 1 MiB size cap, the correct shebang, a sentinel string, and a
  trailing end-of-file sentinel line that a truncated download would be
  missing (`bash -n` alone accepts an empty file; the downloaded file is
  never *executed* as part of this check). The new script and the rewritten
  sidecar are both fully prepared (content + permissions matched to the
  originals) before either atomic replace (write-temp-then-`mv`), so an
  already-running instance keeps its old file undisturbed, and a failure
  between the two replaces is reported as **PARTIALLY APPLIED** (exit `14`,
  distinct from a clean refusal — the sidecar still names the old sha), not
  a clean refusal; Ctrl-C/SIGTERM mid-sync clean up (including any
  in-progress ancestry-check scratch directory) and exit non-zero rather
  than resuming. Prints the old/new sha and a diff summary. Refuses — each
  with its own message and exit code — with no sidecar (`10`); when the
  script path is itself a symlink, on the work tree's own default branch (or
  an undeterminable one — never guessed) or a detached HEAD, or when git is
  unavailable/fails to introspect the tree while an ancestor directory still
  looks like a git work tree (`11`, since the update must go through a
  branch/worktree and a PR); or on an irregular/malformed/invalid sidecar,
  this copy's own path failing to resolve to a regular readable file, an
  invalid or mismatched `--expect-repo`/`--expect-path`, a failed ancestry
  check, a failed download, or a downloaded file failing the checks above
  (`12`).

Two environment variables exist **only** for tests, honoured **only** when
`HERDR_EWAIT_TEST_HOOKS=1` is also set (every use prints a stderr WARNING),
so they never touch the real network: `HERDR_EWAIT_RAW_BASE_URL` overrides
the `https://raw.githubusercontent.com` base used to fetch pinned content
(a bare absolute path is converted to a `file://` URL internally, since curl
needs an actual URL), and `HERDR_EWAIT_REMOTE_BASE_URL` overrides the
`https://github.com` base used to resolve refs via `git ls-remote`/`git
fetch` (git accepts a bare absolute path natively). Each must be `file://`,
an absolute local path, or exactly `http://127.0.0.1`/`http://localhost`
(optionally `:<port>`, optionally a path — no userinfo/`@`) — any other
scheme/host/authority is refused, not silently ignored.

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
  asserts every line is present, valid JSON, and not merged/truncated;
- `scripts/herdr-ewait.sh` itself — run as a real `bash` subprocess against a
  fake `herdr` CLI stub on `PATH` whose success/error shapes (including which
  stream each goes to) were verified live and read-only against real herdr
  before being written (re-checked each review round, including one claim
  that did **not** reproduce — see the script header's note on
  `server_not_running`), covering: name-to-`pane_id` resolution (with the
  hit/stall `"target"` field, the startup diagnostic's mapping, and the hit
  line's JSON validity all verified), a `pane_id` whose agent herdr hasn't
  classified yet but whose *pane* herdr confirms exists (kept as-is, not
  rejected) versus a `pane_id` that does not exist at all (exit `6`, never
  waited out), a herdr *success* response with an unexpected shape (kept
  as-is for a `pane_id` target, exit `6` with an accurate message for a
  name), an unresolvable NAME including when herdr itself is unreachable or
  its socket is down (exit `6` with herdr's own error code, or the raw
  failure text when there is no code to surface) — and, for a `pane_id`
  target specifically, that the SAME herdr-unreachable/socket-down
  conditions are ridden out instead (not exit `6`), with a dedicated
  recovery test proving the wait still succeeds once herdr comes back — an
  empty `--targets` entry
  (skipped, not fatal), every invalid-interval case — including the exact
  300s `--poll`/`--safety-net` ceiling boundary (a usage error), the 24h
  `--overall-timeout` ceiling only warning rather than rejecting (so a
  previously-valid 27.8h wait stays accepted), the millisecond hint firing
  regardless of which single flag is set, `--overall-timeout 0`'s
  pre-existing "probe once" idiom staying valid, and an omitted
  `--poll`/`--safety-net` being clamped to fit a short explicit
  `--overall-timeout` rather than rejected,
  while passing all three explicitly and then shortening only
  `--overall-timeout` still correctly errors — and the
  check-first/log-hit/safety-net-hit/overall-timeout paths, plus a name
  target's `pane_id` moving mid-wait — both that the safety-net sweep
  re-resolves the name and switches to the new `pane_id` instead of
  stranding the wait, and that the stall sweep does the same instead of
  misreporting the move as exit `5` (and that a target which has genuinely,
  permanently stopped responding — not merely moved — still correctly exits
  `5`, including the working-but-unchanged flavor of a stall, both exit-`5`
  JSON lines validated field-by-field) — and an unwritable `--cursor-file`
  never costing an otherwise-successful immediate hit.

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
