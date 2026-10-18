#!/usr/bin/env bash
# herdr-ewait.sh — the hardened event-log consumer for deliver-with-herdr (design doc §6).
#
# The single entry point for ANY agent waiting on ANY agent, at every nesting level.
# Hand-rolled polling (a foreground `sleep` loop, `tail -f`, or a bare `herdr agent wait`)
# is forbidden wherever this script is available — see references/supervision.md.
#
# Usage:
#   herdr-ewait.sh --targets "id1,id2" [--states "blocked|done|idle"] \
#                   --log <file> --cursor-file <file> \
#                   [--overall-timeout 3600] [--poll 5] [--safety-net 60] \
#                   [--stall-after 0]
#   herdr-ewait.sh --help    # full usage to stdout, exit 0
#
# --targets accepts, per entry, anything `herdr agent get` accepts: a pane id, an agent
# name, or a label (see rule 8 below) — each is resolved to a pane_id at startup.
# --overall-timeout, --poll and --safety-net are all in SECONDS, not milliseconds
# (see rule 9 below).
#
# Stdout on success (exit 0): exactly one compact JSON line, nothing else:
#   {"pane_id":"...","verified_state":"...","ts":"<ISO8601 UTC>"}
# (Exception: --help/-h also exits 0 but prints human-readable help to stdout, NOT a JSON hit
# line — a caller parsing exit-0 stdout as a hit must not pass --help/-h. See print_help below.)
# Stdout on a suspected stall (exit 5): one compact JSON line, nothing else:
#   {"pane_id":"...","suspected_stall_s":...,"detection_content_seq":...,"agent_status":"working","ts":"<ISO8601 UTC>"}
# Stdout on a target unreachable for a full --stall-after window (exit 5): detection_content_seq
# is JSON null and agent_status is omitted, since neither could be read:
#   {"pane_id":"...","suspected_stall_s":...,"detection_content_seq":null,"ts":"<ISO8601 UTC>"}
#
# Exit codes:
#   0  hit — a target reached one of --states, verified by `herdr agent get`
#   2  overall timeout reached with no verified hit
#   3  log file missing/unreadable at start (caller should fall back to the
#      degraded `herdr agent wait` path — see references/supervision.md)
#   4  usage error (bad/missing flag, an invalid --states token, or an invalid/out-of-range
#      --poll, --safety-net or --overall-timeout — see rule 9 below)
#   5  suspected stall (only possible when --stall-after > 0; see rule 6 below), one of:
#        - a target's `detection_content_seq` has not moved across two bracketing
#          `--stall-after` checks (so at least one full window, confirmed by TWO
#          observations, not one ambiguous sample — a probe-miss or no-seq-field tick in
#          between does NOT reset the bracket, by design; see rule 6) while its live
#          `agent_status` is verified still `working` at both
#        - a target's probe (`herdr agent get`) has failed for a full `--stall-after`
#          window — the pane may no longer exist
#      Either way the caller does not keep waiting silently and does not skip-level
#      inspect the target itself — it raises a REQUEST (`type: worker-stall`) to its own
#      direct parent with this evidence. If the target is reachable but its `herdr agent
#      get` responses carry no `detection_content_seq` field at all, the working-stall
#      check is a no-op for those ticks — a one-time warning is printed to stderr, and the
#      run relies on `--overall-timeout` unless/until the field starts appearing.
#      NOTE — worst-case detection latency: because a working-stall verdict needs TWO
#      bracketing checks, and a stall that begins mid-wait first consumes one window
#      re-baselining against the last real content change (that tick observes a MOVED
#      seq, so it can't itself start the bracket), the worst case is roughly 3x
#      `--stall-after` (~2x for a target already stalled when the wait starts). Size
#      `--stall-after` well under a THIRD of `--overall-timeout` accordingly (the shipped
#      default, 600s vs. a 3600s timeout, has ~6x headroom).
#   6  a --targets entry could not be resolved to a pane_id via `herdr agent get` at
#      startup (unknown target, pane gone, or herdr itself unreachable) — see rule 8
#      below. The waiter never starts rather than watching a filter that can never match.
#
# Five hardening rules (each numbered comment below fixes a live #820 bug):
#   1. check-first        4. verify-on-hit
#   2. bounded poll, never `tail -f`   5. periodic safety net
#   3. non-configurable default state filter
#
# Rule 6 — optional stall detection (#841, opt-in via --stall-after, default 0/disabled):
#   Rules 1-5 above only ever react to a `blocked|done|idle` *transition* — #823's
#   "27-minute silent stall" was healed as a missed transition event, but `working` itself
#   still carries no progress signal, so nothing before this rule can tell "still working,
#   legitimately slow" from "still working, silently stuck". Rule 6 closes that gap with a
#   cheap, cooperation-free liveness probe: `detection_content_seq` (already returned by
#   every `herdr agent get`, and parsed from the SAME response as `agent_status` — one
#   capture per target per tick, never two separate probes) increments whenever a pane's
#   rendered content changes, independent of the target agent choosing to self-report
#   anything. The last known-good value is retained across probe outages and across ticks
#   where the target is reachable but not `working` (so a flapping probe, or time
#   legitimately spent `blocked`, never manufactures a false verdict or hides a real one),
#   and firing requires TWO bracketing unchanged+`working` observations, not one — closing
#   the single-sample ambiguity a pane can hit right after a legitimate blocked spell. A
#   probe-miss or no-seq-field tick between the two does NOT reset the bracket (deliberately
#   — otherwise a flapping probe could permanently suppress a real verdict), so "two
#   bracketing observations" is not always "two back-to-back ticks".
#   Comparing across a `--stall-after` window lets the target's *direct parent* — the only
#   party allowed to look at it at all — detect a real stall without a skip-level `pane
#   read` of a grandchild, and without waiting out the full `--overall-timeout` to find out.
#
# Rule 7 — --states separator normalization (#903, fixes a live #898 bug):
#   Both grep call sites below splice $STATES verbatim into an ERE alternation
#   (`^($STATES)$`), which only ever worked for a pipe-delimited value. A comma-delimited
#   value — the natural mistake, since --targets itself is comma-delimited — collapses the
#   alternation to a single literal branch that matches nothing, silently killing every
#   state-detection path (rules 1, 5, and the log pre-filter) with zero error, hanging the
#   caller to --overall-timeout (this actually froze the #898 delivery for ~15 minutes). Rule
#   7 normalizes --states immediately after argument parsing: comma/whitespace/pipe separators
#   are all accepted in any combination (runs and surrounding whitespace collapse) and
#   canonicalized to a pipe alternation, and every token is validated against the three real
#   states — an unknown token, or a value with no real state at all, is now a loud usage error
#   (exit 4), never a silent no-op filter.
#
# Rule 8 — resolve every target to a pane_id at startup (#9):
#   The log pre-filter (both this rule's grep call sites and the one above) matches only
#   `"pane_id":"<id>"` — event lines carry a pane_id, never an agent name or label. A caller
#   that passes a NAME (herdr's `agent get` accepts a pane id, a name, or a label) silently
#   loses the entire log-detection path (rules 1, 4, 5, the pre-filter): only --safety-net
#   can ever fire, and only once --safety-net has elapsed. #9 observed exactly this —
#   two waiters configured by name sat for 4 and 9 real minutes after their targets
#   finished, invisible until a 30000s safety-net (itself a unit mistake, see rule 9) that
#   never came. Rule 8 resolves every --targets entry to its canonical pane_id via one
#   `herdr agent get` call at startup, before any waiting begins, and uses that pane_id for
#   every subsequent call (log filter and live verification alike). A target that does not
#   resolve — unknown, pane gone, or herdr itself unreachable — exits 6 immediately: this
#   script never starts a waiter watching a filter that can never match.
#
# Rule 9 — validate --poll/--safety-net/--overall-timeout as seconds (#9):
#   All three are documented as seconds, but nothing enforced that: #9's root cause was a
#   caller passing millisecond-sized values (10000/30000/2400000) for second-based flags —
#   --poll became a ~2h47m `sleep`, and --safety-net a sweep every ~8h20m, both inside a
#   script whose whole job is to wake up promptly. Rule 9 rejects, as a usage error (exit 4):
#   any of the three non-numeric or <= 0; --poll greater than --safety-net, or --safety-net
#   greater than --overall-timeout (an inversion that can only ever delay detection); and
#   --poll or --safety-net above INTERVAL_CEILING_S (a named constant, not a magic number —
#   see below), whose error names the millisecond-vs-second mistake directly, since a
#   five-digit-or-larger value for either flag is far more likely to be milliseconds than a
#   genuine multi-minute poll/safety-net interval.

set -euo pipefail

TARGETS=""
STATES="blocked|done|idle"   # rule 3: hard default; NOT overridable via config, only via this flag
LOG=""
CURSOR_FILE=""
OVERALL_TIMEOUT=3600
POLL=5
SAFETY_NET=60
STALL_AFTER=0   # rule 6: opt-in; 0 = disabled, fully backward compatible
readonly INTERVAL_CEILING_S=300   # rule 9: named ceiling for --poll/--safety-net, in seconds

usage() {
  echo "usage: herdr-ewait.sh --targets \"id1,id2\" [--states \"blocked|done|idle\"] --log <file> --cursor-file <file> [--overall-timeout N] [--poll N] [--safety-net N] [--stall-after N]" >&2
  echo "run '$0 --help' for full usage" >&2
  exit 4
}

# --help / -h: full usage to STDOUT, exit 0 (a discoverable entry point so an agent can learn the
# contract without reading the source or tripping the exit-4 usage() error). Kept in sync with the
# flag list, the --states contract (rule 7), and the exit codes documented in the header above.
print_help() {
  cat <<'EOF'
herdr-ewait.sh — the hardened event-log consumer for deliver-with-herdr.
The single entry point for ANY agent waiting on ANY agent, at every nesting level.

USAGE:
  herdr-ewait.sh --targets "id1,id2" --log <file> --cursor-file <file> \
                 [--states "blocked|done|idle"] \
                 [--overall-timeout 3600] [--poll 5] [--safety-net 60] [--stall-after 0]
  herdr-ewait.sh --help

REQUIRED:
  --targets "id1,id2"   Comma-separated targets to watch — each one anything `herdr agent
                        get` accepts: a pane id, an agent name, or a label. Every entry is
                        resolved to its pane_id at startup (rule 8); an entry that doesn't
                        resolve exits 6 immediately, before any waiting begins. Wakes on
                        whichever target moves first.
  --log <file>          The herdr-event-log file (the event bus) to consume.
  --cursor-file <file>  This waiter's own byte-cursor file (independent per consumer).

OPTIONAL:
  --states "s1|s2"      States that count as a hit. Default: blocked|done|idle.
                        Separators: comma, whitespace, and pipe are all accepted, in any
                        combination — runs and surrounding whitespace collapse (e.g.
                        "idle,done" == "idle done" == "idle | done" == "idle|done").
                        Allowed tokens: blocked, done, idle. An unknown token, or a value
                        with no real state at all, is a usage error (exit 4) — never a
                        silent no-op filter. Prefer omitting this unless you genuinely need
                        to NARROW the set — the default already covers blocked|done|idle.
  --overall-timeout N   Max SECONDS to wait before giving up. Default: 3600.
  --poll N              SECONDS between log-cursor polls. Default: 5. Must be <=
                        --safety-net and <= INTERVAL_CEILING_S (300).
  --safety-net N        SECONDS between unconditional live `agent get` sweeps. Default: 60.
                        Must be <= --overall-timeout and <= INTERVAL_CEILING_S (300).
  --stall-after N       Opt-in working-stall detection window in seconds. Default: 0 (off).
                        Size it well under a third of --overall-timeout (see header, rule 6).
  --help, -h            Print this help to stdout and exit 0.

  --poll, --safety-net and --overall-timeout are all SECONDS, never milliseconds (rule 9).
  Each must be a positive integer; --poll must not exceed --safety-net, which must not
  exceed --overall-timeout; and --poll/--safety-net must not exceed 300s — a larger value
  (e.g. 10000) almost always means the caller passed milliseconds by mistake.

EXIT CODES:
  0  hit — a target reached one of --states, verified live by `herdr agent get`
     (also exit 0 for --help/-h, which prints this help to stdout instead of a hit JSON line)
  2  overall timeout reached with no verified hit
  3  log file missing/unreadable at start (caller falls back to `herdr agent wait`)
  4  usage error (bad/missing flag, an unknown --states token, --states with no real state,
     or an invalid/out-of-range --poll, --safety-net or --overall-timeout — see rule 9)
  5  suspected stall (only when --stall-after > 0; escalate via a worker-stall REQUEST)
  6  a --targets entry could not be resolved to a pane_id via `herdr agent get` (rule 8)

STDOUT (one compact JSON line — except --help/-h, which prints this help text):
  hit (exit 0):    {"pane_id":"...","verified_state":"...","ts":"<ISO8601 UTC>"}
  stall (exit 5):  {"pane_id":"...","suspected_stall_s":...,"detection_content_seq":...,"agent_status":"working","ts":"..."}
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) print_help ;;
    --targets) TARGETS="$2"; shift 2 ;;
    --states) STATES="$2"; shift 2 ;;
    --log) LOG="$2"; shift 2 ;;
    --cursor-file) CURSOR_FILE="$2"; shift 2 ;;
    --overall-timeout) OVERALL_TIMEOUT="$2"; shift 2 ;;
    --poll) POLL="$2"; shift 2 ;;
    --safety-net) SAFETY_NET="$2"; shift 2 ;;
    --stall-after) STALL_AFTER="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ -n "$TARGETS" ] || usage
[ -n "$LOG" ] || usage
[ -n "$CURSOR_FILE" ] || usage
# rule 6: reject a non-numeric/negative/overlong --stall-after loudly (usage error) rather
# than silently disabling the stall-detection the caller explicitly asked for. The length
# cap matters as much as the digits-only check: past ~19 digits `[ "$STALL_AFTER" -gt 0 ]`
# itself errors ("integer expression expected") and every call site swallows that via
# `2>/dev/null`, which would otherwise silently disable rule 6 for the whole run exactly
# like the non-numeric case this guard exists to catch.
case "$STALL_AFTER" in ''|*[!0-9]*) usage ;; esac
[ "${#STALL_AFTER}" -le 9 ] || usage

# rule 9 (#9): reject a non-numeric/zero/negative/overlong --poll, --safety-net or
# --overall-timeout loudly (usage error), the same way rule 6 guards --stall-after above —
# the length cap matters as much as the digits-only check, since past ~19 digits the
# arithmetic comparisons below would themselves error ("integer expression expected"),
# letting an absurd value slip past unnoticed instead of failing closed.
validate_positive_int() {
  local flag="$1" value="$2"
  case "$value" in
    ''|*[!0-9]*)
      echo "herdr-ewait: --$flag must be a positive integer number of seconds, got '$value'" >&2
      usage
      ;;
  esac
  if [ "${#value}" -gt 9 ]; then
    echo "herdr-ewait: --$flag is too large, got '$value'" >&2
    usage
  fi
  if [ "$value" -le 0 ]; then
    echo "herdr-ewait: --$flag must be > 0, got '$value'" >&2
    usage
  fi
}

validate_positive_int poll "$POLL"
validate_positive_int safety-net "$SAFETY_NET"
validate_positive_int overall-timeout "$OVERALL_TIMEOUT"

if [ "$POLL" -gt "$SAFETY_NET" ]; then
  echo "herdr-ewait: --poll (${POLL}s) must not exceed --safety-net (${SAFETY_NET}s)" >&2
  usage
fi
if [ "$SAFETY_NET" -gt "$OVERALL_TIMEOUT" ]; then
  echo "herdr-ewait: --safety-net (${SAFETY_NET}s) must not exceed --overall-timeout (${OVERALL_TIMEOUT}s)" >&2
  usage
fi
# rule 9 continued: #9's actual root cause — a caller passed millisecond-sized values
# (10000/30000) for second-based flags. A value past this ceiling is overwhelmingly more
# likely to be a unit mistake than a genuine multi-minute interval, so say so directly.
if [ "$POLL" -gt "$INTERVAL_CEILING_S" ] || [ "$SAFETY_NET" -gt "$INTERVAL_CEILING_S" ]; then
  echo "herdr-ewait: --poll and --safety-net must each be <= ${INTERVAL_CEILING_S}s (got poll=${POLL}s, safety-net=${SAFETY_NET}s) — a value this large almost certainly means milliseconds, not seconds" >&2
  usage
fi

# rule 7 (#903): normalize + validate --states before it ever reaches an ERE. Both grep call sites
# below splice $STATES verbatim into "^($STATES)$"-shaped alternations, which only works when the
# caller's separator is a pipe — a comma-delimited value (the natural typo, since --targets uses
# commas) collapses to a single literal branch that matches nothing, silently killing every
# state-detection path (rule 1, rule 5, the log pre-filter) with no error, just a hang to
# --overall-timeout (this froze the #898 delivery for ~15 minutes). Accept comma, whitespace, and
# pipe separators in ANY combination — including whitespace around a comma/pipe ("blocked, done",
# "blocked | done") — by translating each to a pipe, squeezing separator RUNS to one, and trimming
# the ends. Collapsing redundant/leading/trailing separators is safe: it only ever yields a valid
# sub-filter of real states, never a silently-wrong one (unlike the original comma bug, which
# matched nothing). What IS rejected loudly (exit 4) is a value with no real state at all, or any
# token that is not blocked/done/idle — never a silent no-op filter.
STATES="$(printf '%s' "$STATES" | tr ',[:space:]' '|' | tr -s '|' | sed 's/^|//; s/|$//')"
[ -n "$STATES" ] || usage
IFS='|' read -r -a _states <<< "$STATES"
for s in "${_states[@]}"; do
  case "$s" in blocked|done|idle) ;; *) echo "herdr-ewait: invalid --states token '$s' (allowed: blocked done idle, separated by comma/space/pipe)" >&2; usage ;; esac
done

# --- log availability check (exit 3 = caller falls back to the degraded path) ---
if [ ! -r "$LOG" ]; then
  echo "herdr-ewait: log file unreadable: $LOG" >&2
  exit 3
fi

IFS=',' read -r -a TARGET_ARR <<< "$TARGETS"
# F3: trim surrounding whitespace from each target — "a, b" must match "b", not " b".
for i in "${!TARGET_ARR[@]}"; do
  t="${TARGET_ARR[$i]}"
  t="${t#"${t%%[![:space:]]*}"}"
  t="${t%"${t##*[![:space:]]}"}"
  TARGET_ARR[$i]="$t"
done

# Rule 8 (#9): resolve each --targets entry — pane id, agent name, or label — to its
# canonical pane_id via `herdr agent get`, once, right here. From this point on,
# TARGET_ARR holds pane_ids only: the log pre-filter below matches `"pane_id":"<id>"`,
# never a name, so every later call (check-first, log-match verify, safety net, stall
# sweep) must use the resolved form too, or it silently can't match the log at all.
resolve_pane_id() {
  local target="$1"
  herdr agent get "$target" 2>/dev/null \
    | grep -o '"pane_id":"[^"]*"' \
    | head -n1 \
    | sed -E 's/"pane_id":"([^"]*)"/\1/'
}

for i in "${!TARGET_ARR[@]}"; do
  t="${TARGET_ARR[$i]}"
  resolved="$(resolve_pane_id "$t" || true)"
  if [ -z "$resolved" ]; then
    echo "herdr-ewait: could not resolve target '$t' to a pane_id via 'herdr agent get' (unknown target, pane gone, or herdr unreachable)" >&2
    exit 6
  fi
  TARGET_ARR[$i]="$resolved"
done

# Parse "agent_status":"<state>" out of one `herdr agent get <id>` JSON line, grep/sed only.
# Real observed shape: {"id":"cli:agent:get",...,"agent_status":"working",...,"pane_id":"w1:p1",...}
get_status() {
  local target="$1"
  herdr agent get "$target" 2>/dev/null \
    | grep -o '"agent_status":"[^"]*"' \
    | head -n1 \
    | sed -E 's/"agent_status":"([^"]*)"/\1/'
}

# Rule 6: parse agent_status / detection_content_seq out of an ALREADY-CAPTURED `herdr agent
# get <id>` response (never make a second live call) — the stall sweep below captures one
# response per target per tick and parses both fields from that single capture, so there is
# no window between two separate probes in which the pane's real state could change and be
# read inconsistently. detection_content_seq is an unquoted integer that increments whenever
# the pane's rendered content changes, independent of agent_status. Empty on a probe miss OR
# on a response that has no detection_content_seq field at all — the two are disambiguated by
# whether agent_status can still be parsed from the same response (see the stall sweep below).
parse_agent_status() {
  printf '%s' "$1" \
    | grep -o '"agent_status":"[^"]*"' \
    | head -n1 \
    | sed -E 's/"agent_status":"([^"]*)"/\1/'
}

parse_content_seq() {
  printf '%s' "$1" \
    | grep -o '"detection_content_seq":[0-9]*' \
    | head -n1 \
    | sed -E 's/"detection_content_seq":([0-9]*)/\1/'
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

emit_hit() {
  local pane="$1" state="$2"
  printf '{"pane_id":"%s","verified_state":"%s","ts":"%s"}\n' "$pane" "$state" "$(now_iso)"
}

# Rule 4 (verify-on-hit): re-check a candidate hit with `agent get` before trusting it.
# A log match is a wake-up signal, not the source of truth; if the live state no longer
# matches, treat it as spurious and keep waiting.
verify_and_maybe_emit() {
  local target="$1"
  local status
  status="$(get_status "$target")"
  if [ -n "$status" ] && printf '%s' "$status" | grep -Eq "^($STATES)\$"; then
    emit_hit "$target" "$status"
    return 0
  fi
  return 1
}

# Rule 1 (check-first): before any waiting, check every target once. Kills the
# "first observed state is already terminal" race — cursor-snapshot timing stops
# being safety-critical because we never rely on the log alone.
for t in "${TARGET_ARR[@]}"; do
  if verify_and_maybe_emit "$t"; then
    exit 0
  fi
done

# Establish/resume the byte cursor.
if [ -f "$CURSOR_FILE" ]; then
  CURSOR="$(cat "$CURSOR_FILE" 2>/dev/null || echo 0)"
  case "$CURSOR" in ''|*[!0-9]*) CURSOR=0 ;; esac
else
  # F1: a fresh waiter has no interest in history — check-first (rule 1, above) already
  # covers "the target is already settled". Starting at 0 would replay the entire
  # session log on tick one, spending one spurious `agent get` per stale pre-filter
  # match. Start at the log's CURRENT size instead, and persist it immediately.
  CURSOR="$(wc -c < "$LOG" 2>/dev/null | tr -d ' ' || true)"
  case "$CURSOR" in ''|*[!0-9]*) CURSOR=0 ;; esac
  printf '%s' "$CURSOR" > "$CURSOR_FILE"
fi

# Startup diagnostic (#9): print exactly what this run resolved to, in seconds, so a
# misconfigured waiter is visible in the caller's own output immediately — instead of
# only showing up, hours later, as unexplained silence (see #9's root cause).
echo "herdr-ewait: targets=$(IFS=,; echo "${TARGET_ARR[*]}") states=$STATES poll=${POLL}s safety-net=${SAFETY_NET}s overall-timeout=${OVERALL_TIMEOUT}s cursor=$CURSOR" >&2

START_TS=$(date +%s)
LAST_SAFETY_NET=$START_TS
LAST_STALL_CHECK=$START_TS

# Rule 6 setup: establish a baseline detection_content_seq per target so the first
# stall-check tick has something to compare against. Skipped entirely when --stall-after is
# 0 (the default) — zero extra `agent get` calls for every existing caller.
# STALL_SEQ_ARR/STALL_TS_ARR track the last known-good seq and how long it's held; a
# separate STALL_MISS_SINCE_ARR tracks a genuine probe outage (no response at all) — kept
# apart so a flapping probe never loses the seq baseline it had before the flap (see the
# stall sweep below for why that matters). STALL_PREV_WORKING_ARR requires two bracketing
# unchanged+working observations before a stall may fire (an intervening probe-miss/no-seq
# tick does not reset it), so a single ambiguous sample (e.g. a pane observed working right
# after it stopped being legitimately blocked) can't fire on its own — see the stall sweep
# below.
if [ "$STALL_AFTER" -gt 0 ] 2>/dev/null; then
  for i in "${!TARGET_ARR[@]}"; do
    # F4: `|| true` on every parse below — a probe failure is a top-level command
    # substitution under `set -euo pipefail`; without the guard, one bad `herdr agent get`
    # would kill the whole script.
    RESP="$(herdr agent get "${TARGET_ARR[$i]}" 2>/dev/null || true)"
    STALL_SEQ_ARR[$i]="$(parse_content_seq "$RESP" || true)"
    STALL_TS_ARR[$i]=$START_TS
    STALL_MISS_SINCE_ARR[$i]=""
    STALL_PREV_WORKING_ARR[$i]=""
    if [ -z "${STALL_SEQ_ARR[$i]}" ] && [ -z "$(parse_agent_status "$RESP" || true)" ]; then
      STALL_MISS_SINCE_ARR[$i]=$START_TS
    fi
  done
fi

while :; do
  NOW_TS=$(date +%s)
  ELAPSED=$(( NOW_TS - START_TS ))
  if [ "$ELAPSED" -ge "$OVERALL_TIMEOUT" ]; then
    echo "herdr-ewait: overall timeout (${OVERALL_TIMEOUT}s) reached with no verified hit" >&2
    exit 2
  fi

  # Rule 2: bounded incremental read from the byte cursor. Never `tail -f` — pipe-close
  # termination on a long-lived log is unreliable across shells/harnesses.
  # F2: failure-tolerant — if the log vanishes mid-run, `wc -c <` fails; under
  # `set -euo pipefail` an unguarded pipeline failure here would kill the whole script
  # with an undocumented exit code. `|| true` on the substitution degrades this tick to
  # LOG_SIZE=0 instead, so the run falls through to safety-net-only sweeps (rule 5).
  LOG_SIZE=$( { wc -c < "$LOG"; } 2>/dev/null | tr -d ' ' || true)
  [ -n "$LOG_SIZE" ] || LOG_SIZE=0
  case "$LOG_SIZE" in ''|*[!0-9]*) LOG_SIZE=0 ;; esac
  # F1 continued: log rotation/truncation guard — if our cursor is now past the log's
  # current size (the file was rotated or truncated out from under us), `-gt` would
  # never fire again and only the safety net would keep working. Reset to 0 so the
  # next size increase is detected as new bytes again.
  if [ "$CURSOR" -gt "$LOG_SIZE" ]; then
    CURSOR=0
  fi
  if [ "$LOG_SIZE" -gt "$CURSOR" ]; then
    NEW_BYTES="$(tail -c +$((CURSOR + 1)) "$LOG" 2>/dev/null || true)"
    CURSOR="$LOG_SIZE"
    printf '%s' "$CURSOR" > "$CURSOR_FILE"

    if [ -n "$NEW_BYTES" ]; then
      for t in "${TARGET_ARR[@]}"; do
        # Filter lines by pane_id AND agent_status regex before ever calling out — this is
        # the cheap pre-filter; the actual truth check is still verify_and_maybe_emit below.
        if printf '%s\n' "$NEW_BYTES" | grep -F "\"pane_id\":\"$t\"" | grep -Eq "\"agent_status\":\"($STATES)\""; then
          if verify_and_maybe_emit "$t"; then
            exit 0
          fi
          # Rule 4 continued: log said hit, live state disagreed — spurious, keep polling.
        fi
      done
    fi
  fi

  # Rule 5: unconditional safety-net sweep every --safety-net seconds, even with no log
  # hit — heals any event the log-filter path missed within one interval (#823's stall).
  if [ $(( NOW_TS - LAST_SAFETY_NET )) -ge "$SAFETY_NET" ]; then
    LAST_SAFETY_NET="$NOW_TS"
    for t in "${TARGET_ARR[@]}"; do
      if verify_and_maybe_emit "$t"; then
        exit 0
      fi
    done
  fi

  # Rule 6 (optional, opt-in): stall detection. Every --stall-after seconds, compare each
  # target's detection_content_seq against the value recorded at the previous check. No
  # movement across a full window, while the target is verified still `working`, is a
  # suspected stall (exit 5) — the caller escalates via REQUEST rather than waiting out
  # --overall-timeout. A target whose probe itself fails for a full window (pane gone,
  # herdr socket down) is reported the same way, with detection_content_seq:null, so a
  # persistently unreachable target isn't silently waited out for --overall-timeout either.
  if [ "$STALL_AFTER" -gt 0 ] 2>/dev/null && [ $(( NOW_TS - LAST_STALL_CHECK )) -ge "$STALL_AFTER" ]; then
    LAST_STALL_CHECK="$NOW_TS"
    for i in "${!TARGET_ARR[@]}"; do
      t="${TARGET_ARR[$i]}"
      # F4/F5: ONE `herdr agent get` capture per target per tick — both seq and status are
      # parsed from the SAME response (see the setup loop above), so there is no window
      # between two separate probes in which the pane's real state could change and be read
      # inconsistently. `|| true` is required — see the setup loop above.
      RESP="$(herdr agent get "$t" 2>/dev/null || true)"
      seq="$(parse_content_seq "$RESP" || true)"

      if [ -z "$seq" ]; then
        # No detection_content_seq in the response — could mean the probe failed, or the
        # target is reachable but this herdr build's response just lacks the field. Only
        # the former is evidence of a stall, and only the former may claim the pane "may no
        # longer exist"; check agent_status from the SAME response to tell them apart.
        status="$(parse_agent_status "$RESP" || true)"
        if [ -n "$status" ]; then
          # Reachable — this herdr build/response just has no detection_content_seq field,
          # so the working-stall check is a no-op for THIS tick (not a run-level disable —
          # if the field starts appearing later, detection resumes normally). Not evidence
          # of a stall either way; warn once so --stall-after isn't silently a no-op.
          STALL_MISS_SINCE_ARR[$i]=""
          if [ -z "${STALL_NO_SEQ_WARNED:-}" ]; then
            echo "herdr-ewait: --stall-after is set but a 'herdr agent get' response carried no detection_content_seq field — the working-stall check is a no-op for such ticks until the field appears" >&2
            STALL_NO_SEQ_WARNED=1
          fi
          continue
        fi
        miss_since="${STALL_MISS_SINCE_ARR[$i]:-}"
        if [ -z "$miss_since" ]; then
          # First tick of a genuine outage — start timing it; don't report yet.
          STALL_MISS_SINCE_ARR[$i]="$NOW_TS"
        elif [ $(( NOW_TS - miss_since )) -ge "$STALL_AFTER" ]; then
          # Unreachable for a full window — report rather than silently waiting out
          # --overall-timeout for a target that may no longer exist.
          printf '{"pane_id":"%s","suspected_stall_s":%s,"detection_content_seq":null,"ts":"%s"}\n' \
            "$t" "$(( NOW_TS - miss_since ))" "$(now_iso)"
          exit 5
        fi
        continue
      fi

      # Probe succeeded — the target is reachable, so any prior outage is over. Note this
      # never clears STALL_SEQ_ARR/STALL_TS_ARR: a probe that flaps (fails, then recovers to
      # the SAME seq it had before the flap) must still be recognised as "unchanged since the
      # original baseline", not reset to a fresh one — otherwise a genuinely stalled worker
      # behind an intermittently failing socket would never trip rule 6.
      STALL_MISS_SINCE_ARR[$i]=""

      prev="${STALL_SEQ_ARR[$i]:-}"
      if [ -n "$prev" ] && [ "$seq" = "$prev" ]; then
        # Content hasn't moved — only a real stall if the target is still `working`. A
        # `blocked` pane (e.g. under a caller-narrowed --states that excludes `blocked`) is
        # legitimately static: it's waiting on input, not stuck.
        status="$(parse_agent_status "$RESP" || true)"
        if [ "$status" = "working" ]; then
          if [ -n "${STALL_PREV_WORKING_ARR[$i]:-}" ]; then
            # This is the SECOND bracketing tick observed unchanged+working (an intervening
            # probe-miss/no-seq tick does not reset the bracket, by design) — the two
            # observations bracket a full window, so a single ambiguous sample (e.g. a
            # pane checked right after it stopped being legitimately blocked, whose
            # between-tick blocked time this rule can't otherwise see) can never fire on
            # its own; only a confirmed full window can.
            printf '{"pane_id":"%s","suspected_stall_s":%s,"detection_content_seq":%s,"agent_status":"%s","ts":"%s"}\n' \
              "$t" "$(( NOW_TS - STALL_TS_ARR[i] ))" "$seq" "$status" "$(now_iso)"
            exit 5
          fi
          # First unchanged+working observation of a new bracket — record it and restart
          # the clock so the elapsed time reported on a future fire reflects only the
          # confirmed working window, not whatever came before it.
          STALL_PREV_WORKING_ARR[$i]=1
          STALL_TS_ARR[$i]="$NOW_TS"
          continue
        fi
        # Static but not verified `working` (e.g. currently `blocked`) — this interval must
        # not count toward a future working-stall verdict, so restart the clock and the
        # bracket.
        STALL_PREV_WORKING_ARR[$i]=""
        STALL_TS_ARR[$i]="$NOW_TS"
        continue
      fi

      STALL_PREV_WORKING_ARR[$i]=""
      STALL_SEQ_ARR[$i]="$seq"
      STALL_TS_ARR[$i]="$NOW_TS"
    done
  fi

  sleep "$POLL"
done
