#!/usr/bin/env bash
# herdr-ewait.sh — the hardened event-log consumer for deliver-with-herdr (design doc §6).
#
# The single entry point for ANY agent waiting on ANY agent, at every nesting level.
# Hand-rolled polling (a foreground `sleep` loop, `tail -f`, or a bare `herdr agent wait`)
# is forbidden wherever this script is available — see references/supervision.md.
#
# SIBLING COPY — keep in sync: edbayside/edbright-portal-core
# .claude/skills/deliver-with-herdr/scripts/herdr-ewait.sh is a sibling of this script with
# the same flags, exit codes, stdout JSON and stderr messages (code-identical apart from
# help-text wording that is specific to each repo). A behaviour change to either copy must
# be mirrored in the other.
#
# Usage:
#   herdr-ewait.sh --targets "id1,id2" [--states "blocked|done|idle"] \
#                   --log <file> --cursor-file <file> \
#                   [--overall-timeout 3600] [--poll 5] [--safety-net 60] \
#                   [--stall-after 0]
#   herdr-ewait.sh --help    # full usage to stdout, exit 0
#
# --targets accepts, per entry, anything `herdr agent get` accepts: a pane id or a unique
# live agent name (see rule 8 below) — each is resolved to a pane_id at startup. A pane id
# whose agent herdr has not classified yet (`agent_not_found`) is kept as-is rather than
# rejected, since that is a normal detection-lag race, not a bad target (rule 8).
# --overall-timeout, --poll and --safety-net are all in SECONDS, not milliseconds; an
# explicitly-set one is validated strictly, but an OMITTED --poll/--safety-net is clamped
# down to fit an explicit, nonzero --overall-timeout rather than rejected (see rule 9
# below). --overall-timeout 0 is a special case, kept working as a pre-existing idiom:
# "probe once (check-first), then give up immediately" (exit 2) — see rule 9.
#
# Stdout on success (exit 0): exactly one compact JSON line, nothing else:
#   {"pane_id":"...","verified_state":"...","ts":"<ISO8601 UTC>","target":"..."}
# (Exception: --help/-h also exits 0 but prints human-readable help to stdout, NOT a JSON hit
# line — a caller parsing exit-0 stdout as a hit must not pass --help/-h. See print_help below.)
# Stdout on a suspected stall (exit 5): one compact JSON line, nothing else:
#   {"pane_id":"...","suspected_stall_s":...,"detection_content_seq":...,"agent_status":"working","ts":"<ISO8601 UTC>","target":"..."}
# Stdout on a target unreachable for a full --stall-after window (exit 5): detection_content_seq
# is JSON null and agent_status is omitted, since neither could be read:
#   {"pane_id":"...","suspected_stall_s":...,"detection_content_seq":null,"ts":"<ISO8601 UTC>","target":"..."}
# "target" is the original --targets entry this pane_id was resolved from — equal to
# pane_id itself for a caller that already passed a pane id. Appended after every
# pre-existing field so a consumer matching the pre-"target" shape positionally or by
# regex is unaffected.
#
# Exit codes:
#   0  hit — a target reached one of --states, verified by `herdr agent get`
#   2  overall timeout reached with no verified hit
#   3  log file missing/unreadable at start (caller should fall back to the
#      degraded `herdr agent wait` path — see references/supervision.md)
#   4  usage error (bad/missing flag, an invalid --states token, an invalid/out-of-range
#      --poll/--safety-net/--overall-timeout — see rule 9 below — a --targets value
#      containing a newline, a --targets entry containing a '"' or '\', or an unwritable
#      --cursor-file once a run actually needs to persist one)
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
#   6  a --targets entry could not be resolved to a pane_id at startup — an unresolvable
#      NAME (including when herdr itself is unreachable — a name has no fallback
#      identity), or a pane id that does not exist (confirmed via `herdr pane get`, not
#      just a guess — see rule 8 below). (NOT a pane id that exists but whose agent herdr
#      simply hasn't classified yet; NOT a pane id when herdr is only TEMPORARILY
#      unreachable — ridden out instead, since a pane id has nothing to resolve either
#      way; and NOT an empty entry — those are dropped silently; an all-empty --targets
#      is a usage error, exit 4.) The waiter
#      never starts rather than watching a filter that can never match.
#
# Five hardening rules:
#   1. check-first        4. verify-on-hit
#   2. bounded poll, never `tail -f`   5. periodic safety net
#   3. non-configurable default state filter
#
# Rule 6 — optional stall detection (opt-in via --stall-after, default 0/disabled):
#   Rules 1-5 above only ever react to a `blocked|done|idle` *transition*, but a target
#   still `working` carries no progress signal of its own, so nothing before this rule can
#   tell "still working, legitimately slow" from "still working, silently stuck". Rule 6
#   closes that gap with a cheap, cooperation-free liveness probe: `detection_content_seq`
#   (already returned by every `herdr agent get`, and parsed from the SAME response as
#   `agent_status` — one capture per target per tick, never two separate probes)
#   increments whenever a pane's rendered content changes, independent of the target
#   agent choosing to self-report anything. The last known-good value is retained across
#   probe outages and across ticks where the target is reachable but not `working` (so a
#   flapping probe, or time legitimately spent `blocked`, never manufactures a false
#   verdict or hides a real one), and firing requires TWO bracketing unchanged+`working`
#   observations, not one — closing the single-sample ambiguity a pane can hit right after
#   a legitimate blocked spell. A probe-miss or no-seq-field tick between the two does NOT
#   reset the bracket (deliberately — otherwise a flapping probe could permanently
#   suppress a real verdict), so "two bracketing observations" is not always "two
#   back-to-back ticks".
#   Comparing across a `--stall-after` window lets the target's *direct parent* — the only
#   party allowed to look at it at all — detect a real stall without a skip-level `pane
#   read` of a grandchild, and without waiting out the full `--overall-timeout` to find out.
#   A probe-miss tick here gives a NAME-originated target the same one-shot re-resolve the
#   safety-net sweep (rule 5) uses, via the shared `reresolve_if_stale` helper, BEFORE
#   counting the miss toward an outage window — without it, a mid-wait `herdr pane move`
#   makes the OLD pane_id probed here permanently unreachable (not a flapping probe, a
#   dead one), which this rule would otherwise wrongly report as exit 5 "may no longer
#   exist" while the agent is alive under its new pane_id.
#
# Rule 7 — --states separator normalization:
#   Both grep call sites below splice $STATES verbatim into an ERE alternation
#   (`^($STATES)$`), which only works for a pipe-delimited value. A comma-delimited
#   value — the natural mistake, since --targets itself is comma-delimited — collapses the
#   alternation to a single literal branch that matches nothing, silently killing every
#   state-detection path (rules 1, 5, and the log pre-filter) with zero error, hanging the
#   caller to --overall-timeout. Rule 7 normalizes --states immediately after argument
#   parsing: comma/whitespace/pipe separators are all accepted in any combination (runs
#   and surrounding whitespace collapse) and canonicalized to a pipe alternation, and
#   every token is validated against the three real states — an unknown token, or a value
#   with no real state at all, is a loud usage error (exit 4), never a silent no-op filter.
#
# Rule 8 — resolve every target to a pane_id at startup:
#   The log pre-filter (both this rule's grep call sites and the one above) matches only
#   `"pane_id":"<id>"` — event lines carry a pane_id, never an agent name. (herdr's own
#   `--skill` text: agent commands accept a unique live agent name or the pane id currently
#   hosting that agent — never a bare label, and names are unique among live agents, so
#   there is no cross-workspace ambiguity to resolve either.) A caller that passes a NAME
#   would otherwise lose the entire log-detection path (rules 1, 4, 5, the pre-filter):
#   only --safety-net could ever fire, and only once it elapses. Rule 8 resolves every
#   --targets entry to its canonical pane_id via one `herdr agent get` call at startup,
#   before any waiting begins, and uses that pane_id for every subsequent call (log filter
#   and live verification alike). The original entry is kept alongside its resolution (in
#   ORIG_TARGET_ARR) purely for display and for the optional "target" field on a hit/stall
#   line — never for lookups. Each entry is trimmed of surrounding whitespace, an empty
#   entry (from a doubled/trailing comma) is dropped rather than resolved, and an entry
#   starting with "-" is rejected as a usage error before resolution — neither a pane id
#   nor a herdr name can start with a flag character.
#
#   A target that fails to resolve is NOT always a bad target: `herdr agent get` on a pane
#   that exists but whose agent herdr has not classified yet returns `agent_not_found` —
#   the normal result of a supervisor starting a wait immediately after dispatching a
#   fresh pane, before herdr's (asynchronous) detection catches up. herdr writes its error
#   JSON to STDERR and its success JSON to stdout, so the resolve call captures both
#   streams (`2>&1`); `get_status` and the stall sweep below only ever need success fields
#   and keep discarding stderr. `agent_not_found` on something that already looks like a
#   pane id (`$PANE_ID_RE`) is still ambiguous on its own, though: herdr returns that same
#   code for "pane exists, no agent classified yet" (keep waiting) and for "no such pane"
#   (a typo'd/stale id), and conflating them would let a typo wait out the full
#   --overall-timeout, exactly the failure mode this script exists to prevent. So this
#   rule asks one more question in that specific case — `herdr pane get` — which returns a
#   pane_id for any real pane (regardless of its agent) and `pane_not_found` for one that
#   doesn't exist: a found pane keeps the target as-is (one-time warning) and lets rules
#   1/4/5 retry `agent get` on their own schedule; no pane found exits 6 right here. Every
#   other target resolves with the single `agent get` call above — this extra probe only
#   fires for the one ambiguous case.
#
#   A non-JSON failure (herdr absent from PATH, a shell permission error, a panic printed
#   as plain text) has no `code` to surface; the exit-6 message then includes the first
#   non-blank line of whatever herdr/the shell actually printed (trimmed, length-capped),
#   so "no herdr on PATH" doesn't read as "bad target name". herdr can also exit 0
#   (success) with a response that simply doesn't contain `"pane_id":"..."` — an
#   unexpected/renamed shape, not a failure herdr reported at all; this is handled the same
#   way as the detection-lag race above (a pane-id-shaped target is kept as-is; a NAME
#   still exits 6, with a message that blames the response shape, not the target).
#   herdr itself being only TEMPORARILY unreachable (its socket down, or absent from PATH)
#   is not a resolution failure for a target that already IS a pane id, since there is
#   nothing to resolve either way: it is kept as-is and rides out the outage, the same way
#   every in-flight probe elsewhere in this script already tolerates herdr being briefly
#   down. A NAME has no fallback identity, so it still exits 6 in that case. Exit 6 is
#   otherwise reserved for an unresolvable NAME or a pane id confirmed (via `herdr pane
#   get`) not to exist; the stderr message includes herdr's own error `code` when one was
#   returned, so a caller can tell "fix my target" apart from "herdr is down".
#
#   Resolution happens exactly once, at startup — which would leave a NAME target stale
#   after a mid-wait `herdr pane move` (herdr's own docs: a moved pane gets a NEW,
#   workspace-qualified pane_id, and the old one stops resolving — a name caller
#   presumably wants to follow the agent, not the now-dead pane_id). The safety-net sweep
#   (rule 5) and the stall sweep (rule 6) both re-resolve the ORIGINAL name on any tick
#   whose probe of the current pane_id comes back completely empty (not merely "not in
#   --states yet" — a healthy but still-working pane never pays for this) — see
#   `reresolve_if_stale` below.
#
#   Note: two --targets entries that resolve to the SAME pane (a duplicate, or a name
#   alongside its own pane id) are each probed independently every tick — harmless, if
#   mildly wasteful — and a hit reports whichever entry's turn came first in --targets
#   order; this is not deduplicated.
#
# Rule 9 — validate --poll/--safety-net/--overall-timeout as seconds:
#   All three are documented as seconds, but nothing enforced that — a caller passing
#   millisecond-sized values (e.g. 10000/30000/2400000) for second-based flags turns
#   --poll into a ~2h47m `sleep`, and --safety-net into a sweep every ~8h20m, inside a
#   script whose whole job is to wake up promptly. Rule 9 rejects, as a usage error
#   (exit 4): any of the three non-numeric or negative; --poll/--safety-net also when
#   exactly 0 (--overall-timeout 0 is exempt — see below); --poll greater than
#   --safety-net, or --safety-net greater than --overall-timeout (an inversion that can
#   only ever delay detection); and --poll or --safety-net above INTERVAL_CEILING_S (a
#   named constant, not a magic number — see below), whose error names the
#   millisecond-vs-second mistake directly, since a five-digit-or-larger value for either
#   flag is far more likely to be milliseconds than a genuine multi-minute interval. This
#   ceiling check runs BEFORE the ordering checks, so the millisecond hint fires for every
#   value past it regardless of what the other flags are set to.
#   --overall-timeout itself has a separate, far more generous ceiling
#   (OVERALL_TIMEOUT_CEILING_S, 24h) for the same mistake when --poll/--safety-net are
#   omitted — but past it the script only WARNS and keeps running with the caller's value,
#   never rejects: a multi-hour or multi-day supervision wait is plausible in a way a
#   multi-minute --poll never is, so a hard ceiling here would reject a genuine long wait,
#   not just a unit mistake.
#   --overall-timeout 0 is a pre-existing, meaningful idiom ("probe once via check-first,
#   then give up immediately") that predates this validation. It is exempted from the > 0
#   requirement (via validate_nonnegative_int, not validate_positive_int) and from the
#   clamp/ordering checks below, which would otherwise try to clamp --safety-net/--poll
#   DOWN TO ZERO — meaningless, since the main loop body that would use them never runs
#   when --overall-timeout is 0 anyway.
#   The ordering/ceiling checks only bind a flag the caller actually passed. Applying them
#   to the UNCHANGED defaults (60/5) as well would reject a perfectly ordinary short wait
#   (e.g. `--overall-timeout 30` alone, a common "poll for a quick child" call, since the
#   default --safety-net of 60 exceeds it). So: an omitted --safety-net is clamped down to
#   `min(60, overall-timeout)`, and an omitted --poll to `min(5, safety-net)` — silently,
#   before validation — so a caller who only ever sets --overall-timeout keeps working.
#   Only a flag the caller explicitly set takes part in the checks as a hard constraint;
#   the clamped-down defaults always satisfy them by construction. This clamp chains — an
#   explicit --safety-net below the --poll default (e.g. --safety-net 2 with --poll
#   omitted) also clamps --poll's default down to 2s. A caller who passes ALL of
#   --poll/--safety-net/--overall-timeout explicitly gets no clamp at all — a real ordering
#   violation there is a genuine usage error, not something this rule silently repairs; the
#   fix in that case is to stop passing the unchanged defaults explicitly.
#   --stall-after is a separate, independently-validated flag (rule 6) and is NOT part of
#   this ordering — sizing it relative to --overall-timeout is the caller's job (see rule
#   6's own "well under a third" guidance), not something rule 9 enforces.
#   --poll/--safety-net/--overall-timeout are all integer-only by design, not oversight:
#   the ordering/ceiling checks above, and the `${#value}` length guards this rule and
#   rule 6 rely on, are bash integer comparisons — supporting a fractional value like
#   `0.5` would mean reimplementing all of that arithmetic through an external tool
#   (`awk`/`bc`, not universally on PATH the way `sleep`/`grep`/`sed` are) for a sub-second
#   interval against agent state that itself only changes on human/agent-action
#   timescales. validate_positive_int rejects non-digit input (so `0.5`, like `5s` or
#   `-1`) by design.

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
readonly OVERALL_TIMEOUT_CEILING_S=86400   # rule 9: --overall-timeout sanity-warning threshold, 24h
# rule 9: track which interval flags the caller actually passed, so an omitted one can be
# clamped to fit an explicit --overall-timeout instead of rejected.
POLL_SET=0
SAFETY_NET_SET=0
# rule 8: shape of herdr's own pane id form (workspace:pane, e.g. "w1:p4"). Used only to
# decide whether an `agent_not_found` response means "bad target" or "this is already a
# pane id herdr just hasn't classified yet".
readonly PANE_ID_RE='^w[0-9A-Za-z]+:p[0-9A-Za-z]+$'

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
  --targets "id1,id2"   Comma-separated targets to watch — each one a pane id OR a unique
                        live agent name (whatever `herdr agent get` itself accepts; it does
                        NOT accept a bare label). Every entry is resolved to its pane_id at
                        startup (rule 8); an entry that genuinely can't be resolved (an
                        unknown name — including when herdr itself is unreachable — or a
                        nonexistent pane id) exits 6 immediately, before any waiting
                        begins. A pane id target rides out herdr being only TEMPORARILY
                        unreachable instead (same as `main`), since it has nothing to
                        resolve either way. An empty entry (from a doubled or
                        trailing comma) is dropped, not resolved — an all-empty --targets
                        is a usage error, exit 4. A pane id that DOES exist but whose agent
                        herdr hasn't classified yet is kept as-is, not rejected — see
                        rule 8. Wakes on whichever target moves first; the hit/stall JSON
                        line also carries this original entry back as
                        "target", alongside the resolved "pane_id".
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
  --overall-timeout N   Max SECONDS to wait before giving up. Default: 3600. 0 is a
                        special case: "probe once (check-first), then give up
                        immediately" (exit 2) — a pre-existing idiom, kept working as-is.
                        Otherwise must be > 0; past 86400s (24h) this only WARNS (not a
                        usage error — issue 9 never asked for a ceiling here) that the
                        value might be milliseconds, and keeps running with it as given.
  --poll N              SECONDS between log-cursor polls. Default: 5, clamped down to fit
                        --safety-net when omitted. Must be <= --safety-net and <= 300s.
  --safety-net N        SECONDS between unconditional live `agent get` sweeps. Default: 60,
                        clamped down to fit --overall-timeout when omitted. Must be <=
                        --overall-timeout and <= 300s.
  --stall-after N       Opt-in working-stall detection window in seconds. Default: 0 (off).
                        Size it well under a third of --overall-timeout (see header, rule
                        6) — this is the caller's job; --stall-after is NOT part of the
                        --poll/--safety-net/--overall-timeout ordering below.
  --help, -h            Print this help to stdout and exit 0.

  --poll, --safety-net and --overall-timeout are all SECONDS, never milliseconds (rule 9).
  --poll/--safety-net must be a positive integer <= 300s (a usage error past that — a
  value this large almost always means milliseconds); --overall-timeout must be 0 (see
  above) or a positive integer, with only a WARNING (not a usage error) past 86400s,
  since issue 9 never asked for a ceiling on --overall-timeout and a genuine multi-day
  wait is plausible there in a way a multi-minute --poll never is. The --poll/--safety-net
  ceiling is checked BEFORE the ordering rule below, so it fires regardless of what the
  other flags happen to be.
  --poll must not exceed --safety-net, which must not exceed --overall-timeout (skipped
  entirely when --overall-timeout is 0, since nothing in that case ever uses them). These
  three ordering/ceiling checks only bind a flag you actually pass: an OMITTED
  --poll/--safety-net is clamped down to fit an explicit, nonzero --overall-timeout
  instead of being rejected, so `--overall-timeout 30` alone (a short wait with
  everything else left at its default) stays valid exactly as before this rule existed.

EXIT CODES:
  0  hit — a target reached one of --states, verified live by `herdr agent get`
     (also exit 0 for --help/-h, which prints this help to stdout instead of a hit JSON line)
  2  overall timeout reached with no verified hit
  3  log file missing/unreadable at start (caller falls back to `herdr agent wait`)
  4  usage error (bad/missing flag, an unknown --states token, --states with no real state,
     an invalid/out-of-range --poll, --safety-net or --overall-timeout — see rule 9 — a
     --targets with no non-empty entries left after dropping doubled/trailing commas, or
     an unwritable --cursor-file once a run actually needs to persist one — never for a
     run whose check-first already hits, exit 0, same as `main`)
  5  suspected stall (only when --stall-after > 0; escalate via a worker-stall REQUEST)
  6  a --targets entry could not be resolved to a pane_id — an unresolvable name
     (including when herdr itself is unreachable), or a nonexistent pane id (NOT a
     pane id that exists but whose agent hasn't classified yet; NOT a pane id when
     herdr is only temporarily unreachable — ridden out instead, same as `main`; and
     NOT an empty entry — see rule 8 and --targets above)

STDOUT (one compact JSON line — except --help/-h, which prints this help text):
  hit (exit 0):    {"pane_id":"...","verified_state":"...","ts":"<ISO8601 UTC>","target":"..."}
  stall (exit 5):  {"pane_id":"...","suspected_stall_s":...,"detection_content_seq":...,"agent_status":"working","ts":"...","target":"..."}
  "target" is the original --targets entry this line's "pane_id" was resolved from (equal
  to "pane_id" itself for a caller that already passed a pane id), appended last so it
  never reorders the fields that predate it.
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
    --poll) POLL="$2"; POLL_SET=1; shift 2 ;;
    --safety-net) SAFETY_NET="$2"; SAFETY_NET_SET=1; shift 2 ;;
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

# rule 9: reject a non-numeric/zero/negative/overlong --poll, --safety-net or
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

# --overall-timeout alone is the one flag where 0 is a pre-existing, meaningful value —
# "probe once (check-first), then exit 2 immediately" — that worked on `main` with no
# validation at all (the main loop's very first `ELAPSED -ge OVERALL_TIMEOUT` check fires
# before anything else runs). A plain `validate_positive_int` would reject it. Only
# --overall-timeout gets this non-negative variant; --poll/--safety-net still require > 0
# (a zero interval there is never intentional — it would busy-loop or skip verification
# entirely).
validate_nonnegative_int() {
  local flag="$1" value="$2"
  case "$value" in
    ''|*[!0-9]*)
      echo "herdr-ewait: --$flag must be a non-negative integer number of seconds, got '$value'" >&2
      usage
      ;;
  esac
  if [ "${#value}" -gt 9 ]; then
    echo "herdr-ewait: --$flag is too large, got '$value'" >&2
    usage
  fi
}

# Validate --overall-timeout first: the clamping below needs a sane, already-validated
# value to clamp the omitted defaults DOWN to.
validate_nonnegative_int overall-timeout "$OVERALL_TIMEOUT"
# OVERALL_TIMEOUT_CEILING_S (24h) is deliberately far more generous than
# INTERVAL_CEILING_S — a multi-hour or even multi-day supervision wait is plausible in a
# way a multi-minute --poll never is. 0 is exempt (see above): it is never a scaled-up
# millisecond value, since 0ms == 0s. Past the ceiling this only WARNS (still naming the
# millisecond mistake) and keeps the caller's value — never a usage error — so a genuine
# long supervision wait is never rejected, only flagged.
if [ "$OVERALL_TIMEOUT" -gt "$OVERALL_TIMEOUT_CEILING_S" ]; then
  echo "herdr-ewait: warning: --overall-timeout is ${OVERALL_TIMEOUT}s, above the ${OVERALL_TIMEOUT_CEILING_S}s (24h) sanity threshold — if this was meant to be milliseconds, divide by 1000; proceeding with the value as given" >&2
fi

# --poll/--safety-net are only ever USED inside the main loop body, which
# --overall-timeout 0 never reaches (check-first already ran; the loop's first iteration
# exits 2 before any sleep or safety-net sweep). Clamping them against a zero timeout, or
# checking their ordering against it, would be both meaningless and actively harmful (it
# would clamp a default SAFETY_NET/POLL down to 0, which then fails their own > 0
# validation below) — so skip both the clamp and the ordering checks entirely in this
# case. An explicitly-passed --poll/--safety-net still gets its own positive-int and
# ceiling validation either way; only the OVERALL_TIMEOUT-relative parts are skipped.
if [ "$OVERALL_TIMEOUT" -gt 0 ]; then
  # An omitted --safety-net/--poll is clamped to fit an explicit --overall-timeout rather
  # than validated against its unchanged default — see rule 9 above for why. Only ever
  # clamps DOWN, and only when the caller did not pass the flag itself, so an explicit
  # value (valid or not) is never silently overridden.
  if [ "$SAFETY_NET_SET" -eq 0 ] && [ "$OVERALL_TIMEOUT" -lt "$SAFETY_NET" ]; then
    SAFETY_NET="$OVERALL_TIMEOUT"
  fi
fi
validate_positive_int safety-net "$SAFETY_NET"

if [ "$OVERALL_TIMEOUT" -gt 0 ] && [ "$POLL_SET" -eq 0 ] && [ "$SAFETY_NET" -lt "$POLL" ]; then
  POLL="$SAFETY_NET"
fi
validate_positive_int poll "$POLL"

# The ceiling check must run BEFORE the ordering checks below, not after — a bare
# `--poll 10000` (safety-net left at its default 60) would otherwise be rejected by the
# poll>safety-net ORDERING check first, whose "omit --poll ... instead of passing the
# default explicitly" message doesn't describe what the caller actually did (they passed
# an explicit, oversized value, not a default). Checking the ceiling first means the
# millisecond hint fires for every value past it, regardless of what the other two flags
# happen to be set to — a caller passing millisecond-sized values (10000/30000) for
# second-based flags is overwhelmingly more likely than a genuine multi-minute
# poll/safety-net interval, so say so directly.
if [ "$POLL" -gt "$INTERVAL_CEILING_S" ] || [ "$SAFETY_NET" -gt "$INTERVAL_CEILING_S" ]; then
  echo "herdr-ewait: --poll and --safety-net must each be <= ${INTERVAL_CEILING_S}s (got poll=${POLL}s, safety-net=${SAFETY_NET}s) — a value this large almost certainly means milliseconds, not seconds" >&2
  usage
fi

# The clamp above only ever applies to an OMITTED flag — a caller who passes all three
# explicitly (e.g. copying the README's own example verbatim and then shortening just
# --overall-timeout) gets a real ordering violation here, not a clamp. That is
# intentional (an explicit value is never silently overridden), but the cheapest fix is
# usually to stop passing the default explicitly, so say that directly.
if [ "$OVERALL_TIMEOUT" -gt 0 ]; then
  if [ "$POLL" -gt "$SAFETY_NET" ]; then
    echo "herdr-ewait: --poll (${POLL}s) must not exceed --safety-net (${SAFETY_NET}s) — omit --poll (and/or --safety-net) to let it clamp down to --overall-timeout automatically instead of passing the default explicitly" >&2
    usage
  fi
  if [ "$SAFETY_NET" -gt "$OVERALL_TIMEOUT" ]; then
    echo "herdr-ewait: --safety-net (${SAFETY_NET}s) must not exceed --overall-timeout (${OVERALL_TIMEOUT}s) — omit --safety-net (and/or --poll) to let it clamp down to --overall-timeout automatically instead of passing the default explicitly" >&2
    usage
  fi
fi
# Normalize to plain base-10 integers (e.g. "007" -> "7") now that every value has passed
# validation. `[` already compares these in decimal regardless, so this is cosmetic only —
# it keeps the startup diagnostic line below from echoing a confusing "poll=007s".
POLL=$((10#$POLL))
SAFETY_NET=$((10#$SAFETY_NET))
OVERALL_TIMEOUT=$((10#$OVERALL_TIMEOUT))
STALL_AFTER=$((10#$STALL_AFTER))

# rule 7: normalize + validate --states before it ever reaches an ERE. Both grep call sites
# below splice $STATES verbatim into "^($STATES)$"-shaped alternations, which only works when the
# caller's separator is a pipe — a comma-delimited value (the natural typo, since --targets uses
# commas) collapses to a single literal branch that matches nothing, silently killing every
# state-detection path (rule 1, rule 5, the log pre-filter) with no error, just a hang to
# --overall-timeout. Accept comma, whitespace, and pipe separators in ANY combination — including
# whitespace around a comma/pipe ("blocked, done", "blocked | done") — by translating each to a
# pipe, squeezing separator RUNS to one, and trimming the ends. Collapsing redundant/leading/
# trailing separators is safe: it only ever yields a valid sub-filter of real states, never a
# silently-wrong one. What IS rejected loudly (exit 4) is a value with no real state at all, or any
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

# `read` below stops at the first newline, silently dropping every later target; reject a
# newline or CR instead (sibling-sync note above).
case "$TARGETS" in
  *$'\n'* | *$'\r'*)
    echo "herdr-ewait: --targets must be a single comma-separated line (newline found)" >&2
    usage
    ;;
esac
IFS=',' read -r -a TARGET_ARR <<< "$TARGETS"
# Trim surrounding whitespace from each target — "a, b" must match "b", not " b".
for i in "${!TARGET_ARR[@]}"; do
  t="${TARGET_ARR[$i]}"
  t="${t#"${t%%[![:space:]]*}"}"
  t="${t%"${t##*[![:space:]]}"}"
  TARGET_ARR[$i]="$t"
done

# A doubled/trailing comma ("a,,b", "a,") leaves an empty entry after the split above
# (bash drops only a single trailing empty field, not an interior one). `herdr agent get
# ""` always fails, so an empty entry would otherwise exit 6 with a confusing "could not
# resolve target ''" message. Drop empty entries instead — they were never going to match
# anything either way — and only fail (as a usage error, not exit 6) if NOTHING real is
# left.
_filtered=()
for t in "${TARGET_ARR[@]}"; do
  [ -n "$t" ] && _filtered+=("$t")
done
# Check emptiness (via length, always safe) and bail out BEFORE spreading _filtered back
# into TARGET_ARR below: under `set -u`, "${arr[@]}" on a truly empty array is itself an
# "unbound variable" error on bash < 4.4 (e.g. macOS's bundled bash 3.2) — exiting first
# means that edge case gets our own usage message, not a raw bash error.
if [ "${#_filtered[@]}" -eq 0 ]; then
  echo "herdr-ewait: --targets has no non-empty entries (check for a doubled or trailing comma)" >&2
  usage
fi
TARGET_ARR=("${_filtered[@]}")

# Neither a pane id nor a herdr name can start with "-", so an entry that does is a
# usage error, not a target to resolve — herdr treats "-h"/"--help" specially rather
# than failing closed on them the way it does for every other unresolvable target.
for t in "${TARGET_ARR[@]}"; do
  case "$t" in
    -*)
      echo "herdr-ewait: --targets entry '$t' looks like a flag, not a pane id or herdr name" >&2
      usage
      ;;
  esac
done

# An entry is echoed back verbatim as the JSON "target" field, so a '"' or '\' would make the
# stdout line invalid JSON; reject it as a usage error (sibling-sync note above).
for t in "${TARGET_ARR[@]}"; do
  case "$t" in
    *'"'* | *'\'*)
      echo "herdr-ewait: --targets entry '$t' contains a '\"' or '\\' character, which cannot appear in the JSON \"target\" field" >&2
      usage
      ;;
  esac
done

# Rule 8: resolve each --targets entry — a pane id or a unique live agent name — to its
# canonical pane_id via `herdr agent get`, once, right here. ORIG_TARGET_ARR keeps the
# original entry (name or pane id, as the caller wrote it) alongside TARGET_ARR's
# resolved pane_id, purely for display and for the "target" field on a hit/stall line
# below — every lookup (log pre-filter, live verification) uses the resolved pane_id
# only, in TARGET_ARR.
ORIG_TARGET_ARR=()
for i in "${!TARGET_ARR[@]}"; do
  t="${TARGET_ARR[$i]}"
  ORIG_TARGET_ARR[$i]="$t"

  # herdr writes its SUCCESS json to stdout but its ERROR json to STDERR, so the resolve
  # call captures both streams here with `2>&1`; `get_status`/the stall sweep below only
  # ever need success fields and keep discarding stderr. RESOLVE_STATUS is captured
  # separately via `|| RESOLVE_STATUS=$?` rather than `|| true`, so later checks can tell
  # "herdr itself reported failure" apart from "herdr exited 0 but its response didn't
  # parse the way we expected" — the two need different handling below. `|| true` on the
  # grep pipeline: under `set -o pipefail`, a no-match `grep` (exit 1) — the normal case
  # for a pane_id-less response — would otherwise fail the whole pipeline and kill the
  # script right here via `set -e`, before the fallback logic ever runs.
  RESOLVE_STATUS=0
  RESOLVE_RESP="$(herdr agent get "$t" 2>&1)" || RESOLVE_STATUS=$?
  resolved="$(printf '%s' "$RESOLVE_RESP" | grep -o '"pane_id":"[^"]*"' | head -n1 | sed -E 's/"pane_id":"([^"]*)"/\1/' || true)"
  if [ -n "$resolved" ]; then
    TARGET_ARR[$i]="$resolved"
    continue
  fi

  # Surface herdr's own error `code` (e.g. "agent_not_found") instead of discarding it —
  # it is what lets the check just below distinguish "this pane simply hasn't been
  # classified yet" from a genuinely bad target, and what lets the caller reading stderr
  # tell "fix my target" apart from "herdr itself is unreachable".
  code="$(printf '%s' "$RESOLVE_RESP" | grep -o '"code":"[^"]*"' | head -n1 | sed -E 's/"code":"([^"]*)"/\1/' || true)"

  # herdr exited 0 (success) but nothing matched `"pane_id":"..."` — an unexpected/renamed
  # response shape, not a failure herdr itself reported. This is NOT the same situation as
  # an unresolvable target: herdr didn't say anything was wrong. If the target already
  # looks like a pane id, there's nothing to resolve in the first place — keep it as-is
  # (same posture as the detection-lag fallback just below) rather than fail-closed on a
  # parsing gap that isn't the caller's fault. For a NAME there is no safe fallback
  # identity, so this still exits 6, but says accurately that herdr succeeded and the
  # shape was the problem, not "unknown target".
  if [ "$RESOLVE_STATUS" -eq 0 ] && [ -z "$code" ]; then
    if [[ "$t" =~ $PANE_ID_RE ]]; then
      echo "herdr-ewait: warning: 'herdr agent get $t' succeeded but its response had no recognizable pane_id field (unexpected response shape) — using '$t' as-is and continuing to wait" >&2
      continue
    fi
    echo "herdr-ewait: could not resolve target '$t': herdr returned success (exit 0) but its response had no recognizable pane_id field (unexpected response shape, not an unresolvable target)" >&2
    exit 6
  fi

  # A pane id is already the canonical form `herdr agent get` would otherwise give us —
  # there is nothing to resolve. But `agent_not_found` on something that already LOOKS
  # like a pane id ($PANE_ID_RE) is ambiguous on its own: herdr returns the SAME code
  # whether the pane exists with no classified agent yet (the normal race right after
  # dispatching a fresh pane — keep waiting) or the pane doesn't exist at all (a
  # typo'd/stale id — "never start a waiter that cannot match" applies just as much
  # here). `herdr pane get` tells the two apart: it returns a pane_id for any real pane
  # regardless of its agent, and `pane_not_found` for one that isn't. Only probe this —
  # one extra call — in this specific ambiguous case; every other target resolves with
  # the single `agent get` call above.
  if [ "$code" = "agent_not_found" ] && [[ "$t" =~ $PANE_ID_RE ]]; then
    PANE_RESP="$(herdr pane get "$t" 2>&1 || true)"
    pane_found="$(printf '%s' "$PANE_RESP" | grep -o '"pane_id":"[^"]*"' | head -n1 | sed -E 's/"pane_id":"([^"]*)"/\1/' || true)"
    if [ -n "$pane_found" ]; then
      echo "herdr-ewait: warning: '$t' looks like a pane id but herdr has not detected an agent there yet (agent_not_found) — using it as-is and continuing to wait" >&2
      continue
    fi
    pane_code="$(printf '%s' "$PANE_RESP" | grep -o '"code":"[^"]*"' | head -n1 | sed -E 's/"code":"([^"]*)"/\1/' || true)"
    if [ -n "$pane_code" ]; then
      echo "herdr-ewait: could not resolve target '$t' to a pane_id via 'herdr agent get' (agent_not_found; herdr pane get also failed: $pane_code — the pane itself does not appear to exist)" >&2
    else
      echo "herdr-ewait: could not resolve target '$t' to a pane_id via 'herdr agent get' (agent_not_found; the pane itself does not appear to exist either)" >&2
    fi
    exit 6
  fi

  # On `main`, a pane-id caller had nothing to resolve in the first place, so it rode out
  # a transient herdr outage at startup for free — every probe elsewhere in this script
  # is unconditionally tolerant (`|| true`) of herdr being briefly unreachable. A pane-id
  # target gets the same treatment here: herdr being down (not a bad target) is not a
  # resolution failure for a target that already IS a pane id. A NAME still exits 6: it
  # has no identity to fall back on, and retrying the resolution call itself would be a
  # materially larger change.
  if [[ "$t" =~ $PANE_ID_RE ]]; then
    if [ -n "$code" ]; then
      echo "herdr-ewait: warning: 'herdr agent get $t' failed ($code) — herdr itself may be temporarily unreachable; using '$t' as-is and continuing to wait" >&2
    else
      echo "herdr-ewait: warning: 'herdr agent get $t' produced no usable response — herdr itself may be temporarily unreachable; using '$t' as-is and continuing to wait" >&2
    fi
    continue
  fi

  if [ -n "$code" ]; then
    echo "herdr-ewait: could not resolve target '$t' to a pane_id via 'herdr agent get' ($code)" >&2
  else
    # A non-JSON failure (herdr absent from PATH, a shell permission error, a panic
    # printed as plain text) has no "code" to surface. Surface the first non-blank line
    # of the captured output (trimmed, length-capped so one giant stack trace can't
    # flood stderr) when there is one, so "no herdr on PATH" doesn't read as "bad target
    # name". `|| true` on every stage of this pipeline, including `cut`: a missing/failed
    # tool on a split-tools PATH must degrade to the no-detail message below, not kill
    # the script via `set -e`/`pipefail` on what is already a failure-reporting path.
    raw_line="$(printf '%s' "$RESOLVE_RESP" | grep -m1 -v '^[[:space:]]*$' || true)"
    raw_line="$(printf '%s' "$raw_line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | cut -c1-160 || true)"
    if [ -n "$raw_line" ]; then
      echo "herdr-ewait: could not resolve target '$t' to a pane_id via 'herdr agent get' (unknown target, pane gone, or herdr unreachable — herdr said: \"$raw_line\")" >&2
    else
      echo "herdr-ewait: could not resolve target '$t' to a pane_id via 'herdr agent get' (unknown target, pane gone, or herdr unreachable)" >&2
    fi
  fi
  exit 6
done

# Parse "agent_status":"<state>" out of one `herdr agent get <id>` JSON line, grep/sed only.
# Real observed shape: {"id":"cli:agent:get",...,"agent_status":"working",...,"pane_id":"w1:p1",...}
# Every call site below guards the invocation with `|| true` (never inside the function
# itself, matching the parse_* helpers' convention elsewhere in this script): under
# `set -o pipefail`, a response with no "agent_status" field at all — a legitimate,
# expected case (a probe miss, or a target that just vanished) — fails this pipeline via
# `grep`'s no-match exit, which would otherwise kill the whole script via `set -e` on a
# condition the surrounding code is explicitly designed to treat as "no hit this tick,
# keep going", not a fatal error.
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

# "target" carries the original --targets entry (name or pane id, as the caller wrote it)
# so a multi-target caller can tell which of ITS OWN entries fired — before this, a name
# caller only ever saw a resolved pane_id it never passed, with no way to map a hit back
# to its own bookkeeping without an extra skip-level `agent get` of its own. Additive
# field, APPENDED after every pre-existing field — inserting it before "ts" would reorder
# the line rather than only adding to it, which would break a consumer matching on
# `..."verified_state":"...","ts":...` positionally or by regex, where appending strictly
# after "ts" cannot.
emit_hit() {
  local pane="$1" state="$2" orig="$3"
  printf '{"pane_id":"%s","verified_state":"%s","ts":"%s","target":"%s"}\n' "$pane" "$state" "$(now_iso)" "$orig"
}

# Rule 4 (verify-on-hit): re-check a candidate hit with `agent get` before trusting it.
# A log match is a wake-up signal, not the source of truth; if the live state no longer
# matches, treat it as spurious and keep waiting.
verify_and_maybe_emit() {
  local pane="$1" orig="$2"
  local status
  status="$(get_status "$pane" || true)"
  if [ -n "$status" ] && printf '%s' "$status" | grep -Eq "^($STATES)\$"; then
    emit_hit "$pane" "$status" "$orig"
    return 0
  fi
  return 1
}

# A NAME target is resolved to a pane_id exactly once, at startup (rule 8). herdr's own
# docs say a pane moved to another workspace (`herdr pane move`) gets a NEW,
# workspace-qualified pane_id, and the old one stops resolving for general callers — so a
# mid-wait move leaves a name caller's TARGET_ARR entry pointing at a pane_id that no
# longer exists, with no way to notice short of re-asking herdr about the ORIGINAL name.
# Called from the safety-net sweep and the stall sweep, on any tick whose probe of the
# current pane_id comes back completely empty (not merely "not in --states yet" — a
# healthy but still-working pane must never pay for this) AND the target was originally a
# name, not an identity pane-id caller with nothing to re-resolve. On success, updates
# TARGET_ARR in place and returns 0 so the caller can retry immediately; this is the ONLY
# place TARGET_ARR changes after the startup resolution loop.
reresolve_if_stale() {
  local i="$1"
  local orig="${ORIG_TARGET_ARR[$i]}"
  local current="${TARGET_ARR[$i]}"
  [ "$orig" = "$current" ] && return 1
  local resp new_id
  resp="$(herdr agent get "$orig" 2>&1 || true)"
  new_id="$(printf '%s' "$resp" | grep -o '"pane_id":"[^"]*"' | head -n1 | sed -E 's/"pane_id":"([^"]*)"/\1/' || true)"
  if [ -n "$new_id" ] && [ "$new_id" != "$current" ]; then
    echo "herdr-ewait: note: '$orig' now resolves to pane_id '$new_id' (was '$current') — the pane likely moved; updating and retrying" >&2
    TARGET_ARR[$i]="$new_id"
    return 0
  fi
  return 1
}

# Establish (but do not yet persist) the byte cursor. The VALUE is computed here, before
# check-first, so the startup diagnostic below can include it — but the write-to-disk is
# deliberately NOT done here. It is restored to its position on `main` — AFTER check-first
# — below (CURSOR_IS_FRESH records which branch this was, since the "already exists"
# branch never writes at all, matching `main`). An unwritable --cursor-file path must not
# crash under `set -e` with a raw bash error even when the target was already terminal —
# that would lose a hit `main` would have reported with exit 0.
if [ -f "$CURSOR_FILE" ]; then
  CURSOR="$(cat "$CURSOR_FILE" 2>/dev/null || echo 0)"
  case "$CURSOR" in ''|*[!0-9]*) CURSOR=0 ;; esac
  CURSOR_IS_FRESH=0
else
  # A fresh waiter has no interest in history — check-first (below) already covers "the
  # target is already settled". Starting at 0 would replay the entire session log on
  # tick one, spending one spurious `agent get` per stale pre-filter match. Start at the
  # log's CURRENT size instead; persisted after check-first, below.
  CURSOR="$(wc -c < "$LOG" 2>/dev/null | tr -d ' ' || true)"
  case "$CURSOR" in ''|*[!0-9]*) CURSOR=0 ;; esac
  CURSOR_IS_FRESH=1
fi

# Startup diagnostic: print exactly what this run resolved to, in seconds, so a
# misconfigured waiter is visible in the caller's own output immediately — instead of
# only showing up, hours later, as unexplained silence. Printed BEFORE check-first so it
# always prints, even on a run that hits immediately. Each target is shown as
# original=resolved (e.g. "alice=w7:p3"), equal on both sides for a caller that already
# passed a pane id, so the mapping — not just the resolved id — is visible without a
# separate `herdr agent get` of the caller's own.
TARGETS_DISPLAY=""
for i in "${!TARGET_ARR[@]}"; do
  entry="${ORIG_TARGET_ARR[$i]}=${TARGET_ARR[$i]}"
  if [ -z "$TARGETS_DISPLAY" ]; then
    TARGETS_DISPLAY="$entry"
  else
    TARGETS_DISPLAY="$TARGETS_DISPLAY,$entry"
  fi
done
echo "herdr-ewait: targets=$TARGETS_DISPLAY states=$STATES poll=${POLL}s safety-net=${SAFETY_NET}s overall-timeout=${OVERALL_TIMEOUT}s stall-after=${STALL_AFTER}s cursor=$CURSOR" >&2

# Rule 1 (check-first): before any waiting, check every target once. Kills the
# "first observed state is already terminal" race — cursor-snapshot timing stops
# being safety-critical because we never rely on the log alone.
for i in "${!TARGET_ARR[@]}"; do
  if verify_and_maybe_emit "${TARGET_ARR[$i]}" "${ORIG_TARGET_ARR[$i]}"; then
    exit 0
  fi
done

# Persist a FRESH cursor only now, after check-first — same position as `main` — so an
# immediate hit above is never lost to a bad --cursor-file path. Guarded (rather than left
# to crash under `set -e`) so an unwritable path is a documented usage error, not a raw
# bash error with an undocumented exit code.
if [ "$CURSOR_IS_FRESH" -eq 1 ]; then
  printf '%s' "$CURSOR" > "$CURSOR_FILE" || {
    echo "herdr-ewait: cannot write cursor file: $CURSOR_FILE" >&2
    exit 4
  }
fi

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
    # `|| true` on every parse below — a probe failure is a top-level command
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
  # Failure-tolerant — if the log vanishes mid-run, `wc -c <` fails; under
  # `set -euo pipefail` an unguarded pipeline failure here would kill the whole script
  # with an undocumented exit code. `|| true` on the substitution degrades this tick to
  # LOG_SIZE=0 instead, so the run falls through to safety-net-only sweeps (rule 5).
  LOG_SIZE=$( { wc -c < "$LOG"; } 2>/dev/null | tr -d ' ' || true)
  [ -n "$LOG_SIZE" ] || LOG_SIZE=0
  case "$LOG_SIZE" in ''|*[!0-9]*) LOG_SIZE=0 ;; esac
  # Log rotation/truncation guard — if our cursor is now past the log's current size (the
  # file was rotated or truncated out from under us), `-gt` would never fire again and
  # only the safety net would keep working. Reset to 0 so the next size increase is
  # detected as new bytes again.
  if [ "$CURSOR" -gt "$LOG_SIZE" ]; then
    CURSOR=0
  fi
  if [ "$LOG_SIZE" -gt "$CURSOR" ]; then
    NEW_BYTES="$(tail -c +$((CURSOR + 1)) "$LOG" 2>/dev/null || true)"
    CURSOR="$LOG_SIZE"
    printf '%s' "$CURSOR" > "$CURSOR_FILE" || {
      echo "herdr-ewait: cannot write cursor file: $CURSOR_FILE" >&2
      exit 4
    }

    if [ -n "$NEW_BYTES" ]; then
      for i in "${!TARGET_ARR[@]}"; do
        t="${TARGET_ARR[$i]}"
        # Filter lines by pane_id AND agent_status regex before ever calling out — this is
        # the cheap pre-filter; the actual truth check is still verify_and_maybe_emit below.
        if printf '%s\n' "$NEW_BYTES" | grep -F "\"pane_id\":\"$t\"" | grep -Eq "\"agent_status\":\"($STATES)\""; then
          if verify_and_maybe_emit "$t" "${ORIG_TARGET_ARR[$i]}"; then
            exit 0
          fi
          # Rule 4 continued: log said hit, live state disagreed — spurious, keep polling.
        fi
      done
    fi
  fi

  # Rule 5: unconditional safety-net sweep every --safety-net seconds, even with no log
  # hit — heals any event the log-filter path missed within one interval.
  if [ $(( NOW_TS - LAST_SAFETY_NET )) -ge "$SAFETY_NET" ]; then
    LAST_SAFETY_NET="$NOW_TS"
    for i in "${!TARGET_ARR[@]}"; do
      t="${TARGET_ARR[$i]}"
      orig="${ORIG_TARGET_ARR[$i]}"
      status="$(get_status "$t" || true)"
      if [ -n "$status" ]; then
        if printf '%s' "$status" | grep -Eq "^($STATES)\$"; then
          emit_hit "$t" "$status" "$orig"
          exit 0
        fi
        continue
      fi
      # The probe came back completely empty (not just "not in --states yet") for a
      # NAME-originated target — the pane may have moved. One extra `agent get` of the
      # ORIGINAL name only in this specific case; a healthy pane-id caller, or a name
      # caller whose probe still succeeds, never pays for it.
      if [ "$orig" != "$t" ] && reresolve_if_stale "$i"; then
        t="${TARGET_ARR[$i]}"
        status="$(get_status "$t" || true)"
        if [ -n "$status" ] && printf '%s' "$status" | grep -Eq "^($STATES)\$"; then
          emit_hit "$t" "$status" "$orig"
          exit 0
        fi
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
      # ONE `herdr agent get` capture per target per tick — both seq and status are
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

        # Before counting this as a genuine outage tick, give a NAME-originated target
        # (never a pane-id caller — reresolve_if_stale itself also checks this) one chance
        # to re-resolve, the same trigger the safety-net sweep uses. Without this, a
        # mid-wait `herdr pane move` would count every probe of the now-permanently-dead
        # old pane_id toward "unreachable for a full window" and could exit 5 claiming the
        # pane "may no longer exist" while the agent is alive under its new pane_id — a
        # false stall this rule exists to avoid, not cause.
        if [ "${ORIG_TARGET_ARR[$i]}" != "$t" ] && reresolve_if_stale "$i"; then
          t="${TARGET_ARR[$i]}"
          RESP="$(herdr agent get "$t" 2>/dev/null || true)"
          seq="$(parse_content_seq "$RESP" || true)"
          status="$(parse_agent_status "$RESP" || true)"
          if [ -n "$seq" ] || [ -n "$status" ]; then
            # Reachable again under the new pane_id. Re-baseline rather than carry the old
            # pane_id's seq/working-bracket state forward — that baseline belongs to a
            # pane_id that no longer exists; the next tick resumes stall detection fresh
            # against the new one.
            STALL_MISS_SINCE_ARR[$i]=""
            STALL_SEQ_ARR[$i]="$seq"
            STALL_TS_ARR[$i]=$NOW_TS
            STALL_PREV_WORKING_ARR[$i]=""
            continue
          fi
          # Still unreachable even under the freshly re-resolved pane_id — fall through to
          # the normal miss-timer handling below, now against the new pane_id.
        fi

        miss_since="${STALL_MISS_SINCE_ARR[$i]:-}"
        if [ -z "$miss_since" ]; then
          # First tick of a genuine outage — start timing it; don't report yet.
          STALL_MISS_SINCE_ARR[$i]="$NOW_TS"
        elif [ $(( NOW_TS - miss_since )) -ge "$STALL_AFTER" ]; then
          # Unreachable for a full window — report rather than silently waiting out
          # --overall-timeout for a target that may no longer exist.
          printf '{"pane_id":"%s","suspected_stall_s":%s,"detection_content_seq":null,"ts":"%s","target":"%s"}\n' \
            "$t" "$(( NOW_TS - miss_since ))" "$(now_iso)" "${ORIG_TARGET_ARR[$i]}"
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
            printf '{"pane_id":"%s","suspected_stall_s":%s,"detection_content_seq":%s,"agent_status":"%s","ts":"%s","target":"%s"}\n' \
              "$t" "$(( NOW_TS - STALL_TS_ARR[i] ))" "$seq" "$status" "$(now_iso)" "${ORIG_TARGET_ARR[$i]}"
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
