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
#                   [--overall-timeout 3600] [--poll 5] [--safety-net 60]
#
# Stdout on success: exactly one compact JSON line, nothing else:
#   {"pane_id":"...","verified_state":"...","ts":"<ISO8601 UTC>"}
#
# Exit codes:
#   0  hit — a target reached one of --states, verified by `herdr agent get`
#   2  overall timeout reached with no verified hit
#   3  log file missing/unreadable at start (caller should fall back to the
#      degraded `herdr agent wait` path — see references/supervision.md)
#   4  usage error
#
# Five hardening rules (each numbered comment below fixes a live #820 bug):
#   1. check-first        4. verify-on-hit
#   2. bounded poll, never `tail -f`   5. periodic safety net
#   3. non-configurable default state filter

set -euo pipefail

TARGETS=""
STATES="blocked|done|idle"   # rule 3: hard default; NOT overridable via config, only via this flag
LOG=""
CURSOR_FILE=""
OVERALL_TIMEOUT=3600
POLL=5
SAFETY_NET=60

usage() {
  echo "usage: herdr-ewait.sh --targets \"id1,id2\" [--states \"blocked|done|idle\"] --log <file> --cursor-file <file> [--overall-timeout N] [--poll N] [--safety-net N]" >&2
  exit 4
}

while [ $# -gt 0 ]; do
  case "$1" in
    --targets) TARGETS="$2"; shift 2 ;;
    --states) STATES="$2"; shift 2 ;;
    --log) LOG="$2"; shift 2 ;;
    --cursor-file) CURSOR_FILE="$2"; shift 2 ;;
    --overall-timeout) OVERALL_TIMEOUT="$2"; shift 2 ;;
    --poll) POLL="$2"; shift 2 ;;
    --safety-net) SAFETY_NET="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ -n "$TARGETS" ] || usage
[ -n "$LOG" ] || usage
[ -n "$CURSOR_FILE" ] || usage

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

# Parse "agent_status":"<state>" out of one `herdr agent get <id>` JSON line, grep/sed only.
# Real observed shape: {"id":"cli:agent:get",...,"agent_status":"working",...,"pane_id":"w1:p1",...}
get_status() {
  local target="$1"
  herdr agent get "$target" 2>/dev/null \
    | grep -o '"agent_status":"[^"]*"' \
    | head -n1 \
    | sed -E 's/"agent_status":"([^"]*)"/\1/'
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

START_TS=$(date +%s)
LAST_SAFETY_NET=$START_TS

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

  sleep "$POLL"
done
