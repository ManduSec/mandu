#!/usr/bin/env bash
#
# run-matrix.sh — run EVERY target × its declared SUITES; aggregate a summary.
# Design: docs/design/testing/os-test-matrix.md §2, §5 (SKIP vs --require).
#
# Usage:
#   scripts/matrix/run-matrix.sh [--require <target>]...
#
# --require <target>: that target being unavailable (any of its suites SKIPs at
# the executor level) is a FAILURE — CI uses this so a target cannot rot
# silently while the summary stays green.
#
# Exit: 0 = no failures (SKIPs allowed unless required); 1 = any failure.
set -uo pipefail

MATRIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$MATRIX_DIR/lib/common.sh"

REQUIRED=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --require) [[ $# -ge 2 ]] || { err "--require needs a target"; exit 2; }
               REQUIRED+=("$2"); shift 2 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "unknown option '$1'"; exit 2 ;;
  esac
done

is_required() {
  local t="$1" r
  for r in ${REQUIRED[@]+"${REQUIRED[@]}"}; do [[ "$r" == "$t" ]] && return 0; done
  return 1
}

# A required target must exist at all.
for r in ${REQUIRED[@]+"${REQUIRED[@]}"}; do
  [[ -f "$MATRIX_DIR/targets/$r.conf" ]] || { err "--require '$r': no such target"; exit 2; }
done

# suites_for <conf> — the target's declared SUITES, read in a subshell so conf
# vars never leak between targets.
suites_for() { ( SUITES=""; source "$1" >/dev/null 2>&1; echo "$SUITES" ); }

NAMES=(); STATUS=(); OVERALL_RC=0
for conf in "$MATRIX_DIR"/targets/*.conf; do
  target="$(basename "${conf%.conf}")"
  for suite in $(suites_for "$conf"); do
    say "════ matrix: $target/$suite ════"
    "$MATRIX_DIR/run.sh" "$target" "$suite"; rc=$?
    case $rc in
      0) st="PASS" ;;
      3) if is_required "$target"; then st="FAIL (SKIP but --require $target)"; OVERALL_RC=1
         else st="SKIP"; fi ;;
      *) st="FAIL"; OVERALL_RC=1 ;;
    esac
    NAMES+=("$target/$suite"); STATUS+=("$st")
    echo
  done
done

say "════════════════════ matrix summary ════════════════════"
for i in "${!NAMES[@]}"; do
  case "${STATUS[$i]}" in
    PASS)  ok   "${NAMES[$i]} — PASS" ;;
    SKIP)  warn "${NAMES[$i]} — SKIP" ;;
    *)     err  "${NAMES[$i]} — ${STATUS[$i]}" ;;
  esac
done
exit $OVERALL_RC
