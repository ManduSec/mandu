#!/usr/bin/env bash
# host.sh — host executor for the OS test matrix (docs/design/testing/os-test-matrix.md §2).
# Runs the suite directly in this checkout (cwd = $REPO_ROOT), with a throwaway
# MATRIX_WORK scratch dir under $RUN_WORK. Sourced by run.sh; uses common.sh.
#
# Contract: executor_check → 0 ready / 3 unavailable;
#           executor_run <suite> → 0 pass / 1 fail / 3 skip.

executor_check() {
  local deps missing=0
  deps="$(parse_deps "$MATRIX_DIR/suites/$SUITE_NAME.sh")"
  for d in $deps; do
    if have "$d"; then ok "dep on host: $d"
    else warn "dep MISSING on host: $d"; missing=1; fi
  done
  [[ $missing -eq 0 ]] && { ok "host executor ready"; return 0; }
  echo "skip: missing host deps"; return 3
}

executor_run() {
  local suite="$1" suite_sh="$MATRIX_DIR/suites/$1.sh"
  local deps d
  deps="$(parse_deps "$suite_sh")"
  for d in $deps; do
    have "$d" || { echo "skip: suite '$suite' needs '$d', not on host PATH"; return 3; }
  done

  local work="$RUN_WORK/suite-work"
  mkdir -p "$work"
  info "running suite '$suite' on host (cwd=$REPO_ROOT, log→$RUN_WORK/suite.log)"
  ( cd "$REPO_ROOT" && \
    MATRIX_TARGET="$TARGET_NAME" MATRIX_LABELS="$LABELS" MATRIX_WORK="$work" \
    bash "$suite_sh" ) 2>&1 | tee "$RUN_WORK/suite.log"
  local rc=${PIPESTATUS[0]}
  case $rc in
    0)  return 0 ;;
    77) echo "skip: suite '$suite' self-skipped (exit 77)"; return 3 ;;
    *)  return 1 ;;
  esac
}
