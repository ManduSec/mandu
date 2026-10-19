#!/usr/bin/env bash
#
# run.sh — run ONE suite on ONE target of the OS test matrix.
# Design: docs/design/testing/os-test-matrix.md (§2 executor contract, §5 SKIP semantics).
#
# Usage:
#   scripts/matrix/run.sh <target> <suite>      # e.g.  run.sh host smoke
#   scripts/matrix/run.sh --check <target> <suite>   # executor preflight only
#   scripts/matrix/run.sh --keep  <target> <suite>   # keep $RUN_WORK artifacts
#   scripts/matrix/run.sh --interactive <target> [<suite>]
#                                  # boot for ssh; the suite's host prep only
#   --keep-credential              # allow --keep / --interactive with a live
#                                  # leg (FRESH_INSTALL_LIVE / FRESH_AGENTS_LIVE)
#
# Every run's results are recorded under ~/.mandu/runs/matrix/<runId>/
# (lib/record.sh; the dashboard's 🖥 VM matrix tab reads them).
# MANDU_MATRIX_RECORD=0 turns that off.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = usage error, 3 = SKIP (reason printed).
set -uo pipefail

MATRIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$MATRIX_DIR/../.." && pwd)"
# shellcheck source=lib/common.sh
source "$MATRIX_DIR/lib/common.sh"
# shellcheck source=lib/record.sh
source "$MATRIX_DIR/lib/record.sh"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  echo "targets: $(ls "$MATRIX_DIR/targets" 2>/dev/null | sed 's/\.conf$//' | tr '\n' ' ')"
  echo "suites:  $(ls "$MATRIX_DIR/suites" 2>/dev/null | sed 's/\.sh$//' | tr '\n' ' ')"
}

KEEP=0; CHECK=0; INTERACTIVE=0; KEEP_CREDENTIAL=0; args=()
for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    --check) CHECK=1 ;;
    --interactive) INTERACTIVE=1 ;;
    --keep-credential) KEEP_CREDENTIAL=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) err "unknown option '$a'"; usage >&2; exit 2 ;;
    *) args+=("$a") ;;
  esac
done
if [[ $INTERACTIVE -eq 1 ]]; then
  [[ ${#args[@]} -eq 1 || ${#args[@]} -eq 2 ]] || { usage >&2; exit 2; }
else
  [[ ${#args[@]} -eq 2 ]] || { usage >&2; exit 2; }
fi
TARGET_NAME="${args[0]}"; SUITE_NAME="${args[1]:-}"

conf="$MATRIX_DIR/targets/$TARGET_NAME.conf"
suite_sh="$MATRIX_DIR/suites/$SUITE_NAME.sh"
[[ -f "$conf" ]] || { err "no such target '$TARGET_NAME'"; usage >&2; exit 2; }
[[ -z "$SUITE_NAME" || -f "$suite_sh" ]] || { err "no such suite '$SUITE_NAME'"; usage >&2; exit 2; }

# A kept overlay or a long-lived interactive guest outlives the moment the
# live leg's reduced credential is used for (os-test-matrix.md §10.3.5):
# refuse the combination unless the user says so.
LIVE=0
[[ "${FRESH_INSTALL_LIVE:-0}" == 1 || "${FRESH_AGENTS_LIVE:-0}" == 1 ]] && LIVE=1
if [[ $LIVE -eq 1 && ( $KEEP -eq 1 || $INTERACTIVE -eq 1 ) && $KEEP_CREDENTIAL -eq 0 ]]; then
  err "--keep / --interactive with a live leg keeps a Claude/OpenAI credential copy around; add --keep-credential to accept that"
  exit 2
fi

# Conf defaults, then the target's declaration overrides.
EXECUTOR=""; IMAGE_URL=""; IMAGE_SHA256=""; CPUS=4; MEM=4096; TIMEOUT=2400
LABELS=""; SYSCTLS=""; SUITES=""
# shellcheck source=/dev/null
source "$conf"
if [[ -z "$EXECUTOR" || ! -f "$MATRIX_DIR/lib/$EXECUTOR.sh" ]]; then
  err "target '$TARGET_NAME': EXECUTOR='$EXECUTOR' has no lib/$EXECUTOR.sh"; exit 2
fi
# shellcheck source=/dev/null
source "$MATRIX_DIR/lib/$EXECUTOR.sh"

RUN_WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-matrix.XXXXXX")"
RECORDING=0; TEE_PID=""
cleanup() {
  # A guest still up (this harness was signalled mid-boot) stops with it and
  # leaves the registry (lib/qemu.sh, scripts/lib/guest-registry.sh).
  if declare -F guest_release >/dev/null; then guest_release; fi
  if [[ $KEEP -eq 1 ]]; then info "--keep set; artifacts at $RUN_WORK"; fi
  if [[ $LIVE -eq 1 && $KEEP_CREDENTIAL -eq 1 ]]; then
    info "--keep-credential: the host copy lived in $RUN_WORK/artifacts/ephemeral (deleted when the guest stopped);" \
      "$([[ $KEEP -eq 1 ]] && echo "the guest's copy may remain inside $RUN_WORK/overlay.qcow2" || echo "the overlay is deleted now")"
  fi
  # Drain the console tee before copying its log into the run record.
  if [[ -n "$TEE_PID" ]]; then
    exec 1>&3 2>&4; wait "$TEE_PID" 2>/dev/null || true
    record_console "$RUN_WORK/console.log"
  fi
  [[ $KEEP -eq 1 ]] || rm -rf "$RUN_WORK"
}
trap cleanup EXIT

if [[ $INTERACTIVE -eq 1 ]]; then
  [[ "$(type -t executor_interactive)" == function ]] || { err "executor '$EXECUTOR' has no --interactive"; exit 2; }
  say "matrix: target=$TARGET_NAME interactive (suite prep: ${SUITE_NAME:-none}) executor=$EXECUTOR"
  executor_interactive "$SUITE_NAME"
  exit $?
fi

# Record the run (lib/record.sh): tee the console so the record carries it.
if [[ $CHECK -eq 0 ]] && record_enabled; then
  record_begin; RECORDING=1
  exec 3>&1 4>&2
  exec > >(tee "$RUN_WORK/console.log") 2>&1
  TEE_PID=$!
fi

say "matrix: target=$TARGET_NAME suite=$SUITE_NAME executor=$EXECUTOR"
info "labels: ${LABELS:-—}"

if [[ $CHECK -eq 1 ]]; then
  executor_check; rc=$?
  [[ $rc -eq 0 ]] && ok "CHECK OK   $TARGET_NAME/$SUITE_NAME" || warn "CHECK SKIP $TARGET_NAME/$SUITE_NAME"
  exit $rc
fi

executor_run "$SUITE_NAME"; rc=$?
echo
case $rc in
  0) ok   "PASS  $TARGET_NAME/$SUITE_NAME" ;;
  3) warn "SKIP  $TARGET_NAME/$SUITE_NAME" ;;
  *) err  "FAIL  $TARGET_NAME/$SUITE_NAME"; rc=1 ;;
esac
[[ $RECORDING -eq 1 ]] && record_finish "$rc"
exit $rc
