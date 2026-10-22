#!/usr/bin/env bash
# record.sh — keep every matrix run's results on disk (docs/design/testing/os-test-matrix.md §9).
# Purpose: run.sh works in a throwaway $RUN_WORK and deletes it on exit, so a
# run's per-step results were gone the moment it finished. This copies the
# result files to a durable run store the dashboard's 🖥 VM matrix tab reads
# (the developer view's matrix-runs.ts). run.sh is the single writer.
#
#   <store>/<runId>/meta.json   target, suite, executor, status, rc, commit, labels, times, flags
#   <store>/<runId>/suite.log   the suite's full output (guest or host)
#   <store>/<runId>/steps.log   PASS/FAIL/NOTE step lines, when the suite writes them
#   <store>/<runId>/timings.tsv, report.md   the npm-release suite's timings and summary
#   <store>/<runId>/run.log     the host console of run.sh (ANSI stripped)
#   <store>/<runId>/serial.log  the guest serial console, last 1 MiB, on FAIL only
#   <store>/<runId>/logs-<name>.log  the `all` suite's per-package logs
#
# <store> = the path table's `matrix-results`: ${MANDU_HOME:-~/.mandu}/runs/matrix.
# MANDU_MATRIX_RECORD=0 turns recording off. Never recorded: the artifacts
# share (host-prep secrets such as the live leg's reduced credential live there).
# The newest MANDU_MATRIX_KEEP runs (default 200) are kept.
#
# Sourced by run.sh. Needs: RUN_WORK TARGET_NAME SUITE_NAME EXECUTOR LABELS REPO_ROOT.

# shellcheck source=scripts/paths/mandu-paths.sh
. "$(dirname "${BASH_SOURCE[0]}")/../../paths/mandu-paths.sh"

# The path table's `matrix-results` entry (on-disk-layout.md §5).
matrix_store_dir() { mandu_path matrix-results; }

record_enabled() { [[ "${MANDU_MATRIX_RECORD:-1}" != "0" ]]; }

# json_str <s> — a JSON string literal (backslash, quote, control chars escaped).
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
  printf '"%s"' "$s"
}

strip_ansi() { sed -E 's/\x1b\[[0-9;?]*[A-Za-z]//g'; }

# record_begin — fix the run id and start time. Call once, before the run.
record_begin() {
  RECORD_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  RECORD_T0="$(date +%s)"
  RECORD_RUN_ID="$(date -u +%Y%m%d-%H%M%S)-${TARGET_NAME}-${SUITE_NAME}"
}

# record_commit — the commit under test: the one host prep packed (the
# fresh-install bundle, FRESH_INSTALL_REF honoured), else the checkout's HEAD.
record_commit() {
  local c=""
  [[ -s "$RUN_WORK/artifacts/COMMIT" ]] && c="$(head -c 64 "$RUN_WORK/artifacts/COMMIT" | tr -d '\n')"
  if [[ -z "$c" ]]; then
    c="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    git -C "$REPO_ROOT" diff --quiet 2>/dev/null || c="$c+dirty"
  fi
  printf '%s' "$c"
}

# record_finish <rc> — write <store>/<runId>/ from $RUN_WORK. Best effort: a
# recording failure is a warning, never a change to the run's exit status.
record_finish() {
  local rc="$1" status
  record_enabled || return 0
  case "$rc" in 0) status=pass ;; 3) status=skip ;; *) status=fail ;; esac
  local store dir src
  store="$(matrix_store_dir)"
  dir="$store/$RECORD_RUN_ID"
  mkdir -p "$dir" 2>/dev/null || { warn "matrix record: cannot create $dir"; return 0; }
  chmod 0700 "$store" 2>/dev/null || true

  # The suite's output lives in out/ for the qemu executor, at the top for host.
  src="$RUN_WORK/out"; [[ -d "$src" ]] || src="$RUN_WORK"
  [[ -s "$src/suite.log" ]] && cp "$src/suite.log" "$dir/suite.log"
  [[ -s "$src/steps.log" ]] && cp "$src/steps.log" "$dir/steps.log"
  # The npm-release suite's timing table and summary (os-test-matrix.md §10.18).
  [[ -s "$src/timings.tsv" ]] && cp "$src/timings.tsv" "$dir/timings.tsv"
  [[ -s "$src/report.md" ]] && cp "$src/report.md" "$dir/report.md"
  local reason=""
  [[ -s "$src/RESULT" ]] && reason="$(head -c 400 "$src/RESULT" | tr -d '\n')"
  if [[ -d "$src/test-all-logs" ]]; then
    local f n
    for f in "$src"/test-all-logs/*; do
      [[ -f "$f" ]] || continue
      n="${f##*/}"; n="${n%.log}"; n="${n//[^A-Za-z0-9_.-]/_}"
      cp "$f" "$dir/logs-$n.log"
    done
  fi
  if [[ "$status" == fail && -s "$RUN_WORK/serial.log" ]]; then
    tail -c 1048576 "$RUN_WORK/serial.log" | strip_ansi > "$dir/serial.log"
  fi

  local t1; t1="$(date +%s)"
  {
    printf '{\n'
    printf '  "runId": %s,\n' "$(json_str "$RECORD_RUN_ID")"
    printf '  "target": %s,\n' "$(json_str "$TARGET_NAME")"
    printf '  "suite": %s,\n' "$(json_str "$SUITE_NAME")"
    printf '  "executor": %s,\n' "$(json_str "$EXECUTOR")"
    printf '  "status": %s,\n' "$(json_str "$status")"
    printf '  "rc": %d,\n' "$rc"
    printf '  "reason": %s,\n' "$(json_str "$reason")"
    printf '  "commit": %s,\n' "$(json_str "$(record_commit)")"
    printf '  "ref": %s,\n' "$(json_str "${FRESH_INSTALL_REF:-}")"
    printf '  "live": %s,\n' "$([[ "${FRESH_INSTALL_LIVE:-0}" == 1 ]] && echo true || echo false)"
    printf '  "labels": %s,\n' "$(json_str "${LABELS:-}")"
    printf '  "host": %s,\n' "$(json_str "$(hostname 2>/dev/null || echo unknown)")"
    printf '  "startedAt": %s,\n' "$(json_str "$RECORD_STARTED_AT")"
    printf '  "finishedAt": %s,\n' "$(json_str "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
    printf '  "durationSec": %d\n' "$((t1 - RECORD_T0))"
    printf '}\n'
  } > "$dir/meta.json.tmp" && mv "$dir/meta.json.tmp" "$dir/meta.json"
  info "results recorded: $dir"
  record_prune "$store"
}

# record_console <console log> — the host console, copied after run.sh's tee
# has drained (run.sh's EXIT trap calls this last).
record_console() {
  record_enabled || return 0
  local dir; dir="$(matrix_store_dir)/$RECORD_RUN_ID"
  [[ -d "$dir" && -s "$1" ]] && strip_ansi < "$1" > "$dir/run.log"
  return 0
}

# record_prune <store> — keep the newest MANDU_MATRIX_KEEP run dirs.
record_prune() {
  local keep="${MANDU_MATRIX_KEEP:-200}" d
  [[ "$keep" =~ ^[0-9]+$ && "$keep" -gt 0 ]] || return 0
  # run ids start with a UTC timestamp, so a name sort is a time sort
  ls -1 "$1" 2>/dev/null | grep -E '^[0-9]{8}-[0-9]{6}-' | sort -r | tail -n +"$((keep + 1))" |
    while read -r d; do rm -rf "${1:?}/$d"; done
}
