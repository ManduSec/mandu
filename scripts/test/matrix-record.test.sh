#!/usr/bin/env bash
#
# matrix-record.test.sh — unit + end-to-end tests for the matrix RUN RECORD
# (scripts/matrix/lib/record.sh, os-test-matrix.md §9). run.sh deletes its
# $RUN_WORK on exit; before the record, a run's per-step results died with it
# (the 2026-09-25 26.04 live leg left only a 25-line tail). The record keeps
# them under the store the dashboard's 🖥 VM matrix tab reads.
#
# Part 1 drives record_finish on a fabricated qemu-shaped $RUN_WORK. Part 2 runs
# the real run.sh on the `host` target's cheap `smoke` suite. No VM, no network.
#
# Run:  bash scripts/test/matrix-record.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX="$HERE/../matrix"
PASS=0; FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
json_ok() { node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' "$1" 2>/dev/null; }
json_get() { node -e 'const m=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));console.log(String(m[process.argv[2]]))' "$1" "$2"; }

# fake_work <dir> : a qemu-shaped RUN_WORK after a run
fake_work() {
  mkdir -p "$1/out/test-all-logs" "$1/artifacts/ephemeral"
  printf 'guest line 1\nPASS the thing\n' > "$1/out/suite.log"
  printf 'PASS step=1 installed\nFAIL step=L no read\n' > "$1/out/steps.log"
  printf 'fail: 1 check(s)\n' > "$1/out/RESULT"
  printf 'arbiter output\n' > "$1/out/test-all-logs/arbiter npm.log"
  printf 'abc1234' > "$1/artifacts/COMMIT"
  printf '{"accessToken":"SECRET-TOKEN"}' > "$1/artifacts/ephemeral/.credentials.json"
  printf '\033[31mboot\033[0m\nkernel panic? no\n' > "$1/serial.log"
}

# record <rc> <store> <runwork> [env...] : run record_begin/record_finish in a subshell.
# <store> is <home>/runs/matrix, the table's `matrix-results` under MANDU_HOME=<home>.
record() {
  local rc="$1" store="$2" rw="$3"; shift 3
  ( source "$MATRIX/lib/common.sh"; source "$MATRIX/lib/record.sh"
    export MANDU_HOME="${store%/runs/matrix}" "$@"
    RUN_WORK="$rw" TARGET_NAME=ubuntu-2604 SUITE_NAME=fresh-install EXECUTOR=qemu
    LABELS='os=linux "quoted" back\slash' REPO_ROOT="$HERE/../.."
    record_begin; record_finish "$rc" ) >/dev/null 2>&1
}

# ── 1. a FAILED qemu run: every result file lands, secrets do not ─────────────
rw="$WORK/rw1"; fake_work "$rw"; store="$WORK/home1/runs/matrix"
record 1 "$store" "$rw"
run="$(ls "$store" | head -1)"; d="$store/$run"
check "run id is <UTC stamp>-<target>-<suite>" '[[ "$run" =~ ^[0-9]{8}-[0-9]{6}-ubuntu-2604-fresh-install$ ]]'
check "meta.json is valid JSON (labels with quotes + backslash escaped)" 'json_ok "$d/meta.json"'
check "status=fail for rc=1" '[[ "$(json_get "$d/meta.json" status)" == fail ]]'
check "reason carries the guest RESULT" '[[ "$(json_get "$d/meta.json" reason)" == "fail: 1 check(s)" ]]'
check "commit is the one host prep packed (artifacts/COMMIT)" '[[ "$(json_get "$d/meta.json" commit)" == abc1234 ]]'
check "labels round-trip" "[[ \"\$(json_get \"\$d/meta.json\" labels)\" == 'os=linux \"quoted\" back\\slash' ]]"
check "suite.log copied" 'grep -q "PASS the thing" "$d/suite.log"'
check "steps.log copied" 'grep -q "FAIL step=L" "$d/steps.log"'
check "test-all logs flattened to logs-<safe name>.log" '[[ -f "$d/logs-arbiter_npm.log" ]]'
check "serial.log kept on FAIL, ANSI stripped" 'grep -q "^boot$" "$d/serial.log"'
check "NOTHING from the artifacts share (the reduced credential) is recorded" '! grep -rq "SECRET-TOKEN" "$store"'
check "store dir is private (0700)" '[[ "$(stat -c %a "$store")" == 700 ]]'

# ── 2. a PASSING run keeps no serial log; skip maps to status=skip ────────────
rw="$WORK/rw2"; fake_work "$rw"; store="$WORK/home2/runs/matrix"
record 0 "$store" "$rw"; d="$store/$(ls "$store" | head -1)"
check "status=pass for rc=0" '[[ "$(json_get "$d/meta.json" status)" == pass ]]'
check "no serial.log on PASS" '[[ ! -e "$d/serial.log" ]]'
rw="$WORK/rw3"; mkdir -p "$rw"; store="$WORK/home3/runs/matrix"
record 3 "$store" "$rw"; d="$store/$(ls "$store" | head -1)"
check "status=skip for rc=3, with no out/ at all" '[[ "$(json_get "$d/meta.json" status)" == skip ]]'
check "commit falls back to the checkout HEAD without artifacts/COMMIT" '[[ "$(json_get "$d/meta.json" commit)" =~ ^[0-9a-f]{7,} ]]'

# ── 3. MANDU_MATRIX_RECORD=0 records nothing ────────────────────────────────
rw="$WORK/rw4"; fake_work "$rw"; store="$WORK/home4/runs/matrix"
record 0 "$store" "$rw" MANDU_MATRIX_RECORD=0
check "MANDU_MATRIX_RECORD=0 writes nothing" '[[ ! -d "$store" ]] || [[ -z "$(ls -A "$store")" ]]'

# ── 4. prune keeps the newest MANDU_MATRIX_KEEP ─────────────────────────────
store="$WORK/home5/runs/matrix"; mkdir -p "$store/20260101-000000-a-b" "$store/20260102-000000-a-b" "$store/20260103-000000-a-b" "$store/unrelated"
rw="$WORK/rw5"; fake_work "$rw"
record 0 "$store" "$rw" MANDU_MATRIX_KEEP=2
check "prune keeps the 2 newest runs" '[[ "$(ls "$store" | grep -c "^[0-9]")" == 2 && ! -e "$store/20260102-000000-a-b" ]]'
check "prune leaves non-run entries alone" '[[ -d "$store/unrelated" ]]'

# ── 5. e2e: the real run.sh records a host/smoke run, and --check does not ───
store="$WORK/home6/runs/matrix"
MANDU_HOME="${store%/runs/matrix}" bash "$MATRIX/run.sh" host smoke >/dev/null 2>&1; rc=$?
d="$store/$(ls "$store" 2>/dev/null | head -1)"
check "run.sh host smoke exits 0" '[[ $rc -eq 0 ]]'
check "run.sh wrote meta.json with status=pass" 'json_ok "$d/meta.json" && [[ "$(json_get "$d/meta.json" status)" == pass ]]'
check "run.log holds the whole console, header first" '[[ "$(head -1 "$d/run.log")" == "matrix: target=host suite=smoke executor=host" ]] && grep -q "PASS  host/smoke" "$d/run.log"'
check "run.log is ANSI-free" '! grep -q $'"'"'\033'"'"' "$d/run.log"'
check "suite.log holds the suite output" 'grep -q "smoke ok" "$d/suite.log"'
MANDU_HOME="${store%/runs/matrix}" bash "$MATRIX/run.sh" --check host smoke >/dev/null 2>&1
check "--check records nothing" '[[ "$(ls "$store" | wc -l)" == 1 ]]'

# ── 6. the store is the path table's `matrix-results` (on-disk-layout.md §5) ──
store_for() { ( source "$MATRIX/lib/common.sh"; source "$MATRIX/lib/record.sh"
  unset MANDU_HOME; export "$@"; matrix_store_dir ) 2>/dev/null; }
check "store: the retired MANDU_MATRIX_RESULTS_DIR moves nothing" '[[ "$(store_for MANDU_MATRIX_RESULTS_DIR=/srv/m MANDU_HOME=/m)" == /m/runs/matrix ]]'
check "store: \$MANDU_HOME/runs/matrix" '[[ "$(store_for MANDU_HOME=/var/mandu HOME=/h)" == /var/mandu/runs/matrix ]]'
check "store: ~/.mandu/runs/matrix by default (XDG_STATE_HOME does not move it)" '[[ "$(store_for XDG_STATE_HOME=/s HOME=/home/u)" == /home/u/.mandu/runs/matrix ]]'

echo
echo "matrix-record: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
