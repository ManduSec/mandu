#!/usr/bin/env bash
#
# arbiter-start-fail.test.sh — the live shell suites FAIL, never SKIP, when the
# arbiter they start does not come up (test-organization.md §8.11).
#
# Before, every live suite turned an arbiter that never came up into
# `SKIP: arbiter sockets never appeared` and exit 0: a hung or broken start
# showed green. Now a suite SKIPs only on a prerequisite it checks before the
# start (a tool, a kernel feature, a package install, the 127.0.0.2 alias),
# and a start that does not come up is a FAILURE that carries the arbiter's
# log's last lines.
#
# This runs each live suite that starts an arbiter with a readiness budget of
# 1 ms (MANDU_SERVICE_READY_TIMEOUT_MS=1: the wait ends at its first probe,
# long before a real start binds its sockets) and requires, per suite:
#   - exit 1, a FAIL line saying the arbiter did not come up, and the log's
#     tail (the suites' `--- <log> (last N lines)` frame, or dev-arbiter.sh's
#     `the last lines of`);
#   - or, where this host lacks one of the suite's prerequisites, a SKIP that
#     came BEFORE the start (the suite never got to booting an arbiter). That
#     is not counted: the suite was not reached. A SKIP after the start, or a
#     pass, fails this test.
# The own-spawn suites (net-proxy-live, net-proxy-mitm-live, exec-wrap-live,
# reply-filter-live) need only node, curl, openssl and the loopback alias,
# which the component lane has; the sandbox suites are reached where their
# kernel prerequisites hold.
#
# Offline and unprivileged; each suite's own temp dir and lifeline reap what
# it started. Run:  bash launcher/test/arbiter-start-fail.test.sh
set -uo pipefail
# This suite STATES its axes (protection-modes.md §4); every suite it runs
# pins its own (`secrets`) as well.
export MANDU_AXES_STRICT=1 MANDU_INTEGRITY=0 MANDU_CONFIDENTIALITY=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0 FAIL=0 UNREACHED=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

command -v node >/dev/null 2>&1 || { echo "SKIP: node not on PATH"; echo "arbiter-start-fail.test.sh: 0 passed, 0 failed (skipped)"; exit 0; }

OUT="$(mktemp -d "${TMPDIR:-/tmp}/mandu-startfail.XXXXXX")" || exit 1
trap 'rm -rf "$OUT"' EXIT

# Each suite, and whether it must be reached here: the own-spawn suites run
# in the component lane on every host that runs this file; the sandbox ones
# only where their prerequisites hold.
SUITES=(
  "net-proxy-live:must" "net-proxy-mitm-live:must" "exec-wrap-live:must" "reply-filter-live:must"
  "exec-box-live:may" "pipe-taint-live:may" "derived-label-live:may" "secret-readers-live:may"
)
for entry in "${SUITES[@]}"; do
  name="${entry%%:*}" need="${entry#*:}"
  log="$OUT/$name.log"
  s0=$SECONDS
  MANDU_SERVICE_READY_TIMEOUT_MS=1 timeout 300 bash "$HERE/$name.test.sh" >"$log" 2>&1
  rc=$?
  took=$((SECONDS - s0))
  started=""
  grep -qE 'booting the arbiter|^dev-arbiter: ' "$log" && started=1
  if [[ -z "$started" ]] && grep -q 'SKIP' "$log"; then
    if [[ "$need" == must ]]; then
      echo "--- $name (last lines) ---"; tail -n 15 "$log"
      fail "$name skipped before its start, but this lane has its prerequisites: $(grep -m1 'SKIP' "$log")"
    else
      echo "NOTE: $name not reached here (a prerequisite before its start): $(grep -m1 'SKIP' "$log")"
      UNREACHED=$((UNREACHED + 1))
    fi
    continue
  fi
  why=""
  [[ "$rc" -eq 1 ]] || why+=" exit $rc, not 1;"
  grep -q 'SKIP' "$log" && why+=" a SKIP after the start;"
  grep -qE '^FAIL: |^  NOT OK — ' "$log" || why+=" no FAIL line;"
  grep -q 'did not come up' "$log" || why+=" no 'did not come up';"
  grep -qE '\(last [0-9]+ lines\) ---|^dev-arbiter: the last lines of |is empty or missing|^dev-arbiter: .* is empty' "$log" || why+=" no log tail;"
  if [[ -z "$why" ]]; then
    pass "$name FAILS (exit 1, with the log's tail) when its arbiter does not come up (${took} s)"
  else
    echo "--- $name (last lines) ---"; tail -n 25 "$log"
    fail "$name on a start that did not come up:$why"
  fi
done

echo "─────────────────────────────────────────"
echo "arbiter-start-fail.test.sh: $PASS passed, $FAIL failed ($UNREACHED not reached here)"
[[ "$FAIL" -eq 0 ]]
