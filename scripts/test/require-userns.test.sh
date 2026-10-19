#!/usr/bin/env bash
#
# require-userns.test.sh — unit tests for scripts/require-userns.sh, the CI HARD
# GATE that turns "unprivileged userns unavailable" from a silent SKIP (which would
# make the every-push `test` job a false green) into a job FAILURE.
#
# The script's userns probe is injectable via $MANDU_USERNS_PROBE (a command
# string) so these tests force the available / unavailable paths deterministically,
# without toggling real kernel state. The default (no override) probe is also
# exercised on this host as a smoke check.
#
# Run:  bash scripts/test/require-userns.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../require-userns.sh"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# run <probe-override> -> sets RC + captures OUT/ERR
run() {
  local probe="$1"
  OUT="$(MANDU_USERNS_PROBE="$probe" bash "$SCRIPT" 2>/tmp/require-userns-err.$$)"
  RC=$?
  ERR="$(cat /tmp/require-userns-err.$$ 2>/dev/null)"
  rm -f /tmp/require-userns-err.$$
}

# 1. probe reports AVAILABLE  → exit 0
run 'true'
[[ $RC -eq 0 ]] && pass "available probe exits 0" || fail "available probe exits 0 (got rc=$RC)"

# 2. probe reports UNAVAILABLE → non-zero exit (hard fail)
run 'false'
[[ $RC -ne 0 ]] && pass "unavailable probe exits non-zero" || fail "unavailable probe exits non-zero (got rc=$RC)"

# 3. the failure message is actionable (names userns, on stderr)
run 'false'
if grep -qiE 'userns|user namespace' <<<"$ERR" && grep -qiE 'unavailable|skip|refus' <<<"$ERR"; then
  pass "unavailable path prints an actionable stderr message"
else
  fail "unavailable path prints an actionable stderr message (err=$ERR)"
fi

# 4. default probe (no override) must agree with a real unshare on this host.
#    Skip-as-pass only if unshare(1) is missing; otherwise the script's verdict
#    must match the real probe so CI can trust it.
if command -v unshare >/dev/null 2>&1; then
  if unshare --user --map-root-user --mount --net --pid --fork -- bash -c '[[ "$(id -u)" == 0 ]]' >/dev/null 2>&1; then
    real_ok=0   # userns available
  else
    real_ok=1
  fi
  OUT="$(bash "$SCRIPT" >/dev/null 2>&1)"; RC=$?
  if [[ $real_ok -eq 0 && $RC -eq 0 ]] || [[ $real_ok -ne 0 && $RC -ne 0 ]]; then
    pass "default probe matches a real unshare verdict (real_ok=$real_ok rc=$RC)"
  else
    fail "default probe matches a real unshare verdict (real_ok=$real_ok rc=$RC)"
  fi
else
  pass "default probe check skipped — unshare(1) not on PATH"
fi

echo
echo "require-userns.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
