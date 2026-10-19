#!/usr/bin/env bash
#
# ready-deadline.test.sh — scripts/lib/ready-deadline.sh, the readiness budget
# of a dev or test arbiter start (runtime-instances.md §14.6, "Tests and the
# dev arbiter"). The numbers are the ones launcher/test/unit/arbiter-ready.test.ts
# pins for the TS copy of the rule:
#
#   - 30 s idle; stretched by the load per CPU over 1; the load-scaled part
#     capped at 120 s; doubled on CI (CI set, not false/0/no/empty);
#   - MANDU_SERVICE_READY_TIMEOUT_MS exactly (uncapped, not doubled); a
#     garbled one is ignored; nonsense host figures give the base;
#   - the host's load average and CPU count are read when not given;
#   - mdu_wait_sockets: 0 once every socket is bound, 2 at once when the
#     started process is gone, 1 at the budget; MDU_WAITED_S either way;
#   - mdu_ready_why says which ended it; mdu_log_tail puts the log's last
#     lines (30, or N) on stderr, and says so when there is no log.
#
# That a live suite FAILS (never SKIPs) on a start that does not come up is
# launcher/test/arbiter-start-fail.test.sh.
#
# Run:  bash scripts/test/ready-deadline.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS=0 FAIL=0 FAILED=()
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); FAILED+=("$1"); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

T="$(mktemp -d /tmp/mdu-rd.XXXXXX)"
KIDS=()
trap '{ for k in "${KIDS[@]}"; do kill -9 "$k"; done; wait; } 2>/dev/null; rm -rf "$T"' EXIT
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO/scripts/lib/ready-deadline.sh"

# dl ENV... -- LOAD100 NCPU: the budget under exactly these variables.
dl() {
  local -a envs=()
  while [ "$1" != -- ]; do envs+=("$1"); shift; done
  shift
  env -u CI -u MANDU_SERVICE_READY_TIMEOUT_MS "${envs[@]}" bash -c '. "$1"; shift; mdu_ready_deadline_ms "$@"' _ "$REPO/scripts/lib/ready-deadline.sh" "$@"
}

# ── the budget ────────────────────────────────────────────────────────────────
check "idle, not CI: the 30 s base" "[ \"\$(dl -- 50 4)\" = 30000 ]"
check "idle CI runner: doubled" "[ \"\$(dl CI=true -- 50 4)\" = 60000 ]"
check "twice the CPU count in load: twice the time" "[ \"\$(dl -- 800 4)\" = 60000 ]"
check "load scaling and CI compose" "[ \"\$(dl CI=true -- 800 4)\" = 120000 ]"
check "the load-scaled part is capped at 120 s" "[ \"\$(dl -- 40000 2)\" = 120000 ]"
check "so a CI wait is at most 240 s" "[ \"\$(dl CI=true -- 40000 2)\" = 240000 ]"
check "nonsense host figures: the base" "[ \"\$(dl -- x 0)\" = 30000 ] && [ \"\$(dl -- '' 4)\" = 30000 ]"
for v in false FALSE 0 no ''; do
  check "CI=$v is not CI" "[ \"\$(dl CI=$v -- 50 4)\" = 30000 ]"
done
check "the override is taken exactly" "[ \"\$(dl MANDU_SERVICE_READY_TIMEOUT_MS=5000 -- 50 4)\" = 5000 ]"
check "... on CI too (not doubled)" "[ \"\$(dl MANDU_SERVICE_READY_TIMEOUT_MS=5000 CI=true -- 50 4)\" = 5000 ]"
check "... uncapped: the operator asked" "[ \"\$(dl MANDU_SERVICE_READY_TIMEOUT_MS=500000 -- 50 4)\" = 500000 ]"
check "... spaces around it are ignored" "[ \"\$(dl 'MANDU_SERVICE_READY_TIMEOUT_MS= 7000 ' -- 50 4)\" = 7000 ]"
for v in 0 -5 5s abc; do
  check "a garbled override ($v) is ignored" "[ \"\$(dl MANDU_SERVICE_READY_TIMEOUT_MS=$v CI=true -- 50 4)\" = 60000 ]"
done
host="$(dl --)"
check "the host's figures are read when not given ($host ms)" "[[ '$host' =~ ^[0-9]+$ ]] && [ '$host' -ge 30000 ] && [ '$host' -le 120000 ]"
check "the load average reads as hundredths ($(mdu_load100))" "[[ \"\$(mdu_load100)\" =~ ^[0-9]+$ ]]"
check "the CPU count reads ($(mdu_ncpu))" "[ \"\$(mdu_ncpu)\" -ge 1 ]"
check "the note names the override" "CI= mdu_ready_note 30000 | grep -q '^budget 30 s; MANDU_SERVICE_READY_TIMEOUT_MS'"
check "the note says when CI doubled it" "CI=true mdu_ready_note 60000 | grep -q '^budget 60 s, doubled on CI;'"

# ── the wait ──────────────────────────────────────────────────────────────────
# A stand-in daemon: binds its sockets after a delay each, then stays.
standin() { # DELAY_MS SOCK...
  node -e '
    const net = require("net");
    const [delay, ...socks] = process.argv.slice(1);
    setTimeout(() => { for (const s of socks) net.createServer().listen(s); }, Number(delay));
    setInterval(() => {}, 1e9);' "$@" &
  SP=$!
  KIDS+=("$SP")
}
standin 300 "$T/a.sock" "$T/b.sock"
mdu_wait_sockets "$SP" 20000 "$T/a.sock" "$T/b.sock"
rc=$?
check "0 once every socket is bound (waited ${MDU_WAITED_S:-?} s)" "[ $rc -eq 0 ] && [ -S '$T/a.sock' ] && [ -S '$T/b.sock' ]"

standin 60000 "$T/c.sock"
kill -9 "$SP"
wait "$SP" 2>/dev/null
s0=$SECONDS
mdu_wait_sockets "$SP" 60000 "$T/c.sock"
rc=$?
check "2 at once when the started process is gone ($((SECONDS - s0)) s)" "[ $rc -eq 2 ] && [ $((SECONDS - s0)) -lt 10 ]"

mdu_wait_sockets "" 300 "$T/never.sock"
rc=$?
check "1 at the budget, with the time spent (${MDU_WAITED_S:-unset} s)" "[ $rc -eq 1 ] && [[ '${MDU_WAITED_S:-}' =~ ^[0-9]+$ ]]"

# ── the failure line and the log's tail ──────────────────────────────────────
MDU_WAITED_S=3
check "why, budget: the time waited and the budget" "CI= mdu_ready_why 1 30000 | grep -q '^its sockets never appeared (waited 3 s; budget 30 s; MANDU_SERVICE_READY_TIMEOUT_MS'"
check "why, exit: the process exited first" "mdu_ready_why 2 30000 | grep -q '^it exited before its sockets appeared (after 3 s)'"
seq 1 50 | sed 's/^/arbiter line /' >"$T/arbiter.log"
tail_out="$(mdu_log_tail "$T/arbiter.log" 2>&1 >/dev/null)"
check "the tail goes to stderr, nothing to stdout" "[ -z \"\$(mdu_log_tail '$T/arbiter.log' 2>/dev/null)\" ]"
check "the tail is the last 30 lines, framed" "printf '%s\n' \"\$tail_out\" | grep -qx 'arbiter line 50' && printf '%s\n' \"\$tail_out\" | grep -qx 'arbiter line 21' && ! printf '%s\n' \"\$tail_out\" | grep -qx 'arbiter line 20' && printf '%s\n' \"\$tail_out\" | head -1 | grep -q 'last 30 lines'"
check "N lines when asked" "[ \"\$(mdu_log_tail '$T/arbiter.log' 5 2>&1 | grep -c '^arbiter line')\" = 5 ]"
check "an empty or missing log says so" "mdu_log_tail '$T/none.log' 2>&1 | grep -q 'empty or missing' && : >'$T/empty.log' && mdu_log_tail '$T/empty.log' 2>&1 | grep -q 'empty or missing'"

echo
for f in "${FAILED[@]}"; do echo "FAILED: $f"; done
echo "ready-deadline: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
