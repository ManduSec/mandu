# shellcheck shell=bash
# ready-deadline.sh — how long a dev or test arbiter start may take before its
# caller gives up (runtime-instances.md §14.6, "Tests and the dev arbiter").
# Sourced, not run; bash 3.2 and up (a macOS run of the suites sources it).
#
#   mdu_ready_deadline_ms [LOAD100 NCPU]   prints the budget in milliseconds
#   mdu_wait_sockets PID MS SOCK...        waits until every SOCK is a socket
#   mdu_ready_why RC MS                    why that wait ended, for a FAIL line
#   mdu_log_tail FILE [N]                  the log's last lines, on stderr
#
# A start that does not come up is a FAILURE of the suite that asked for it,
# never a SKIP: a suite SKIPs only on a prerequisite it checked before the
# start (a missing tool, kernel feature or package install). A SKIP after a
# failed start would show a hung or broken arbiter as green
# (test-organization.md §8.6).
#
# The budget is the launcher's readiness deadline (launcher/src/services/
# primitives.ts serviceReadyDeadlineMs): MANDU_SERVICE_READY_TIMEOUT_MS when
# it holds a positive integer, taken exactly; else 30 s, stretched by the
# 1-minute load average per CPU when that exceeds 1, capped at 120 s. On a CI
# runner (CI set, not false/0/no) the computed budget doubles: the first start
# of a job runs with a cold tsx cache while the job's other suites compile on
# the same few vCPUs, and the load average lags behind that burst. The TS
# suites' copy of the rule is launcher/test/lib/arbiter-ready.ts; both are
# pinned to the same numbers (scripts/test/ready-deadline.test.sh,
# launcher/test/unit/arbiter-ready.test.ts). A long budget costs a passing run
# nothing (the wait ends when the socket appears) and a broken start nothing
# (it ends when the started process exits).
#
# PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.

MDU_READY_BASE_MS=30000
MDU_READY_MAX_MS=120000

# mdu_load100 — the 1-minute load average times 100, as an integer; nothing
# when it cannot be read.
mdu_load100() {
  local raw="" rest
  if [ -r /proc/loadavg ]; then
    read -r raw rest </proc/loadavg
  else
    raw="$(sysctl -n vm.loadavg 2>/dev/null || true)" # macOS: "{ 1.86 1.93 1.97 }"
    raw="${raw#\{ }"
    raw="${raw%% *}"
  fi
  [[ "$raw" =~ ^([0-9]+)(\.([0-9]*))?$ ]] || return 0
  local int="${BASH_REMATCH[1]}" frac="${BASH_REMATCH[3]}00"
  echo $((10#$int * 100 + 10#${frac:0:2}))
}

# mdu_ncpu — the CPUs this process may run on (nproc honours the affinity
# mask, as node's availableParallelism does).
mdu_ncpu() {
  nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1
}

# mdu_on_ci — 0 on a CI runner (CI set, and not false, 0, no or empty).
mdu_on_ci() {
  case "$(printf '%s' "${CI:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
    "" | 0 | false | no) return 1 ;;
  esac
  return 0
}

# mdu_ready_overridden — 0 when MANDU_SERVICE_READY_TIMEOUT_MS holds a usable
# override (a positive integer, at most 9 digits); a garbled value is ignored.
mdu_ready_overridden() {
  local raw="${MANDU_SERVICE_READY_TIMEOUT_MS:-}"
  raw="${raw//[[:space:]]/}"
  [[ "$raw" =~ ^[0-9]{1,9}$ ]] && [ "$((10#$raw))" -gt 0 ]
}

# mdu_ready_deadline_ms [LOAD100 NCPU] — the budget (the header's rule). The
# host figures are read unless given (the test gives them).
mdu_ready_deadline_ms() {
  if mdu_ready_overridden; then
    local raw="${MANDU_SERVICE_READY_TIMEOUT_MS//[[:space:]]/}"
    echo $((10#$raw))
    return 0
  fi
  local load ncpu ms=$MDU_READY_BASE_MS
  if [ $# -ge 2 ]; then load="$1" ncpu="$2"; else load="$(mdu_load100)" ncpu="$(mdu_ncpu)"; fi
  if [[ "$load" =~ ^[0-9]+$ && "$ncpu" =~ ^[0-9]+$ ]] && [ "$ncpu" -gt 0 ]; then
    ms=$((MDU_READY_BASE_MS * load / (ncpu * 100)))
    if [ "$ms" -lt "$MDU_READY_BASE_MS" ]; then ms=$MDU_READY_BASE_MS; fi
    if [ "$ms" -gt "$MDU_READY_MAX_MS" ]; then ms=$MDU_READY_MAX_MS; fi
  fi
  if mdu_on_ci; then ms=$((ms * 2)); fi
  echo "$ms"
}

# mdu_ready_note MS — the budget in words, for a failure line.
mdu_ready_note() {
  local s=$((($1 + 999) / 1000)) extra=""
  if ! mdu_ready_overridden && mdu_on_ci; then extra=", doubled on CI"; fi
  echo "budget ${s} s${extra}; MANDU_SERVICE_READY_TIMEOUT_MS (milliseconds) sets it"
}

# mdu_wait_sockets PID MS SOCK... — wait, probing every 100 ms, until every
# SOCK is a socket. Returns 0 then; 2 as soon as PID (the started process;
# empty: none to watch) is gone; 1 at the budget. Sets MDU_WAITED_S to the
# seconds spent either way.
mdu_wait_sockets() {
  local pid="$1" ms="$2" i n p all s0=$SECONDS
  shift 2
  n=$(((ms + 99) / 100))
  for ((i = 0; ; i++)); do
    all=1
    for p in "$@"; do if [ ! -S "$p" ]; then all=""; break; fi; done
    if [ -n "$all" ]; then MDU_WAITED_S=$((SECONDS - s0)); return 0; fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then MDU_WAITED_S=$((SECONDS - s0)); return 2; fi
    if [ "$i" -ge "$n" ]; then break; fi
    sleep 0.1
  done
  MDU_WAITED_S=$((SECONDS - s0))
  return 1
}

# mdu_ready_why RC MS — why a mdu_wait_sockets wait that returned RC (1 or 2)
# on a budget of MS ended, in words, with MDU_WAITED_S.
mdu_ready_why() {
  if [ "$1" = 2 ]; then
    echo "it exited before its sockets appeared (after ${MDU_WAITED_S:-?} s)"
  else
    echo "its sockets never appeared (waited ${MDU_WAITED_S:-?} s; $(mdu_ready_note "$2"))"
  fi
}

# mdu_log_tail FILE [N] — the last N (default 30) lines of a started
# process's log on stderr, so the suite's own output keeps why a start failed
# when its work dir is a temp dir that goes with the run.
mdu_log_tail() {
  local n="${2:-30}"
  if [ -s "$1" ]; then
    echo "--- $1 (last $n lines) ---" >&2
    tail -n "$n" "$1" >&2 2>/dev/null || true
    echo "--- end of $1 ---" >&2
  else
    echo "($1 is empty or missing: the process wrote nothing)" >&2
  fi
}
