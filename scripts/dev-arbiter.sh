#!/usr/bin/env bash
# dev-arbiter.sh — the BLESSED ad-hoc arbiter spawn for dev/test sessions
# (runtime-instances.md §10).
#
# Why this exists: hand-rolled `setsid npx tsx ipc/server-main.ts <sock> &`
# spawns produced 17h-orphan arbiters that nothing could enumerate or safely
# kill (the whole setsid'd chain stays alive together, so even parent-pid
# heuristics never fire). This script spawns the SAME pinned-socket arbiter but
#   - gives it a throwaway Mandu home in the work dir (MANDU_HOME=$WORK/home),
#     so nothing reaches the real home (the arbiter would refuse the shared
#     DB anyway: symbol-DB single-writer). Its symbol DB and events are placed
#     with the arbiter's flags at $WORK/mandu.db and $WORK/events, where the
#     callers look (the live shell tests, the SIEM scenarios). Want a policy?
#     Export MANDU_POLICY_FILE first;
#   - is the TEST tenant, unless MANDU_DEV_ARBITER_TENANT=live says otherwise
#     (a filmed demo: its own arbiter, but its sessions must read as Live on
#     the product page, which lists no test session; any other value refused);
#   - keeps the real runtime dir (MANDU_RUNTIME_DIR, if you set one), so the
#     instance registry sees it;
#   - declares MANDU_OWNER_PID=<your shell> so the registry knows whose
#     death makes it garbage — `mandu reap` then collects it;
#   - registers in the instance registry like every arbiter (visible in
#     `mandu status`);
#   - with MANDU_LIFELINE_FIFO set (a FIFO whose only write end the caller
#     holds on fd 9, as launcher/test/lib/lifeline.sh opens it), reads that
#     FIFO as its stdin with MANDU_LIFELINE=stdin, so it exits when the caller
#     dies however it dies (runtime-instances.md §8). A test that scopes the
#     registry to its own work dir (MANDU_RUNTIME_DIR) passes it, since
#     `mandu reap` cannot find an arbiter registered there.
#
# Usage:
#   scripts/dev-arbiter.sh [workdir]     # prints WORK/SOCK env lines
#   eval "$(scripts/dev-arbiter.sh)"     # exports MANDU_ARBITER_SOCK for you
#   scripts/dev-arbiter.sh stop [workdir]  # done early? stop it yourself
#                                        #   (workdir default: $MANDU_DEV_ARBITER_WORK;
#                                        #   a work dir literally named `stop`: ./stop)
#
# The arbiter runs as ONE node process (packaging.md §5.1): the checkout's
# fresh bundle (launcher/dist), else the source through arbiter's own tsx
# (`node --import <tsx> ipc/server-main.ts`); `$WORK/form` says which.
#
# Stopping (runtime-instances.md §10.2): `$WORK/pid` is the setsid'd daemon
# itself, the leader of its own process group (it was `npm run serve`, npm →
# sh → tsx → mandu-arbiter, where `kill <that pid>` left the daemon serving,
# reparented to init: the orphan this script exists to prevent). `stop` still
# collects the whole group, whatever it holds: it SIGTERMs the daemon first
# (its graceful shutdown closes the sockets and tidies its instance dir), then
# the rest of the group, waits for the whole group to exit (SIGKILL after
# MANDU_DEV_ARBITER_STOP_GRACE seconds, default 10) and removes the pid file.
# It refuses a group that is not this work dir's arbiter (a stale pid file
# whose number was reused). `kill -- -"$(cat "$WORK/pid")"` is the bare
# equivalent, without the wait.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# group_members PGID — the pids in process group PGID, one per line (none: gone).
group_members() {
  local p g
  ps -eo pid=,pgid= | while read -r p g; do if [ "$g" = "$1" ]; then echo "$p"; fi; done
}

# start_gone PGID — the start recorded as PGID has exited: its group is empty
# AND the recorded pid is gone (or a zombie no one has reaped yet). The group
# alone does not say it: until setsid(1) has run in the forked child, the group
# is empty though the start is alive (the 2026-10-04 GitLab flake: "it exited
# before its socket appeared" from a start that was still on its way).
start_gone() {
  [ -z "$(group_members "$1")" ] || return 1
  local st
  st="$(ps -o stat= -p "$1" 2>/dev/null || true)"
  [ -z "$st" ] || [[ "$st" == *Z* ]]
}

# log_tail FILE — the last lines of the arbiter's log, on stderr: the caller's
# own log then keeps why a start failed even when the work dir is a temp dir
# that goes with its run (a CI guest's /tmp).
log_tail() {
  if [ -s "$1" ]; then
    echo "dev-arbiter: the last lines of $1:" >&2
    { tail -n 30 "$1" 2>/dev/null || true; } | sed 's/^/dev-arbiter: | /' >&2
  else
    echo "dev-arbiter: $1 is empty (the server wrote nothing)" >&2
  fi
}

# is_arbiter_of PID SOCK — PID was started for the arbiter on SOCK (its
# environment names that socket). Without /proc (not Linux) nothing can be
# checked, and the pid file is trusted. grep reads to the end (no -q): under
# pipefail a grep -q that exits at its match leaves tr's next write of a large
# environment to die of SIGPIPE, and the pipeline then fails although it
# matched (a live arbiter refused as "not the arbiter").
is_arbiter_of() {
  [ -d /proc/self ] || return 0
  tr '\0' '\n' <"/proc/$1/environ" 2>/dev/null | grep -xF "MANDU_ARBITER_SOCK=$2" >/dev/null
}

# wait_group PGID SECONDS — 0 once the group is gone, 1 if it outlives SECONDS.
wait_group() {
  local i
  for ((i = 0; i < $2 * 10; i++)); do
    [ -z "$(group_members "$1")" ] && return 0
    sleep 0.1
  done
  [ -z "$(group_members "$1")" ]
}

stop_arbiter() {
  local work="${1:-${MANDU_DEV_ARBITER_WORK:-}}"
  if [ -z "$work" ]; then
    echo "dev-arbiter: stop needs the work dir (an argument, or MANDU_DEV_ARBITER_WORK)" >&2
    return 2
  fi
  local pidf="$work/pid" sock="$work/arbiter.sock" grace="${MANDU_DEV_ARBITER_STOP_GRACE:-10}"
  if [ ! -f "$pidf" ]; then
    echo "dev-arbiter: no $pidf, nothing to stop" >&2
    return 0
  fi
  local pgid
  pgid="$(cat "$pidf")"
  if ! [[ "$pgid" =~ ^[0-9]+$ ]] || [ "$pgid" -le 1 ]; then
    echo "dev-arbiter: $pidf holds no pid ('$pgid')" >&2
    return 1
  fi
  local members ours="" daemons="" p
  members="$(group_members "$pgid")"
  if [ -z "$members" ]; then
    echo "dev-arbiter: process group $pgid is already gone" >&2
    rm -f "$pidf"
    return 0
  fi
  for p in $members; do
    is_arbiter_of "$p" "$sock" || continue
    ours=1
    if [ "$(cat "/proc/$p/comm" 2>/dev/null)" = mandu-arbiter ]; then daemons="$daemons $p"; fi
  done
  if [ -z "$ours" ]; then
    echo "dev-arbiter: process group $pgid is not the arbiter of $work (stale pid file?); not signalling it" >&2
    return 1
  fi
  # The daemon first: its own graceful shutdown, not the tsx shim's relay.
  local how=TERM i
  if [ -n "$daemons" ]; then
    # shellcheck disable=SC2086
    kill -TERM $daemons 2>/dev/null || true
    for ((i = 0; i < grace * 10; i++)); do
      # shellcheck disable=SC2086
      kill -0 $daemons 2>/dev/null || break
      sleep 0.1
    done
  fi
  kill -TERM -- "-$pgid" 2>/dev/null || true
  if ! wait_group "$pgid" "$grace"; then
    how=KILL
    kill -KILL -- "-$pgid" 2>/dev/null || true
    if ! wait_group "$pgid" 5; then
      echo "dev-arbiter: process group $pgid survived SIGKILL" >&2
      return 1
    fi
  fi
  # A graceful shutdown removed the sockets; a SIGKILLed daemon leaves them.
  local s
  for s in "$sock" "$work/admin.sock"; do if [ -S "$s" ]; then rm -f "$s"; fi; done
  rm -f "$pidf"
  echo "dev-arbiter: stopped process group $pgid (SIG$how)" >&2
}

if [ "${1:-}" = stop ]; then
  shift
  stop_arbiter "$@"
  exit
fi

TENANT="${MANDU_DEV_ARBITER_TENANT:-test}"
case "$TENANT" in
  test|live) ;;
  *) echo "dev-arbiter: MANDU_DEV_ARBITER_TENANT must be test or live, not '$TENANT'" >&2; exit 2 ;;
esac

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/mandu-dev.XXXXXX")}"
mkdir -p "$WORK/home"
SOCK="$WORK/arbiter.sock"

# The lifeline (see the header): stdin is the caller's FIFO, else /dev/null
# (what a background job's stdin is anyway).
LIFELINE_IN=/dev/null LIFELINE_MODE=""
if [ -n "${MANDU_LIFELINE_FIFO:-}" ]; then
  if [ ! -p "$MANDU_LIFELINE_FIFO" ]; then
    echo "dev-arbiter: MANDU_LIFELINE_FIFO=$MANDU_LIFELINE_FIFO is not a FIFO" >&2
    exit 2
  fi
  LIFELINE_IN="$MANDU_LIFELINE_FIFO" LIFELINE_MODE=stdin
fi

# The start form (packaging.md §5.1, the rule launcher/mandu-run.sh applies):
# the checkout's prebuilt bundle (launcher/dist) while its build record says
# it matches the source, else the source through the arbiter package's own
# tsx. Either way ONE node process, never `npm run serve` (npm, sh and the tsx
# binary re-spawning node: three more processes and about two seconds). A
# stale bundle never runs, and none is built here. MANDU_FROM_SOURCE=1 forces
# the source; MANDU_DEV_ARBITER_DIST names another build (a test's private one).
DIST="${MANDU_DEV_ARBITER_DIST:-$REPO_DIR/launcher/dist}"
FORM="" WHY=""
case "${MANDU_FROM_SOURCE:-}" in
  1 | true | TRUE | True | yes | on) WHY="MANDU_FROM_SOURCE is set" ;;
  *)
    if WHY="$(node "$REPO_DIR/launcher/scripts/bundle-stamp.mjs" --why --root="$REPO_DIR" "$DIST" 2>&1)"; then FORM=bundle; fi
    ;;
esac
if [ "$FORM" = bundle ]; then
  START=(node --no-warnings=ExperimentalWarning "$DIST/arbiter.mjs")
  START_CWD="$REPO_DIR/launcher"
  echo "# dev arbiter: from the checkout's bundle ($DIST)" >&2
else
  FORM=source
  # An absolute path is an ESM specifier node resolves as a file.
  START=(node --import "$REPO_DIR/arbiter/node_modules/tsx/dist/esm/index.mjs" "$REPO_DIR/arbiter/ipc/server-main.ts")
  START_CWD="$REPO_DIR/arbiter"
  echo "# dev arbiter: from source (${WHY:-no build record})" >&2
fi
echo "$FORM" >"$WORK/form"

(
  cd "$START_CWD"
  # OWNER: the shell that invoked this script (its death → reapable).
  # 9>&-: the caller's lifeline write end never reaches the arbiter.
  MANDU_OWNER_PID="${MANDU_OWNER_PID:-$PPID}" \
  MANDU_ARBITER_SOCK="$SOCK" \
  MANDU_HOME="$WORK/home" \
  MANDU_ADMIN_SOCK="$WORK/admin.sock" \
  MANDU_TENANT="$TENANT" \
  MANDU_LIFELINE="$LIFELINE_MODE" \
  setsid "${START[@]}" --symbol-db "$WORK/mandu.db" --event-dir "$WORK/events" <"$LIFELINE_IN" 9>&- >"$WORK/arbiter.log" 2>&1 &
  # A background child of a non-interactive shell is not a group leader, so
  # setsid(1) does not fork: $! is the new session's and group's leader.
  echo $! >"$WORK/pid"
)

# The readiness deadline (runtime-instances.md §14.6, scripts/lib/
# ready-deadline.sh): the launcher's load-aware deadline (30 s idle, stretched
# by load per CPU, capped at 120 s), doubled on a CI runner, or
# MANDU_SERVICE_READY_TIMEOUT_MS (a positive integer, ms) exactly. A fixed
# 10 s missed a cold start on a fresh CI runner (the first tsx start there).
# A group that exits ends the wait at once: a longer deadline never makes a
# broken start slower to report.
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO_DIR/scripts/lib/ready-deadline.sh"
READY_MS="$(mdu_ready_deadline_ms)"
ADMIN="$WORK/admin.sock"
PGID="$(cat "$WORK/pid")"
# Ready is BOTH sockets: the eval'd output below names the admin socket too,
# and the daemon binds it a moment after the data socket (server.ts listen():
# the human plane, the data socket, then the admin channel), so a caller told
# "up" on the data socket alone could find no admin socket yet.
# $PGID leads its own group only once setsid(1) has run in it: until then the
# group is empty though the start is alive. The exit check asks start_gone
# (the recorded pid too), never the group alone: a group-only check read that
# window as an exit (2026-10-04, GitLab pipelines 8805, 8811, 8834).
s0=$SECONDS
why="not ready within $(((READY_MS + 999) / 1000)) s$(if ! mdu_ready_overridden && mdu_on_ci; then echo ", doubled on CI"; fi); MANDU_SERVICE_READY_TIMEOUT_MS (milliseconds) sets a longer deadline"
for ((i = 0; i < (READY_MS + 199) / 200; i++)); do
  [ -S "$SOCK" ] && [ -S "$ADMIN" ] && break
  if start_gone "$PGID"; then why="it exited before its socket appeared"; break; fi
  sleep 0.2
done
if [ ! -S "$SOCK" ] || [ ! -S "$ADMIN" ]; then
  missing=""
  [ -S "$SOCK" ] || missing="$SOCK"
  [ -S "$ADMIN" ] || missing="${missing:+$missing and }$ADMIN"
  echo "dev-arbiter: did not come up ($why; waited $((SECONDS - s0)) s, $missing missing) — see $WORK/arbiter.log" >&2
  log_tail "$WORK/arbiter.log"
  # The stop finds the start by its group: wait (10 s bound) for setsid(1) to
  # have run, or for the start to exit, or the stop finds the group "already
  # gone" and leaves a slow start to come up and serve. `|| true`: once the
  # start has exited ps fails, and under `set -e -o pipefail` the assignment
  # would end this script before the stop.
  for ((i = 0; i < 200; i++)); do
    g="$(ps -o pgid= -p "$PGID" 2>/dev/null | tr -d ' ' || true)"
    if [ -z "$g" ] || [ "$g" = "$PGID" ]; then break; fi
    sleep 0.05
  done
  # A slow start may still be on its way: stop the group, never leave it serving.
  stop_arbiter "$WORK" || true
  exit 1
fi

# eval-able output (comments go to stderr).
echo "# dev arbiter up — log: $WORK/arbiter.log; stop: $REPO_DIR/scripts/dev-arbiter.sh stop $WORK; or later: mandu reap" >&2
echo "export MANDU_ARBITER_SOCK=\"$SOCK\""
# DEV-ONLY admin channel (policy-surface.md §2.6): human-decision ops
# (approvals, labels, posture, deleteSession) are refused on the data socket;
# a dev rig reaches them on this PATH. A path is reachable by every same-uid
# process, so never run an agent against a dev arbiter and call it protected.
echo "export MANDU_ADMIN_SOCK=\"$WORK/admin.sock\""
# A dev arbiter is the TEST tenant (policy-surface.md §2.7): sessions
# launched against it are stamped test and never mix with live runs. A filmed
# demo asks for live (MANDU_DEV_ARBITER_TENANT): still its own home, DB and
# events, so nothing reaches the person's live store.
echo "export MANDU_TENANT=$TENANT"
echo "export MANDU_DEV_ARBITER_WORK=\"$WORK\""
