# scripts/ci/nightly-stack.sh — the nightly stack, shared by the CI pipeline
# (scripts/ci/pipeline.sh --network) and a host lane run (scripts/test-all.sh
# --lane). Sourced, not run. docs/design/testing/continuous-integration.md §9.4.
#
#   nightly_stack_start <repo-root> <owner-pid>
#       Starts what the nightly suites need beside themselves and exports it:
#       a `secrets`-mode arbiter of the test tenant (scripts/dev-arbiter.sh,
#       the drill labels of drill-runner.md §2 as its policy) as
#       MANDU_ARBITER_SOCK / MANDU_ADMIN_SOCK / MANDU_TENANT=test, the
#       launcher as MANDU_BIN, and MANDU_TEST_DASHBOARD=1. Says what it did
#       on stdout (names and paths, never a credential). Returns 1 when the
#       arbiter did not come up (MANDU_BIN and MANDU_TEST_DASHBOARD are
#       exported anyway); the caller decides whether the run goes on.
#       <owner-pid> is the shell whose death makes the arbiter garbage
#       (dev-arbiter.sh's MANDU_OWNER_PID): `mandu reap` collects an arbiter
#       a killed run left behind.
#   nightly_stack_stop [<arbiter-log-copy>]
#       Stops the arbiter's whole process group (dev-arbiter.sh setsid's it):
#       `dev-arbiter.sh stop` first (the daemon's own graceful shutdown, then
#       the group; runtime-instances.md §10.2), then, whatever that did, the
#       group itself, TERM then, after 5 s, KILL; keeps the last 5 MiB of its
#       log at <arbiter-log-copy> when given; removes the stack's directory.
#       Idempotent: a trap may call it more than once.
#
# Its sockets live in a directory of their own, short enough for a Unix
# socket's 107-byte sun_path whatever TMPDIR is: $TMPDIR when that is short,
# else /tmp (a scratch TMPDIR once put them over the limit).
#
# State: NIGHTLY_STACK_WORK (the directory), NIGHTLY_STACK_PID (the arbiter's
# process group), NIGHTLY_STACK_ROOT (the repo whose dev-arbiter.sh started it).

NIGHTLY_STACK_WORK="" NIGHTLY_STACK_PID="" NIGHTLY_STACK_ROOT=""

# nightly_stack_tmpdir: a fresh directory whose sockets fit sun_path.
nightly_stack_tmpdir() {
  local base="${TMPDIR:-/tmp}" d
  # The longest socket, "<base>/mandu-stack.XXXXXX/arbiter/arbiter.sock",
  # is the base plus 40 bytes: a base of up to 60 leaves room under 107.
  [[ ${#base} -le 60 && -d "$base" && -w "$base" ]] || base=/tmp
  d="$(mktemp -d "$base/mandu-stack.XXXXXX")" || return 1
  # "/arbiter/arbiter.sock" is 21 bytes.
  if (( ${#d} + 21 > 107 )); then rm -rf "$d"; return 1; fi
  printf '%s\n' "$d"
}

nightly_stack_start() {
  local root="$1" owner="$2"
  NIGHTLY_STACK_ROOT="$root"
  NIGHTLY_STACK_WORK="$(nightly_stack_tmpdir)" || { echo "arbiter: no directory short enough for its sockets"; return 1; }
  # The claude-e2e cut needs a running arbiter of the test tenant in
  # `secrets` mode. The drill entries start their own (drill-run.ts
  # --own-arbiter, with the same labels); this one serves every other suite
  # and a drill run by hand. The pattern labels are drill-runner.md §2's, one
  # checked-in copy (a copy here: the arbiter may write its file), found
  # through the drill-tree resolver. The drills are not in the public tree:
  # there it finds none, and the arbiter runs with no policy file, as the
  # unit suites do.
  local policy=/dev/null/mandu-test-no-policy.yaml tree
  tree="$(node "$root/scripts/drill-tree.mjs" "$root" 2>/dev/null)" || tree=""
  if [[ -n "$tree" && -f "$tree/live/drill-policy.yaml" ]]; then
    policy="$NIGHTLY_STACK_WORK/drill-policy.yaml"
    cp "$tree/live/drill-policy.yaml" "$policy"
  fi
  local rc=0
  if MANDU_MODE=secrets MANDU_POLICY_FILE="$policy" MANDU_OWNER_PID="$owner" \
       bash "$root/scripts/dev-arbiter.sh" "$NIGHTLY_STACK_WORK/arbiter" > "$NIGHTLY_STACK_WORK/arbiter.env" 2>> "$NIGHTLY_STACK_WORK/arbiter.err"; then
    # shellcheck disable=SC1091
    . "$NIGHTLY_STACK_WORK/arbiter.env"
    NIGHTLY_STACK_PID="$(cat "$NIGHTLY_STACK_WORK/arbiter/pid" 2>/dev/null)"
    echo "arbiter: secrets, tenant test, socket $MANDU_ARBITER_SOCK (owner pid $owner; log $NIGHTLY_STACK_WORK/arbiter/arbiter.log)"
  else
    NIGHTLY_STACK_PID="$(cat "$NIGHTLY_STACK_WORK/arbiter/pid" 2>/dev/null)"
    echo "arbiter: did not start:"; cat "$NIGHTLY_STACK_WORK/arbiter.err" "$NIGHTLY_STACK_WORK/arbiter/arbiter.log" 2>/dev/null | tail -n 20
    rc=1
  fi
  export MANDU_BIN="$root/launcher/mandu-run.sh" MANDU_TEST_DASHBOARD=1
  echo "MANDU_BIN=$MANDU_BIN MANDU_TEST_DASHBOARD=1"
  return "$rc"
}

nightly_stack_stop() {
  local copy="${1:-}" p="$NIGHTLY_STACK_PID" i
  # Interrupted inside dev-arbiter.sh (its readiness wait for the sockets): the
  # arbiter may be up with only its pid file to say so.
  [[ -z "$p" && -n "$NIGHTLY_STACK_WORK" ]] && p="$(cat "$NIGHTLY_STACK_WORK/arbiter/pid" 2>/dev/null)"
  NIGHTLY_STACK_PID=""
  if [[ "$p" =~ ^[0-9]+$ && -n "$NIGHTLY_STACK_ROOT" && -n "$NIGHTLY_STACK_WORK" ]]; then
    # The script's own stop: the daemon first, so its graceful shutdown
    # tidies its sockets and instance dir, then the group, and it waits.
    MANDU_DEV_ARBITER_STOP_GRACE=5 bash "$NIGHTLY_STACK_ROOT/scripts/dev-arbiter.sh" stop "$NIGHTLY_STACK_WORK/arbiter" 2>/dev/null || true
  fi
  if [[ "$p" =~ ^[0-9]+$ ]]; then
    # And the group itself, whatever the stop did (a refusal, a stub):
    # dev-arbiter.sh setsid's the arbiter: its pid is its process group.
    kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null
    for i in $(seq 1 50); do
      kill -0 -- "-$p" 2>/dev/null || kill -0 "$p" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL -- "-$p" 2>/dev/null; kill -KILL "$p" 2>/dev/null
  fi
  if [[ -n "$NIGHTLY_STACK_WORK" ]]; then
    if [[ -n "$copy" && -f "$NIGHTLY_STACK_WORK/arbiter/arbiter.log" && -d "$(dirname "$copy")" ]]; then
      tail -c $((5 * 1024 * 1024)) "$NIGHTLY_STACK_WORK/arbiter/arbiter.log" > "$copy" 2>/dev/null
    fi
    rm -rf "$NIGHTLY_STACK_WORK"
    NIGHTLY_STACK_WORK=""
  fi
  return 0
}
