#!/usr/bin/env bash
#
# dev-arbiter.test.sh — scripts/dev-arbiter.sh's start form and documented
# stop (runtime-instances.md §10.2, packaging.md §5.1). A real dev arbiter
# (ONE node process leading its own setsid'd group) is started and stopped the
# way the script's hint says; nothing of it may survive.
#
#   - the start form: the checkout's bundle while its build record is fresh
#     (a private build, MANDU_DEV_ARBITER_DIST), the source through arbiter's
#     own tsx when that record is stale (an input changed since the build) or
#     MANDU_FROM_SOURCE=1; never `npm run serve`; the group is the daemon
#     alone;
#   - the start hint names `dev-arbiter.sh stop <work>`, not a bare kill;
#   - `stop <work>` ends every process of the group (the daemon included),
#     the daemon shut down gracefully (sockets and its registry instance dir
#     gone), the pid file removed; a second stop is a no-op;
#   - `kill <pid>` (the old hint, which once killed only npm and left the
#     daemon serving) now ends the daemon itself, gracefully, and `stop`
#     afterwards finds nothing left;
#   - `stop` with no argument reads MANDU_DEV_ARBITER_WORK (the eval'd export);
#   - a stale pid file naming a group that is not this arbiter is refused and
#     that group is left alone;
#   - a group that ignores SIGTERM is SIGKILLed after the grace;
#   - a start that misses its readiness deadline (MANDU_SERVICE_READY_TIMEOUT_MS)
#     is refused and its group stopped, also when setsid(1) runs late in it; a start whose arbiter exits (a policy
#     file that does not validate, or a server that exits at once) is refused
#     at once, not at the deadline, with its log's tail on stderr; a start
#     whose setsid(1) runs late is no exit, and comes up; a refusal says
#     the time spent and which socket was missing;
#   - ready is both sockets (a stand-in daemon): an admin socket bound late
#     is waited for, and a data socket without one is refused, not "up";
#   - with MANDU_LIFELINE_FIFO the arbiter arms its lifeline: SIGKILLing the
#     caller that holds the FIFO's write end ends the whole group (graceful,
#     instance dir tidied) with no stop; a path that is no FIFO is refused.
#
# The registry is scoped to a throwaway MANDU_RUNTIME_DIR, and the work dirs
# live under /tmp so the socket path fits sun_path (107 bytes).
#
# Run:  bash scripts/test/dev-arbiter.test.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DEV="$REPO/scripts/dev-arbiter.sh"
PASS=0 FAIL=0 FAILED=()
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); FAILED+=("$1"); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

for pkg in arbiter launcher; do
  if [ ! -d "$REPO/$pkg/node_modules" ]; then
    echo "FAIL: $pkg/node_modules is missing (cd $pkg && npm ci)"
    exit 1
  fi
done

# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO/scripts/lib/ready-deadline.sh"

T="$(mktemp -d /tmp/mdu-da.XXXXXX)"
GROUPS_STARTED=()
cleanup() {
  local g
  for g in "${GROUPS_STARTED[@]}"; do kill -KILL -- "-$g" 2>/dev/null; done
  rm -rf "$T"
}
trap cleanup EXIT
export MANDU_RUNTIME_DIR="$T/rt"
mkdir -p "$MANDU_RUNTIME_DIR"
# The suite runner's MANDU_HOME / MANDU_POLICY_FILE placeholders stay; the
# script gives the arbiter its own home. The mode states the axes.
export MANDU_MODE=secrets MANDU_OWNER_PID=$$
unset MANDU_DEV_ARBITER_WORK MANDU_ARBITER_SOCK MANDU_ADMIN_SOCK

# members PGID — the pids of process group PGID.
members() { ps -eo pid=,pgid= | while read -r p g; do if [ "$g" = "$1" ]; then echo "$p"; fi; done; }
# comms PGID — the command names of process group PGID, space-separated.
comms() { local p; for p in $(members "$1"); do cat "/proc/$p/comm" 2>/dev/null; done | tr '\n' ' '; }
instances() { find "$MANDU_RUNTIME_DIR/instances" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; }
# naming SOCK — how many processes carry MANDU_ARBITER_SOCK=SOCK in their
# environment. A count, not `! grep … | grep -q .`: under pipefail a /proc
# file grep cannot read makes that pipeline fail, and its negation pass.
naming() { { grep -lszxF "MANDU_ARBITER_SOCK=$1" /proc/[0-9]*/environ 2>/dev/null || true; } | tr '\0' '\n' | grep -c . || true; }

# cwdof PID — the process's working directory (its argv is not readable: the
# arbiter sets its process title over it).
cwdof() { readlink "/proc/$1/cwd" 2>/dev/null; }

# no_wrapper PGID — the recorded pid IS the daemon: it leads its group, no
# member is npm, a shell or the tsx binary, and any other member is the
# daemon's own child (from source, tsx's esbuild service). Counting members is
# not the property: such a child may be there.
no_wrapper() {
  local p c pp
  [ "$(ps -o pgid= -p "$1" 2>/dev/null | tr -d ' ')" = "$1" ] || return 1
  for p in $(members "$1"); do
    c="$(cat "/proc/$p/comm" 2>/dev/null)" || continue
    case "$c" in npm | "npm exec" | sh | bash | dash | tsx) return 1 ;; esac
    [ "$p" = "$1" ] && continue
    pp="$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')"
    [ -z "$pp" ] || [ "$pp" = "$1" ] || return 1
  done
}

# start NAME — start a dev arbiter in $T/NAME; sets W and G (its group).
start() {
  W="$T/$1"
  if ! bash "$DEV" "$W" >"$T/$1.out" 2>"$T/$1.err"; then
    fail "$1: the dev arbiter starts ($(tail -n 3 "$T/$1.err" "$W/arbiter.log" 2>/dev/null))"
    G=""
    return 1
  fi
  G="$(cat "$W/pid")"
  GROUPS_STARTED+=("$G")
}

# ── the documented stop ───────────────────────────────────────────────────────
if start a; then
  check "the start hint names the stop subcommand" "grep -qF 'stop: $DEV stop $W' '$T/a.err'"
  check "the start hint no longer offers a bare kill of the pid" "! grep -q 'kill' '$T/a.err'"
  check "the pid file names its own group's leader" "[ \"\$(ps -o pgid= -p $G | tr -d ' ')\" = '$G' ]"
  check "the group holds the daemon (mandu-arbiter)" "[[ ' $(comms "$G")' == *' mandu-arbiter '* ]]"
  check "the daemon registered an instance" "[ $(instances) -eq 1 ]"
  check "its sockets exist" "[ -S '$W/arbiter.sock' ] && [ -S '$W/admin.sock' ]"
  bash "$DEV" stop "$W" 2>"$T/a.stop"
  rc=$?
  check "stop exits 0 ($(cat "$T/a.stop"))" "[ $rc -eq 0 ]"
  check "stop: no process of the group survives" "[ -z \"\$(members $G)\" ]"
  check "stop: the daemon went on SIGTERM (graceful)" "grep -q 'SIGTERM' '$T/a.stop'"
  check "stop: the daemon logged its graceful shutdown" "grep -q 'received SIGTERM, shutting down' '$W/arbiter.log'"
  check "stop: both sockets are gone" "[ ! -e '$W/arbiter.sock' ] && [ ! -e '$W/admin.sock' ]"
  check "stop: the instance dir is tidied" "[ $(instances) -eq 0 ]"
  check "stop: the pid file is removed" "[ ! -e '$W/pid' ]"
  bash "$DEV" stop "$W" 2>"$T/a.stop2"
  rc=$?
  check "a second stop is a no-op (exit 0)" "[ $rc -eq 0 ] && grep -q 'nothing to stop' '$T/a.stop2'"
fi

# ── the old hint: `kill <pid>` now ends the daemon itself ─────────────────────
# (It was npm's pid, and the daemon kept serving: the orphan.)
if start b; then
  check "the pid is the daemon, with no npm, shell or tsx binary in front (group: $(comms "$G"))" "no_wrapper $G"
  kill "$G"
  for _ in $(seq 100); do [ -z "$(members "$G")" ] && break; sleep 0.1; done
  check "kill <pid> (the old hint) ends the whole group: the pid is the daemon" "[ -z \"\$(members $G)\" ]"
  check "... gracefully (socket gone, instance dir tidied)" "[ ! -e '$W/arbiter.sock' ] && [ $(instances) -eq 0 ]"
  MANDU_DEV_ARBITER_WORK="$W" bash "$DEV" stop 2>"$T/b.stop"
  rc=$?
  check "stop (work dir from MANDU_DEV_ARBITER_WORK) afterwards exits 0 ($(cat "$T/b.stop"))" "[ $rc -eq 0 ] && grep -q 'already gone' '$T/b.stop'"
fi

# ── the start form: a fresh bundle, a stale one, MANDU_FROM_SOURCE ────────────
# A private build of the real bundle (--outdir): the checkout's own
# launcher/dist, which other suites and sessions use, is never touched.
PDIST="$T/pdist"
if node "$REPO/launcher/scripts/build-bundle.mjs" --outdir="$PDIST" --no-native --quiet >"$T/build.log" 2>&1 \
   && node "$REPO/launcher/scripts/bundle-stamp.mjs" --root="$REPO" "$PDIST"; then
  export MANDU_DEV_ARBITER_DIST="$PDIST"
  if start fresh; then
    check "fresh bundle: the form file says bundle" "[ \"\$(cat '$W/form')\" = bundle ]"
    check "fresh bundle: the daemon runs where a bundle does (cwd $(cwdof "$G"))" "[ '$(cwdof "$G")' = '$REPO/launcher' ]"
    check "fresh bundle: the pid is the daemon, nothing in front of it" "no_wrapper $G"
    check "fresh bundle: the start says which form" "grep -qF \"from the checkout's bundle ($PDIST)\" '$T/fresh.err'"
    bash "$DEV" stop "$W" 2>/dev/null
    check "fresh bundle: stop leaves nothing" "[ -z \"\$(members $G)\" ] && [ $(instances) -eq 0 ]"
  fi
  export MANDU_FROM_SOURCE=1
  if start forced; then
    check "MANDU_FROM_SOURCE=1: the source even with a fresh bundle (cwd $(cwdof "$G"))" "[ \"\$(cat '$W/form')\" = source ] && [ '$(cwdof "$G")' = '$REPO/arbiter' ]"
    bash "$DEV" stop "$W" 2>/dev/null
  fi
  unset MANDU_FROM_SOURCE
  # An input changed since the build: the record's entry for it moves (the
  # real source is not touched; other suites read it).
  node -e '
    const fs = require("fs"); const p = process.argv[1];
    const rec = JSON.parse(fs.readFileSync(p, "utf8"));
    const rel = "arbiter/ipc/server-main.ts";
    if (!rec.inputs[rel]) process.exit(3);
    rec.inputs[rel] = [rec.inputs[rel][0] - 1000, rec.inputs[rel][1]];
    fs.writeFileSync(p, JSON.stringify(rec));' "$PDIST/.bundle-stamp.json"
  check "the private build's record now says stale" "! node '$REPO/launcher/scripts/bundle-stamp.mjs' --root='$REPO' '$PDIST'"
  if start stale; then
    check "stale bundle: never run; the source runs (cwd $(cwdof "$G"))" "[ \"\$(cat '$W/form')\" = source ] && [ '$(cwdof "$G")' = '$REPO/arbiter' ]"
    check "stale bundle: the start says why" "grep -qF 'from source (arbiter/ipc/server-main.ts changed since the build)' '$T/stale.err'"
    check "stale bundle: the pid is the daemon, nothing in front of it" "no_wrapper $G"
    bash "$DEV" stop "$W" 2>/dev/null
  fi
  unset MANDU_DEV_ARBITER_DIST
else
  fail "a private build of the bundle ($(tail -n 3 "$T/build.log"))"
fi
check "the script starts no npm" "! grep -qE '^[^#]*npm run' '$DEV'"

# ── the lifeline: the caller SIGKILLed, the arbiter goes with it ──────────────
# The caller holds the FIFO's only write end on fd 9 (launcher/test/lib/
# lifeline.sh) and passes MANDU_LIFELINE_FIFO; no trap, no stop runs.
mkfifo "$T/ll.fifo"
bash -c 'exec 9<>"$1"; MANDU_LIFELINE_FIFO="$1" bash "$2" "$3" >"$3.out" 2>"$3.err" || exit 1; : >"$3.up"; exec sleep 600' \
  _ "$T/ll.fifo" "$DEV" "$T/ll" &
HOLDER=$!
# The holder ends when the script fails, so this bound only stops a hang: the
# script's own readiness budget (it may double on CI) and its stop's grace.
for _ in $(seq $((($(mdu_ready_deadline_ms) + 20000) / 100))); do [ -e "$T/ll.up" ] || ! kill -0 "$HOLDER" 2>/dev/null && break; sleep 0.1; done
if [ -e "$T/ll.up" ]; then
  G="$(cat "$T/ll/pid")"
  GROUPS_STARTED+=("$G")
  # The arbiter logs the line after listen(), its manifest and its promotion
  # (server-main.ts), so it can land just after the socket answers and the
  # script calls the start up: wait for it (seen on a loaded CI runner).
  for _ in $(seq 50); do grep -q 'lifeline armed' "$T/ll/arbiter.log" 2>/dev/null && break; sleep 0.1; done
  check "lifeline: the arbiter armed it" "grep -q 'lifeline armed' '$T/ll/arbiter.log'"
  check "lifeline: the daemon registered an instance" "[ $(instances) -eq 1 ]"
  kill -KILL "$HOLDER"
  { wait "$HOLDER"; } 2>/dev/null
  for _ in $(seq 150); do [ -z "$(members "$G")" ] && break; sleep 0.1; done
  check "lifeline: the caller's death ends every process of the group" "[ -z \"\$(members $G)\" ]"
  check "lifeline: the daemon shut down on the EOF" "grep -q 'lifeline EOF' '$T/ll/arbiter.log'"
  check "lifeline: the instance dir is tidied" "[ $(instances) -eq 0 ]"
else
  fail "lifeline: the dev arbiter starts ($(tail -n 3 "$T/ll.err" "$T/ll/arbiter.log" 2>/dev/null))"
fi
MANDU_LIFELINE_FIFO="$T/not-a-fifo" bash "$DEV" "$T/nf" >/dev/null 2>"$T/nf.err"
rc=$?
check "a MANDU_LIFELINE_FIFO that is not a FIFO is refused (exit 2)" "[ $rc -eq 2 ] && grep -q 'not a FIFO' '$T/nf.err'"
# The tenant (a film take asks for live): only test or live, and the export
# names the one the arbiter was started with.
MANDU_DEV_ARBITER_TENANT=prod bash "$DEV" "$T/tn" >/dev/null 2>"$T/tn.err"
rc=$?
check "a MANDU_DEV_ARBITER_TENANT other than test or live is refused (exit 2)" "[ $rc -eq 2 ] && grep -q 'must be test or live' '$T/tn.err' && [ ! -e '$T/tn/pid' ]"
check "the started tenant is the exported one (default test)" "grep -q 'MANDU_TENANT=\"\$TENANT\"' '$DEV' && grep -q 'export MANDU_TENANT=\$TENANT' '$DEV' && grep -q 'MANDU_DEV_ARBITER_TENANT:-test' '$DEV'"

# ── a start that does not come up ─────────────────────────────────────────────
# A deadline (1 ms) no real start meets: refused, and the slow start is stopped.
MANDU_SERVICE_READY_TIMEOUT_MS=1 bash "$DEV" "$T/slow" >/dev/null 2>"$T/slow.err"
rc=$?
check "a start past its readiness deadline is refused (exit 1, $(head -n 1 "$T/slow.err"))" "[ $rc -eq 1 ] && grep -q 'did not come up (not ready within 1 s' '$T/slow.err'"
check "the slow start's group is stopped (not found gone: it was still starting)" "grep -q 'stopped process group' '$T/slow.err' && [ ! -e '$T/slow/pid' ]"
check "no process names the slow start's socket" "[ $(naming "$T/slow/arbiter.sock") -eq 0 ]"
check "the slow start's instance dir is tidied" "[ $(instances) -eq 0 ]"
check "the refusal says the time spent and what was missing" "grep -qE 'did not come up \(.*; waited [0-9]+ s, .*(arbiter|admin)\.sock.* missing\)' '$T/slow.err'"
# Ready is both sockets. A stand-in daemon (the stand-in `node` takes only the
# daemon's start, either form, and hands every other call to the real node)
# binds the data socket at once and the admin socket only after
# STANDIN_ADMIN_MS (never, when negative): the script must not call that "up"
# on the data socket alone, since its output names the admin socket too.
mkdir -p "$T/admbin"
cat >"$T/admbin/node" <<EOF
#!/usr/bin/env bash
case " \$* " in
  *" --import "* | *"/arbiter.mjs "*)
    exec $(printf '%q' "$(command -v node)") -e '
      const net = require("net");
      net.createServer().listen(process.env.MANDU_ARBITER_SOCK);
      const ms = Number(process.env.STANDIN_ADMIN_MS);
      if (ms >= 0) setTimeout(() => net.createServer().listen(process.env.MANDU_ADMIN_SOCK), ms);
      setInterval(() => {}, 1e9);' ;;
esac
exec $(printf '%q' "$(command -v node)") "\$@"
EOF
chmod +x "$T/admbin/node"
if STANDIN_ADMIN_MS=1500 PATH="$T/admbin:$PATH" bash "$DEV" "$T/adm" >"$T/adm.out" 2>"$T/adm.err"; then
  GROUPS_STARTED+=("$(cat "$T/adm/pid")")
  check "a late admin socket is waited for: both sockets are bound when the start returns" "[ -S '$T/adm/arbiter.sock' ] && [ -S '$T/adm/admin.sock' ]"
  bash "$DEV" stop "$T/adm" 2>/dev/null
else
  fail "a late admin socket is waited for ($(tail -n 3 "$T/adm.err"))"
fi
STANDIN_ADMIN_MS=-1 MANDU_SERVICE_READY_TIMEOUT_MS=1500 PATH="$T/admbin:$PATH" bash "$DEV" "$T/noadm" >"$T/noadm.out" 2>"$T/noadm.err"
rc=$?
lg="$(grep -o 'process group [0-9]*' "$T/noadm.err" | grep -o '[0-9]*$' | head -n 1 || true)"
if [ -n "$lg" ]; then GROUPS_STARTED+=("$lg"); fi
check "a data socket without its admin socket is not up (exit 1, $(head -n 1 "$T/noadm.err"))" "[ $rc -eq 1 ] && grep -qF '$T/noadm/admin.sock missing' '$T/noadm.err' && [ ! -s '$T/noadm.out' ]"
check "... and that start is stopped" "grep -q 'stopped process group' '$T/noadm.err' && [ $(naming "$T/noadm/arbiter.sock") -eq 0 ]"
# The same start with setsid(1) running late (a descheduled child, the GitLab
# flake): until it runs, the start is alive but its group is empty. It is still
# a slow start, not an exited one, and its stop collects it rather than finding
# the group gone and leaving the start to come up and serve.
mkdir -p "$T/latebin"
printf '#!/usr/bin/env bash\nsleep 0.5\nexec %q "$@"\n' "$(command -v setsid)" >"$T/latebin/setsid"
chmod +x "$T/latebin/setsid"
PATH="$T/latebin:$PATH" MANDU_SERVICE_READY_TIMEOUT_MS=1 bash "$DEV" "$T/late" >/dev/null 2>"$T/late.err"
rc=$?
# The exit trap collects the group even if the stop left it running.
lg="$(grep -o 'process group [0-9]*' "$T/late.err" | grep -o '[0-9]*$' | head -n 1 || true)"
if [ -n "$lg" ]; then GROUPS_STARTED+=("$lg"); fi
check "a late setsid is a slow start, not an exited one (exit 1, $(head -n 1 "$T/late.err"))" "[ $rc -eq 1 ] && grep -q 'did not come up (not ready within 1 s' '$T/late.err'"
check "the late start's group is stopped (not found gone)" "grep -q 'stopped process group' '$T/late.err' && [ ! -e '$T/late/pid' ]"
sleep 1
check "nothing of the late start comes up afterwards" "[ ! -e '$T/late/arbiter.sock' ] && [ $(naming "$T/late/arbiter.sock") -eq 0 ]"
check "the late start's instance dir is tidied" "[ $(instances) -eq 0 ]"
# An arbiter that refuses to start (a policy file that does not validate):
# the wait ends when its group exits, well inside the default 30 s.
printf 'inbound: [\n' >"$T/bad-policy.yaml"
s0=$SECONDS
MANDU_POLICY_FILE="$T/bad-policy.yaml" bash "$DEV" "$T/dead" >/dev/null 2>"$T/dead.err"
rc=$?
took=$((SECONDS - s0))
check "a start whose arbiter exits is refused (exit 1, $(head -n 1 "$T/dead.err"))" "[ $rc -eq 1 ] && grep -q 'did not come up (it exited before its socket appeared; waited [0-9]* s' '$T/dead.err'"
check "... at once, not at the deadline (${took}s)" "[ $took -lt 25 ]"
check "... and its stderr carries the arbiter's log tail (a caller's log keeps why)" "grep -q '^dev-arbiter: the last lines of $T/dead/arbiter.log:' '$T/dead.err' && grep -q '^dev-arbiter: | ' '$T/dead.err'"
# A server that exits before the start's first look (the daemon's node failing
# at once): reported like any exit, its log on stderr. The setsid wait's ps
# failed on the gone pid and, under set -e, ended the script silently (exit 1,
# no line). The stand-in `node` fails only the daemon's start (either form:
# `--import <tsx>` or a bundle) and hands every other call, the build-record
# check among them, to the real node.
mkdir -p "$T/failbin"
printf '#!/usr/bin/env bash\ncase " $* " in *" --import "*|*"/arbiter.mjs "*) echo "fake-node: refused at once" >&2; exit 3 ;; esac\nexec %q "$@"\n' "$(command -v node)" >"$T/failbin/node"
chmod +x "$T/failbin/node"
PATH="$T/failbin:$PATH" bash "$DEV" "$T/quick" >/dev/null 2>"$T/quick.err"
rc=$?
check "a server that exits at once is reported, not a silent exit 1 ($(head -n 1 "$T/quick.err"))" "[ $rc -eq 1 ] && grep -q 'did not come up (it exited before its socket appeared; waited [0-9]* s' '$T/quick.err'"
check "... with its log tail on stderr" "grep -qx 'dev-arbiter: | fake-node: refused at once' '$T/quick.err'"
check "... and its pid file is tidied" "[ ! -e '$T/quick/pid' ]"
# A start whose setsid(1) runs late, under the default deadline: for its first
# second the readiness wait sees an empty group, yet the start is alive, so it
# is NOT an exit (start_gone also asks whether the recorded pid lives) and it
# comes up. A group-only check called it "exited before its socket appeared"
# (the drill-own-arbiter flake, GitLab pipelines 8805, 8811, 8834).
printf '#!/usr/bin/env bash\nsleep 1\nexec %q "$@"\n' "$(command -v setsid)" >"$T/latebin/setsid"
if PATH="$T/latebin:$PATH" bash "$DEV" "$T/later" >/dev/null 2>"$T/later.err"; then
  GROUPS_STARTED+=("$(cat "$T/later/pid")")
  pass "a start whose setsid runs late is no exit: it comes up"
  bash "$DEV" stop "$T/later" 2>/dev/null
  check "... and its stop collects it" "[ $(naming "$T/later/arbiter.sock") -eq 0 ] && [ $(instances) -eq 0 ]"
else
  fail "a start whose setsid runs late is no exit: it comes up ($(head -n 1 "$T/later.err"))"
fi

# ── refusals and the SIGKILL fallback (stand-in groups, no arbiter) ───────────
bash "$DEV" stop 2>"$T/noarg.err"
rc=$?
check "stop with no work dir and no MANDU_DEV_ARBITER_WORK exits 2" "[ $rc -eq 2 ]"

# A group of some other program, named by a stale pid file. `$!` is the
# background child before setsid(1) has run in it: until then the group
# $OTHER has no member, and stop rightly reads the pid file as "already gone"
# (exit 0, the file removed: pipeline 11654). So wait, on the condition, for
# the group to exist before stop looks at it.
setsid sleep 600 &
OTHER=$!
GROUPS_STARTED+=("$OTHER")
for _ in $(seq 300); do [ -n "$(members "$OTHER")" ] && break; sleep 0.1; done
check "the stand-in group exists before stop looks at it" "[ -n \"\$(members $OTHER)\" ]"
mkdir -p "$T/stale"
echo "$OTHER" >"$T/stale/pid"
bash "$DEV" stop "$T/stale" 2>"$T/stale.err"
rc=$?
check "a stale pid file naming another group is refused (exit 1)" "[ $rc -eq 1 ] && grep -q 'not the arbiter' '$T/stale.err'"
check "that group is left alone" "kill -0 $OTHER 2>/dev/null"
check "the stale pid file is kept for a human to look at" "[ -f '$T/stale/pid' ]"

# A group of this work dir's arbiter (its environment names the socket) that
# ignores SIGTERM: stop SIGKILLs it after the grace.
mkdir -p "$T/stubborn"
MANDU_ARBITER_SOCK="$T/stubborn/arbiter.sock" setsid bash -c 'trap "" TERM; sleep 600 & wait' &
STUB=$!
GROUPS_STARTED+=("$STUB")
echo "$STUB" >"$T/stubborn/pid"
for _ in $(seq 300); do [ "$(members "$STUB" | wc -l)" -ge 2 ] && break; sleep 0.1; done
check "the stubborn group is up (its shell and its sleep) before stop looks at it" "[ \"\$(members $STUB | wc -l)\" -ge 2 ]"
MANDU_DEV_ARBITER_STOP_GRACE=1 bash "$DEV" stop "$T/stubborn" 2>"$T/stubborn.err"
rc=$?
{ wait "$STUB"; } 2>/dev/null
check "a group that ignores SIGTERM is stopped (exit 0, $(cat "$T/stubborn.err"))" "[ $rc -eq 0 ] && grep -q 'SIGKILL' '$T/stubborn.err'"
check "no process of it survives" "[ -z \"\$(members $STUB)\" ]"

echo
# The failures again, last: a CI log shows only the tail.
for f in "${FAILED[@]}"; do echo "FAILED: $f"; done
echo "dev-arbiter: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
