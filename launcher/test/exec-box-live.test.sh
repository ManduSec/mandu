#!/usr/bin/env bash
#
# exec-box-live.test.sh — LIVE e2e oracle for --exec-box (the launcher's
# PATH-shadow shim that BOXES a command through mandu-exec-box, exec-routing.md
# §7). Distinct from exec-wrap (which only GATES a symbol-as-command): an
# exec-box shim runs its command inside the net-off / RO-root AgentShell.
#
# Proves, on real infrastructure (a real arbiter, the committed box bin, real
# bwrap/userns):
#   1. writeExecBoxShims produces a shim that ROUTES through the box bin — a
#      boxed `cat` reads the RO real filesystem and returns its contents.
#   2. The box turns NETWORK OFF: a boxed command's CONNECT to a live loopback
#      listener is denied, while a BARE run of the same probe connects.
#   3c. THE RO ROOT: a boxed write at a cwd on the real filesystem (outside
#      every bind) is denied and leaves no host file.
#   3d. A PROJECT UNDER /tmp (checklist a7): a no-view shim baked with the
#      project root runs at a /tmp cwd, reads the project, cannot see a /tmp
#      sibling, and cannot write the project (the RO re-bind over the fresh /tmp).
#   3e. THE SOCKET ALLOW-LIST (§4.2): a boxed command reaches a Unix socket it
#      bound and is refused a host socket, alone and under the real guard
#      (which serves the box when it holds the chain's only listener); under
#      a guard that does not serve boxes every connect is refused.
#   3f. A SECRET-BEARING COMMAND (confidentiality.md §7.1, exec-classify.ts
#      resolveExecArgv): with a file labelled `no-model` and its bytes
#      symbolized, a boxed (AgentShell) command keeps the secret's symbol
#      opaque, and a network command (curl, routed to the net-on HumanShell)
#      carrying the symbol is REFUSED before it runs (exit 77): the loopback
#      sink never sees the secret. Control: the same curl carrying an ordinary
#      (public) symbol runs and the sink receives its value, so the refusal is
#      the secret's label, not a dead path.
#   3g. THE `secrets` WORKSPACE (2026-10-01, exec-routing.md §7.2): with no
#      AgentView pair and integrity OFF the shim bakes a writable project, so
#      a boxed `sed -i` / `sort -o` edits the real files (and without the flag
#      fails EROFS, the over-block reproduced); a write outside the project is
#      still refused, the box is still net-off, and a `no-model` labelled file
#      in the project, confined by its twin with the box nested in the wrap,
#      still reads as its symbol: no raw byte lands anywhere in the project.
#      And (2026-10-19) the same flag shows the box the agent's own /tmp: a
#      boxed cat reads a file the agent wrote there, a boxed write lands
#      there, a Unix socket in it is masked; without the flag /tmp is fresh.
#   4. applyExecBox DEGRADES gracefully (warn + no shim dir, never throws) when
#      the box bin is absent — so --exec-box never fails a launch.
#
# Runs in `secrets` mode (re-pinned 2026-09-29, test-organization.md §7). The
# box is shared code (protection-modes.md §10.2); the integrity-only leg, the
# writable AgentView of the fs-view co-design, moved with the whole pre-move
# form to the frozen lane: launcher/test/integrity/exec-box-live.test.sh.
#
# SKIPs cleanly (exit 0) when node / bwrap / unprivileged userns / the arbiter
# tsx / the box bin are unavailable — environment gaps, not failures. An
# arbiter that never comes up is a FAILURE, with its log's last lines.
#
# Run:  bash launcher/test/exec-box-live.test.sh
#
set -uo pipefail
# This suite STATES its axes (docs/design/architecture/protection-modes.md §4): the arbiter it
# spawns and the launcher it runs both read these, so a change of the built-in
# default can never quietly change what the suite proves. STRICT makes an
# unstated axis a startup error in the arbiter. `secrets`: confidentiality ON,
# integrity OFF.
export MANDU_AXES_STRICT=1 MANDU_INTEGRITY=0 MANDU_CONFIDENTIALITY=1
# No host policy.yaml: the only label in force is the one this suite sets.
export MANDU_POLICY_FILE=/dev/null/mandu-test-no-policy.yaml

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
ARBITER_TSX="$REPO_ROOT/arbiter/node_modules/.bin/tsx"
ARBITER_MAIN="$REPO_ROOT/arbiter/ipc/server-main.ts"
LAUNCHER_TSX="$REPO_ROOT/launcher/node_modules/.bin/tsx"

PASS=0; FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() {
  echo "SKIP: $1"
  echo "─────────────────────────────────────────"
  echo "exec-box-live.test.sh: 0 passed, 0 failed (skipped)"
  exit 0
}

# A broken run, not a missing prerequisite: the arbiter this suite started did
# not come up. FAIL with why and the log's last lines
# (scripts/lib/ready-deadline.sh), never SKIP: a suite that goes quiet must
# not show green.
abort() {
  echo "FAIL: $1"
  if [[ -n "${2:-}" ]]; then mdu_log_tail "$2"; fi
  echo "─────────────────────────────────────────"
  echo "exec-box-live.test.sh: $PASS passed, $((FAIL + 1)) failed"
  exit 1
}

# ── 0. environment gates ──────────────────────────────────────────────────────
command -v node  >/dev/null 2>&1 || skip "node not on PATH"
command -v bwrap >/dev/null 2>&1 || skip "bwrap (bubblewrap) not installed — the box cannot run"
unshare --user --map-root-user --mount -- true >/dev/null 2>&1 || skip "unprivileged user namespaces unavailable"
[[ -x "$ARBITER_TSX" ]] || skip "arbiter tsx not installed — run 'cd arbiter && npm install'"
[[ -x "$LAUNCHER_TSX" ]] || skip "launcher tsx not installed — run 'cd launcher && npm install'"

BOX="${MANDU_EXEC_BOX_BIN:-}"
if [[ -z "$BOX" || ! -x "$BOX" ]]; then
  for cand in "$REPO_ROOT/interceptors/target/release/mandu-exec-box" \
              "$REPO_ROOT/interceptors/target/debug/mandu-exec-box"; do
    [[ -x "$cand" ]] && { BOX="$cand"; break; }
  done
fi
[[ -n "$BOX" && -x "$BOX" ]] \
  || skip "mandu-exec-box not built — cd interceptors && cargo build -p exec-supervisor --features kernel --bins"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-execbox-live.XXXXXX")" || skip "mktemp failed"
# The runtime base (the instance registry, the human-plane socket): the
# suite's own, never the caller's $XDG_RUNTIME_DIR/mandu, also when the suite
# is killed (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
SOCK="$WORK/arbiter.sock"
ADMIN_SOCK="$WORK/admin.sock"
arbiter_pid=""; listen_pid=""; sink_pid=""
cleanup() {
  [[ -n "$listen_pid" ]] && kill "$listen_pid" 2>/dev/null
  [[ -n "$sink_pid" ]] && kill "$sink_pid" 2>/dev/null
  [[ -n "$arbiter_pid" ]] && mdu_stop_group "$arbiter_pid"
  # With the legs' own dirs (under $HOME and /tmp), should a leg die before it
  # removes them (test-organization.md §8.5).
  [[ -n "${host_pid:-}" && -d "${SK:-/nonexistent}" ]] && kill "$host_pid" 2>/dev/null
  rm -rf "$WORK" "${RO_DIR:-}" "${TP_BASE:-}" "${SK:-}" "${WSB:-}" 2>/dev/null || true
}
trap cleanup EXIT
# Lifeline backstop (lib/lifeline.sh): reaps the arbiter if this shell dies
# without its trap (SIGKILL / abandoned hang).
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

# ── the legs' own dirs, outside $WORK (test-organization.md §8.5) ─────────────
# Three legs need a dir under $HOME (the box replaces /tmp) and §3d one in the
# real /tmp, outside the runner's TMPDIR. The EXIT trap removes them, but a
# SIGKILL skips the trap. So each dir carries a lock this shell holds
# (flock(2) on `.owner.lock`, which the kernel drops however the shell dies),
# and every run first removes this user's dirs whose lock nobody holds. A
# lock, not a pid: a pid read from another pid namespace (ns-run, the CI
# guest) names someone else, and a sweep must never take a live run's dir.
owned_dir() { # VAR mktemp-template: make the dir and hold its lock until this shell exits
  local d f
  d="$(mktemp -d "$2")" || return 1
  printf -v "$1" '%s' "$d"
  command -v flock >/dev/null 2>&1 || return 0
  # Locked under another name, then renamed: no sweep ever meets an
  # unlocked `.owner.lock` of a live run. Read-only: the boxed commands
  # inherit the descriptor and can write nothing through it.
  { : > "$d/.owner.lock.new" && exec {f}<"$d/.owner.lock.new" && flock -s "$f" && mv "$d/.owner.lock.new" "$d/.owner.lock"; } || true
}
sweep_stale_dirs() {
  local d
  for d in "$HOME"/.mandu-boxro.?????? "$HOME"/.mandu-boxsock.?????? "$HOME"/.mandu-boxws.?????? \
           /tmp/mandu-execbox-tmpproj.??????; do
    [[ -d "$d" && ! -L "$d" && -O "$d" ]] || continue
    if [[ -e "$d/.owner.lock" ]]; then
      command -v flock >/dev/null 2>&1 || continue
      flock -n -x "$d/.owner.lock" true 2>/dev/null || continue   # its run is alive
    else
      # No lock (made before the lock existed, or still being made): only
      # once it is a day old; the suite's own timeout is 10 minutes.
      [[ -n "$(find "$d" -maxdepth 0 -mmin +1440 2>/dev/null)" ]] || continue
    fi
    rm -rf -- "$d"
  done
}
sweep_stale_dirs

# ── 1. a real arbiter (the box classifies exec through it — fail-closed w/o it) ─
echo "[1/4] booting the arbiter on $SOCK ..."
setsid env MANDU_ARBITER_SOCK="$SOCK" MANDU_ADMIN_SOCK="$ADMIN_SOCK" \
  MANDU_HOME="$WORK/mandu-home" \
  MANDU_LIFELINE=stdin \
  "$ARBITER_TSX" "$ARBITER_MAIN" "$SOCK" <"$MANDU_LIFELINE_FIFO" 9>&- >"$WORK/arbiter.log" 2>&1 &
arbiter_pid=$!
# The readiness budget (scripts/lib/ready-deadline.sh, runtime-instances.md
# §14.6): load-aware, doubled on CI; the wait ends at once if the daemon exits.
# A start that does not come up FAILS the suite (with the log's last lines),
# never SKIPs it: the prerequisites were all checked above.
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO_ROOT/scripts/lib/ready-deadline.sh"
ready_ms="$(mdu_ready_deadline_ms)"
mdu_wait_sockets "$arbiter_pid" "$ready_ms" "$SOCK" "$ADMIN_SOCK" \
  || abort "the arbiter did not come up: $(mdu_ready_why $? "$ready_ms")" "$WORK/arbiter.log"
echo "      arbiter up (pid $arbiter_pid)."

# ── 2. write the box shims via the REAL writer (writeExecBoxShims) ────────────
echo "[2/4] generating box shims via writeExecBoxShims ..."
cat > "$WORK/gen.ts" <<EOF
import { writeExecBoxShims } from "$REPO_ROOT/launcher/src/services/exec-box-shims.js";
const dir = writeExecBoxShims(["cat", "bash"], "$BOX", "$SOCK", "$WORK");
console.log(dir);
EOF
SHIMDIR="$("$LAUNCHER_TSX" "$WORK/gen.ts" 2>"$WORK/gen.err")" || { cat "$WORK/gen.err" >&2; skip "could not run the shim writer via tsx"; }
[[ -x "$SHIMDIR/cat" && -x "$SHIMDIR/bash" ]] || { cat "$WORK/gen.err" >&2; fail "the writer did not produce executable shims"; }
# The shim body must route through the box bin.
if grep -qF "exec \"$BOX\" --cwd \"\$PWD\" -- \"cat\"" "$SHIMDIR/cat"; then
  pass "the cat shim routes through the box bin (exec line as writeExecBoxShims emits)"
else
  echo "--- shim body ---"; cat "$SHIMDIR/cat"; fail "the cat shim does not exec the box bin as expected"
fi

# ── 3. the boxed `cat` runs in AgentShell and reads the RO real FS ────────────
# NOTE: the box mounts a FRESH tmpfs at /tmp, so a marker under $WORK (in /tmp) is
# shadowed inside the box. Read a stable RO file OUTSIDE /tmp instead and compare
# the boxed output to the bare output — proving read-through of the real RO root.
echo "[3/4] running the boxed cat shim (AgentShell, RO root) ..."
RO_FILE="/etc/hostname"; [[ -r "$RO_FILE" ]] || RO_FILE="/etc/os-release"
if [[ -r "$RO_FILE" ]]; then
  bare_cat="$(cat "$RO_FILE")"
  boxed_out="$(MANDU_ARBITER_SOCK="$SOCK" "$SHIMDIR/cat" "$RO_FILE" 2>"$WORK/cat.err")"
  box_rc=$?
  echo "      boxed rc=$box_rc, matches bare: $([[ "$boxed_out" == "$bare_cat" ]] && echo yes || echo no)"
  if [[ "$boxed_out" == "$bare_cat" && -n "$bare_cat" && $box_rc -eq 0 ]]; then
    pass "the boxed cat ran inside the AgentShell box and read $RO_FILE through the RO root (matches bare)"
  else
    echo "--- cat.err ---"; cat "$WORK/cat.err" >&2
    fail "the boxed cat did not match the real $RO_FILE (routing/boxing broke): '$boxed_out' rc=$box_rc"
  fi
else
  echo "NOTE: no stable RO file to read — skipping the read-through assertion"
fi

# ── 3b. the box turns NETWORK OFF (a boxed connect is denied) ─────────────────
# The listener binds port 0 and writes its port to a file once bound, and stays
# bound (the port-file handshake, test-organization.md §8.4: no pick-then-close).
node -e 'require("net").createServer(s=>s.destroy()).listen(0,"127.0.0.1",function(){require("fs").writeFileSync(process.argv[1]+".tmp",String(this.address().port));require("fs").renameSync(process.argv[1]+".tmp",process.argv[1])})' "$WORK/port" >/dev/null 2>&1 &
listen_pid=$!
for _ in $(seq 1 100); do [[ -s "$WORK/port" ]] && break; sleep 0.1; done
PORT="$(cat "$WORK/port" 2>/dev/null)"
[[ -n "$PORT" ]] || skip "could not stand up a loopback listener"
PROBE='if (exec 3<>/dev/tcp/127.0.0.1/'"$PORT"') 2>/dev/null; then echo CONNECTED; else echo BLOCKED; fi'
bare_net="$(bash -c "$PROBE")"
boxed_net="$(MANDU_ARBITER_SOCK="$SOCK" "$SHIMDIR/bash" -c "$PROBE" 2>/dev/null)"
echo "      bare=$bare_net boxed=$boxed_net (listener :$PORT)"
if [[ "$bare_net" == "CONNECTED" && "$boxed_net" == "BLOCKED" ]]; then
  pass "the box turns NETWORK OFF: a boxed connect is denied while a bare connect succeeds"
elif [[ "$bare_net" != "CONNECTED" ]]; then
  echo "NOTE: bare probe did not connect ('$bare_net') — cannot attribute the box result; treating as SKIP-worthy"
else
  fail "a boxed command reached the network (net was NOT off): boxed='$boxed_net'"
fi

# ── 3b'. loader variables are unset inside the box (learn-from-nono §3.7) ─────
bare_env="$(NODE_OPTIONS=--trace-warnings BASH_ENV=/nonexistent/rc bash -c 'echo "[$NODE_OPTIONS|$BASH_ENV]"')"
boxed_env="$(NODE_OPTIONS=--trace-warnings BASH_ENV=/nonexistent/rc MANDU_ARBITER_SOCK="$SOCK" "$SHIMDIR/bash" -c 'echo "[$NODE_OPTIONS|$BASH_ENV]"' 2>/dev/null)"
if [[ "$bare_env" == "[--trace-warnings|/nonexistent/rc]" && "$boxed_env" == "[|]" ]]; then
  pass "loader variables (NODE_OPTIONS, BASH_ENV, …) are unset inside the box, kept outside it"
else
  fail "loader variables: bare='$bare_env' boxed='$boxed_env'"
fi

# ── 3c. the RO root: a boxed write outside every bind is denied ──────────────
# A no-view shim (no AgentView pair, no project named) at a cwd on the real
# filesystem (under $HOME, off the box's fresh /tmp) cannot write there; §3g
# covers the `secrets` launch's writable project and the RO root around it. (The
# writable-AgentView form of this leg is integrity-only and lives in the frozen
# lane, launcher/test/integrity/exec-box-live.test.sh §3c.)
echo "[3c] a boxed write on the RO root is denied ..."
owned_dir RO_DIR "$HOME/.mandu-boxro.XXXXXX" || skip "cannot create a dir under \$HOME"
# The box must RUN (rc 0, the marker printed) and the write inside it fail: a
# box that never started would leave no file either, and prove nothing.
ro_out="$( cd "$RO_DIR" && MANDU_ARBITER_SOCK="$SOCK" "$SHIMDIR/bash" -c '{ echo nope > out.txt; } 2>/dev/null && echo WRITE-OK || echo WRITE-DENIED' 2>"$WORK/ro.err" )"
ro_rc=$?
if [[ $ro_rc -eq 0 && "$ro_out" == "WRITE-DENIED" && ! -e "$RO_DIR/out.txt" ]]; then
  pass "a boxed write outside every bind was denied by the RO root (no host file)"
else
  echo "--- ro.err ---"; cat "$WORK/ro.err" >&2
  fail "RO root: expected the box to run and the write to be denied (rc=$ro_rc, out='$ro_out', out.txt present: $([[ -e "$RO_DIR/out.txt" ]] && echo yes || echo no))"
fi
rm -rf "$RO_DIR"

# ── 3d. a PROJECT UNDER /tmp (open-source-release checklist a7) ──────────────
# The box mounts a fresh tmpfs at /tmp, so a no-view launch from /tmp/x/proj
# died on every boxed command with `bwrap: Can't chdir`. The shim now bakes the
# launch's project (writeExecBoxShims' projectRoot) and the box re-binds it
# READ-ONLY over its /tmp: the command runs at its cwd and reads the project,
# a sibling elsewhere in the real /tmp stays invisible, the project stays RO.
echo "[3d] a no-view box runs in a project under /tmp (RO, siblings hidden) ..."
owned_dir TP_BASE /tmp/mandu-execbox-tmpproj.XXXXXX || skip "cannot create a /tmp project"
TP="$TP_BASE/proj"; mkdir -p "$TP"
printf 'HELLO-TMP' > "$TP/README.md"
printf 'AKIA-SIBLING' > "$TP_BASE/sibling-secret.txt"
cat > "$WORK/gen-tmp.ts" <<EOF
import { writeExecBoxShims } from "$REPO_ROOT/launcher/src/services/exec-box-shims.js";
const dir = writeExecBoxShims(["sh"], "$BOX", "$SOCK", "$WORK/tmpproj", undefined, undefined, undefined, "$TP");
console.log(dir);
EOF
TSHIMDIR="$("$LAUNCHER_TSX" "$WORK/gen-tmp.ts" 2>"$WORK/gentmp.err")" || { cat "$WORK/gentmp.err" >&2; rm -rf "$TP_BASE"; skip "could not run the /tmp-project shim writer"; }
( cd "$TP" && MANDU_ARBITER_SOCK="$SOCK" "$TSHIMDIR/sh" -c \
    "test \"\$(cat README.md)\" = HELLO-TMP && ! test -e $TP_BASE/sibling-secret.txt && ! ( echo x > w.txt ) 2>/dev/null && echo TMP-PROJECT-OK" \
) >"$WORK/tp.out" 2>"$WORK/tp.err"
tp_rc=$?
if [[ $tp_rc -eq 0 && "$(cat "$WORK/tp.out")" == "TMP-PROJECT-OK" && ! -e "$TP/w.txt" ]]; then
  pass "a boxed command in a /tmp project ran at its cwd, read the project, could not see its /tmp sibling or write the project"
else
  echo "--- tp.err ---"; cat "$WORK/tp.err" >&2
  if grep -q "Can't chdir" "$WORK/tp.err"; then
    fail "the /tmp project is hidden by the box's fresh /tmp (bwrap: Can't chdir) — is $BOX rebuilt? (scripts/build-native.sh)"
  else
    fail "the /tmp-project boxed run failed (rc=$tp_rc, out='$(cat "$WORK/tp.out")')"
  fi
fi
rm -rf "$TP_BASE"

# ── 3e. the box connects only to sockets it bound (exec-routing.md §4.2) ─────
# The socket allow-list, end to end on the real binaries. A host socket parked
# deep under $HOME (outside /tmp, which the box replaces, and below the scan's
# depth) and the box's own socket on its /tmp: the box reaches its own and is
# refused the host's, both when it serves its own seccomp listener and when
# the real whole-agent guard holds the chain's only listener and serves it
# (MANDU_NET_GUARD_BOX_SOCKETS=1). Under the guard WITHOUT that, nobody can
# supervise the box and every connect in it is refused (fail-closed), which
# also proves the hand-off is what keeps the other two legs working.
echo "[3e] the box's socket allow-list, alone and under the guard ..."
GUARD="$REPO_ROOT/interceptors/target/release/mandu-net-guard"
[[ -x "$GUARD" ]] || GUARD="$REPO_ROOT/interceptors/target/debug/mandu-net-guard"
if ! command -v python3 >/dev/null 2>&1; then
  echo "NOTE: python3 not found — skipping the socket allow-list legs"
else
  owned_dir SK "$HOME/.mandu-boxsock.XXXXXX" || skip "cannot create a socket dir under \$HOME"
  mkdir -p "$SK/a/b/c"
  HOST_SOCK="$SK/a/b/c/host.sock"
  cat > "$SK/host.py" <<'PY'
import socket, sys
srv = socket.socket(socket.AF_UNIX)
srv.bind(sys.argv[1])
srv.listen(16)
log = open(sys.argv[2], "a", buffering=1)
while True:
    c, _ = srv.accept()
    log.write("ACCEPTED\n")
    c.close()
PY
  cat > "$SK/probe.py" <<'PY'
import socket, sys
own = "/tmp/own.sock"
srv = socket.socket(socket.AF_UNIX)
srv.bind(own)
srv.listen(1)
def c(p):
    s = socket.socket(socket.AF_UNIX)
    try:
        s.connect(p)
        return "OK"
    except OSError as e:
        return "ERR:%d" % e.errno
print("OWN %s HOST %s" % (c(own), c(sys.argv[1])))
PY
  python3 "$SK/host.py" "$HOST_SOCK" "$SK/accepted.log" &
  host_pid=$!
  for _ in $(seq 1 50); do [[ -S "$HOST_SOCK" ]] && break; sleep 0.1; done
  printf 'import { writeExecBoxShims } from "%s/launcher/src/services/exec-box-shims.js";\nconsole.log(writeExecBoxShims(["python3"], "%s", "%s", "%s/py"));\n' \
    "$REPO_ROOT" "$BOX" "$SOCK" "$WORK" > "$WORK/gen-py.ts"
  PYSHIMDIR="$("$LAUNCHER_TSX" "$WORK/gen-py.ts" 2>"$WORK/genpy.err")" || { cat "$WORK/genpy.err" >&2; kill "$host_pid"; rm -rf "$SK"; skip "could not run the python3 shim writer"; }
  bare_host="$(python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); print("OK")' "$HOST_SOCK" 2>&1)"
  sleep 0.2; : > "$SK/accepted.log"
  alone="$(cd "$SK" && env -u MANDU_NET_GUARD_BOX_SOCKETS MANDU_ARBITER_SOCK="$SOCK" "$PYSHIMDIR/python3" "$SK/probe.py" "$HOST_SOCK" 2>"$WORK/sk-alone.err")"
  echo "      bare=$bare_host box-alone='$alone'"
  if [[ "$bare_host" == "OK" && "$alone" == "OWN OK HOST ERR:111" ]]; then
    pass "the box alone reaches its own socket and is refused a host socket the bare host reaches"
  else
    echo "--- sk-alone.err ---"; cat "$WORK/sk-alone.err" >&2
    fail "box alone: expected 'OWN OK HOST ERR:111', got '$alone' (bare '$bare_host'); is $BOX rebuilt? (scripts/build-native.sh)"
  fi
  if [[ -x "$GUARD" ]]; then
    served="$(cd "$SK" && MANDU_NET_GUARD_BOX_SOCKETS=1 MANDU_ARBITER_SOCK="$SOCK" "$GUARD" --allow tcp:127.0.0.1/32:1 -- "$PYSHIMDIR/python3" "$SK/probe.py" "$HOST_SOCK" 2>"$WORK/sk-guard.err")"
    unserved="$(cd "$SK" && env -u MANDU_NET_GUARD_BOX_SOCKETS MANDU_ARBITER_SOCK="$SOCK" "$GUARD" --allow tcp:127.0.0.1/32:1 -- "$PYSHIMDIR/python3" "$SK/probe.py" "$HOST_SOCK" 2>"$WORK/sk-unserved.err")"
    echo "      under the guard: served='$served' unserved='$unserved'"
    if [[ "$served" == "OWN OK HOST ERR:111" ]]; then
      pass "under the real guard (one listener per chain), the guard serves the box: own socket reached, host socket refused"
    else
      echo "--- sk-guard.err ---"; cat "$WORK/sk-guard.err" >&2
      fail "under the guard: expected 'OWN OK HOST ERR:111', got '$served'; is $GUARD rebuilt? (scripts/build-native.sh)"
    fi
    if [[ "$unserved" == "OWN ERR:13 HOST ERR:13" ]]; then
      pass "a box nobody can supervise (guard not serving boxes) refuses every connect (fail-closed)"
    else
      echo "--- sk-unserved.err ---"; cat "$WORK/sk-unserved.err" >&2
      fail "unserved box: expected 'OWN ERR:13 HOST ERR:13', got '$unserved'"
    fi
  else
    echo "NOTE: mandu-net-guard not built — skipping the under-the-guard legs"
  fi
  if [[ ! -s "$SK/accepted.log" ]]; then
    pass "the host socket never saw a connection from a box"
  else
    fail "a box reached the host socket: $(wc -l < "$SK/accepted.log") connection(s)"
  fi
  kill "$host_pid" 2>/dev/null; wait "$host_pid" 2>/dev/null
  rm -rf "$SK"
fi

# ── 3f. a SECRET-bearing command (confidentiality.md §7.1) ───────────────────
# The user labels a file `no-model` (admin channel); its bytes are symbolized
# with the file as origin, so the arbiter derives the level itself. Then:
#   - AgentShell (a boxed bash): the box never desymbolizes, so the command
#     prints the secret's symbol, never its bytes;
#   - HumanShell (curl, routed net-on by the box's network-program list): the
#     arbiter's resolveExecArgv never resolves a secret symbol into a
#     net-enabled argv: the placeholder stays as written and the command runs
#     (2026-10-05; before, the box refused it with exit 77). This suite runs no
#     egress proxy, so the loopback sink receives the placeholder and never
#     the secret. A secret leaves only through the network gate at a bound
#     destination, never via argv.
#   - CONTROL: the same curl carrying an ordinary (public) symbol runs and the
#     sink receives its value: the HumanShell path resolves by label.
echo "[3f] a secret-bearing command: symbol stays opaque in the box and in a HumanShell argv ..."
command -v curl >/dev/null 2>&1 || fail "curl is needed for the secret-egress leg (declared in the manifest's needs)"
# rpc <sock> <op> <key=value…>: one NDJSON request, prints the response line.
rpc() {
  node -e '
    const net = require("net");
    const [sock, op, ...kv] = process.argv.slice(1);
    const req = { id: 1, op };
    for (const f of kv) { const i = f.indexOf("="); req[f.slice(0, i)] = f.slice(i + 1); }
    const c = net.connect(sock, () => c.write(JSON.stringify(req) + "\n"));
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      process.stdout.write(buf.slice(0, nl));
      c.end();
      process.exit(0);
    });
    c.on("error", (e) => { process.stderr.write(String(e)); process.exit(1); });
    setTimeout(() => { process.stderr.write("rpc timed out"); process.exit(1); }, 5000);
  ' "$@" 2>>"$WORK/rpc.err"
}
symbolize() { # $1=value $2=origin path → prints the allocated symbol name
  rpc "$SOCK" symbolize tool=Read "value=$1" "origin=$2" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);if(j.ok&&j.result&&j.result.symbol){process.stdout.write(j.result.symbol);return}}catch{}process.stderr.write("symbolize failed: "+s+"\n");process.exit(1)})' \
    2>>"$WORK/rpc.err"
}
mkdir -p "$WORK/secret" "$WORK/pub"
SECRET="EXECBOX_SECRET_$$_$RANDOM"; SECRET_FILE="$WORK/secret/deploy-notes.txt"
PUBLIC="EXECBOX_PUBLIC_$$_$RANDOM"; PUBLIC_FILE="$WORK/pub/readme.txt"
printf '%s\n' "$SECRET" > "$SECRET_FILE"; printf '%s\n' "$PUBLIC" > "$PUBLIC_FILE"
LBL="$(rpc "$ADMIN_SOCK" setPathLabel "path=$SECRET_FILE" confidentiality=no-model)"
[[ "$LBL" == *'"ok":true'* ]] || { echo "$LBL"; cat "$WORK/rpc.err" >&2; fail "setPathLabel failed"; }
SSYM="$(symbolize "$SECRET" "$SECRET_FILE")"
PSYM="$(symbolize "$PUBLIC" "$PUBLIC_FILE")"
echo "      secret symbol=$SSYM  public symbol=$PSYM"
if [[ "$SSYM" == '$MDU:nomodel_'* && "$PSYM" == '$MDU:'* && "$PSYM" != '$MDU:nomodel_'* ]]; then
  pass "the labelled file's bytes mint a no-model (SECRET) symbol, the unlabelled one an ordinary symbol"
else
  cat "$WORK/rpc.err" >&2
  fail "symbol levels wrong (the label did not reach the level): secret=$SSYM public=$PSYM"
fi

# (i) AgentShell: the box leaves the symbol opaque. The symbol sits in the argv
#     literally (single-quoted for the inner bash), where the arbiter could see it.
agent_out="$(MANDU_ARBITER_SOCK="$SOCK" "$SHIMDIR/bash" -c "echo 'k=$SSYM'" 2>"$WORK/sf-agent.err")"
echo "      boxed echo → '$agent_out'"
if [[ "$agent_out" == "k=$SSYM" && "$agent_out" != *"$SECRET"* ]]; then
  pass "AgentShell: a boxed command carrying the secret's symbol prints the symbol, never the secret"
else
  echo "--- sf-agent.err ---"; cat "$WORK/sf-agent.err" >&2
  fail "AgentShell: expected the opaque symbol, got '$agent_out'"
fi

# (ii) HumanShell: a loopback sink (port 0 + port file, kept bound) records
#      every request it receives.
node -e '
  const fs = require("fs"), [portFile, log] = process.argv.slice(1);
  require("http").createServer((q, r) => {
    let b = ""; q.on("data", (d) => b += d);
    q.on("end", () => { fs.appendFileSync(log, q.url + " " + b + "\n"); r.end("OK"); });
  }).listen(0, "127.0.0.1", function () {
    fs.writeFileSync(portFile + ".tmp", String(this.address().port)); fs.renameSync(portFile + ".tmp", portFile);
  });
' "$WORK/sink.port" "$WORK/sink.log" >/dev/null 2>&1 &
sink_pid=$!
for _ in $(seq 1 100); do [[ -s "$WORK/sink.port" ]] && break; sleep 0.1; done
SINK_PORT="$(cat "$WORK/sink.port" 2>/dev/null)"
[[ -n "$SINK_PORT" ]] || skip "could not stand up the loopback sink"
: > "$WORK/sink.log"
printf 'import { writeExecBoxShims } from "%s/launcher/src/services/exec-box-shims.js";\nconsole.log(writeExecBoxShims(["curl"], "%s", "%s", "%s/curl"));\n' \
  "$REPO_ROOT" "$BOX" "$SOCK" "$WORK" > "$WORK/gen-curl.ts"
CSHIMDIR="$("$LAUNCHER_TSX" "$WORK/gen-curl.ts" 2>"$WORK/gencurl.err")" || { cat "$WORK/gencurl.err" >&2; skip "could not run the curl shim writer"; }

# CONTROL first: an ordinary symbol in a data slot is resolved in place and sent.
MANDU_ARBITER_SOCK="$SOCK" "$CSHIMDIR/curl" -sS -m 10 -o /dev/null -d "k=$PSYM" "http://127.0.0.1:$SINK_PORT/public" 2>"$WORK/sf-pub.err"
pub_rc=$?
if [[ $pub_rc -eq 0 ]] && grep -qxF "/public k=$PUBLIC" "$WORK/sink.log"; then
  pass "control: HumanShell curl with an ORDINARY symbol ran and the sink received its value"
else
  echo "--- sf-pub.err ---"; cat "$WORK/sf-pub.err" >&2; echo "--- sink.log ---"; cat "$WORK/sink.log" >&2
  fail "control: the public-symbol curl did not deliver its value (rc=$pub_rc)"
fi

# The secret: runs with its placeholder left as written (confidentiality.md §7.1).
MANDU_ARBITER_SOCK="$SOCK" "$CSHIMDIR/curl" -sS -m 10 -o /dev/null -d "k=$SSYM" "http://127.0.0.1:$SINK_PORT/secret" 2>"$WORK/sf-sec.err"
sec_rc=$?
echo "      secret curl rc=$sec_rc; stderr: $(head -c 300 "$WORK/sf-sec.err" | tr '\n' ' ')"
# THE ORACLE first: the secret's bytes never reached the sink.
if ! grep -qF "$SECRET" "$WORK/sink.log"; then
  pass "the sink never received the secret's bytes"
else
  echo "--- sink.log ---"; cat "$WORK/sink.log" >&2
  fail "SECURITY: the secret's bytes reached the network sink"
fi
if [[ $sec_rc -eq 0 ]] && ! grep -q "blocked, nothing ran" "$WORK/sf-sec.err" && grep -qxF "/secret k=$SSYM" "$WORK/sink.log"; then
  pass "HumanShell: the curl carrying the SECRET's symbol ran with the placeholder as written (the sink got the placeholder)"
else
  echo "--- sink.log ---"; cat "$WORK/sink.log" >&2
  fail "HumanShell: expected the secret-bearing curl to run with its placeholder, got rc=$sec_rc"
fi
kill "$sink_pid" 2>/dev/null; wait "$sink_pid" 2>/dev/null; sink_pid=""

# ── 3g. the `secrets` workspace is writable in the box (2026-10-01) ──────────
# The over-block a replay smoke run found: in `secrets` there is no AgentView
# pair, the box was RO-root + /tmp, and every in-place writer the box shadows
# failed in the workspace (`sed: couldn't open temporary file src/sedXXXXXX:
# Read-only file system`). With integrity OFF the launcher now bakes
# MANDU_EXEC_BOX_WORKSPACE_RW=1 and the box binds the project WRITABLE at its
# own path (exec-routing.md §7.2, "The workspace without an AgentView"):
#   - the bug: a shim WITHOUT the flag fails `sed -i` with EROFS, file as was;
#   - the fix: `sed -i` and `sort -o` edit the real files;
#   - a write outside the project is still refused by the RO root;
#   - a no-model labelled file in the project, confined by its twin as the
#     launcher's secret wrap does (planSecretTwins, the box nested inside the
#     wrap as in a live session), still reads as its symbol in the box: `cat`,
#     a copy written INTO the writable project, and `sed -i` on the file (which
#     fails at the twin's mount point) never put the raw bytes anywhere, and
#     the real file is untouched.
echo "[3g] the secrets-mode workspace: boxed in-place writers work, a labelled file stays a symbol ..."
owned_dir WSB "$HOME/.mandu-boxws.XXXXXX" || skip "cannot create a project dir under \$HOME"
PROJ="$WSB/proj"; mkdir -p "$PROJ/src" "$WSB/outside"
printf 'const a = 1;\n' > "$PROJ/src/x.js"
printf 'b\na\n' > "$PROJ/list.txt"
WS_SECRET="WSRW_SECRET_$$_$RANDOM"; WS_SECRET_FILE="$PROJ/deploy.env"
printf 'TOKEN=%s\n' "$WS_SECRET" > "$WS_SECRET_FILE"
printf 'import { writeExecBoxShims } from "%s/launcher/src/services/exec-box-shims.js";\nconst [dir, rw] = process.argv.slice(2);\nconsole.log(writeExecBoxShims(["sed", "sort", "cat", "bash"], "%s", "%s", dir, undefined, undefined, false, "%s", undefined, rw === "1"));\n' \
  "$REPO_ROOT" "$BOX" "$SOCK" "$PROJ" > "$WORK/gen-ws.ts"
RO_SHIMS="$("$LAUNCHER_TSX" "$WORK/gen-ws.ts" "$WORK/ws-ro" 0 2>"$WORK/genws.err")" || { cat "$WORK/genws.err" >&2; rm -rf "$WSB"; skip "could not run the workspace shim writer"; }
RW_SHIMS="$("$LAUNCHER_TSX" "$WORK/gen-ws.ts" "$WORK/ws-rw" 1 2>>"$WORK/genws.err")" || { cat "$WORK/genws.err" >&2; rm -rf "$WSB"; skip "could not run the workspace shim writer"; }
if grep -qx 'export MANDU_EXEC_BOX_WORKSPACE_RW="1"' "$RW_SHIMS/sed" && grep -qx 'unset MANDU_EXEC_BOX_WORKSPACE_RW' "$RO_SHIMS/sed"; then
  pass "the shim bakes the writable workspace HARD when asked (export) and unsets it otherwise"
else
  fail "the workspace flag is not baked as expected: $(grep -h WORKSPACE_RW "$RW_SHIMS/sed" "$RO_SHIMS/sed" | tr '\n' ' ')"
fi

# The bug, reproduced: no flag → EROFS, the file as it was.
( cd "$PROJ" && MANDU_ARBITER_SOCK="$SOCK" "$RO_SHIMS/sed" -i 's/a/b/' src/x.js ) >/dev/null 2>"$WORK/ws-ro.err"
ws_ro_rc=$?
if [[ $ws_ro_rc -ne 0 ]] && grep -q "Read-only file system" "$WORK/ws-ro.err" && [[ "$(cat "$PROJ/src/x.js")" == "const a = 1;" ]]; then
  pass "without the flag a boxed sed -i fails EROFS in the workspace (the 2026-10-01 over-block, reproduced)"
else
  echo "--- ws-ro.err ---"; cat "$WORK/ws-ro.err" >&2
  fail "the read-only control did not reproduce the over-block (rc=$ws_ro_rc, x.js='$(cat "$PROJ/src/x.js")')"
fi

# The fix: both in-place writers edit the real files.
( cd "$PROJ" && MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/sed" -i 's/a/b/' src/x.js && MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/sort" -o list.txt list.txt ) >/dev/null 2>"$WORK/ws-rw.err"
ws_rw_rc=$?
if [[ $ws_rw_rc -eq 0 && "$(cat "$PROJ/src/x.js")" == "const b = 1;" && "$(cat "$PROJ/list.txt")" == $'a\nb' ]]; then
  pass "with the flag a boxed sed -i and sort -o edit the real files in the workspace"
else
  echo "--- ws-rw.err ---"; cat "$WORK/ws-rw.err" >&2
  if grep -q "Read-only file system" "$WORK/ws-rw.err"; then
    fail "the workspace is still read-only in the box — is $BOX rebuilt? (scripts/build-native.sh)"
  else
    fail "the boxed in-place writers failed (rc=$ws_rw_rc, x.js='$(cat "$PROJ/src/x.js")', list='$(tr '\n' ' ' < "$PROJ/list.txt")')"
  fi
fi
# Outside the project the RO root still holds (box ran: marker printed).
ws_out="$( cd "$WSB/outside" && MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/bash" -c '{ echo nope > out.txt; } 2>/dev/null && echo WRITE-OK || echo WRITE-DENIED' 2>"$WORK/ws-out.err" )"
if [[ "$ws_out" == "WRITE-DENIED" && ! -e "$WSB/outside/out.txt" ]]; then
  pass "a boxed write outside the writable workspace is still refused by the RO root"
else
  echo "--- ws-out.err ---"; cat "$WORK/ws-out.err" >&2
  fail "outside the workspace: expected WRITE-DENIED, got '$ws_out'"
fi
# The box is still net-off with the workspace writable.
ws_net="$(MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/bash" -c "$PROBE" 2>/dev/null)"
if [[ "$ws_net" == "BLOCKED" ]]; then
  pass "the box with a writable workspace is still net-off"
else
  fail "the box with a writable workspace reached the network: '$ws_net'"
fi

# The labelled file, confined by its twin (the launcher's secret wrap), with
# the box nested inside the wrap as in a live session.
WLBL="$(rpc "$ADMIN_SOCK" setPathLabel "path=$WS_SECRET_FILE" confidentiality=no-model)"
[[ "$WLBL" == *'"ok":true'* ]] || { echo "$WLBL"; fail "setPathLabel (workspace secret) failed"; }
WSSYM="$(symbolize "TOKEN=$WS_SECRET" "$WS_SECRET_FILE")"
cat > "$WORK/twin-plan.ts" <<EOF
import { writeFileSync, mkdirSync } from "node:fs";
import { planSecretTwins } from "$REPO_ROOT/launcher/src/secret-twins.js";
const plan = planSecretTwins([{ path: "$WS_SECRET_FILE", symbol: "$WSSYM", level: "no-model" }], "$WORK/twins", "$(command -v bwrap)");
mkdirSync("$WORK/twins", { recursive: true });
for (const f of plan.files) writeFileSync(f.twinPath, f.content, { mode: 0o600 });
console.log(plan.wrapArgv.join("\n"));
EOF
mapfile -t TWIN_WRAP < <("$LAUNCHER_TSX" "$WORK/twin-plan.ts" 2>"$WORK/twinplan.err")
if [[ "$WSSYM" != '$MDU:nomodel_'* || ${#TWIN_WRAP[@]} -eq 0 ]]; then
  cat "$WORK/twinplan.err" "$WORK/rpc.err" >&2
  fail "could not build the twin wrap for the workspace secret (symbol='$WSSYM')"
elif ! "${TWIN_WRAP[@]}" bwrap --unshare-user --unshare-pid --unshare-net --ro-bind / / -- true >/dev/null 2>&1; then
  echo "NOTE: a sandbox cannot start inside the twin wrap on this host (the nesting probe, secret-twins.ts) — skipping the twin legs"
else
  tw_cat="$( cd "$PROJ" && "${TWIN_WRAP[@]}" env MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/cat" deploy.env 2>"$WORK/tw-cat.err" )"
  ( cd "$PROJ" && "${TWIN_WRAP[@]}" env MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/bash" -c 'cat deploy.env > copy.txt' ) 2>"$WORK/tw-copy.err"
  ( cd "$PROJ" && "${TWIN_WRAP[@]}" env MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/sed" -i 's/TOKEN/LEAK/' deploy.env ) >/dev/null 2>"$WORK/tw-sed.err"
  tw_sed_rc=$?
  echo "      in-box cat → '$tw_cat'; copy.txt → '$(cat "$PROJ/copy.txt" 2>/dev/null)'; sed -i rc=$tw_sed_rc"
  if [[ "$tw_cat" == "$WSSYM" && "$tw_cat" != *"$WS_SECRET"* ]]; then
    pass "a boxed cat of the labelled workspace file reads its symbol through the writable bind, never the bytes"
  else
    echo "--- tw-cat.err ---"; cat "$WORK/tw-cat.err" >&2
    fail "SECURITY: the boxed cat of the labelled file did not read its symbol: '$tw_cat'"
  fi
  if [[ "$(cat "$PROJ/copy.txt" 2>/dev/null)" == "$WSSYM" ]]; then
    pass "a copy the box writes into the writable workspace carries the symbol, not the secret"
  else
    echo "--- tw-copy.err ---"; cat "$WORK/tw-copy.err" >&2
    fail "the in-box copy into the workspace is not the symbol: '$(cat "$PROJ/copy.txt" 2>/dev/null)'"
  fi
  if [[ $tw_sed_rc -ne 0 && "$(cat "$WS_SECRET_FILE")" == "TOKEN=$WS_SECRET" ]]; then
    pass "sed -i on the labelled file fails at its twin's mount point; the real file is untouched"
  else
    echo "--- tw-sed.err ---"; cat "$WORK/tw-sed.err" >&2
    fail "sed -i on the labelled file: rc=$tw_sed_rc, real file now '$(cat "$WS_SECRET_FILE")'"
  fi
  leaks="$(grep -rlF "$WS_SECRET" "$PROJ" 2>/dev/null | grep -vxF "$WS_SECRET_FILE")"
  if [[ -z "$leaks" ]]; then
    pass "no file in the writable workspace but the labelled one holds the secret's bytes"
  else
    fail "SECURITY: the secret's bytes reached the workspace through the box: $leaks"
  fi
fi
# The agent's own /tmp (2026-10-19, exec-routing.md §7.2): demo-c14's agent
# wrote `curl -o /tmp/reset1042.out …` unboxed, then a boxed `cat` of it read
# the box's fresh tmpfs ("No such file or directory"). With the flag the box
# shows the real /tmp (its sockets masked); without it, a fresh one.
TMPF="/tmp/mandu-boxtmp-$$-$RANDOM"
printf 'processing\n' > "$TMPF.out"
TMPS="$TMPF.sock"
tmps_pid=""
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); time.sleep(60)' "$TMPS" &
  tmps_pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -S "$TMPS" ]] && break; sleep 0.2; done
fi
rw_tmp="$( cd "$PROJ" 2>/dev/null || cd "$WSB"; MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/cat" "$TMPF.out" 2>"$WORK/tmp-rw.err" )"
ro_tmp="$( cd "$WSB"; MANDU_ARBITER_SOCK="$SOCK" "$RO_SHIMS/cat" "$TMPF.out" 2>&1 )"
rw_sock="$( cd "$WSB"; MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/bash" -c "if test -S '$TMPS'; then echo SOCKET; elif test -c '$TMPS'; then echo MASKED; else echo GONE; fi" 2>/dev/null )"
( cd "$WSB"; MANDU_ARBITER_SOCK="$SOCK" "$RW_SHIMS/bash" -c "echo boxed > '$TMPF.box'" ) 2>/dev/null
[[ -n "$tmps_pid" ]] && { kill "$tmps_pid" 2>/dev/null; wait "$tmps_pid" 2>/dev/null; }
if [[ "$rw_tmp" == "processing" ]]; then
  pass "integrity off: a boxed cat reads the file the agent wrote to /tmp (the agent's own /tmp)"
else
  echo "--- tmp-rw.err ---"; cat "$WORK/tmp-rw.err" >&2
  fail "integrity off: the boxed cat did not see the agent's /tmp file: '$rw_tmp' — is $BOX rebuilt? (scripts/build-native.sh)"
fi
if [[ "$(cat "$TMPF.box" 2>/dev/null)" == "boxed" ]]; then
  pass "integrity off: a boxed write to /tmp lands in the agent's /tmp"
else
  fail "integrity off: the boxed write to /tmp did not reach the real /tmp"
fi
if [[ -z "$tmps_pid" ]]; then
  echo "NOTE: python3 not found — skipping the /tmp socket mask leg"
elif [[ "$rw_sock" == "MASKED" ]]; then
  pass "integrity off: a Unix socket in the real /tmp is masked in-box"
else
  fail "SECURITY: the /tmp socket in the box reads '$rw_sock', not masked"
fi
if [[ "$ro_tmp" == *"No such file"* ]]; then
  pass "without the flag the box keeps a fresh /tmp (the integrity-ON scratch)"
else
  fail "without the flag the box saw the real /tmp: '$ro_tmp'"
fi
rm -f "$TMPF.out" "$TMPF.box" "$TMPS"
rm -rf "$WSB"

# ── 3h. the box's `bwrap --help`, kept by content (exec-routing.md §4) ───────
# The launcher asks the box's bubblewrap `--help` once and bakes the sha256 of
# its bytes into the shims; the box skips its own probe only for exactly those
# bytes. Two stand-ins on PATH ahead of the real bubblewrap, each delegating
# to it and logging every `--help`: NEW (as the real one) and OLD (a bwrap
# < 0.8: no --disable-userns in its help, and the flag rejected). Proves: the
# kept answer skips the probe; a changed binary is probed again; a kept answer
# naming the OLD one's bytes (a forged positive, whoever set it) makes the box
# fail closed, never run the command less confined; without one, the OLD one
# is probed and the box runs with the seccomp denial instead.
echo "[3h] the kept bwrap --help answer ..."
REAL_BWRAP="$(command -v bwrap)"
KB="$WORK/kept-bwrap"; mkdir -p "$KB/new" "$KB/old"
cat > "$KB/new/bwrap" <<EOF
#!/bin/sh
[ "\$1" = --help ] && echo help >> "$KB/new.log"
exec "$REAL_BWRAP" "\$@"
EOF
cat > "$KB/old/bwrap" <<EOF
#!/bin/sh
if [ "\$1" = --help ]; then echo help >> "$KB/old.log"; "$REAL_BWRAP" --help | grep -v -e '--disable-userns'; exit 0; fi
for a in "\$@"; do [ "\$a" = --disable-userns ] && { echo "bwrap: Unknown option --disable-userns" >&2; exit 1; }; done
exec "$REAL_BWRAP" "\$@"
EOF
chmod 755 "$KB/new/bwrap" "$KB/old/bwrap"
cat > "$KB/gen.ts" <<EOF
import { writeExecBoxShims } from "$REPO_ROOT/launcher/src/services/exec-box-shims.js";
import { keptBwrapDisableUserns } from "$REPO_ROOT/launcher/src/exec-box-setup.js";
const [dir, forged] = process.argv.slice(2);
const kept = forged === "-" ? keptBwrapDisableUserns(dir === "-" ? undefined : dir) : forged === "none" ? undefined : forged;
console.log(writeExecBoxShims(["cat"], "$BOX", "$SOCK", "$KB/" + (dir === "-" ? "none" : dir.split("/").pop()) + "-" + (forged === "-" ? "probed" : forged === "none" ? "unset" : "forged"), undefined, undefined, undefined, undefined, undefined, undefined, kept));
EOF
kb_gen() { "$LAUNCHER_TSX" "$KB/gen.ts" "$@" 2>>"$KB/gen.err"; }
kb_helps() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }
KB_NEW_SHIMS="$(kb_gen "$KB/new" -)"; KB_UNSET_SHIMS="$(kb_gen "$KB/new" none)"
OLD_SHA="$(sha256sum "$KB/old/bwrap" | cut -d' ' -f1)"
KB_FORGED_SHIMS="$(kb_gen "$KB/old" "$OLD_SHA")"
KB_OLD_UNSET_SHIMS="$(kb_gen "$KB/old" none)"
if [[ ! -x "$KB_NEW_SHIMS/cat" || ! -x "$KB_FORGED_SHIMS/cat" ]]; then
  cat "$KB/gen.err" >&2; fail "could not write the kept-bwrap shims"
else
  probes_at_launch="$(kb_helps "$KB/new.log")"
  if grep -qF "export MANDU_BWRAP_DISABLE_USERNS_SHA256=\"$(sha256sum "$KB/new/bwrap" | cut -d' ' -f1)\"" "$KB_NEW_SHIMS/cat"; then
    pass "the launcher probed the box's bubblewrap once and baked the sha256 of its bytes"
  else
    fail "the shim does not carry the NEW stand-in's hash: $(grep BWRAP "$KB_NEW_SHIMS/cat")"
  fi
  RO_FILE="/etc/hostname"; [[ -r "$RO_FILE" ]] || RO_FILE="/etc/os-release"
  kb_out="$(PATH="$KB/new:$PATH" MANDU_ARBITER_SOCK="$SOCK" "$KB_NEW_SHIMS/cat" "$RO_FILE" 2>"$KB/new.err")"; kb_rc=$?
  if [[ $kb_rc -eq 0 && "$kb_out" == "$(cat "$RO_FILE")" && "$(kb_helps "$KB/new.log")" == "$probes_at_launch" ]]; then
    pass "with the kept answer the box ran the command and asked bwrap --help no more"
  else
    cat "$KB/new.err" >&2; fail "kept answer: rc=$kb_rc, --help asked $(kb_helps "$KB/new.log") times (at launch: $probes_at_launch)"
  fi
  PATH="$KB/new:$PATH" MANDU_ARBITER_SOCK="$SOCK" "$KB_UNSET_SHIMS/cat" "$RO_FILE" >/dev/null 2>&1
  if [[ "$(kb_helps "$KB/new.log")" -eq $((probes_at_launch + 1)) ]]; then
    pass "control: without a kept answer the box asks bwrap --help itself"
  else
    fail "control: --help asked $(kb_helps "$KB/new.log") times, expected $((probes_at_launch + 1))"
  fi
  # The bubblewrap changed under the kept answer: probed again.
  echo "# changed" >> "$KB/new/bwrap"
  before="$(kb_helps "$KB/new.log")"
  kb_out="$(PATH="$KB/new:$PATH" MANDU_ARBITER_SOCK="$SOCK" "$KB_NEW_SHIMS/cat" "$RO_FILE" 2>/dev/null)"; kb_rc=$?
  if [[ $kb_rc -eq 0 && "$(kb_helps "$KB/new.log")" -eq $((before + 1)) ]]; then
    pass "a bubblewrap whose bytes changed is probed again (the kept answer names the old bytes)"
  else
    fail "changed bubblewrap: rc=$kb_rc, --help asked $(kb_helps "$KB/new.log") times (before: $before)"
  fi
  # A forged positive for a bubblewrap that lacks the flag: fail closed.
  kb_out="$(PATH="$KB/old:$PATH" MANDU_ARBITER_SOCK="$SOCK" "$KB_FORGED_SHIMS/cat" "$RO_FILE" 2>"$KB/forged.err")"; kb_rc=$?
  if [[ $kb_rc -ne 0 && -z "$kb_out" && "$(kb_helps "$KB/old.log")" -eq 0 ]] && grep -q "Unknown option --disable-userns" "$KB/forged.err"; then
    pass "a forged kept answer for an old bubblewrap fails the command closed (it never ran)"
  else
    cat "$KB/forged.err" >&2; fail "SECURITY: a forged kept answer: rc=$kb_rc, out='$kb_out'"
  fi
  # And the OLD one probed (no kept answer): it runs, the denial in seccomp.
  kb_out="$(PATH="$KB/old:$PATH" MANDU_ARBITER_SOCK="$SOCK" "$KB_OLD_UNSET_SHIMS/cat" "$RO_FILE" 2>"$KB/old.err")"; kb_rc=$?
  if [[ $kb_rc -eq 0 && "$kb_out" == "$(cat "$RO_FILE")" && "$(kb_helps "$KB/old.log")" -eq 1 ]]; then
    pass "without a kept answer an old bubblewrap is probed and the box still runs"
  else
    cat "$KB/old.err" >&2; fail "old bubblewrap, probed: rc=$kb_rc, --help asked $(kb_helps "$KB/old.log") times"
  fi
fi

# ── 4. graceful degrade: applyExecBox with the bin ABSENT warns, sets no dir ──
echo "[4/4] applyExecBox degrades gracefully when the box bin is absent ..."
cat > "$WORK/degrade.ts" <<EOF
import { applyExecBox } from "$REPO_ROOT/launcher/src/exec-box-setup.js";
const plan: any = { execBox: true, execBoxCmds: ["cat"], arbiterSock: "$SOCK" };
const logs: string[] = [];
const r = applyExecBox(plan, "$WORK", {
  resolveBin: () => null,           // bin not built
  commandExists: () => true, usernsOk: () => true, arbiterSockExists: () => true,
  log: (m: string) => logs.push(m),
});
if (r !== null) { console.error("degrade returned non-null"); process.exit(1); }
if (plan.execBoxShimDir !== undefined) { console.error("shim dir set on degrade"); process.exit(1); }
if (!logs.some((l) => /not built/.test(l) && /WITHOUT/.test(l))) { console.error("no degrade warning: " + JSON.stringify(logs)); process.exit(1); }
console.log("DEGRADE_OK");
EOF
if "$LAUNCHER_TSX" "$WORK/degrade.ts" 2>"$WORK/degrade.err" | grep -q DEGRADE_OK; then
  pass "applyExecBox warns + proceeds WITHOUT boxing when the bin is absent (never fails the launch)"
else
  echo "--- degrade.err ---"; cat "$WORK/degrade.err" >&2
  fail "applyExecBox did not degrade gracefully with the bin absent"
fi

echo "─────────────────────────────────────────"
echo "exec-box-live.test.sh: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
