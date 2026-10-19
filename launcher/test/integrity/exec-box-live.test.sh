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
#   3. WRITABLE AgentView (fs-view co-design, §7.2): a shim baked with the
#      session's MANDU_AGENTVIEW_ROOT/WORKSPACE, run with cwd = the AgentView
#      real path, WRITES a relative file that lands in the AgentView on the host
#      (the identity bind), while the same write outside any bind is denied.
#   3d. A PROJECT UNDER /tmp (checklist a7): a no-view shim baked with the
#      project root runs at a /tmp cwd, reads the project, cannot see a /tmp
#      sibling, and cannot write the project (the RO re-bind over the fresh /tmp).
#   3e. THE SOCKET ALLOW-LIST (§4.2): a boxed command reaches a Unix socket it
#      bound and is refused a host socket, alone and under the real guard
#      (which serves the box when it holds the chain's only listener); under
#      a guard that does not serve boxes every connect is refused.
#   4. applyExecBox DEGRADES gracefully (warn + no shim dir, never throws) when
#      the box bin is absent — so --exec-box never fails a launch.
#
# SKIPs cleanly (exit 0) when node / bwrap / unprivileged userns / the arbiter
# tsx / the box bin are unavailable — environment gaps, not failures.
#
# Run:  MANDU_EXPERIMENTAL_INTEGRITY=1 bash launcher/test/integrity/exec-box-live.test.sh
#
# FROZEN LANE (protection-modes.md §10.5, §10.7): the pre-2026-09-29 integrity form
# of launcher/test/exec-box-live.test.sh, copied verbatim (only the two
# repo-relative paths changed for the deeper directory). Its integrity-only leg
# is §3c, the writable AgentView (fs-view co-design, AgentView is integrity-
# only); the default-lane form runs the shared legs in `secrets`.
#
set -uo pipefail
# This suite STATES its axes (docs/design/architecture/protection-modes.md §4): the arbiter it
# spawns and the launcher it runs both read these, so a change of the built-in
# default can never quietly change what the suite proves. STRICT makes an
# unstated axis a startup error in the arbiter.
export MANDU_AXES_STRICT=1 MANDU_INTEGRITY=1 MANDU_CONFIDENTIALITY=0

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
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
SOCK="$WORK/arbiter.sock"
arbiter_pid=""; listen_pid=""
cleanup() {
  [[ -n "$listen_pid" ]] && kill "$listen_pid" 2>/dev/null
  [[ -n "$arbiter_pid" ]] && { kill -- "-$arbiter_pid" 2>/dev/null || kill "$arbiter_pid" 2>/dev/null; }
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
# Lifeline backstop (lib/lifeline.sh): reaps the arbiter if this shell dies
# without its trap (SIGKILL / abandoned hang).
source "$(dirname "${BASH_SOURCE[0]}")/../lib/lifeline.sh"
mdu_lifeline_init "$WORK"

# ── 1. a real arbiter (the box classifies exec through it — fail-closed w/o it) ─
echo "[1/4] booting the arbiter on $SOCK ..."
setsid env MANDU_ARBITER_SOCK="$SOCK" MANDU_HOME="$WORK/mandu-home" \
  MANDU_LIFELINE=stdin \
  "$ARBITER_TSX" "$ARBITER_MAIN" "$SOCK" <"$MANDU_LIFELINE_FIFO" 9>&- >"$WORK/arbiter.log" 2>&1 &
arbiter_pid=$!
tries=200
while (( tries-- > 0 )); do
  [[ -S "$SOCK" ]] && break
  kill -0 "$arbiter_pid" 2>/dev/null || { cat "$WORK/arbiter.log" >&2; skip "arbiter exited early"; }
  sleep 0.1
done
[[ -S "$SOCK" ]] || { cat "$WORK/arbiter.log" >&2; skip "arbiter socket never appeared"; }
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
node -e 'require("net").createServer(s=>s.destroy()).listen(0,"127.0.0.1",function(){process.stdout.write(String(this.address().port))})' >"$WORK/port" 2>/dev/null &
listen_pid=$!; sleep 0.5; PORT="$(cat "$WORK/port" 2>/dev/null)"
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

# ── 3c. WRITABLE AgentView: a view-baked shim writes at its AgentView cwd ──────
# fs-view cwd's the live agent INTO the AgentView worktree, so the box must make
# that cwd writable (the identity bind). Bake a shim with the session view pair,
# run it with cwd = the AgentView real path, and assert a relative write lands in
# the AgentView on the host — and that the same write OUTSIDE any bind is denied.
echo "[3c] a view-baked box writes at its AgentView cwd (and nowhere else) ..."
AV="$WORK/agentview"; WS="$WORK/workspace"; OUTSIDE="$WORK/outside"
mkdir -p "$AV" "$WS" "$OUTSIDE"
echo "marker" > "$AV/marker.txt"
cat > "$WORK/gen-view.ts" <<EOF
import { writeExecBoxShims } from "$REPO_ROOT/launcher/src/services/exec-box-shims.js";
const dir = writeExecBoxShims(["sh"], "$BOX", "$SOCK", "$WORK/view", { agentViewRoot: "$AV", workspace: "$WS" });
console.log(dir);
EOF
VSHIMDIR="$("$LAUNCHER_TSX" "$WORK/gen-view.ts" 2>"$WORK/genview.err")" || { cat "$WORK/genview.err" >&2; skip "could not run the view shim writer"; }
# Confirm the shim baked the ViewConfig env (the co-design wiring).
if grep -qF "MANDU_AGENTVIEW_ROOT=\"$AV\"" "$VSHIMDIR/sh" && grep -qF "MANDU_WORKSPACE=\"$WS\"" "$VSHIMDIR/sh"; then
  pass "the view-baked shim exports MANDU_AGENTVIEW_ROOT/WORKSPACE (fs-view co-design wired)"
else
  echo "--- view shim ---"; cat "$VSHIMDIR/sh"; fail "the view shim did not bake the ViewConfig env"
fi
# Write at the AgentView cwd: lands in the AgentView on the host (writes to the
# workspace-path bind ALSO reach the AgentView src, so the host AV is the oracle).
( cd "$AV" && MANDU_ARBITER_SOCK="$SOCK" "$VSHIMDIR/sh" -c 'test -f marker.txt && echo boxed-write > out.txt' ) >"$WORK/vw.out" 2>"$WORK/vw.err"
vw_rc=$?
if [[ $vw_rc -eq 0 && -f "$AV/out.txt" && "$(cat "$AV/out.txt")" == "boxed-write" ]]; then
  pass "a boxed write at the AgentView cwd landed in the AgentView on the host (identity bind live)"
else
  echo "--- vw.err ---"; cat "$WORK/vw.err" >&2
  fail "the boxed AgentView write did not land (rc=$vw_rc, out.txt present: $([[ -f "$AV/out.txt" ]] && echo yes || echo no))"
fi
# The workspace real dir must NOT have received the write (writes go to the
# AgentView src via the bind, not the real workspace path).
if [[ ! -f "$WS/out.txt" ]]; then
  pass "the real workspace dir was untouched (writes route to the AgentView, not the HumanView)"
else
  fail "the boxed write leaked into the real workspace dir"
fi
# A write OUTSIDE any bind (a sibling real dir) is denied by the RO root.
( cd "$OUTSIDE" && MANDU_ARBITER_SOCK="$SOCK" "$VSHIMDIR/sh" -c 'echo nope > out.txt' ) >/dev/null 2>"$WORK/vo.err"
if [[ ! -f "$OUTSIDE/out.txt" ]]; then
  pass "a boxed write outside every bind was denied by the RO root (no host file)"
else
  fail "a boxed write escaped the box to an unbound real dir"
fi

# ── 3d. a PROJECT UNDER /tmp (open-source-release checklist a7) ──────────────
# The box mounts a fresh tmpfs at /tmp, so a no-view launch from /tmp/x/proj
# died on every boxed command with `bwrap: Can't chdir`. The shim now bakes the
# launch's project (writeExecBoxShims' projectRoot) and the box re-binds it
# READ-ONLY over its /tmp: the command runs at its cwd and reads the project,
# a sibling elsewhere in the real /tmp stays invisible, the project stays RO.
echo "[3d] a no-view box runs in a project under /tmp (RO, siblings hidden) ..."
TP_BASE="$(mktemp -d /tmp/mandu-execbox-tmpproj.XXXXXX)" || skip "cannot create a /tmp project"
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
  SK="$(mktemp -d "$HOME/.mandu-boxsock.XXXXXX")" || skip "cannot create a socket dir under \$HOME"
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
