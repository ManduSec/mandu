#!/usr/bin/env bash
#
# reply-filter-live.test.sh — LIVE e2e oracle: the Mandu USER-REPLY egress
# chokepoint is a real, unprivileged, cooperative chokepoint wired through
# `mandu-run.sh` — ON BY DEFAULT (no flag needed; step [2] deliberately
# passes no reply-filter flag to prove the default; `--reply-filter` remains
# the redundant-but-explicit opt-in, exercised in step [3]; step [4] proves
# `--no-reply-filter` disables the wrapping entirely).
#
# Proves HumanView reply fidelity END-TO-END through the launcher: the agent's
# stdout carries an opaque $MDU:* token (exactly what T-LLM's final answer
# looks like — its context only ever holds symbols), and the human reading the
# terminal sees the ORIGINAL value instead (paper: "resolve symbols in
# user-facing replies"; OpenClaw hook: message_sending). The registered symbol
# is deliberately NESTED (a symbol whose value contains another symbol) so this
# also proves the arbiter's DEEP desymbolize through the whole launcher path.
#
# Runs in `secrets` mode (test-organization.md §7, re-pinned 2026-09-29): the
# symbol is a SECRET's. A workspace file is labelled `no-model` over the
# arbiter's admin channel (the user's act) and its bytes are symbolized with
# that file as origin, so the arbiter derives the level itself
# (`$MDU:nomodel_…`). The reply filter is a HumanView surface: the human owns
# their secrets at every level, so its deep desymbolize reveals the value
# (confidentiality.md §4/§7, the reply-filter row). The control leg [1c] shows
# the confidentiality gate is live on the same symbol: the model-facing deep
# `resolve` (the U-LLM quarantine path) is REFUSED for it. The secret never
# reaches stdout with the filter off or the arbiter down, nor the launcher's
# stderr. (The pre-2026-09-29 form pinned integrity and minted an untrusted
# Read symbol; the reply filter is shared code, protection-modes.md §10.2, so no
# integrity-only assertion was dropped.)
#
# The arbiter-mandatory dual: with a DEAD arbiter socket (autostart disabled) the
# TS launcher FAIL-CLOSES — it refuses to run the agent ungated, so nothing can
# leak (a stronger guarantee than the retired bash launcher's passthrough-degrade).
#
# Offline + unprivileged: a real arbiter daemon on a temp socket + isolated
# symbol DB / event dir; the "agent" is a bash one-liner echoing the symbol.
# Every launch gets a throwaway HOME, so the launcher's `secrets` walk never
# scans the developer's home. Everything under a temp dir, reaped (group-kill the arbiter) on exit.
#
# SKIPs cleanly (exit 0) when node / npm or the arbiter / reply-filter deps are
# unavailable — environment gaps, not failures. An arbiter that never comes
# up (or refuses the setup calls) is a FAILURE, with its log's last lines.
#
# Run:  bash launcher/test/reply-filter-live.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$HERE/../mandu-run.sh"
# mandu-run.sh now shims the TS launcher, which turns ON every rung by default.
# This oracle tests ONLY the reply-filter egress (default-on + the --no-reply-filter
# opt-out), so isolate that: disable the OTHER rungs via env (fs-sync's worktree, the
# kernel confines, net-proxy, exec-wrap, the model proxy) — but LEAVE reply-filter to
# its default so the by-default case still exercises it and the opt-out flag still wins.
export MANDU_FS_SYNC=0 MANDU_NO_KERNEL=1 MANDU_NO_CONTEXT_PROXY=1 MANDU_NET_PROXY=0 MANDU_EXEC_WRAP=0
# The rung banners this oracle greps print only under --verbose since the
# one-line default display (launch-banner.ts, release checklist a6).
export MANDU_VERBOSE=1
# This suite STATES its axes (docs/design/architecture/protection-modes.md §4): the arbiter it
# spawns and the launcher it runs both read these, so a change of the built-in
# default can never quietly change what the suite proves. STRICT makes an
# unstated axis a startup error in the arbiter. `secrets`: confidentiality ON,
# integrity OFF (the built-in default, named here all the same).
export MANDU_AXES_STRICT=1 MANDU_INTEGRITY=0 MANDU_CONFIDENTIALITY=1
# No host policy.yaml: the only label in force is the one this suite sets.
export MANDU_POLICY_FILE=/dev/null/mandu-test-no-policy.yaml
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
ARBITER_DIR="$REPO_ROOT/arbiter"
ARBITER_MAIN="$ARBITER_DIR/ipc/server-main.ts"
ARBITER_TSX="$ARBITER_DIR/node_modules/.bin/tsx"
REPLYFILTER_DIR="$REPO_ROOT/interceptors/reply-filter"
REPLYFILTER_TSX="$REPLYFILTER_DIR/node_modules/.bin/tsx"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

skip() {
  echo "SKIP: $1"
  echo "─────────────────────────────────────────"
  echo "reply-filter-live.test.sh: 0 passed, 0 failed (skipped)"
  exit 0
}

# A broken run, not a missing prerequisite: the arbiter this suite started did
# not come up, or refused the setup calls. FAIL with why and the log's last
# lines (scripts/lib/ready-deadline.sh), never SKIP: a suite that goes quiet
# must not show green.
abort() {
  echo "FAIL: $1"
  if [[ -n "${2:-}" ]]; then mdu_log_tail "$2"; fi
  echo "─────────────────────────────────────────"
  echo "reply-filter-live.test.sh: $PASS passed, $((FAIL + 1)) failed"
  exit 1
}

# ── 0. environment gates (skip, not fail, on a missing toolchain) ─────────────
command -v node >/dev/null 2>&1 || skip "node not on PATH"
command -v npm  >/dev/null 2>&1 || skip "npm not on PATH"
[[ -x "$ARBITER_TSX" ]] || skip "arbiter tsx not installed ($ARBITER_TSX) — run 'cd arbiter && npm install'"
[[ -x "$REPLYFILTER_TSX" && -f "$REPLYFILTER_DIR/src/run.ts" ]] \
  || skip "reply-filter deps not installed ($REPLYFILTER_DIR) — run 'cd interceptors/reply-filter && npm install'"

# ── 1. scratch dirs + a real arbiter daemon on a temp socket ───────────────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-replyfilter-live.XXXXXX")" || skip "mktemp failed"
# The Mandu home: a temp one under $WORK with no config.toml, so no host
# ~/.mandu/config.toml is read (the 7cdfc2c e2e rule) and nothing lands in the
# real home; the arbiter and every launch below inherit it.
export MANDU_HOME="$WORK/mandu-home"
# The runtime base (the instance registry, the human-plane socket, the
# launches' scope dirs): the suite's own, never the caller's
# $XDG_RUNTIME_DIR/mandu (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
ARBITER_SOCK="$WORK/arbiter.sock"
ADMIN_SOCK="$WORK/admin.sock"
# The launches' throwaway HOME (the launcher's secrets walk reads HOME).
LHOME="$WORK/home"
mkdir -p "$LHOME"

arbiter_pid=""
cleanup() {
  if [[ -n "$arbiter_pid" ]]; then
    mdu_stop_group "$arbiter_pid"
  fi
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
# Lifeline backstop (lib/lifeline.sh): reaps the arbiter if this shell dies
# without its trap (SIGKILL / abandoned hang).
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

echo "[1/?] booting the arbiter daemon on $ARBITER_SOCK ..."
setsid env MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
           MANDU_ADMIN_SOCK="$ADMIN_SOCK" \
           MANDU_HOME="$MANDU_HOME" \
           MANDU_LIFELINE=stdin \
  "$ARBITER_TSX" "$ARBITER_MAIN" "$ARBITER_SOCK" <"$MANDU_LIFELINE_FIFO" 9>&- >"$WORK/arbiter.log" 2>&1 &
arbiter_pid=$!

# The readiness budget (scripts/lib/ready-deadline.sh, runtime-instances.md
# §14.6): load-aware, doubled on CI; the wait ends at once if the daemon exits.
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO_ROOT/scripts/lib/ready-deadline.sh"
ready_ms="$(mdu_ready_deadline_ms)"
# A start that does not come up FAILS the suite (with the log's last lines),
# never SKIPs it: the prerequisites were all checked above.
mdu_wait_sockets "$arbiter_pid" "$ready_ms" "$ARBITER_SOCK" "$ADMIN_SOCK" \
  || abort "the arbiter did not come up: $(mdu_ready_why $? "$ready_ms")" "$WORK/arbiter.log"
echo "      arbiter up (pid $arbiter_pid)."

# ── 1b. register a NESTED chain of SECRET symbols via the arbiter ─────────────
# The secret lives in a workspace file the user labels `no-model` (admin
# channel, as the claude-e2e CONF-* scenarios arrange it). INNER: the file's
# bytes, symbolized with the file as origin, so the arbiter derives the level
# from the label. OUTER: a value CONTAINING the inner symbol, same origin. The
# reply filter's deep desymbolize must collapse BOTH layers.
SECRET="REPLY_SECRET_$$_$RANDOM"
SECRET_FILE="$WORK/ws/notes.md"
mkdir -p "$WORK/ws"
printf '%s\n' "$SECRET" > "$SECRET_FILE"
# rpc <sock> <op> <json-fields…>: one NDJSON request, prints the response line.
# The fields are "key=value" strings; values go through JSON.stringify.
rpc() {
  node -e '
    const net = require("net");
    const [sock, op, ...kv] = process.argv.slice(1);
    const req = { id: 1, op };
    for (const f of kv) { const i = f.indexOf("="); const v = f.slice(i + 1); req[f.slice(0, i)] = v === "true" ? true : v; }
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
symbolize() { # $1=value → prints the allocated symbol name
  rpc "$ARBITER_SOCK" symbolize tool=Read "value=$1" "origin=$SECRET_FILE" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);if(j.ok&&j.result&&j.result.symbol){process.stdout.write(j.result.symbol);return}}catch{}process.stderr.write("symbolize failed: "+s+"\n");process.exit(1)})' \
    2>>"$WORK/rpc.err"
}

echo "[1b/?] labelling the workspace file no-model; registering a NESTED chain of its symbols ..."
LBL="$(rpc "$ADMIN_SOCK" setPathLabel "path=$SECRET_FILE" confidentiality=no-model)"
[[ "$LBL" == *'"ok":true'* ]] || { echo "$LBL"; cat "$WORK/rpc.err" >&2; abort "the arbiter refused setPathLabel" "$WORK/arbiter.log"; }
INNER="$(symbolize "$SECRET")"
[[ "$INNER" == *'$MDU:'* ]] || { cat "$WORK/rpc.err" >&2; abort "could not register the inner symbol" "$WORK/arbiter.log"; }
OUTER="$(symbolize "wrapped: $INNER")"
[[ "$OUTER" == *'$MDU:'* ]] || { cat "$WORK/rpc.err" >&2; abort "could not register the outer symbol" "$WORK/arbiter.log"; }
echo "      inner=$INNER  outer=$OUTER"
# Both are SECRET symbols: the level came from the label, not from the caller.
if [[ "$INNER" == '$MDU:nomodel_'* && "$OUTER" == '$MDU:nomodel_'* ]]; then
  pass "both symbols carry the no-model level derived from the file's label (a SECRET's symbols)"
else
  fail "the symbols are not no-model secrets (the label did not reach the level): inner=$INNER outer=$OUTER"
fi

# ── 1c. CONTROL: the confidentiality gate is live on this very symbol ─────────
# The model-facing deep resolve (the U-LLM quarantine call is an egress to the
# model provider) REFUSES a no-model symbol in `secrets` mode
# (confidentiality.md §3.2/§3.3); only the HumanView desymbolize below reveals
# it. Without this leg, a run whose confidentiality axis went quiet would pass.
echo "[1c/?] control: the model-facing deep resolve of the outer symbol must be REFUSED ..."
RES="$(rpc "$ARBITER_SOCK" resolve "symbol=$OUTER" deep=true)"
echo "      resolve → ${RES:0:240}"
if [[ "$RES" == *'"value":null'* && "$RES" != *"$SECRET"* ]]; then
  pass "the model-facing deep resolve withheld the secret (the gate fires in secrets mode)"
else
  fail "the model-facing deep resolve released the secret or did not answer: '${RES:0:300}'"
fi

# ── 2. LIVE (BY DEFAULT): the agent's reply carries the OUTER symbol → the human
# sees the secret. NO reply-filter flag here — this proves the launcher's new
# default-on wiring. The stdout capture below is a PIPE, so the wrapper's
# TTY-safety decision (print-mode.ts) filters, same as any scripted run.
# Quoting discipline (mirrors exec-wrap-live): pass the symbol via an env var and
# reference it single-quoted so only the AGENT's bash expands it — the literal
# $MDU:* token lands on the agent's stdout, exactly like a real T-LLM reply.
echo "[2/?] reply through the launcher, DEFAULT wiring (expect the RAW secret on stdout, no token) ..."
reply_out="$(
  HOME="$LHOME" \
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_TEST_SYM="$OUTER" \
  bash "$LAUNCHER" --target claude --no-scope --no-mcp -- \
    bash -c 'echo "Summary: ${MANDU_TEST_SYM}"' \
    2>"$WORK/reply.err"
)"
reply_rc=$?
echo "      stdout: '$reply_out' (rc=$reply_rc)"

if [[ "$reply_rc" -eq 0 ]]; then
  pass "the launcher run exited 0"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/reply.err" >&2
  fail "the launcher run exited $reply_rc"
fi
if [[ "$reply_out" == *"$SECRET"* ]]; then
  pass "the human sees the RAW secret (deep resolution collapsed the NESTED chain)"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/reply.err" >&2
  fail "the reply did NOT resolve to the secret; got: '$reply_out'"
fi
if [[ "$reply_out" != *'$MDU:'* ]]; then
  pass "no opaque \$MDU:* token reached the human"
else
  fail "an opaque token leaked through to the human: '$reply_out'"
fi
if grep -qF "reply-filter LIVE" "$WORK/reply.err"; then
  pass "the launcher logged the LIVE user-reply egress chokepoint (by DEFAULT, no flag)"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/reply.err" >&2
  fail "the launcher did not log the LIVE reply filter"
fi
# Launch speed (packaging.md §5.3): by default the filter's process starts
# with the services and is handed the agent at the end — the resolved reply
# above came through that early start.
if grep -qF "reply filter started early" "$WORK/reply.err"; then
  pass "the reply filter was started early and handed the agent (the default)"
else
  fail "the default launch did not start the reply filter early"
fi
# The reveal is for the human's stdout alone: the launcher's own log never
# carries the value (it is not a HumanView surface for the reply).
if ! grep -qF "$SECRET" "$WORK/reply.err"; then
  pass "the secret did not reach the launcher's stderr (revealed on the reply surface only)"
else
  fail "the secret leaked into the launcher's stderr"
fi

# ── 3. Arbiter mandatory: DEAD arbiter + no autostart → the launcher FAIL-CLOSES ──
# The TS launcher makes the arbiter mandatory (ensureArbiter refuses to launch
# ungated when the socket is dead and autostart is disabled) — a STRONGER
# guarantee than the retired bash launcher's reply-filter passthrough-degrade: the
# agent never runs, so nothing can leak at all. (The reply-filter's own
# passthrough-when-unresolvable property, for an arbiter that dies MID-stream after
# a good launch, is covered by reply-filter.test.ts + the interceptor's tests.)
# Keeps the explicit --reply-filter flag so it still parses (documented opt-in).
echo "[3/?] arbiter mandatory: DEAD arbiter socket + no autostart → the launcher refuses to run ..."
# A marker only this launch's processes carry: the early-started reply filter
# inherits it, so a filter the refused launch left behind is found below.
abort_mark="$$_$RANDOM"
ABORT_MARK="MANDU_RF_ABORT_MARK=$abort_mark"
degrade_out="$(
  HOME="$LHOME" \
  MANDU_ARBITER_SOCK="$WORK/nothing-listens-here.sock" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_TEST_SYM="$OUTER" \
  MANDU_RF_ABORT_MARK="$abort_mark" \
  bash "$LAUNCHER" --target claude --reply-filter --no-scope --no-mcp -- \
    bash -c 'echo "Summary: ${MANDU_TEST_SYM}"; exit 7' \
    2>"$WORK/degrade.err"
)"
degrade_rc=$?
echo "      stdout: '$degrade_out' (rc=$degrade_rc)"

# Fail-closed = a non-zero exit that is NOT the agent's own 7 (the agent never ran).
if [[ "$degrade_rc" -ne 0 && "$degrade_rc" -ne 7 ]]; then
  pass "the launcher fail-closed on a dead arbiter (refused to run the agent ungated)"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/degrade.err" >&2
  fail "expected a fail-closed refusal on a dead arbiter, got rc=$degrade_rc"
fi
# The agent never ran, so its secret-bearing echo never reached stdout — no leak.
if [[ "$degrade_out" != *"$SECRET"* ]]; then
  pass "no secret reached stdout with the arbiter down (the agent never ran)"
else
  fail "leak: the secret reached stdout though the arbiter was down: '$degrade_out'"
fi
# The refusal came AFTER the reply filter's early start (packaging.md §5.3):
# the aborted launch must have ended it — no process of this launch is left
# by the time the launcher has returned.
if grep -qF "reply filter started early" "$WORK/degrade.err"; then
  pass "the refused launch had started its reply filter early (the abort path is exercised)"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/degrade.err" >&2
  fail "the refused launch did not start the reply filter early (the abort leg proves nothing)"
fi
left="$(grep -lsF "$ABORT_MARK" /proc/[0-9]*/environ 2>/dev/null | tr '\n' ' ')"
if [[ -z "$left" ]]; then
  pass "the aborted launch left no reply-filter process behind"
else
  for e in $left; do p="${e#/proc/}"; p="${p%%/*}"; echo "      left: $p $(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)"; kill -9 "$p" 2>/dev/null; done
  fail "the aborted launch left processes behind: $left"
fi

# ── 4. OPT-OUT: --no-reply-filter → no wrapping at all (token stays opaque) ───
# Even with a LIVE arbiter, the disabled filter must leave the reply untouched
# and the launcher must not log the reply-filter chokepoint.
echo "[4/?] opt-out: --no-reply-filter with a LIVE arbiter (expect the raw token, no LIVE log) ..."
optout_out="$(
  HOME="$LHOME" \
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_TEST_SYM="$OUTER" \
  bash "$LAUNCHER" --target claude --no-reply-filter --no-scope --no-mcp -- \
    bash -c 'echo "Summary: ${MANDU_TEST_SYM}"' \
    2>"$WORK/optout.err"
)"
echo "      stdout: '$optout_out'"

if [[ "$optout_out" == *'$MDU:'* && "$optout_out" != *"$SECRET"* ]]; then
  pass "--no-reply-filter: the token stays OPAQUE (filter disabled, nothing resolved)"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/optout.err" >&2
  fail "--no-reply-filter posture wrong; got: '$optout_out'"
fi
if ! grep -qF "reply-filter LIVE" "$WORK/optout.err"; then
  pass "--no-reply-filter: the launcher did not wire the reply-filter chokepoint"
else
  fail "--no-reply-filter still logged the LIVE reply filter"
fi

# ── 5. PTY RELAY: interactive TUIs get a REAL terminal AND resolved replies ───
# MANDU_REPLY_FILTER_PTY=1 forces the relay (this harness's stdout is a pipe,
# which would otherwise pick plain pipe filtering). The "agent" proves BOTH
# halves of the relay contract at once: stdout is a TTY from where it stands
# (util-linux script gave it a pty slave — a full-screen TUI would work), yet
# the symbol it prints still reaches the human RESOLVED.
if command -v script >/dev/null 2>&1 && script --version 2>/dev/null | grep -q util-linux; then
  echo "[5/?] PTY relay: forced relay — the agent must see a TTY and the reply must resolve ..."
  pty_out="$(
    HOME="$LHOME" \
    MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
    MANDU_NO_ARBITER_AUTOSTART=1 \
    MANDU_REPLY_FILTER_PTY=1 \
    MANDU_TEST_SYM="$OUTER" \
    bash "$LAUNCHER" --target claude --no-scope --no-mcp -- \
      bash -c 'if [ -t 1 ]; then echo "TTY-YES"; else echo "TTY-NO"; fi; echo "Summary: ${MANDU_TEST_SYM}"' \
      2>"$WORK/pty.err"
  )"
  pty_rc=$?
  echo "      stdout: '$pty_out' (rc=$pty_rc)"

  if [[ "$pty_rc" -eq 0 ]]; then
    pass "the PTY-relayed run exited 0"
  else
    echo "--- launcher stderr ---" >&2; cat "$WORK/pty.err" >&2
    fail "the PTY-relayed run exited $pty_rc"
  fi
  if [[ "$pty_out" == *"TTY-YES"* ]]; then
    pass "the agent saw a REAL TTY on stdout (the relay's pty slave — TUIs keep a terminal)"
  else
    echo "--- launcher stderr ---" >&2; cat "$WORK/pty.err" >&2
    fail "the agent did not see a TTY through the relay; got: '$pty_out'"
  fi
  if [[ "$pty_out" == *"$SECRET"* && "$pty_out" != *'$MDU:'* ]]; then
    pass "the relayed reply resolved to the secret (no opaque token reached the human)"
  else
    echo "--- launcher stderr ---" >&2; cat "$WORK/pty.err" >&2
    fail "the relayed reply did not resolve; got: '$pty_out'"
  fi
else
  echo "[5/?] SKIP (not counted): util-linux script not available — PTY relay untestable here"
fi

# ── 6. EARLY START: exit status, and nothing of the hand-off reaches the agent ─
# (packaging.md §5.3.) The early-started filter is the chain's first process:
# the agent's exit status is the launcher's, the agent's env has no human-plane
# socket, and the agent holds no descriptor of the hand-off channel (fd 3).
echo "[6/?] early start: the agent's exit status propagates; no human socket, no fd 3 in the agent ..."
early_out="$(
  HOME="$LHOME" \
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_TEST_SYM="$OUTER" \
  bash "$LAUNCHER" --target claude --no-scope --no-mcp -- \
    bash -c 'echo "human-sock=${MANDU_ARBITER_HUMAN_SOCK:-unset}"; if [ -e /proc/$$/fd/3 ]; then echo fd3=open; else echo fd3=closed; fi; echo "Summary: ${MANDU_TEST_SYM}"; exit 7' \
    2>"$WORK/early.err"
)"
early_rc=$?
echo "      stdout: '$early_out' (rc=$early_rc)"
if [[ "$early_rc" -eq 7 ]] && grep -qF "reply filter started early" "$WORK/early.err"; then
  pass "the agent's exit status (7) came back through the early-started filter"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/early.err" >&2
  fail "early start: expected rc=7 through an early-started filter, got rc=$early_rc"
fi
if [[ "$early_out" == *"human-sock=unset"* && "$early_out" == *"fd3=closed"* ]]; then
  pass "the agent inherited neither the human-plane socket nor the hand-off channel"
else
  fail "the hand-off leaked into the agent: '$early_out'"
fi
if [[ "$early_out" == *"$SECRET"* && "$early_out" != *'$MDU:'* ]]; then
  pass "the early-started filter resolved the reply"
else
  fail "the early-started filter did not resolve the reply: '$early_out'"
fi

# ── 7. SERIAL FORM: MANDU_REPLY_FILTER_PRESTART=0 still filters ───────────────
echo "[7/?] serial form (MANDU_REPLY_FILTER_PRESTART=0): the reply still resolves, no early start ..."
serial_out="$(
  HOME="$LHOME" \
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_REPLY_FILTER_PRESTART=0 \
  MANDU_TEST_SYM="$OUTER" \
  bash "$LAUNCHER" --target claude --no-scope --no-mcp -- \
    bash -c 'echo "Summary: ${MANDU_TEST_SYM}"' \
    2>"$WORK/serial.err"
)"
if [[ "$serial_out" == *"$SECRET"* && "$serial_out" != *'$MDU:'* ]] && ! grep -qF "reply filter started early" "$WORK/serial.err"; then
  pass "the serial form resolves the reply without an early start"
else
  echo "--- launcher stderr ---" >&2; cat "$WORK/serial.err" >&2
  fail "the serial form: got '$serial_out'"
fi

# ── 8. SYSTEMD SCOPE: the filter runs the scope prefix; the agent is in it ────
# With a user systemd, the launch's scope prefix (systemd-run --user --scope)
# is handed to the early-started filter, which runs it in front of the chain:
# the agent lands in the session's mandu-<id>.scope and the reply resolves.
# (systemd-run expands ${VAR} in the command it runs, so the agent reads the
# symbol with printenv rather than a ${…} the scope would expand first.)
if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --scope --quiet true >/dev/null 2>&1; then
  echo "[8/?] systemd scope: the agent runs in the session's scope behind the early-started filter ..."
  scope_out="$(
    HOME="$LHOME" \
    MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
    MANDU_NO_ARBITER_AUTOSTART=1 \
    MANDU_TEST_SYM="$OUTER" \
    bash "$LAUNCHER" --target claude --no-mcp -- \
      bash -c 'sed "s/^/cgroup=/" /proc/self/cgroup; printf "Summary: "; printenv MANDU_TEST_SYM; exit 5' \
      2>"$WORK/scope.err"
  )"
  scope_rc=$?
  echo "      stdout: '$scope_out' (rc=$scope_rc)"
  if [[ "$scope_out" == *"/mandu-"*".scope"* && "$scope_rc" -eq 5 ]]; then
    pass "the agent ran in the session's mandu-*.scope; its exit status came back"
  else
    echo "--- launcher stderr ---" >&2; cat "$WORK/scope.err" >&2
    fail "systemd scope: expected the agent in mandu-*.scope and rc=5, got rc=$scope_rc '$scope_out'"
  fi
  if [[ "$scope_out" == *"$SECRET"* && "$scope_out" != *'$MDU:'* ]]; then
    pass "the reply resolved with the scope prefix run by the filter"
  else
    fail "systemd scope: the reply did not resolve: '$scope_out'"
  fi
else
  echo "[8/?] SKIP (not counted): no user systemd here — the scope form is untestable"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo "─────────────────────────────────────────"
echo "reply-filter-live.test.sh: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
