#!/usr/bin/env bash
# wire-release-live.test.sh — the structured twin's RELEASE AT THE WIRE, live
# (confidentiality-plan-10-flow-taint.md §2.4, §11.5): a shell sources the twin
# of a dotenv, so its $API_KEY is a FIELD SYMBOL; real `curl` sends it through
# the net-proxy with TLS inspection ON (the session CA); at the secret's BOUND
# host the proxy puts the real value back into the HTTPS body (httpbin echoes
# it, so we can see it arrived); at an UNBOUND host the request is refused.
#
# Real arbiter (dev-arbiter.sh, mode secrets), real net-proxy (MITM), real TLS,
# real network (httpbin.org). SKIPs without network / openssl / nc.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PASS=0; FAIL=0
ok()  { echo "  ok — $1"; PASS=$((PASS+1)); }
bad() { echo "  NOT OK — $1"; FAIL=$((FAIL+1)); }
skip() { echo "wire-release-live.test.sh: SKIP ($1)"; echo "1 skipped, 0 failed"; exit 0; }
# A broken run, not a missing prerequisite (the dev arbiter did not come up,
# or refused the setup calls): FAIL with why and, given a log, its last
# lines; never SKIP, or a suite that went quiet shows green
# (scripts/lib/ready-deadline.sh).
# shellcheck source=scripts/lib/ready-deadline.sh
. "$REPO/scripts/lib/ready-deadline.sh"
abort() { echo "  NOT OK — $1"; if [[ -n "${2:-}" ]]; then mdu_log_tail "$2"; fi; echo "wire-release-live.test.sh: $PASS passed, $((FAIL + 1)) failed"; exit 1; }
command -v openssl >/dev/null 2>&1 || skip "openssl not installed"
command -v nc >/dev/null 2>&1 || skip "nc not installed"
curl -sS -m 10 https://httpbin.org/get -o /dev/null || skip "httpbin.org unreachable"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mandu-wire.XXXXXX")"
cleanup() {
  [[ -n "${NP_PID:-}" ]] && kill "$NP_PID" 2>/dev/null
  "$REPO/scripts/dev-arbiter.sh" stop "$WORK/arb" 2>/dev/null  # the whole group, not just npm
  rm -rf "$WORK"
}
trap cleanup EXIT
# The runtime base (the instance registry, the human-plane socket): the
# suite's own, never the caller's $XDG_RUNTIME_DIR/mandu, also when the suite
# is killed; the lifeline (lib/lifeline.sh) ends the dev arbiter then, since
# `mandu reap` cannot see a registry here (test-organization.md §8.5).
export MANDU_RUNTIME_DIR="$WORK/rt"
source "$(dirname "${BASH_SOURCE[0]}")/lib/lifeline.sh"
mdu_lifeline_init "$WORK"

# ── the secret, its binding, its twin ────────────────────────────────────────
WS="$WORK/ws"; mkdir -p "$WS"
CANARY="WIRE_LIVE_CANARY_$RANDOM$RANDOM"
printf 'PORT=3000\nAPI_KEY=%s\n' "$CANARY" > "$WS/.env"

mkdir -p "$WORK/arb"
# dev-arbiter.sh waits for both sockets on the shared readiness budget; a
# start that does not come up makes it say why, with its log's last lines,
# and exit non-zero: that FAILS this suite, never SKIPs it.
arb_env="$(MANDU_MODE=secrets MANDU_TENANT=test MANDU_POLICY_FILE="${MANDU_POLICY_FILE:-/dev/null/mandu-test-no-policy.yaml}" MANDU_LIFELINE_FIFO="$MANDU_LIFELINE_FIFO" "$REPO/scripts/dev-arbiter.sh" "$WORK/arb")" \
  || abort "the dev arbiter did not come up (dev-arbiter.sh exited $?; why and its log's last lines are above)"
eval "$(printf '%s\n' "$arb_env" | grep '^export ')"
SOCK="$MANDU_ARBITER_SOCK"; ADMIN="$MANDU_ADMIN_SOCK"
[[ -S "$SOCK" ]] || abort "dev-arbiter.sh reported up but $SOCK is no socket" "$WORK/arb/arbiter.log"
call() { printf '%s\n' "$2" | timeout 10 nc -U -q1 "$1" 2>/dev/null | head -1; }

# a standing binding: this .env may be released to httpbin.org (a human act, admin channel)
LBL="$(call "$ADMIN" "{\"id\":1,\"op\":\"setPathLabel\",\"path\":\"$WS/.env\",\"confidentiality\":\"no-model\",\"bindings\":[\"httpbin.org\"]}")"
[[ "$LBL" == *'"ok":true'* ]] || { echo "$LBL"; abort "the arbiter refused setPathLabel" "$WORK/arb/arbiter.log"; }
REG="$(call "$SOCK" "{\"id\":2,\"op\":\"registerSecret\",\"path\":\"$WS/.env\"}")"
TWIN_TEXT="$(printf '%s' "$REG" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);process.stdout.write((j.result||{}).twin||"")})')"
[[ -n "$TWIN_TEXT" ]] || { echo "$REG"; bad "no structured twin"; echo "wire-release-live.test.sh: $PASS passed, $FAIL failed"; exit 1; }
printf '%s' "$TWIN_TEXT" > "$WORK/twin.env"
echo "wire-release-live: twin = $(tr '\n' '|' < "$WORK/twin.env")"

# ── the net-proxy with TLS inspection ON ─────────────────────────────────────
mkdir -p "$WORK/ca"
( cd "$REPO/interceptors/net-proxy" && \
  MANDU_ARBITER_SOCK="$SOCK" MANDU_TENANT=test MANDU_NET_PROXY_MITM=1 \
  MANDU_NET_PROXY_MITM_CA_DIR="$WORK/ca" MANDU_NET_PROXY_PORT=0 MANDU_PORT_FILE="$WORK/port" \
  npx tsx src/server-main.ts >"$WORK/net-proxy.log" 2>&1 ) &
NP_PID=$!
for _ in $(seq 1 100); do [[ -f "$WORK/port" ]] && break; sleep 0.2; done
[[ -f "$WORK/port" ]] || abort "the net-proxy did not start" "$WORK/net-proxy.log"
PORT="$(cat "$WORK/port")"; CA="$WORK/ca/mandu-egress-ca.pem"
[[ -f "$CA" ]] || { cat "$WORK/net-proxy.log"; bad "no session CA minted"; }

# ── (1) the bound host: the real value arrives, the token never does ─────────
BOUND="$(sh -c ". '$WORK/twin.env'; curl -sS -m 30 -x http://127.0.0.1:$PORT --cacert '$CA' -d \"key=\$API_KEY\" https://httpbin.org/post" 2>&1)"
if [[ "$BOUND" == *"\"key\": \"$CANARY\""* ]]; then
  ok "bound host: the field symbol was replaced by the real value inside the HTTPS body (httpbin echoed it)"
else
  bad "bound host did not receive the value: ${BOUND:0:400}"
fi
[[ "$BOUND" != *'$MDU:'* ]] && ok "the token itself never reached the bound host" || bad "the token leaked as-is to the bound host"

# ── (2) an UNBOUND host: refused at the proxy, nothing sent ──────────────────
UNB="$(sh -c ". '$WORK/twin.env'; curl -sS -m 30 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:$PORT --cacert '$CA' -d \"key=\$API_KEY\" https://example.com/" 2>&1)"
[[ "$UNB" == "403" ]] && ok "unbound host: the request carrying the symbol is refused (403)" || bad "unbound host answered $UNB"

# ── (3) a benign HTTPS request still flows through the inspected tunnel ──────
BEN="$(curl -sS -m 30 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:$PORT --cacert "$CA" https://httpbin.org/get 2>&1)"
[[ "$BEN" == "200" ]] && ok "a benign HTTPS request through TLS inspection returns 200" || bad "benign request answered $BEN"

# ── (3b) a Node script (confidentiality-plan-13-reader-set-labels.md §10): only the launcher's proxy and
#        trust variables, no flags; NODE_USE_ENV_PROXY brings fetch through ──
NODE_OUT="$(sh -c ". '$WORK/twin.env'; export API_KEY; HTTPS_PROXY=http://127.0.0.1:$PORT NODE_USE_ENV_PROXY=1 NODE_EXTRA_CA_CERTS='$CA' \
  node -e 'fetch(\"https://httpbin.org/post\",{method:\"POST\",headers:{\"content-type\":\"application/x-www-form-urlencoded\"},body:\"key=\"+process.env.API_KEY}).then(r=>r.text()).then(t=>process.stdout.write(t),e=>{console.error(e.cause??e);process.exit(3)})'" 2>&1)"
if [[ "$NODE_OUT" == *"\"key\": \"$CANARY\""* ]]; then
  ok "node fetch: the field symbol was replaced by the real value at the bound host"
else
  bad "node fetch did not receive the value: ${NODE_OUT:0:400}"
fi

# ── (4) the real value never left in the clear: the shell never had it ───────
SHELL_SEES="$(sh -c ". '$WORK/twin.env'; printf '%s' \"\$API_KEY\"")"
[[ "$SHELL_SEES" == '$MDU:nomodel_Read['*'.API_KEY' && "$SHELL_SEES" != *"$CANARY"* ]] \
  && ok "the sourcing shell holds a token, not the key ($SHELL_SEES)" \
  || bad "the shell saw: $SHELL_SEES"

echo "wire-release-live.test.sh: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
