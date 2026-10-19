#!/usr/bin/env bash
#
# net-guard-live.test.sh — LIVE e2e oracle for the whole-agent IP/DOMAIN-aware
# connect-guard (--net-guard → mandu-net-guard --allow …, exec-routing.md §7.5).
#
# Proves, END-TO-END and UNPRIVILEGED (no root, no userns — just no_new_privs),
# the destination-aware egress teeth that CLOSE THE PORT-ONLY GAP: an agent stub
# run UNDER the composed wrap argv (exactly what launcher/src/net-guard.ts's
# planNetGuard emits) may CONNECT only to allow-listed DESTINATIONS —
#   • PORT precision:  same IP, a non-allowed PORT is denied;
#   • IP precision:    same PORT, a non-allowed IP (127.0.0.2 vs 127.0.0.1) is
#                      denied — the thing the port-only Landlock wrap CANNOT do;
#   • HOSTNAME rule:   an allow spec `localhost:<port>` is resolved to its IP and
#                      admitted (domain-aware);
#   • AF_UNIX passthrough: a unix-socket connect (the arbiter's IPC family) still
#                      works under a default-DENY INET policy.
# A denied connect returns EACCES in-kernel even though the port is listening and
# a BARE run connects to it.
#
# No arbiter is needed — the guard decides from its --allow argv.
#
# SKIPs cleanly (exit 0) when: the mandu-net-guard bin is not built, node is
# unavailable, loopback ports can't be bound, or the seccomp connect-trap is
# unavailable on this host — environment gaps, not failures.
#
# Run:  bash launcher/test/net-guard-live.test.sh
#
set -uo pipefail
# No Mandu home (the 7cdfc2c e2e rule: never the host's ~/.mandu): nothing
# here needs one, and a read under this path is "absent", a write fails.
export MANDU_HOME=/dev/null/mandu-test-home

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

PASS=0; FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() {
  echo "SKIP: $1"
  echo "─────────────────────────────────────────"
  echo "net-guard-live.test.sh: 0 passed, 0 failed (skipped)"
  exit 0
}

# ── 0. locate the committed guard bin (env override → release → debug) ────────
GUARD="${MANDU_NET_GUARD_BIN:-}"
if [[ -z "$GUARD" || ! -x "$GUARD" ]]; then
  for cand in "$REPO_ROOT/interceptors/target/release/mandu-net-guard" \
              "$REPO_ROOT/interceptors/target/debug/mandu-net-guard"; do
    [[ -x "$cand" ]] && { GUARD="$cand"; break; }
  done
fi
[[ -n "$GUARD" && -x "$GUARD" ]] \
  || skip "mandu-net-guard not built — cd interceptors && cargo build -p net-supervisor --features kernel --bins"
command -v node >/dev/null 2>&1 || skip "node not on PATH (used to stand up loopback listeners)"

# ── 1. loopback listeners: two ports on 127.0.0.1, one port on 127.0.0.2 ──────
# ONE listener process binds every socket on port 0, keeps them all bound, and
# only then writes their ports to a file the script waits for (the port-file
# handshake, test-organization.md §8.4). The guard's policy names these ports,
# so they must be known before any confined process starts; binding first and
# reading back, instead of picking a free port and closing it, leaves no window
# for another suite to take one. The IP-precision port is bound on 127.0.0.1
# first and the same number then on 127.0.0.2 (retried on a clash; IP2=0 when
# the host has no 127.0.0.2).
PORTS_FILE="$(mktemp -u /tmp/mandu-ng-live.XXXXXX.ports)"
USOCK="$(mktemp -u /tmp/mandu-ng-live.XXXXXX.sock)"
node -e '
  const net = require("net"), fs = require("fs");
  const [portsFile, usock] = process.argv.slice(1);
  const listen = (port, host) => new Promise((res, rej) => {
    const s = net.createServer((c) => c.destroy());
    s.once("error", rej);
    s.listen(port, host, () => res(s));
  });
  (async () => {
    const allow = await listen(0, "127.0.0.1"), deny = await listen(0, "127.0.0.1");
    let ip = null, ip2 = 0;
    for (let i = 0; i < 20 && ip === null; i++) {
      const s = await listen(0, "127.0.0.1");
      try { await listen(s.address().port, "127.0.0.2"); ip = s; ip2 = 1; }
      catch (e) { if (e.code === "EADDRINUSE") s.close(); else ip = s; }
    }
    if (ip === null) ip = await listen(0, "127.0.0.1");
    // AF_UNIX listener (the arbiter-family passthrough leg).
    await new Promise((res) => net.createServer((c) => c.destroy()).listen(usock, res));
    fs.writeFileSync(portsFile + ".tmp", [allow.address().port, deny.address().port, ip.address().port, ip2].join(" "));
    fs.renameSync(portsFile + ".tmp", portsFile);
  })().catch((e) => { console.error(e); process.exit(1); });
' "$PORTS_FILE" "$USOCK" >/dev/null 2>&1 &
L_PID=$!
cleanup() { kill "$L_PID" 2>/dev/null || true; rm -f "$USOCK" "$PORTS_FILE" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 100); do [[ -s "$PORTS_FILE" ]] && break; kill -0 "$L_PID" 2>/dev/null || break; sleep 0.1; done
read -r PORT_ALLOW PORT_DENY PORT_IP IP2 2>/dev/null < "$PORTS_FILE"
[[ -n "${PORT_ALLOW:-}" && -n "${PORT_DENY:-}" && -n "${PORT_IP:-}" && "$PORT_ALLOW" != "$PORT_DENY" ]] \
  || skip "could not bind the loopback listeners"

# ── 2. detect the seccomp connect-trap: run the guard (fail-closed, no
#       --skip-unsupported) denying all; a connect stub must be BLOCKED. If it
#       CONNECTS (the guard degraded / did not enforce) or the guard fails to set
#       up, SKIP — the host lacks the trap. ──────────────────────────────────────
PROBE_ONE='if (exec 3<>/dev/tcp/127.0.0.1/'"$PORT_ALLOW"') 2>/dev/null; then echo CONNECTED; else echo BLOCKED; fi'
probe="$("$GUARD" --allow tcp:127.0.0.1:1 -- bash -c "$PROBE_ONE" 2>/dev/null)"; probe_rc=$?
if [[ $probe_rc -eq 71 ]] || [[ "$probe" != "BLOCKED" ]]; then
  skip "seccomp connect-trap unavailable on this host (needs no_new_privs + kernel >= 5.6); probe='$probe' rc=$probe_rc"
fi

# Does the probe output $1 hold the line $2, whole? Never `echo "$out" | grep -q`:
# under pipefail, grep -q exits at its first match, and the next line of bash's
# line-buffered echo then hits a closed pipe (SIGPIPE, 141), so a CONNECTED on
# the first line read as a failed match on a loaded host (pipeline 11108:
# "127.0.0.1:<port> CONNECTED" printed, and "the allowed IP was blocked"). A
# here-string has no writer to kill; -xF matches the whole line, literally.
has() { grep -qxF -- "$2" <<<"$1"; }

# The agent stub: connect to a list of "ip port" pairs and label each result.
probe_pairs() {
  local script=""
  for pair in "$@"; do
    set -- $pair
    script+='if (exec 3<>/dev/tcp/'"$1"'/'"$2"') 2>/dev/null; then echo "'"$1:$2"' CONNECTED"; else echo "'"$1:$2"' BLOCKED"; fi; '
  done
  echo "$script"
}

# ── 3. BASELINE: bare (no guard) — every listener must be reachable ───────────
echo "[1/5] baseline (no guard): all loopback listeners must be reachable ..."
BASE_PAIRS=("127.0.0.1 $PORT_ALLOW" "127.0.0.1 $PORT_DENY" "127.0.0.1 $PORT_IP")
[[ "$IP2" == 1 ]] && BASE_PAIRS+=("127.0.0.2 $PORT_IP")
bare="$(bash -c "$(probe_pairs "${BASE_PAIRS[@]}")")"
echo "      $(echo "$bare" | tr '\n' ' ')"
if has "$bare" "127.0.0.1:$PORT_ALLOW CONNECTED" && has "$bare" "127.0.0.1:$PORT_DENY CONNECTED"; then
  pass "baseline: loopback listeners reachable (so a deny below is the guard, not ECONNREFUSED)"
else
  fail "baseline did not connect the listeners: '$bare'"
fi

# ── 4. PORT precision: allow ONLY 127.0.0.1:$PORT_ALLOW ───────────────────────
echo "[2/5] guard allows ONLY 127.0.0.1:$PORT_ALLOW → same-IP other port denied ..."
STUB="$(probe_pairs "127.0.0.1 $PORT_ALLOW" "127.0.0.1 $PORT_DENY")"
confined="$("$GUARD" --allow "tcp:127.0.0.1:$PORT_ALLOW" --skip-unsupported -- bash -c "$STUB" 2>/dev/null)"
echo "      $(echo "$confined" | tr '\n' ' ')"
has "$confined" "127.0.0.1:$PORT_ALLOW CONNECTED" \
  && pass "the allowed destination still CONNECTS under the guard" \
  || fail "the allowed destination was blocked — over-confined: '$confined'"
has "$confined" "127.0.0.1:$PORT_DENY BLOCKED" \
  && pass "same IP, non-allowed PORT is DENIED in-kernel" \
  || fail "the non-allowed port CONNECTED — guard did not confine: '$confined'"

# ── 5. IP precision (THE headline: port-only Landlock cannot do this) ─────────
echo "[3/5] guard allows ONLY 127.0.0.1:$PORT_IP → same PORT on 127.0.0.2 denied ..."
if [[ "$IP2" != 1 ]]; then
  echo "NOTE: could not bind 127.0.0.2 (no extra loopback alias) — skipping the IP-precision leg"
else
  STUB_IP="$(probe_pairs "127.0.0.1 $PORT_IP" "127.0.0.2 $PORT_IP")"
  ipres="$("$GUARD" --allow "tcp:127.0.0.1:$PORT_IP" --skip-unsupported -- bash -c "$STUB_IP" 2>/dev/null)"
  echo "      $(echo "$ipres" | tr '\n' ' ')"
  has "$ipres" "127.0.0.1:$PORT_IP CONNECTED" \
    && pass "the allowed IP connects on the shared port" \
    || fail "the allowed IP was blocked on the shared port: '$ipres'"
  has "$ipres" "127.0.0.2:$PORT_IP BLOCKED" \
    && pass "same PORT, non-allowed IP (127.0.0.2) is DENIED — IP precision the port-only wrap lacks" \
    || fail "the non-allowed IP CONNECTED on the shared port — no IP precision: '$ipres'"
fi

# ── 6. HOSTNAME rule: `localhost:<port>` resolves to 127.0.0.1 and is admitted ─
echo "[4/5] guard allows the hostname rule localhost:$PORT_ALLOW (domain-aware resolve) ..."
STUB_H="$(probe_pairs "127.0.0.1 $PORT_ALLOW")"
hres="$("$GUARD" --allow "tcp:localhost:$PORT_ALLOW" --skip-unsupported -- bash -c "$STUB_H" 2>/dev/null)"
echo "      $(echo "$hres" | tr '\n' ' ')"
has "$hres" "127.0.0.1:$PORT_ALLOW CONNECTED" \
  && pass "a hostname allow-rule resolved to its IP and admitted the connect (domain-aware)" \
  || fail "the hostname rule did not admit the resolved IP: '$hres'"

# ── 7. AF_UNIX passthrough: a unix connect survives a default-DENY INET policy ─
echo "[5/5] AF_UNIX passthrough under a deny-all-INET guard (arbiter IPC survives) ..."
UNIX_STUB='const net=require("net");const c=net.connect(process.argv[1],()=>{console.log("UNIX_OK");process.exit(0);});c.on("error",e=>{console.log("UNIX_ERR:"+e.code);process.exit(1);});'
ures="$("$GUARD" --allow tcp:127.0.0.1:1 --skip-unsupported -- node -e "$UNIX_STUB" "$USOCK" 2>/dev/null)"
echo "      $ures"
[[ "$ures" == "UNIX_OK" ]] \
  && pass "AF_UNIX connect passed through the guard (the arbiter socket keeps working)" \
  || fail "AF_UNIX connect was blocked — the guard broke unix IPC: '$ures'"

# ── 8. DENY rules beat every allow (an agent's upload hosts, upload-deny.ts) ───
echo "[deny] --deny beats a matching allow: by IP:port, and by a hostname rule ..."
STUB_D="$(probe_pairs "127.0.0.1 $PORT_ALLOW" "127.0.0.1 $PORT_DENY")"
dres="$("$GUARD" --allow "tcp:127.0.0.1:*" --deny "tcp:127.0.0.1:$PORT_DENY" --skip-unsupported -- bash -c "$STUB_D" 2>/dev/null)"
echo "      $(echo "$dres" | tr '\n' ' ')"
has "$dres" "127.0.0.1:$PORT_ALLOW CONNECTED" \
  && pass "a destination the deny does not name still connects under the same allow" \
  || fail "the deny over-blocked: '$dres'"
has "$dres" "127.0.0.1:$PORT_DENY BLOCKED" \
  && pass "the denied destination is BLOCKED although tcp:127.0.0.1:* admits it" \
  || fail "the denied destination CONNECTED — the deny did not beat the allow: '$dres'"
hdres="$("$GUARD" --allow "tcp:*:*" --deny "tcp:localhost:*" --skip-unsupported -- bash -c "$(probe_pairs "127.0.0.1 $PORT_ALLOW")" 2>/dev/null)"
echo "      $hdres"
has "$hdres" "127.0.0.1:$PORT_ALLOW BLOCKED" \
  && pass "a hostname deny (localhost) resolves to its IP and beats tcp:*:*" \
  || fail "the hostname deny did not hold: '$hdres'"
"$GUARD" --deny "not a spec" --skip-unsupported -- true >/dev/null 2>&1; bad_rc=$?
[[ $bad_rc -eq 71 ]] \
  && pass "a bad --deny spec fails closed (exit 71, the target is not run)" \
  || fail "a bad --deny spec exited $bad_rc (want 71)"

echo "─────────────────────────────────────────"
echo "net-guard-live.test.sh: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
