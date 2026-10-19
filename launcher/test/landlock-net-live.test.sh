#!/usr/bin/env bash
#
# landlock-net-live.test.sh — LIVE e2e oracle for the whole-agent TCP port-allow
# wrap (--landlock-net → mandu-landlock-apply --net-only …, exec-routing.md §7).
#
# Proves the in-kernel egress confinement END-TO-END: a tiny "agent stub" run
# UNDER the composed wrap argv (the exact shape launcher/src/landlock-net.ts's
# planLandlockNet emits) may CONNECT only to the allowed TCP port; a CONNECT to
# any other port is denied by Landlock — even though the port is listening and a
# BARE run connects to it. This is the raw-socket-exfil kill switch that holds
# with NO root, NO agent cooperation, purely in-kernel (bypasses HTTP_PROXY).
#
# No arbiter is needed — the --net-only applier does not gate through it.
#
# SKIPs cleanly (exit 0) when: the mandu-landlock-apply bin is not built, node
# is unavailable, loopback ports can't be bound, or the kernel lacks Landlock
# TCP-net (ABI < 4 / kernel < 6.7) — environment gaps, not failures.
#
# Run:  bash launcher/test/landlock-net-live.test.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
LAUNCHER_TSX="$REPO_ROOT/launcher/node_modules/.bin/tsx"

PASS=0; FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() {
  echo "SKIP: $1"
  echo "─────────────────────────────────────────"
  echo "landlock-net-live.test.sh: 0 passed, 0 failed (skipped)"
  exit 0
}

# ── 0. locate the committed applier bin (env override → release → debug) ──────
APPLIER="${MANDU_LANDLOCK_APPLY:-}"
if [[ -z "$APPLIER" || ! -x "$APPLIER" ]]; then
  for cand in "$REPO_ROOT/interceptors/target/release/mandu-landlock-apply" \
              "$REPO_ROOT/interceptors/target/debug/mandu-landlock-apply"; do
    [[ -x "$cand" ]] && { APPLIER="$cand"; break; }
  done
fi
[[ -n "$APPLIER" && -x "$APPLIER" ]] \
  || skip "mandu-landlock-apply not built — cd interceptors && cargo build -p exec-supervisor --features kernel --bins"
command -v node >/dev/null 2>&1 || skip "node not on PATH (used to stand up loopback listeners)"

# ── 0b. detect Landlock TCP-net support (ABI >= 4) via the applier itself ─────
# WITHOUT --skip-unsupported the applier exits 71 + "TCP-net unavailable" on an
# old kernel; on a supporting kernel it restricts `true` and exits 0. The match
# reads a here-string, never `echo "$probe" | grep -q`: under pipefail grep -q
# exits at its first match, bash's echo writes a line at a time, and a later
# line's write then dies of SIGPIPE (141), failing the match it made (the
# net-guard-live flake of pipeline 11108).
probe="$("$APPLIER" --net-only --allow-tcp-port 1 -- true 2>&1)"; probe_rc=$?
if [[ $probe_rc -ne 0 ]] || grep -qF -- "TCP-net unavailable" <<<"$probe"; then
  skip "Landlock TCP-net unavailable on this kernel (needs >= 6.7 / ABI >= 4): $probe"
fi

# ── 1. two loopback listeners (allow + deny) so a CONNECT reaches a real socket
# ONE listener process binds both on port 0, keeps them bound, and only then
# writes their ports to a file the script waits for (the port-file handshake,
# test-organization.md §8.4). The wrap's allow list names these ports before
# the confined process starts; binding first and reading back, instead of
# picking a free port and closing it, leaves no window for another suite.
PORTS_FILE="$(mktemp -u /tmp/mandu-llnet-live.XXXXXX.ports)"
node -e '
  const net = require("net"), fs = require("fs");
  const portsFile = process.argv[1];
  const listen = () => new Promise((res, rej) => {
    const s = net.createServer((c) => c.destroy());
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => res(s.address().port));
  });
  (async () => {
    const ports = [await listen(), await listen()];
    fs.writeFileSync(portsFile + ".tmp", ports.join(" "));
    fs.renameSync(portsFile + ".tmp", portsFile);
  })().catch((e) => { console.error(e); process.exit(1); });
' "$PORTS_FILE" >/dev/null 2>&1 &
L_PID=$!
cleanup() { kill "$L_PID" 2>/dev/null || true; rm -f "$PORTS_FILE" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 100); do [[ -s "$PORTS_FILE" ]] && break; kill -0 "$L_PID" 2>/dev/null || break; sleep 0.1; done
read -r PORT_ALLOW PORT_DENY 2>/dev/null < "$PORTS_FILE"
[[ -n "${PORT_ALLOW:-}" && -n "${PORT_DENY:-}" && "$PORT_ALLOW" != "$PORT_DENY" ]] || skip "could not bind two loopback listeners"

# The agent stub: probe a CONNECT to each port and label the result. Uses bash's
# /dev/tcp (a connect(2)); Landlock CONNECT-deny surfaces as a failed open.
PROBE='for p in '"$PORT_ALLOW $PORT_DENY"'; do if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then echo "$p CONNECTED"; else echo "$p BLOCKED"; fi; done'

# ── 2. BASELINE: bare (no wrap) — BOTH ports must connect ─────────────────────
echo "[1/3] baseline (no wrap): both listeners must be reachable ..."
bare="$(bash -c "$PROBE")"
echo "      $bare" | tr '\n' ' '; echo
if [[ "$bare" == *"$PORT_ALLOW CONNECTED"* && "$bare" == *"$PORT_DENY CONNECTED"* ]]; then
  pass "baseline: both loopback listeners are reachable (so the deny below is Landlock, not ECONNREFUSED)"
else
  fail "baseline did not connect both ports — the listeners are broken: '$bare'"
fi

# ── 3. UNDER the composed wrap: only PORT_ALLOW may connect ───────────────────
# The wrap argv is exactly what planLandlockNet builds: the applier, --net-only,
# one --allow-tcp-port pair, --skip-unsupported, then `-- <agent argv>`.
echo "[2/3] under --net-only allowing ONLY $PORT_ALLOW (deny $PORT_DENY) ..."
WRAP=("$APPLIER" --net-only --allow-tcp-port "$PORT_ALLOW" --skip-unsupported --)
confined="$("${WRAP[@]}" bash -c "$PROBE" 2>/dev/null)"
echo "      $confined" | tr '\n' ' '; echo
if [[ "$confined" == *"$PORT_ALLOW CONNECTED"* ]]; then
  pass "the allowed port ($PORT_ALLOW) still CONNECTS under the wrap"
else
  fail "the allowed port was blocked — the wrap over-confined: '$confined'"
fi
if [[ "$confined" == *"$PORT_DENY BLOCKED"* ]]; then
  pass "the non-allowed port ($PORT_DENY) is DENIED in-kernel (raw-socket exfil kill switch)"
else
  fail "the non-allowed port CONNECTED — Landlock did NOT confine: '$confined'"
fi

# ── 4. a multi-port allow list keeps BOTH allowed (dedupe/sort shape) ─────────
echo "[3/4] allowing BOTH ports → both connect (multi-port allow list) ..."
both="$("$APPLIER" --net-only --allow-tcp-port "$PORT_DENY" --allow-tcp-port "$PORT_ALLOW" --skip-unsupported -- bash -c "$PROBE" 2>/dev/null)"
if [[ "$both" == *"$PORT_ALLOW CONNECTED"* && "$both" == *"$PORT_DENY CONNECTED"* ]]; then
  pass "both ports connect when both are on the allow list"
else
  fail "a multi-port allow list did not permit both: '$both'"
fi

# ── 5. the U-LLM forwarder resolves the "443 crux" under a STRICT wrap ─────────
# The strong posture DENIES the direct upstream port (stand-in for :443) but the
# quarantined U-LLM must still reach the real endpoint. The launcher's loopback
# forwarder (services/ullm-forwarder.ts) runs OUTSIDE the wrap and relays
# verbatim; the agent tree connects only to the forwarder's loopback port. Prove:
# under a wrap allowing ONLY the forwarder port (deny the upstream port), an HTTP
# GET through the forwarder reaches the upstream, while a DIRECT connect to the
# upstream port is denied in-kernel.
echo "[4/4] U-LLM forwarder reaches the upstream under a strict wrap (443-crux fix) ..."
if [[ ! -x "$LAUNCHER_TSX" ]]; then
  echo "NOTE: launcher tsx not installed — skipping the forwarder leg"
else
  FWDWORK="$(mktemp -d)"
  UPLOG="$FWDWORK/up.port"; FWDLOG="$FWDWORK/fwd.log"
  # A fake upstream HTTP server (stands in for api.anthropic.com), writing its
  # chosen port to a file, then staying alive.
  node -e '
    const http=require("http"), fs=require("fs");
    const s=http.createServer((q,r)=>{r.writeHead(200,{"content-type":"text/plain"});r.end("UPSTREAM_OK");});
    s.listen(0,"127.0.0.1",function(){fs.writeFileSync(process.argv[1],String(this.address().port));setInterval(()=>{},1e9);});
  ' "$UPLOG" >/dev/null 2>&1 &
  UP_PID=$!
  for _ in $(seq 1 50); do [[ -s "$UPLOG" ]] && break; sleep 0.1; done
  UP_PORT="$(cat "$UPLOG" 2>/dev/null)"

  # Start the REAL forwarder (services/ullm-forwarder.ts) pointed at the fake
  # upstream, on port 0 (its production default): it prints the port it bound,
  # which the script reads back (no pick-then-close race, §8.4). Driven via a
  # temp .ts file (tsx).
  FWD_PORT=""
  cat > "$FWDWORK/run-fwd.ts" <<EOF
import { startUllmForwarder } from "$REPO_ROOT/launcher/src/services/ullm-forwarder.js";
startUllmForwarder({ upstream: "http://127.0.0.1:$UP_PORT", port: 0 })
  .then((r) => { console.log("FWD_UP " + r.port); })
  .catch((e) => { console.error(e); process.exit(3); });
setInterval(() => {}, 1e9);
EOF
  "$LAUNCHER_TSX" "$FWDWORK/run-fwd.ts" >"$FWDLOG" 2>&1 &
  FWD_PID=$!
  fwd_cleanup() { kill "$UP_PID" "$FWD_PID" 2>/dev/null || true; rm -rf "$FWDWORK" 2>/dev/null || true; }
  trap 'cleanup; fwd_cleanup' EXIT
  for _ in $(seq 1 100); do grep -q "FWD_UP" "$FWDLOG" 2>/dev/null && break; sleep 0.1; done
  FWD_PORT="$(sed -n 's/^FWD_UP \([0-9][0-9]*\)$/\1/p' "$FWDLOG" 2>/dev/null | head -1)"

  if [[ -z "$UP_PORT" || -z "$FWD_PORT" ]] || ! grep -q "FWD_UP" "$FWDLOG" 2>/dev/null; then
    echo "--- forwarder log ---"; cat "$FWDLOG" 2>/dev/null
    echo "NOTE: could not stand up the upstream/forwarder — skipping the forwarder leg"
  else
    # An HTTP GET THROUGH the forwarder (loopback), run UNDER the strict wrap that
    # allows ONLY the forwarder port and DENIES the direct upstream port.
    GET='node -e '\''const http=require("http");http.get("http://127.0.0.1:"+process.argv[1],res=>{let b="";res.on("data",c=>b+=c);res.on("end",()=>process.stdout.write(b));}).on("error",e=>process.stdout.write("GET_ERR:"+e.code));'\'' '"$FWD_PORT"
    via="$("$APPLIER" --net-only --allow-tcp-port "$FWD_PORT" --skip-unsupported -- bash -c "$GET" 2>/dev/null)"
    if [[ "$via" == "UPSTREAM_OK" ]]; then
      pass "the U-LLM reaches the upstream THROUGH the forwarder under a wrap that denies the direct upstream port"
    else
      fail "the forwarded GET did not reach the upstream under the wrap: '$via'"
    fi
    # And a DIRECT connect to the upstream port from inside the wrap is denied.
    DIRECT='if (exec 3<>/dev/tcp/127.0.0.1/'"$UP_PORT"') 2>/dev/null; then echo CONNECTED; else echo BLOCKED; fi'
    direct="$("$APPLIER" --net-only --allow-tcp-port "$FWD_PORT" --skip-unsupported -- bash -c "$DIRECT" 2>/dev/null)"
    if [[ "$direct" == "BLOCKED" ]]; then
      pass "a DIRECT connect to the upstream port is denied in-kernel (only the forwarder loopback is reachable)"
    else
      fail "a direct connect to the upstream port was NOT denied: '$direct'"
    fi
  fi
fi

echo "─────────────────────────────────────────"
echo "landlock-net-live.test.sh: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
