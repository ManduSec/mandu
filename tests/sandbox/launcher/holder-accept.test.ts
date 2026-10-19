/**
 * holder-accept.test.ts — a server that holds a secret answers only this
 * machine, a Unix client and the hosts its secret is bound to, from inside
 * the REAL launcher sandbox (exec-routing.md §7.5 gap (a), "An inbound
 * connection to a holder", 2026-10-02; enactment
 * interceptors/net-supervisor/src/guard_accept.rs, decision accept_guard.rs).
 * Until 2026-10-18 only the kernel tests
 * (`a_holders_accept_takes_this_machine_and_its_bindings_only`) proved it:
 * a node dev-server version of this leg in tainted-egress was flaky under
 * the peer's load. The servers here are python3, the clients run one at a
 * time, and every wait is on a mark a process writes, never a sleep.
 *
 * Two "machines" on one private network with no root (tests/lib/netns.ts):
 * this side (10.77.0.1) runs the real launcher in `secrets` mode around a
 * shell agent that starts three python3 servers; "the other machine" runs
 * a connect agent the test owns, which connects to this side from either
 * of its addresses when the fixture asks it to: 10.77.0.2 (the bound
 * secret's binding) or 203.0.113.9 (named by nothing). The guard's netns is
 * the servers' own, so the peer is judged as a remote peer, not as "another
 * network namespace" (holder-accept-scenario.fixture.ts has the servers
 * and the legs).
 *
 * Asserted, each server answering five legs in turn (outside, inside,
 * loopback, own address, Unix):
 *   - plain, a NON-holder: every accept returns a connection, and every
 *     client, the other machine's included, reads its answer (the liveness
 *     control: the topology, the clients and the servers work);
 *   - unbound, holding an unbound file through its reader's pipe: both
 *     connections from the other machine are reset, the server's accept
 *     answers ECONNABORTED for each and the server never gets them; the
 *     loopback peer, its own local address and the Unix client are served
 *     the file;
 *   - bound, holding a file bound to 10.77.0.2: the connection from
 *     10.77.0.2 is served, the one from 203.0.113.9 is reset (ECONNABORTED),
 *     this machine and the Unix client are served;
 *   - the oracle: no canary reaches the other machine from an address its
 *     file is not bound to.
 *
 * A reset is the client reading no byte and ECONNRESET, whether the reset
 * lands after its connect returned or before (the connect itself answers
 * ECONNRESET: the guard can accept and reset a connection the kernel
 * completed before the client's poll wakes; pipeline 11803). `refusedLeg`
 * reads the legs and has its own test, which needs no namespace.
 *
 * Self-SKIPs only where the topology cannot be built (no unprivileged user
 * and network namespaces), the guard is not built, or python3 has no
 * stdlib base64.py (the secrets' reader); ci `maxSkip: 0`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runTwoHostNet, twoHostNetUnavailable, TWO_HOST } from "../../lib/netns.js";
import { pickGuard } from "../../lib/native-guard.js";
import { stateAxes } from "../../lib/axes.js";
import { stdlibBase64 } from "../../lib/holder-reader.js";

stateAxes("secrets"); // the confidentiality axis: a holder answers no unbound peer

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..", ".."); // tests/, the package root
const TSX = join(PKG_ROOT, "node_modules", ".bin", "tsx");
const GUARD = pickGuard(resolve(PKG_ROOT, "..", "interceptors", "target"));
const unavailable = process.platform !== "linux" ? "Linux only" : twoHostNetUnavailable();
const skip = unavailable
  ?? (!GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
    : stdlibBase64() === null ? "python3 has no stdlib base64.py (the secrets' reader)"
      : false);

/** The control port of the other machine's connect agent. */
const PEER_CTRL = "7070";

/** The connect agent, both sides' client. Modes:
 *    control PORT READY       the other machine: answer control connections
 *                             on PORT, one at a time (a JSON line {src,
 *                             host, port}: connect from src, read to the
 *                             end, answer the result line)
 *    ask CHOST CPORT SRC HOST PORT   ask that agent for one connection
 *    tcp SRC HOST PORT        one connection from here
 *    unix PATH                one Unix connection from here
 *  A result: "data:<bytes>" (read to EOF), "reset[:<bytes>]",
 *  "timeout", or "connect-e<errno>" (`refusedLeg` reads them). */
const AGENT_PY = String.raw`
import json, socket, sys
def drain(s):
    out = b""
    try:
        while True:
            b = s.recv(4096)
            if not b:
                return "data:" + out.decode("utf-8", "replace")
            out += b
    except ConnectionResetError:
        return "reset" + (":" + out.decode("utf-8", "replace") if out else "")
    except socket.timeout:
        return "timeout"
    finally:
        s.close()
def tcp(src, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(20)
    try:
        s.bind((src, 0)); s.connect((host, int(port)))
    except OSError as e:
        s.close(); return "connect-e%d" % (e.errno or 0)
    return drain(s)
def unix(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(20)
    try:
        s.connect(path)
    except OSError as e:
        s.close(); return "connect-e%d" % (e.errno or 0)
    return drain(s)
mode = sys.argv[1]
if mode == "control":
    l = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("0.0.0.0", int(sys.argv[2]))); l.listen(8)
    open(sys.argv[3], "w").close()
    while True:
        c, _ = l.accept()
        try:
            f = c.makefile("rwb")
            q = json.loads(f.readline())
            f.write((tcp(q["src"], q["host"], q["port"]) + "\n").encode()); f.flush()
        except Exception as e:
            try: c.sendall(("control-error:%s\n" % e).encode())
            except OSError: pass
        finally:
            c.close()
elif mode == "ask":
    chost, cport, src, host, port = sys.argv[2:7]
    c = socket.create_connection((chost, int(cport)), timeout=60)
    c.sendall((json.dumps({"src": src, "host": host, "port": port}) + "\n").encode())
    print(c.makefile("rb").readline().decode().strip())
elif mode == "tcp":
    print(tcp(*sys.argv[2:5]))
elif mode == "unix":
    print(unix(sys.argv[2]))
`;

interface Scenario {
  error?: string;
  code: number;
  outTail: string;
  guardLive: boolean;
  agentDone: boolean;
  ready: Record<string, boolean>;
  legs: Record<string, Record<string, string>>;
  seen: Record<string, string[] | null>;
  fails: Record<string, string>;
  unboundCanary: string;
  boundCanary: string;
}

/** A refused connection, from the client's side: the guard's reset with no
 *  byte read. Either "reset" (the reset came after the client's connect
 *  returned), or "connect-e104" (ECONNRESET from connect itself: python's
 *  timed connect is a non-blocking connect, a poll, then SO_ERROR, and when
 *  the handshake completed in the kernel and the guard's reset (accept,
 *  SO_LINGER 0, close) landed before the client's poll returned, the
 *  connect reads the reset; pipeline 11803, 1 run in about 30; an RST to the
 *  SYN itself would be ECONNREFUSED, e111). Nothing else: data, a reset
 *  after data ("reset:<bytes>"), a timeout (a hang) or any other connect
 *  error is not this refusal. That the guard's trap made the reset, not
 *  something else, is the accepts' check (e103 for each refused leg). */
function refusedLeg(v: string | undefined): boolean {
  return v === "reset" || v === "connect-e104";
}

test("a leg reads as refused only for the guard's reset with no byte read, before or after the client's connect returned", () => {
  assert.equal(refusedLeg("reset"), true);
  assert.equal(refusedLeg("connect-e104"), true, "the reset landed before the client's connect returned (pipeline 11803)");
  for (const v of [undefined, "", "data:", "data:LIVE-plain", "reset:x", "reset:", "timeout",
    "connect-e111", "connect-e110", "connect-e113", "connect-e0", "connect-e1040", "control-error:x"]) {
    assert.equal(refusedLeg(v), false, `${JSON.stringify(v)} is not a refusal`);
  }
});

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("a holder's server answers this machine, a Unix client and its bound host; the other machine gets a reset, and ECONNABORTED is the server's", { skip, timeout: 600_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-holder-accept-"));
  try {
    const agentPy = join(dir, "accept-agent.py");
    writeFileSync(agentPy, AGENT_PY);
    const peerReady = join(dir, "peer.ready");
    const r = await runTwoHostNet({
      hosts: {},
      peer: ["/usr/bin/python3", "-I", agentPy, "control", PEER_CTRL, peerReady],
      peerReady,
      main: [TSX, join(PKG_ROOT, "fixtures", "holder-accept-scenario.fixture.ts")],
      env: {
        ...process.env,
        PEER_ADDR: TWO_HOST.inside,
        PEER_CTRL,
        SELF_ADDR: TWO_HOST.self,
        OUTSIDE_ADDR: TWO_HOST.outside,
        ACCEPT_AGENT_PY: agentPy,
      },
      timeoutMs: 540_000,
    });
    const last = r.stdout.trim().split("\n").pop() ?? "";
    let s: Scenario;
    try {
      s = JSON.parse(last) as Scenario;
    } catch {
      assert.fail(`the scenario printed no result (exit ${r.status}):\n${r.stderr.slice(-4000)}\n${r.stdout.slice(-4000)}`);
    }
    assert.ok(!s.error, `the scenario failed: ${s.error}\n${r.stderr.slice(-3000)}`);
    const diag = `\n--- legs ---\n${JSON.stringify(s.legs, null, 1)}\n--- accepts ---\n${JSON.stringify(s.seen)}\n--- reader failures ---\n${JSON.stringify(s.fails)}\n--- launch output (tail) ---\n${s.outTail}`;
    assert.equal(s.code, 0, `the launch failed${diag}`);
    assert.ok(s.guardLive, `the guard did not engage in the launch${diag}`);
    assert.ok(s.agentDone, `the agent did not finish (a server hung)${diag}`);
    assert.deepEqual(s.ready, { plain: true, unbound: true, bound: true }, `every server must listen${diag}`);

    const has = (v: string | undefined, c: string): boolean => (v ?? "").includes(c);
    const served = (v: string | undefined, c: string): boolean => (v ?? "").startsWith("data:") && has(v, c);
    // A refused connection: reset by the guard, nothing read (`refusedLeg`).
    const refused = refusedLeg;

    // ── the liveness control: a non-holder gets every connection ────────────
    const plain = s.legs["plain"]!;
    for (const k of ["outside", "inside", "loopback", "own", "unix"]) {
      assert.equal(plain[k], "data:LIVE-plain", `control: the non-holder's ${k} client must be served${diag}`);
    }
    assert.deepEqual(s.seen["plain"], ["ok", "ok", "ok", "ok", "unix-ok"], `control: the non-holder's every accept returns a connection${diag}`);

    // ── a holder of an unbound file ─────────────────────────────────────────
    const ub = s.legs["unbound"]!;
    assert.ok(refused(ub["outside"]), `THE LEAK: the other machine (203.0.113.9) was not reset by the unbound holder: ${ub["outside"]}${diag}`);
    assert.ok(refused(ub["inside"]), `THE LEAK: the other machine (10.77.0.2, not this file's binding) was not reset: ${ub["inside"]}${diag}`);
    for (const k of ["loopback", "own", "unix"]) {
      assert.ok(served(ub[k], s.unboundCanary), `this machine's ${k} client must be served the unbound holder's file: ${ub[k]}${diag}`);
    }
    assert.deepEqual(s.seen["unbound"], ["e103", "e103", "ok", "ok", "unix-ok"],
      `the unbound holder's accepts: ECONNABORTED for each remote peer (it never gets them), then this machine and the Unix client${diag}`);

    // ── a holder of a file bound to 10.77.0.2 ───────────────────────────────
    const b = s.legs["bound"]!;
    assert.ok(refused(b["outside"]), `THE LEAK: 203.0.113.9 (not the binding) was not reset by the bound holder: ${b["outside"]}${diag}`);
    assert.ok(served(b["inside"], s.boundCanary), `the bound host (10.77.0.2) must be served: ${b["inside"]}${diag}`);
    for (const k of ["loopback", "own", "unix"]) {
      assert.ok(served(b[k], s.boundCanary), `this machine's ${k} client must be served the bound holder's file: ${b[k]}${diag}`);
    }
    assert.deepEqual(s.seen["bound"], ["e103", "ok", "ok", "ok", "unix-ok"],
      `the bound holder's accepts: ECONNABORTED for 203.0.113.9 only${diag}`);

    // ── the oracle: no canary reached the other machine unbound ─────────────
    for (const v of [ub["outside"], ub["inside"], b["outside"]]) {
      assert.ok(!has(v, s.unboundCanary) && !has(v, s.boundCanary), `THE LEAK: a canary reached an unbound peer: ${v}${diag}`);
    }
    console.error(`holder-accept: legs ${JSON.stringify(s.legs)}`);
    console.error(`holder-accept: accepts ${JSON.stringify(s.seen)}`);
  } finally {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  }
});
