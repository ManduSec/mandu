/**
 * tainted-egress.test.ts — a process that holds a secret sends it to
 * nobody unbound, by any road out, from inside the REAL launcher sandbox
 * (exec-routing.md §7.5, "Sends are judged like connects", 2026-10-01; the
 * `network-egress/dns` gap of test-reorganization.md §11.1).
 *
 * Two "machines" on one private network with no root (tests/lib/netns.ts):
 * this side runs the real launcher in `secrets` mode around a shell agent,
 * and "the other machine" (10.77.0.2) runs a DNS server the test owns, the
 * one this side's resolv.conf names. A second server of the test's forwards
 * on this side's 127.0.0.1:53, as dnsmasq or unbound would (a resolver
 * there carries what it gets off the machine). Both log every byte.
 * (tainted-egress-scenario.fixture.ts has the probes.)
 *
 * The secrets: `~/.npmrc` and the project's `.env`, labelled `no-model`
 * with the reader python3 running the stdlib's base64.py (an R5 script
 * pin) under policy.yaml; `cat` until plan 13 D8's "printers admit
 * nothing", 2026-10-03. (Before plan 13 §8 decision (b),
 * 2026-10-02, `~/.npmrc` had no reader list and node, its default reader,
 * opened it, and policy.yaml named `bash` for `.env`; a shell or node
 * running agent-writable code is no reader now, so each holder holds the
 * secret through the reader's pipe, plan 13 D2.)
 *
 * Asserted, for a process holding the secret (the node probe after it read
 * `~/.npmrc` through the reader; bash after it sourced `.env` through it):
 *   - finding path 1: a datagram sent with an address (a DNS query,
 *     node's unconnected `dgram`) reaches neither server;
 *   - a resolver lookup of `<token>.lookup.example.test` (getaddrinfo, on
 *     a libuv worker thread) reaches neither; nor a connected datagram, nor
 *     DNS over TCP;
 *   - finding path 3: 127.0.0.1:53 (the forwarder) gets nothing;
 *   - finding path 2: a socket connected BEFORE the read refuses the read
 *     (node: a connected UDP and a TCP socket, then the reader's pipe; bash:
 *     `exec 3<>/dev/udp/…` then the reader on `.env`), and a socket connected after
 *     the read is refused;
 *   - §7.5 gap (d), a fork after the taint (2026-10-02): a tainted shell
 *     backgrounds a sender that outlives it; the launcher's guard adopts the
 *     orphan and judges it a holder, so its datagram reaches neither server;
 *   - neither canary appears in either server's log.
 * The liveness control: the same probes from a process that read nothing
 * DO reach both servers (every one of them, by its tag), so the suite cannot
 * pass because the network or the probes are broken.
 *
 * Self-SKIPs only where the topology cannot be built (no unprivileged user
 * and network namespaces), the guard is not built, or no `base64` decodes
 * (the reader's pipe names one by path, `workingBase64`); ci `maxSkip: 0`.
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
import { workingBase64 } from "../../lib/holder-reader.js";

stateAxes("secrets"); // the confidentiality axis: a secret never leaves unbound

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..", ".."); // tests/, the package root
const TSX = join(PKG_ROOT, "node_modules", ".bin", "tsx");
const GUARD = pickGuard(resolve(PKG_ROOT, "..", "interceptors", "target"));
const unavailable = process.platform !== "linux" ? "Linux only" : twoHostNetUnavailable();
const skip = unavailable
  ?? (!GUARD.path ? "mandu-net-guard is not built (scripts/build-native.sh)"
    // The reader's pipe decodes with a base64 named by path (the fixture's
    // READ); a host whose every candidate is dead SKIPs with the reason.
    : process.platform === "linux" && workingBase64() === null ? "no `base64` on PATH (or in /usr/bin, /bin) decodes (the reader's pipe)"
      : false);

interface LogLine { local: string; proto: string; data: string }
interface Scenario {
  error?: string;
  code: number;
  outTail: string;
  guardLive: boolean;
  probes: Array<Record<string, unknown>>;
  bash: string[];
  peer: LogLine[];
  fwd: LogLine[];
  npmToken: string;
  envCanary: string;
  liveTag: string;
}

test("the guard under test is built from the current sources", { skip: process.platform !== "linux" || !GUARD.path }, () => {
  assert.equal(GUARD.stale, null, GUARD.stale ?? "");
});

test("a process holding a secret sends it to no unbound destination by any road; one holding none reaches both servers", { skip, timeout: 600_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-tainted-egress-"));
  try {
    const peerLog = join(dir, "peer.log");
    const peerReady = join(dir, "peer.ready");
    writeFileSync(peerLog, "");
    const r = await runTwoHostNet({
      hosts: {},
      peer: [TSX, join(PKG_ROOT, "fixtures", "netns-dns-peer.fixture.ts")],
      peerReady,
      main: [TSX, join(PKG_ROOT, "fixtures", "tainted-egress-scenario.fixture.ts")],
      env: {
        ...process.env,
        DNS_LOG: peerLog,
        DNS_READY: peerReady,
        PEER_LOG: peerLog,
        PEER_ADDR: TWO_HOST.inside,
      },
      resolvers: [TWO_HOST.inside],
      plainNss: true,
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
    const diag = `\n--- launch output (tail) ---\n${s.outTail}\n--- probes ---\n${JSON.stringify(s.probes, null, 1)}\n${s.bash.join("\n")}`;
    assert.equal(s.code, 0, `the launch failed${diag}`);
    assert.ok(s.guardLive, `the guard did not engage in the launch${diag}`);

    const all = [...s.peer, ...s.fwd].map((l) => l.data).join("\n");
    const peer = s.peer.map((l) => l.data).join("\n");
    const fwd = s.fwd.map((l) => l.data).join("\n");

    // ── the liveness control: every road reaches its server ─────────────────
    const live = s.probes.find((p) => p["mode"] === "untainted");
    assert.ok(live, `no untainted probe ran${diag}`);
    for (const k of ["peer.sendto", "peer.udpconnect", "peer.tcp", "fwd.sendto", "fwd.udpconnect", "fwd.tcp"]) {
      assert.equal(live![k], "sent", `control ${k}: ${String(live![k])}${diag}`);
    }
    for (const [road, log, name] of [
      ["sendto-peer", peer, "the other machine"], ["udpconnect-peer", peer, "the other machine"], ["tcp-peer", peer, "the other machine"],
      ["lookup", peer, "the other machine (the resolver)"],
      ["sendto-fwd", fwd, "127.0.0.1:53"], ["udpconnect-fwd", fwd, "127.0.0.1:53"], ["tcp-fwd", fwd, "127.0.0.1:53"],
    ] as const) {
      assert.ok(log.includes(s.liveTag) && log.includes(road), `control: the untainted ${road} query never reached ${name}${diag}`);
    }

    // ── a process holding the secret ────────────────────────────────────────
    const tainted = s.probes.find((p) => p["mode"] === "tainted");
    assert.ok(tainted, `no tainted probe ran${diag}`);
    assert.equal(tainted!["read"], "raw", `the node probe must get the real ~/.npmrc through its reader (python3 running base64.py; cat admits nothing since plan 13 D8)${diag}`);
    for (const k of ["peer.sendto", "peer.udpconnect", "peer.tcp", "fwd.sendto", "fwd.udpconnect", "fwd.tcp"]) {
      assert.notEqual(tainted![k], "sent", `a holder's ${k} was sent${diag}`);
    }
    assert.ok(!String(tainted!["lookup"]).startsWith("resolved"), `a holder's lookup resolved${diag}`);

    const pre = s.probes.find((p) => p["mode"] === "pretaint");
    assert.ok(pre, `no pre-taint probe ran${diag}`);
    assert.deepEqual(pre!["pre"], ["udp", "tcp"], `control: the sockets opened before the read must connect${diag}`);
    assert.equal(pre!["read"], "EACCES", `a reader whose pipe goes to a process holding a socket to an unbound peer must not get the raw file${diag}`);

    assert.ok(s.bash.includes("BASH control=raw"), `control: bash, sourcing .env through its reader (python3 running base64.py), must get the real file${diag}`);
    assert.ok(s.bash.includes("BASH pre=refused") && !s.bash.includes("BASH pre=read") && !s.bash.includes("BASH pre=noconnect"), `bash with /dev/udp open before sourcing .env${diag}`);
    assert.ok(s.bash.includes("BASH post=refused"), `bash connecting after sourcing .env${diag}`);

    // ── gap (d), a fork after the taint: the orphan reaches nobody ───────────
    // (gap (a), a holder's accept, is proven by the kernel test
    // `a_holders_accept_takes_this_machine_and_its_bindings_only` and,
    // through the real launch, by holder-accept.test.ts (python3 servers,
    // one leg at a time); a node dev-server accept e2e here was flaky under
    // the peer's connection load.)
    assert.ok(s.bash.includes("BASH orphan=spawned"), `the orphan sender was backgrounded${diag}`);

    // ── the oracle: no canary left the machine ──────────────────────────────
    // (the holder's token among them: the accepted connection and the orphan's
    // datagram carry it, so a leak by either shows here too.)
    assert.ok(!all.includes(s.npmToken), `the ~/.npmrc token reached a server${diag}\n${all.slice(0, 2000)}`);
    assert.ok(!all.includes(s.envCanary), `the .env canary reached a server (gap d, the orphan)${diag}`);
    // The evidence, in the log of a green run.
    console.error(`tainted-egress: ${s.peer.length} message(s) at the other machine, ${s.fwd.length} at 127.0.0.1:53, none with a canary`);
    for (const p of s.probes) console.error(`tainted-egress: ${JSON.stringify(p)}`);
    for (const b of s.bash) console.error(`tainted-egress: ${b}`);
  } finally {
    if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  }
});
