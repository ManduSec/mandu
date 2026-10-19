/**
 * wire-release-restart — the session's word that its egress proxy inspects
 * TLS (plan 10 §11.13.1, `registerWireRelease`, human plane) survives an
 * arbiter restart under the live session, and only that (2026-10-17), over
 * the REAL components: an ArbiterServer reading a policy FILE, restarted on
 * the same mandu.db; the open decision asked on the human socket as the
 * guard asks it; and the net-proxy's production adapter (`new
 * ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`)
 * asking the egress gate as the proxy does for an HTTPS request carrying the
 * token's placeholder in its Authorization header.
 *
 * Before: the word lived in the arbiter's memory only. A restart under a live
 * session dropped it and npm read `~/.npmrc` raw until the next launch: the
 * fail-closed direction (npm then holds the token as a confined reader, its
 * output masked, its sends held to the registry), but the npx MCP servers
 * were tainted again, which the wire twin exists to avoid. Now:
 *
 *   1. a word given with a LIVE launcher's pid is taken back by the restarted
 *      arbiter: npm is still served the twin, no taint is recorded, and the
 *      proxy still puts the token back at its registry only;
 *   2. a word whose launcher is gone, or which its launcher withdrew at the
 *      session's end (`inspecting: false`), is not: npm reads raw again;
 *   3. the data socket (the agent's world) cannot give the word at all.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { pollDiskApproving } from "../../arbiter/test/held-disk.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const REGISTRY = "registry.corp.example";
const TOKEN = "npm_WIRERESTART_CANARY_5Kq9";
const LIVE = "sess-live";
const GONE = "sess-gone";
const ENDED = "sess-ended";
/** npm's CLI as the guard reports it: a system script out of the agent's reach. */
const NPM_CLI = { path: "/usr/lib/node_modules/npm/bin/npm-cli.js", sha256: "c".repeat(64), system: true, isolated: true, traced: false };

interface Stack {
  server: ArbiterServer;
  data: ArbiterClient;
  human: ArbiterClient;
  net: NetProxyAdapter;
  close: () => Promise<void>;
}

function harness() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-wire-restart-"));
  const home = join(tmp, "home");
  mkdirSync(home);
  const npmrc = join(home, ".npmrc");
  writeFileSync(npmrc, `registry=https://${REGISTRY}/\n//${REGISTRY}/:_authToken=${TOKEN}\n`);
  // The arbiter's own HOME is not the launch's: a label names the file (the
  // open decision judges the path by the law, the registration by `home`).
  const policy = join(tmp, "policy.yaml");
  // npm's own script, vouched for (plan 13 D8 (12)): node reads the file raw
  // only as that script, which is the read the wire twin replaces.
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${JSON.stringify(npmrc)}\n    level: no-model\n    readers: [{ app: node, script: ${NPM_CLI.path}, prints: nothing }]\n`);
  const dbPath = join(tmp, "mandu.db");
  let starts = 0;
  const start = async (): Promise<Stack> => {
    const n = ++starts;
    const sock = join(tmp, `a${n}.sock`);
    const humanSock = join(tmp, `h${n}`, "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, adminSocketPath: join(tmp, `admin${n}.sock`), humanSocketPath: humanSock,
      dbPath, eventDir: join(tmp, "events"), log: () => {},
      confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const netData = new ArbiterClient(sock); await netData.connect();
    const netHuman = new ArbiterClient(humanSock); await netHuman.connect();
    const net = new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never);
    return {
      server, data, human, net,
      close: async () => {
        data.close(); human.close(); netData.close(); netHuman.close();
        await server.close();
      },
    };
  };
  let opens = 0;
  /** npm (node running npm's script) opening `~/.npmrc` in `session`, asked
   *  on the human socket as the guard asks. */
  const npmOpens = async (s: Stack, session: string): Promise<{ verdict: string; reason: string; procKey: string }> => {
    const procKey = `${7000 + ++opens}-1`;
    const d = await s.human.decideSecretOpen({ path: npmrc, exe: "/usr/bin/node", isAgent: false, exeSystem: true, openerEnv: [], procKey, session, ask: "known", script: NPM_CLI });
    return { verdict: d.verdict, reason: d.reason, procKey };
  };
  /** The egress gate's rule for the placeholder in an HTTPS request's Authorization header. */
  const ruleAt = async (s: Stack, symbol: string, host: string): Promise<string> => {
    const d = await s.net.desymbolizationDecision({ symbol, boundary: "network", destination: host, scheme: "https", positions: ["authorization"] });
    return d.ruleRef?.id ?? (d.allow ? "allow" : "deny");
  };
  return { npmrc, home, start, npmOpens, ruleAt, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

test("a live launcher's word that the session proxy inspects TLS survives an arbiter restart: npm keeps the twin, the token goes to its registry only; an ended or gone launch's word does not come back", async () => {
  const h = harness();
  let s = await h.start();
  // A launcher that has exited: its pid names no process now.
  const gonePid = spawnSync("true").pid;
  assert.ok(typeof gonePid === "number" && gonePid > 0);
  try {
    // The launch: the HOME `.npmrc` registered on the human socket, as the
    // launcher does (the wire grant binds the token to its registry).
    const reg = await s.human.registerSecret({ path: h.npmrc, home: h.home, sessionKey: LIVE });
    assert.ok(reg.symbol && reg.twin, reg.reason);
    assert.ok(!reg.twin!.includes(TOKEN), "the twin holds no secret byte");
    const tokenSym = /:_authToken=(\S+)/.exec(reg.twin!)![1]!;
    assert.match(tokenSym, /^\$MDU:/);

    // No word yet: npm reads raw (the confined-reader default).
    assert.equal((await h.npmOpens(s, LIVE)).verdict, "raw");

    // The data socket (the agent's world) cannot give the word.
    await assert.rejects(s.data.registerWireRelease(LIVE, true, [], { pid: process.pid }), /human-plane/);
    assert.equal((await h.npmOpens(s, LIVE)).verdict, "raw", "the refused word changed nothing");

    // Three launches give it: one alive (this process stands for its
    // launcher), one whose launcher is gone, one that ends and withdraws it.
    assert.deepEqual(await s.human.registerWireRelease(LIVE, true, ["127.0.0.1", "localhost"], { pid: process.pid }), { inspecting: true });
    await s.human.registerWireRelease(GONE, true, [], { pid: gonePid });
    await s.human.registerWireRelease(ENDED, true, [], { pid: process.pid });
    for (const sess of [LIVE, GONE, ENDED]) {
      const d = await h.npmOpens(s, sess);
      assert.equal(d.verdict, "twin", `${sess}: ${d.reason}`);
    }
    // The session ENDED's launcher withdraws its word at the end.
    await s.human.registerWireRelease(ENDED, false, undefined, { pid: process.pid });
    assert.equal((await h.npmOpens(s, ENDED)).verdict, "raw");

    // The arbiter goes down under the live sessions and comes back on the
    // same mandu.db. No launch registers anything again.
    await s.close();
    s = await h.start();
    pollDiskApproving(s.server);

    const live = await h.npmOpens(s, LIVE);
    assert.equal(live.verdict, "twin", `after the restart the live session keeps npm on the twin: ${live.reason}`);
    assert.equal((await s.data.processSecretTaint(live.procKey)).level, null, "the twin holds no byte: no taint after the restart either");
    assert.equal((await h.npmOpens(s, GONE)).verdict, "raw", "a gone launcher's word is not taken back (fail-closed)");
    assert.equal((await h.npmOpens(s, ENDED)).verdict, "raw", "a withdrawn word is not taken back");
    assert.equal((await h.npmOpens(s, "sess-other")).verdict, "raw", "a session nobody vouched for");

    // What npm sends with the twin: the token's placeholder, put back at its
    // own registry only, in the Authorization header only.
    assert.equal(await h.ruleAt(s, tokenSym, REGISTRY), "egress:secret-bound-trusted");
    assert.equal(await h.ruleAt(s, tokenSym, "evil.example"), "egress:secret-unbound");
    const body = await s.net.desymbolizationDecision({ symbol: tokenSym, boundary: "network", destination: REGISTRY, scheme: "https", positions: ["body"] });
    assert.equal(body.ruleRef?.id, "egress:secret-wire-position");

    // The live session ends: withdrawn, and a later restart does not bring it back.
    await s.human.registerWireRelease(LIVE, false, undefined, { pid: process.pid });
    assert.equal((await h.npmOpens(s, LIVE)).verdict, "raw");
    await s.close();
    s = await h.start();
    pollDiskApproving(s.server);
    assert.equal((await h.npmOpens(s, LIVE)).verdict, "raw", "an ended session's word stays gone across a restart");
  } finally {
    await s.close();
    h.cleanup();
  }
});
