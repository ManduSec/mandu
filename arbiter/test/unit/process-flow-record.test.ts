/**
 * process-flow-record.test.ts — confidentiality plan 13 §9 R1, the arbiter
 * half: a process that received a holder's bytes through a channel the
 * guard found (a connection to the holder's listener, a socket pair or pipe
 * end passed after the taint, a pipe) holds what the holder holds, and the
 * arbiter now knows it (`recordProcessFlow`), not only the guard.
 *
 * Before: the guard told the arbiter a process's writers only as
 * `flowsFrom` on the two exits it asks about (`taintedProcessBindings`,
 * `labelWrittenPathTainted`), so the MODEL exit's fold (`callTaint`) never
 * saw them: a tool call whose `curl localhost:3000` received the secret from a
 * dev server left running by an earlier call (a holder outside the call's
 * tree) reached the model raw. Asserted here:
 *
 *   - a recorded flow is walked like a parent by `processSecretTaint`
 *     (never for `attestedOnly`: more held taint must not buy a raw read of a
 *     derived copy) and folded by `treeTaint` for every process of the tree;
 *   - no lineage edge is recorded (the writer is not the reader's parent);
 *   - over IPC, through the guard's (human) socket: a bound call whose
 *     process received from a holder outside its tree is masked; the same
 *     call without the flow is raw (the control); the receiver's exits are
 *     held to the holder's bindings with no `flowsFrom` on the request;
 *   - from the data socket a flow is a claim: it still adds taint (only a
 *     tightening); the guard records it on its own (human) socket.
 *
 * The guard half (who receives, at the accept and at the pass) is
 * interceptors/net-supervisor tests/socket_flow_integration.rs; the e2e under
 * the real guard and arbiter is launcher/test/socket-flow-live.test.sh.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { ProvenanceStore } from "../../provenance/provenance-store.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: where a holder's bytes reach through a socket

test("a recorded flow is walked like a parent and folded over the tree; no edge; never for attestedOnly", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-r1-prov-"));
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  try {
    // call 1 left a dev server running that read .env
    p.taintProcessSecret({ procKey: "srv-1", path: "/w/.env", level: "no-model", app: "node", exe: "/usr/bin/node", via: "reader" });
    // call 2: bash → curl, which connected to the server after its taint
    p.recordLineage("curl-3", "bash-2");
    assert.equal(p.treeTaint("bash-2").level, null, "before the flow: call 2's tree holds nothing");
    p.recordProcessFlow("curl-3", ["srv-1"], "s");
    assert.equal(p.processSecretTaint("curl-3").level, "no-model");
    assert.deepEqual(p.processSecretTaint("curl-3").rows.map((r) => r.path), ["/w/.env"]);
    assert.equal(p.processSecretTaint("curl-3", { attestedOnly: true }).level, null, "a flow never buys a raw read of a derived copy");
    const t = p.treeTaint("bash-2");
    assert.equal(t.level, "no-model", "the model exit's fold sees what curl received");
    assert.deepEqual(t.rows.map((r) => r.procKey), ["srv-1"]);
    assert.equal(p.processSecretTaint("bash-2").level, null, "no edge: curl's real parent did not inherit");
    // a child of the receiver holds through it
    p.recordLineage("tee-4", "curl-3");
    assert.equal(p.processSecretTaint("tee-4").level, "no-model");
    // cycles are walked once
    p.recordProcessFlow("srv-1", ["curl-3"]);
    assert.equal(p.processSecretTaint("srv-1").rows.length, 1);
    // a flow to itself, or an empty key, is not recorded
    p.recordProcessFlow("x-9", ["x-9", ""]);
    assert.deepEqual(p.flowsOf("x-9"), []);
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Plan 13 §8 decision (b): the node server reads only as the script it runs,
 *  reported by the guard as R5's checks pin it. */
const SERVER_JS = { path: "/opt/srv/server.js", sha256: "f".repeat(64), system: true, isolated: true, traced: false };

async function rig(): Promise<{ guard: ArbiterClient; agent: ArbiterClient; env: string; done: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-r1-"));
  const env = join(dir, ".env");
  writeFileSync(env, "STRIPE_KEY=sk_live_R1CANARY0000000001\n");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"),
    eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", readers: [{ app: "node", script: SERVER_JS.path, prints: "nothing" }], bindings: ["api.stripe.com"] }] },
  });
  await s.listen();
  const guard = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxies' channel (plan 13 D9)
  const agent = new ArbiterClient(join(dir, "a.sock")); // what the agent's processes reach
  await guard.connect(); await agent.connect();
  return { guard, agent, env, done: async () => { guard.close(); agent.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("over IPC: a call whose process received a holder's bytes from outside its tree is masked; without the flow it is raw; its exits hold to the holder's bindings", async () => {
  const { guard, env, done } = await rig();
  try {
    const sess = "r1";
    // call 1: a dev server (node, a reader of .env) left running
    assert.equal((await guard.decideSecretOpen({ path: env, exe: "/usr/bin/node", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], script: SERVER_JS, procKey: "r1-node-1", session: sess })).verdict, "raw");
    // call 2: curl localhost:3000; the guard found curl receiving from the server
    const cmd = "curl -s localhost:3000/debug";
    await guard.execGate({ command: cmd, sessionKey: sess, callId: "toolu_r1a" });
    await guard.recordExecRoot({ procKey: "r1-bash-2", ancestors: ["r1-agent-0"], argv: ["bash", "-lc", cmd], session: sess, callRoot: true });
    await guard.recordExecRoot({ procKey: "r1-curl-3", ancestors: ["r1-bash-2", "r1-agent-0"], argv: ["curl", "-s", "localhost:3000/debug"], session: sess });
    await guard.recordProcessFlow({ procKey: "r1-curl-3", flowsFrom: ["r1-node-1"], session: sess });
    const t = await guard.callTaint("toolu_r1a", { command: cmd, session: sess });
    assert.equal(t.root, "r1-bash-2", JSON.stringify(t));
    assert.equal(t.evidence, "tree");
    assert.equal(t.level, "no-model", `masked: before, curl's call reached the model raw: ${JSON.stringify(t)}`);
    // the control: the same shape with no flow is raw
    const cmd2 = "curl -s localhost:3000/health";
    await guard.execGate({ command: cmd2, sessionKey: sess, callId: "toolu_r1b" });
    await guard.recordExecRoot({ procKey: "r1-bash-4", ancestors: ["r1-agent-0"], argv: ["bash", "-lc", cmd2], session: sess, callRoot: true });
    await guard.recordExecRoot({ procKey: "r1-curl-5", ancestors: ["r1-bash-4", "r1-agent-0"], argv: ["curl", "-s", "localhost:3000/health"], session: sess });
    const clean = await guard.callTaint("toolu_r1b", { command: cmd2, session: sess });
    assert.equal(clean.root, "r1-bash-4");
    assert.equal(clean.level, null, JSON.stringify(clean));
    // the receiver's network exit, asked with no flowsFrom (a later event)
    const b = await guard.taintedProcessBindings({ procKey: "r1-curl-3", session: sess });
    assert.equal(b.tainted, true);
    assert.deepEqual(b.bindings, ["api.stripe.com"]);
  } finally { await done(); }
});

test("from the data socket a flow is a claim that still adds taint (only a tightening); the guard records the same flow on its own socket", async () => {
  const { guard, agent, env, done } = await rig();
  try {
    assert.equal((await guard.decideSecretOpen({ path: env, exe: "/usr/bin/node", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], script: SERVER_JS, procKey: "r1c-node-1" })).verdict, "raw");
    await agent.recordProcessFlow({ procKey: "r1c-cat-2", flowsFrom: ["r1c-node-1"] });
    const b = await guard.taintedProcessBindings({ procKey: "r1c-cat-2" });
    assert.equal(b.tainted, true, "a claimed flow only tightens, so it is kept");
    // a claim never buys a raw read: the derived-copy shortcut reads the guard's records alone (attestedOnly)
    await guard.recordProcessFlow({ procKey: "r1c-cat-2", flowsFrom: ["r1c-node-1"] });
    assert.equal((await guard.taintedProcessBindings({ procKey: "r1c-cat-2" })).tainted, true);
  } finally { await done(); }
});
