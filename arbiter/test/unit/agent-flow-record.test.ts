/**
 * agent-flow-record.test.ts — confidentiality plan 13 §4.5.1, the decision
 * of 2026-10-02 (mask, do not refuse), the arbiter half: the agent process
 * itself is never made a holder (D2's exemption), so when IT connects to a
 * holder (an HTTP MCP server that read `.env`, a local dev server it fetches)
 * the guard records an agent flow (`recordAgentFlow`), and a result the
 * agent itself produced during a call whose window overlaps the flow is
 * masked at the holder's level (`agentReceiptTaint`), as is a side call
 * (Claude Code's WebFetch summarizer) made while such a call is out.
 *
 * Before: nothing recorded the agent's own connection, and the reply reached
 * the model with only the exact registered-value scan (a hex or base64 of the
 * file passed). Asserted here:
 *
 *   - the window: from the proxy's relay of the call (`recordCallCommand`,
 *     with or without a command) to its first ask on the human socket; a
 *     flow open across it, opened in it, or closed in it masks; one closed
 *     before the relay or opened after the ask does not; a call whose relay
 *     was never recorded is masked by every flow before its ask
 *     (fail-closed, `unattributed`);
 *   - which tools: not a shell's (its tree answers), not a file tool's, not
 *     a harness-local one; WebFetch, MCP and an unknown tool are;
 *   - D9: an open from the data socket is a claim that still masks; a close
 *     from it is not recorded; an ask from it is read-only (it cannot end a
 *     call's window before the flow opens);
 *   - the side call: masked whole while a flow overlaps the oldest call
 *     still out (or is open), raw otherwise;
 *   - (2026-10-02) a named pipe a holder writes that the agent reads with
 *     its own file tool: the guard records an agent flow whose channel is
 *     the FIFO's path; a file tool's result is masked by such a flow in its
 *     window and by no socket flow (red before: a Read of the FIFO reached
 *     the model raw whenever its path carried no label).
 *
 * The guard half is interceptors/net-supervisor
 * tests/agent_flow_integration.rs; the e2e under the real guard, arbiter and
 * AnthropicProxy is tests/sandbox/guard/agent-flow.test.ts.
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
import Database from "../../db/sqlite.js";
import { isAgentFileTool, isAgentReceiptTool, HARNESS_LOCAL_TOOLS } from "../../policy/agent-receipt.js";
import { isFileChannel } from "../../provenance/provenance-store.js";
import { gateSurfaceForSpec } from "../../policy/tool-gate-surface.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: a holder's bytes reaching the model through the agent itself

/** Plan 13 §8 decision (b): the dev server python3 runs, as the guard
 *  reports a script R5's checks pin (an interpreter is a reader only so). */
const SERVER_PY = { path: "/opt/srv/server.py", sha256: "f".repeat(64), system: true, isolated: true, traced: false };

const tick = (ms = 5): Promise<void> => new Promise((ok) => setTimeout(ok, ms));

test("which tools: the agent's own receipts (WebFetch, MCP, unknown) are covered; shells, file tools and harness-local tools are not", () => {
  const cc = gateSurfaceForSpec("claude-code");
  for (const t of ["WebFetch", "mcp__dev__query", "SomeNewTool", "__unknown__"]) assert.equal(isAgentReceiptTool(t, cc), true, t);
  // TaskOutput is a poll of a background task: a mapped shell since 2026-10-02 (plan 10 §11.12), masked at the session's level, a superset of this leg.
  for (const t of ["Bash", "BashOutput", "TaskOutput", "Monitor", "Read", "Grep", "Glob", "Edit", "Write", "NotebookEdit", ...HARNESS_LOCAL_TOOLS]) assert.equal(isAgentReceiptTool(t, cc), false, t);
  const oc = gateSurfaceForSpec("opencode");
  assert.equal(isAgentReceiptTool("bash", oc), false);
  assert.equal(isAgentReceiptTool("webfetch", oc), true);
  // 2026-10-02: the file tools, masked only by a flow on a file-like channel.
  for (const t of ["Read", "Grep", "Glob", "Edit", "Write", "NotebookEdit"]) assert.equal(isAgentFileTool(t, cc), true, t);
  for (const t of ["Bash", "WebFetch", "mcp__dev__query", "TodoWrite"]) assert.equal(isAgentFileTool(t, cc), false, t);
  assert.equal(isFileChannel("/tmp/w/pipe.fifo"), true);
  assert.equal(isFileChannel("socket:[41]"), false);
});

test("the store: a file tool counts a FIFO flow in its window and no socket flow; a network tool counts both", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-flow-"));
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  try {
    p.taintProcessSecret({ procKey: "w-1", path: "/w/.env", level: "no-model", app: "cat" });
    p.recordCallPending("R1", "s");
    p.recordCallPending("F1", "s");
    await tick();
    p.recordAgentFlow("socket:[71]", ["w-1"], "s");
    await tick();
    assert.equal(p.agentReceiptTaint("R1", { session: "s", channels: "file" }).level, null, "a socket the agent holds is not what its Read read");
    assert.equal(p.agentReceiptTaint("F1", { session: "s" }).level, "no-model", "a network tool counts every flow");
    p.closeAgentFlow("socket:[71]");
    p.recordCallPending("R2", "s");
    await tick();
    p.recordAgentFlow("/w/pipe.fifo", ["w-1"], "s");
    await tick();
    const r2 = p.agentReceiptTaint("R2", { session: "s", channels: "file" });
    assert.equal(r2.level, "no-model", `before: the agent's Read of a FIFO a holder writes reached the model raw: ${JSON.stringify(r2)}`);
    assert.deepEqual(r2.rows.map((r) => r.path), ["/w/.env"]);
    p.closeAgentFlow("/w/pipe.fifo");
    await tick();
    p.recordCallPending("R3", "s");
    await tick();
    assert.equal(p.agentReceiptTaint("R3", { session: "s", channels: "file" }).level, null, "a Read after the FIFO closed is raw");
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the store: a call's window (relay → first ask) against each flow's [open, close]", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-flow-"));
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  try {
    p.taintProcessSecret({ procKey: "srv-1", path: "/w/.env", level: "no-model", app: "python3", exe: "/usr/bin/python3", via: "reader" });
    // A flow closed before call A is relayed: not A's.
    p.recordAgentFlow("socket:[11]", ["srv-1"], "s");
    await tick();
    assert.equal(p.closeAgentFlow("socket:[11]"), 1);
    await tick();
    p.recordCallPending("A", "s");
    await tick();
    const a = p.agentReceiptTaint("A", { session: "s" });
    assert.equal(a.level, null, `a flow closed before the relay: ${JSON.stringify(a)}`);
    assert.equal(a.relayKnown, true);
    // Call B: the flow opens inside its window.
    p.recordCallPending("B", "s");
    await tick();
    p.recordAgentFlow("socket:[12]", ["srv-1"], "s");
    await tick();
    const b = p.agentReceiptTaint("B", { session: "s" });
    assert.equal(b.level, "no-model");
    assert.deepEqual(b.rows.map((r) => r.path), ["/w/.env"]);
    // Call C: relayed while socket:[12] is still open (keep-alive): masked.
    p.recordCallPending("C", "s");
    await tick();
    assert.equal(p.agentReceiptTaint("C", { session: "s" }).level, "no-model", "a connection open across the call masks it (conservative)");
    // The window of B is fixed at its first ask: later asks answer the same.
    p.closeAgentFlow("socket:[12]");
    await tick();
    assert.equal(p.agentReceiptTaint("B", { session: "s" }).level, "no-model");
    // Call D: relayed after the close, a flow opened only after D's ask.
    p.recordCallPending("D", "s");
    await tick();
    assert.equal(p.agentReceiptTaint("D", { session: "s" }).level, null);
    await tick();
    p.recordAgentFlow("socket:[13]", ["srv-1"], "s");
    assert.equal(p.agentReceiptTaint("D", { session: "s" }).level, null, "a flow opened after the call's first ask is not the call's");
    // Unattributed: no relay recorded: every flow before the ask counts.
    const u = p.agentReceiptTaint("U", { session: "s" });
    assert.equal(u.level, "no-model");
    assert.equal(u.relayKnown, false);
    // Another session's flow is not this one's.
    p.recordCallPending("E", "other");
    await tick();
    assert.equal(p.agentReceiptTaint("E", { session: "other" }).level, null, "a flow of session s is not another session's");
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the store: a session's flows only; a holder with nothing held masks nothing; one open is recorded once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-flow-"));
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  try {
    p.taintProcessSecret({ procKey: "srv-1", path: "/w/.env", level: "no-model", app: "python3" });
    p.recordAgentFlow("socket:[21]", ["srv-1"], "s1");
    assert.equal(p.recordAgentFlow("socket:[21]", ["srv-1"], "s1"), 0, "an open flow is not recorded twice");
    p.recordCallPending("X", "s2");
    await tick();
    assert.equal(p.agentReceiptTaint("X", { session: "s2" }).level, null, "another session's flow");
    p.recordAgentFlow("socket:[22]", ["clean-9"], "s2");
    p.recordCallPending("Y", "s2");
    await tick();
    assert.equal(p.agentReceiptTaint("Y", { session: "s2" }).level, null, "a connection to a process that holds nothing");
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the store: a side call is masked while a flow overlaps the oldest call still out, or is open", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-flow-"));
  const p = new ProvenanceStore({ dbPath: join(dir, "p.db") });
  try {
    p.taintProcessSecret({ procKey: "srv-1", path: "/w/.env", level: "no-model", app: "python3" });
    assert.equal(p.sideCallAgentTaint("s").level, null, "nothing out, nothing open");
    p.recordCallPending("W", "s"); // WebFetch relayed
    await tick();
    p.recordAgentFlow("socket:[31]", ["srv-1"], "s");
    await tick();
    p.closeAgentFlow("socket:[31]"); // the fetch's connection closed
    await tick();
    assert.equal(p.sideCallAgentTaint("s").level, "no-model", "the summarizer while the WebFetch is out");
    p.agentReceiptTaint("W", { session: "s" }); // the WebFetch result came back
    assert.equal(p.sideCallAgentTaint("s").level, null, "after the result: nothing out, nothing open");
    p.recordAgentFlow("socket:[32]", ["srv-1"], "s");
    assert.equal(p.sideCallAgentTaint("s").level, "no-model", "a flow open now");
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

/** WAL frames written since the last checkpoint, read and reset from a
 *  second connection: one commit writes a few frames, a commit per row at
 *  least one per row (each commit is also one WAL sync). */
function walFrames(dbPath: string): number {
  const db = new Database(dbPath);
  try {
    const [r] = db.pragma("wal_checkpoint(PASSIVE)") as Array<{ busy: number; log: number }>;
    const [t] = db.pragma("wal_checkpoint(TRUNCATE)") as Array<{ busy: number }>;
    assert.equal(r!.busy + t!.busy, 0, "the checkpoints ran");
    return r!.log;
  } finally { db.close(); }
}

test("the store: every call of one request is asked about in ONE commit, with the answers of the calls asked one by one (CI 10995, 11016: a commit per call outran the proxy's 5 s deadline on a slow disk)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-flow-"));
  const dbPath = join(dir, "p.db");
  const p = new ProvenanceStore({ dbPath });
  try {
    p.taintProcessSecret({ procKey: "srv-1", path: "/w/.env", level: "no-model", app: "python3", exe: "/usr/bin/python3", via: "reader" });
    const N = 82;
    const ids = (k: string) => Array.from({ length: N }, (_, i) => `${k}${i}`);
    for (const id of [...ids("one-"), ...ids("all-")]) p.recordCallPending(id, "s");
    await tick();
    p.recordAgentFlow("socket:[21]", ["srv-1"], "s");
    await tick();
    // Each call's opts as the arbiter's op builds them: a network tool, a
    // file tool, a tool this leg does not cover.
    const opts = (i: number) => ({ session: "s", ...(i % 3 === 1 ? { channels: "file" as const } : {}), ...(i % 3 === 2 ? { recordOnly: true } : {}) });
    walFrames(dbPath);
    const oneByOne = ids("one-").map((id, i) => p.agentReceiptTaint(id, opts(i)));
    const before = walFrames(dbPath);
    const batched = p.agentReceiptTaints(ids("all-").map((callId, i) => ({ callId, opts: opts(i) })));
    const after = walFrames(dbPath);
    assert.ok(before >= N, `one by one, a commit per call: ${before} WAL frames`);
    assert.ok(after < 10, `before: ${before} WAL frames (a sync each) for one request's ${N} calls; now ${after}`);
    assert.deepEqual(batched, oneByOne, "the same answers");
    assert.deepEqual(batched.map((t) => t.level).slice(0, 3), ["no-model", null, null], "the socket flow masks the network tool only");
    // Each call's first ask is recorded: the windows end there, as before.
    assert.equal(p.agentReceiptTaint("all-0", { session: "s" }).level, "no-model");
    assert.deepEqual(p.agentReceiptTaints([]), []);
  } finally {
    p.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

async function rig(): Promise<{ human: ArbiterClient; agent: ArbiterClient; env: string; dbPath: string; done: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-agent-flow-ipc-"));
  const env = join(dir, ".env");
  writeFileSync(env, "STRIPE_KEY=sk_live_AGENTFLOW00000001\n");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"),
    eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    // Plan 13 §8 decision (b): python3 reads only as the script it runs.
    policyDocument: { version: 1, paths: [{ path: env, level: "no-model", readers: [{ app: "python3", script: SERVER_PY.path, prints: "nothing" }] }] },
  });
  await s.listen();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's and the proxies' channel (plan 13 D9)
  const agent = new ArbiterClient(join(dir, "a.sock")); // what the agent's processes reach
  await human.connect(); await agent.connect();
  return { human, agent, env, dbPath: join(dir, "db.sqlite"), done: async () => { human.close(); agent.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("over IPC: the guard's record masks a WebFetch and an MCP result in the window, not a Read or a Bash; a call relayed after the close is raw", async () => {
  const { human, env, done } = await rig();
  try {
    const sess = "af";
    assert.equal((await human.decideSecretOpen({ path: env, exe: "/usr/bin/python3", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], script: SERVER_PY, procKey: "af-srv-1", session: sess })).verdict, "raw");
    for (const id of ["toolu_fetch", "toolu_mcp", "toolu_read"]) assert.equal((await human.recordCallCommand({ callId: id, sessionKey: sess })).recorded, true, "a command-less relay is recorded");
    await tick();
    await human.recordAgentFlow({ channel: "socket:[41]", flowsFrom: ["af-srv-1"], session: sess });
    await tick();
    const r = await human.agentReceiptTaint([
      { callId: "toolu_fetch", tool: "WebFetch" }, { callId: "toolu_mcp", tool: "mcp__dev__env" }, { callId: "toolu_read", tool: "Read" }, { callId: "toolu_bash", tool: "Bash" },
    ], sess);
    const lv = Object.fromEntries(r.calls.map((c) => [c.callId, c.level]));
    assert.equal(lv["toolu_fetch"], "no-model", `before: the agent's own fetch of a holder reached the model raw: ${JSON.stringify(r)}`);
    assert.equal(lv["toolu_mcp"], "no-model");
    assert.equal(lv["toolu_read"], null, "a file tool is not the agent's receipt");
    assert.equal(lv["toolu_bash"], null, "a shell result is its tree's (callTaint)");
    assert.equal(r.calls.find((c) => c.callId === "toolu_bash")!.callId, "toolu_bash");
    assert.deepEqual(r.calls.find((c) => c.callId === "toolu_fetch")!.files, [env]);
    // The guard sees the agent drop the connection; a later call is raw.
    assert.equal((await human.recordAgentFlow({ channel: "socket:[41]", closed: true, session: sess })).recorded, true);
    await tick();
    await human.recordCallCommand({ callId: "toolu_fetch2", sessionKey: sess });
    await tick();
    const later = await human.agentReceiptTaint([{ callId: "toolu_fetch2", tool: "WebFetch" }], sess);
    assert.equal(later.calls[0]!.level, null, `utility: a fetch after the connection closed is raw: ${JSON.stringify(later)}`);
  } finally { await done(); }
});

test("over IPC: one ask about a request's 82 results is one commit, and each answer is its call's (CI 10995, 11016: 82 WAL syncs outran the proxy's 5 s deadline)", async () => {
  const { human, env, dbPath, done } = await rig();
  try {
    const sess = "afb";
    assert.equal((await human.decideSecretOpen({ path: env, exe: "/usr/bin/python3", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], script: SERVER_PY, procKey: "afb-srv-1", session: sess })).verdict, "raw");
    const calls = Array.from({ length: 82 }, (_, i) => ({ callId: `toolu_b${i}`, tool: i % 2 === 0 ? "Read" : "WebFetch" }));
    for (const c of calls) await human.recordCallCommand({ callId: c.callId, sessionKey: sess });
    await tick();
    await human.recordAgentFlow({ channel: "socket:[61]", flowsFrom: ["afb-srv-1"], session: sess });
    await tick();
    walFrames(dbPath);
    const r = await human.agentReceiptTaint(calls, sess);
    const frames = walFrames(dbPath);
    assert.ok(frames < 10, `before: a commit (a WAL sync) per call, ${calls.length} or more frames; now ${frames}`);
    assert.deepEqual(r.calls.map((c) => c.callId), calls.map((c) => c.callId), "every call answered, in order");
    assert.deepEqual(r.calls.map((c) => c.level), calls.map((c) => (c.tool === "WebFetch" ? "no-model" : null)), "the socket flow masks the fetches, not the Reads");
  } finally { await done(); }
});

test("over IPC: the agent's Read of a FIFO a holder writes is masked by the guard's FIFO record; a Read beside a socket flow stays raw", async () => {
  const { human, env, done } = await rig();
  try {
    const sess = "aff";
    assert.equal((await human.decideSecretOpen({ path: env, exe: "/usr/bin/python3", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], script: SERVER_PY, procKey: "aff-w-1", session: sess })).verdict, "raw");
    for (const id of ["toolu_read_sock", "toolu_read_fifo", "toolu_grep_fifo"]) await human.recordCallCommand({ callId: id, sessionKey: sess });
    await tick();
    await human.recordAgentFlow({ channel: "socket:[81]", flowsFrom: ["aff-w-1"], session: sess });
    await tick();
    const sock = await human.agentReceiptTaint([{ callId: "toolu_read_sock", tool: "Read" }], sess);
    assert.equal(sock.calls[0]!.level, null, "utility: a Read is not masked by a socket the agent holds");
    await human.recordAgentFlow({ channel: "/w/pipe.fifo", flowsFrom: ["aff-w-1"], session: sess });
    await tick();
    const r = await human.agentReceiptTaint([{ callId: "toolu_read_fifo", tool: "Read" }, { callId: "toolu_grep_fifo", tool: "Grep" }], sess);
    const lv = Object.fromEntries(r.calls.map((c) => [c.callId, c.level]));
    assert.equal(lv["toolu_read_fifo"], "no-model", `before: the agent's own Read of a FIFO a holder writes reached the model raw: ${JSON.stringify(r)}`);
    assert.equal(lv["toolu_grep_fifo"], "no-model");
    assert.deepEqual(r.calls.find((c) => c.callId === "toolu_read_fifo")!.files, [env]);
  } finally { await done(); }
});

test("D9 over IPC: the data socket's open is a claim that masks; its close and its ask change nothing", async () => {
  const { human, agent, env, done } = await rig();
  try {
    const sess = "af9";
    assert.equal((await human.decideSecretOpen({ path: env, exe: "/usr/bin/python3", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], script: SERVER_PY, procKey: "af9-srv-1", session: sess })).verdict, "raw");
    // An ask from the agent's tree before the flow opens must not end the
    // call's window there (it would let the result pass raw).
    await human.recordCallCommand({ callId: "toolu_x", sessionKey: sess });
    assert.equal((await agent.recordCallCommand({ callId: "toolu_forged", sessionKey: sess })).recorded, false, "a relay from the data socket is not recorded");
    await tick();
    const early = await agent.agentReceiptTaint([{ callId: "toolu_x", tool: "WebFetch" }], sess);
    assert.equal(early.calls[0]!.level, null);
    await tick();
    await human.recordAgentFlow({ channel: "socket:[51]", flowsFrom: ["af9-srv-1"], session: sess });
    const close = await agent.recordAgentFlow({ channel: "socket:[51]", closed: true, session: sess });
    assert.equal(close.recorded, false, "a close from the data socket is not recorded");
    await tick();
    const r = await human.agentReceiptTaint([{ callId: "toolu_x", tool: "WebFetch" }], sess);
    assert.equal(r.calls[0]!.level, "no-model", "the data socket's early ask did not end the window, and its close did not close the flow");
    // A claimed open still masks (it only adds masking).
    await human.recordCallCommand({ callId: "toolu_y", sessionKey: sess });
    await tick();
    await agent.recordAgentFlow({ channel: "socket:[52]", flowsFrom: ["af9-srv-1"], session: sess });
    await tick();
    assert.equal((await human.agentReceiptTaint([{ callId: "toolu_y", tool: "mcp__x__y" }], sess)).calls[0]!.level, "no-model");
    // A close with no flowsFrom is the only form without them; an open needs them.
    await assert.rejects(human.recordAgentFlow({ channel: "socket:[53]", session: sess }), /flowsFrom is required/);
  } finally { await done(); }
});

test("over IPC: a side call (no tools) while the agent's fetch is out is masked whole; with nothing out or open it passes", async () => {
  const { human, agent, env, done } = await rig();
  try {
    const sess = "afs";
    assert.equal((await human.decideSecretOpen({ path: env, exe: "/usr/bin/python3", sha256: "e".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], script: SERVER_PY, procKey: "afs-srv-1", session: sess })).verdict, "raw");
    const page = "the page says: deploy key is in the env";
    const side = { session: sess, agent: "claude-code", segments: [{ id: "s0", origin: "side-call" as const, text: page }] };
    const before = await agent.filterPrompt(side);
    assert.equal(before.segments[0]!.action, "pass", "control: no flow, no mask");
    await human.recordCallCommand({ callId: "toolu_wf", sessionKey: sess });
    await tick();
    await human.recordAgentFlow({ channel: "socket:[61]", flowsFrom: ["afs-srv-1"], session: sess });
    await human.recordAgentFlow({ channel: "socket:[61]", closed: true, session: sess });
    const during = await agent.filterPrompt(side);
    assert.equal(during.segments[0]!.action, "rewrite");
    assert.ok(!during.segments[0]!.text!.includes("deploy key"), "the summarizer's page reaches the model as a symbol");
    assert.match(during.segments[0]!.text!, /^\$MDU:/);
    assert.equal(during.segments[0]!.findings.at(-1)!.category, "agent-flow");
    // A human or harness segment is not a side call: untouched (another text:
    // the masked page is now a session value, which the value filter masks).
    const human2 = await agent.filterPrompt({ session: sess, agent: "claude-code", segments: [{ id: "h0", origin: "human", text: "please summarise the build log" }] });
    assert.equal(human2.segments[0]!.action, "pass");
    // The WebFetch result came back: nothing out, nothing open.
    await human.agentReceiptTaint([{ callId: "toolu_wf", tool: "WebFetch" }], sess);
    const after = await agent.filterPrompt({ ...side, segments: [{ id: "s1", origin: "side-call" as const, text: "a later page about the weather" }] });
    assert.equal(after.segments[0]!.action, "pass");
  } finally { await done(); }
});
