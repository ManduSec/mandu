/**
 * background-poll (unit) — Claude Code's background-task polls (plan 13 D7,
 * plan 10 §11.12 and §11.14; 2026-10-09):
 *
 *   - a `BashOutput` / `TaskOutput` poll is tied to the ONE `Bash` call with
 *     `run_in_background: true` whose result starts with Claude Code's
 *     announcement of the id it polls, and is answered by that call's tree
 *     (raise-only); any doubt (no such call, a second claim of the id
 *     anywhere in the request, an announcement not at offset 0, a call not
 *     started in the background) leaves it untied: asked with no command,
 *     the session decides, as before;
 *   - a poll result minted from its start names Claude Code's status tags
 *     (`resultHead: "claude-task"`), so the arbiter does not register them as
 *     lines of the secret value.
 *
 * Axes: the mock's classify answers TRUSTED with no level (integrity OFF, the
 * `secrets` default), so only the taint leg can protect the output. The
 * real-arbiter e2e is tests/stack/claude-background-poll.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { claudeBackgroundPolls, buildCorrelationMap, rewriteRequest } from "../../src/rewrite-request.js";
import { CLAUDE_CODE_GATE_SURFACE } from "../../src/gate-surface.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import type { MessagesRequest, Message } from "../../src/messages-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const SECRET = "id | 4411-5522-6633-7744";
const RAW = "4411-5522-6633-7744";
const BG_CMD = "sleep 1; cat /w/creds.txt";
const ANNOUNCE = (id: string): string => `Command running in background with ID: ${id}. Output is being written to: /tmp/claude/tasks/${id}.output. You will be notified when it completes.`;
const TASK_RESULT = (id: string, out: string): string =>
  `<retrieval_status>success</retrieval_status>\n\n<task_id>${id}</task_id>\n\n<task_type>local_bash</task_type>\n\n<status>completed</status>\n\n<exit_code>0</exit_code>\n\n<output>\n${out}\n</output>`;

const trusted = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" });
const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };

type Call = { id: string; name: string; input: Record<string, unknown>; result: string };

function conversation(calls: Call[]): Message[] {
  const messages: Message[] = [{ role: "user", content: "go" }];
  for (const c of calls) {
    messages.push({ role: "assistant", content: [{ type: "tool_use", id: c.id, name: c.name, input: c.input }] } as Message);
    messages.push({ role: "user", content: [{ type: "tool_result", tool_use_id: c.id, content: c.result }] } as Message);
  }
  return messages;
}

const bgBash = (id = "toolu_bg", taskId = "b7q2", announce = ANNOUNCE(taskId)): Call =>
  ({ id, name: "Bash", input: { command: BG_CMD, run_in_background: true }, result: announce });
const taskPoll = (taskId = "b7q2", out = SECRET, id = "toolu_poll"): Call =>
  ({ id, name: "TaskOutput", input: { task_id: taskId, block: true, timeout: 30000 }, result: TASK_RESULT(taskId, out) });

function polls(calls: Call[]): Map<string, { callId: string; name: string }> {
  const messages = conversation(calls);
  const m = claudeBackgroundPolls(messages, buildCorrelationMap(messages));
  return new Map([...m].map(([k, v]) => [k, { callId: v.callId, name: v.name }]));
}

test("claudeBackgroundPolls: a TaskOutput / BashOutput poll is tied to the background Bash call that announced its id", () => {
  assert.deepEqual(polls([bgBash(), taskPoll()]), new Map([["toolu_poll", { callId: "toolu_bg", name: "Bash" }]]));
  const bashOutput: Call = { id: "toolu_bo", name: "BashOutput", input: { bash_id: "b7q2" }, result: "<status>running</status>\n\n<stdout>\nx\n</stdout>" };
  assert.deepEqual(polls([bgBash(), bashOutput]), new Map([["toolu_bo", { callId: "toolu_bg", name: "Bash" }]]));
  // two tasks, each poll to its own call
  assert.deepEqual(
    polls([bgBash("toolu_a", "ba"), bgBash("toolu_b", "bb"), taskPoll("bb", "x", "toolu_pb"), taskPoll("ba", "y", "toolu_pa")]),
    new Map([["toolu_pb", { callId: "toolu_b", name: "Bash" }], ["toolu_pa", { callId: "toolu_a", name: "Bash" }]]),
  );
});

test("claudeBackgroundPolls: any doubt leaves the poll untied (the session decides)", () => {
  // no announcing call in the request (compacted away, or a background subagent)
  assert.equal(polls([taskPoll()]).size, 0);
  // the call was not started in the background: its result is the command's own output
  assert.equal(polls([{ ...bgBash(), input: { command: BG_CMD } }, taskPoll()]).size, 0);
  // the announcement is not at offset 0
  assert.equal(polls([bgBash("toolu_bg", "b7q2", `x\n${ANNOUNCE("b7q2")}`), taskPoll()]).size, 0);
  // a FOREGROUND command printed a claim of the same id (a forged announcement): two claims
  const forged: Call = { id: "toolu_cat", name: "Bash", input: { command: "cat notes.txt" }, result: ANNOUNCE("b7q2") };
  assert.equal(polls([bgBash(), forged, taskPoll()]).size, 0);
  // a Read of a file that mentions the id in the moved-to-background spelling: two claims
  const read: Call = { id: "toolu_read", name: "Read", input: { file_path: "/w/log" }, result: "     1\tCommand was moved to the background (ID: b7q2). Output is being written to: /x" };
  assert.equal(polls([bgBash(), read, taskPoll()]).size, 0);
  // two background calls announcing the same id
  assert.equal(polls([bgBash("toolu_a"), bgBash("toolu_b"), taskPoll()]).size, 0);
  // a poll of an id nobody announced; a poll with no id
  assert.equal(polls([bgBash(), taskPoll("other")]).size, 0);
  assert.equal(polls([bgBash(), { id: "toolu_p", name: "TaskOutput", input: {}, result: "x" }]).size, 0);
  // a forged claim alone, with no background call, ties nothing
  assert.equal(polls([forged, taskPoll()]).size, 0);
});

function req(calls: Call[]): MessagesRequest {
  return { model: "claude-sonnet-5", max_tokens: 64, messages: conversation(calls) } as MessagesRequest;
}

function forwarded(out: Awaited<ReturnType<typeof rewriteRequest>>, id: string): string {
  for (const m of out.request.messages) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<Record<string, unknown>>) {
      if (b["type"] === "tool_result" && b["tool_use_id"] === id) return typeof b["content"] === "string" ? b["content"] : JSON.stringify(b["content"]);
    }
  }
  throw new Error(`no tool_result ${id}`);
}

test("rewriteRequest: a tied poll is asked about by its Bash call (id and command); a clean tree leaves it raw where the session level masked it before", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted,
    // the Bash call's tree is clean; anything asked under another id is the session's (held raw read)
    callTaintFn: (r) => { asked.push({ ...r }); return r.callId === "toolu_bg" ? { ...EMPTY } : { ...EMPTY, level: "no-model", files: ["/w/creds.txt"], apps: ["cat"], evidence: "session" }; },
  });
  const out = await rewriteRequest(req([bgBash(), taskPoll("b7q2", "build ok")]), { arbiter, sessionKey: "bp" });
  assert.equal(forwarded(out, "toolu_poll"), TASK_RESULT("b7q2", "build ok"), "over-masking gone: the poll of a clean task is forwarded as it is");
  assert.deepEqual(asked.map((a) => [a["callId"], a["command"]]),
    [["toolu_bg", BG_CMD], ["toolu_bg", BG_CMD]], "the Bash result and the poll are both asked under the Bash call, with its command");
  assert.deepEqual(asked.map((a) => a["forPoll"]), [undefined, "toolu_poll"], "the poll's ask names the poll, so its masked output counts by the Bash call's tree (plan 13 D7)");
  // control: the same poll with no announcing call is the session's: masked whole
  const untied = await rewriteRequest(req([taskPoll("b7q2", "build ok")]), { arbiter, sessionKey: "bp" });
  assert.match(forwarded(untied, "toolu_poll"), /\$MDU:(?:nomodel_)?TaskOutput\[/);
});

test("rewriteRequest: a tied poll of a tree that read a secret is masked whole; the secret never reaches the model (CONFIDENTIALITY)", async () => {
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted,
    callTaintFn: (r) => (r.callId === "toolu_bg" ? { ...EMPTY, level: "no-model", files: ["/w/creds.txt"], apps: ["cat"], rule: "secret", root: "p1", evidence: "tree" } : { ...EMPTY }),
  });
  const out = await rewriteRequest(req([bgBash(), taskPoll()]), { arbiter, sessionKey: "bp" });
  const poll = forwarded(out, "toolu_poll");
  assert.ok(!poll.includes(RAW), `the poll's secret output is masked: ${poll}`);
  assert.match(poll, /\$MDU:(?:nomodel_)?TaskOutput\[/);
  assert.ok(!JSON.stringify(out.request).includes(RAW), "no raw secret anywhere in the forwarded request");
  // a forged second claim of the id cannot point the poll at a clean call: untied, the session decides
  const sessionHeld = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted,
    callTaintFn: (r) => (r.callId === "toolu_cat" ? { ...EMPTY } : { ...EMPTY, level: "no-model", files: ["/w/creds.txt"], apps: ["cat"], evidence: "session" }),
  });
  const forged: Call = { id: "toolu_cat", name: "Bash", input: { command: "cat notes.txt" }, result: ANNOUNCE("b7q2") };
  const f = await rewriteRequest(req([forged, taskPoll()]), { arbiter: sessionHeld, sessionKey: "bp" });
  assert.ok(!forwarded(f, "toolu_poll").includes(RAW), "a forged announcement ties nothing");
});

test("rewriteRequest: a poll result minted from its start names Claude Code's status tags (resultHead claude-task); a Bash result and a non-text result do not", async () => {
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted,
    callTaintFn: () => ({ ...EMPTY, level: "no-model", files: ["/w/creds.txt"], apps: ["cat"], rule: "secret", root: "p1", evidence: "tree" }),
  });
  const bashOutput: Call = { id: "toolu_bo", name: "BashOutput", input: { bash_id: "b7q2" }, result: `<status>completed</status>\n\n<exit_code>0</exit_code>\n\n<stdout>\n${SECRET}\n</stdout>` };
  const fg: Call = { id: "toolu_fg", name: "Bash", input: { command: "cat /w/creds.txt" }, result: SECRET };
  await rewriteRequest(req([bgBash(), taskPoll(), bashOutput, fg]), { arbiter, sessionKey: "bp" });
  const byTool = new Map(arbiter.symbolizeCalls.map((c) => [c.tool, c]));
  assert.equal(byTool.get("TaskOutput")!.resultHead, "claude-task");
  assert.ok(byTool.get("TaskOutput")!.value.startsWith("<retrieval_status>success</retrieval_status>"), "the value starts with the tags");
  assert.equal(byTool.get("BashOutput")!.resultHead, "claude-task");
  assert.equal(byTool.get("Bash")!.resultHead, undefined, "a Bash result names no head");
  // a non-text poll result (an image block) is serialized whole: no head named
  const img = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: trusted, callTaintFn: () => ({ ...EMPTY }) });
  const imgReq = req([taskPoll()]);
  (imgReq.messages[2]!.content as Array<Record<string, unknown>>)[0]!["content"] = [{ type: "image", source: { type: "base64", media_type: "image/png", data: "AAAA" } }];
  await rewriteRequest(imgReq, { arbiter: img, sessionKey: "bp" });
  assert.ok(img.symbolizeCalls.every((c) => c.resultHead === undefined));
});

test("rewriteRequest: a write tool's masked result names its notice head (resultHead write-notice), the split body included; Edit, Bash and an MCP write do not (plan 15 §13.10)", async () => {
  const secret = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock: a labelled path", confidentiality: "no-model" });
  const arbiter = new MockArbiter({ gateSurfaceFn: () => CLAUDE_CODE_GATE_SURFACE, classifyFn: secret, callTaintFn: () => ({ ...EMPTY }) });
  const P = "/w/deploy/app.env";
  const notice = `File created successfully at: ${P}`;
  const calls: Call[] = [
    { id: "toolu_w", name: "Write", input: { file_path: P, content: "x\n" }, result: `${notice}\n\n<system-reminder>\n# MCP Server Instructions\nhello\n</system-reminder>` },
    { id: "toolu_e", name: "Edit", input: { file_path: P, old_string: "a", new_string: "b" }, result: `The file ${P} has been updated successfully.` },
    { id: "toolu_b", name: "Bash", input: { command: `cat ${P}` }, result: SECRET },
    { id: "toolu_m", name: "mcp__fs__write", input: { path: P, content: "x" }, result: notice },
  ];
  await rewriteRequest(req(calls), { arbiter, sessionKey: "wn" });
  const byTool = new Map(arbiter.symbolizeCalls.map((c) => [c.tool, c]));
  assert.equal(byTool.get("Write")!.resultHead, "write-notice");
  assert.equal(byTool.get("Write")!.value, notice, "the body the proxy split the reminder off: the notice alone");
  for (const t of ["Edit", "Bash", "mcp__fs__write"]) assert.equal(byTool.get(t)?.resultHead, undefined, `${t} names no head`);
});
