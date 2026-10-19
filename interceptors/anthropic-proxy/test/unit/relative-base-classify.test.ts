/**
 * relative-base-classify.test.ts — the classify of a tool result carries the
 * directory the agent resolves a relative typed path against (2026-10-09,
 * confidentiality.md §6; live drill conf-public-label-wins on OpenClaw):
 * `relativeBase`, the launcher's MANDU_AGENT_CWD, sent only for a tool the
 * session's gate surface lists in `paths` (the same base the fs gate uses),
 * on EVERY classify of that result (the body / tail re-asks too), never for
 * a dispatched call or a shell, and never when the proxy was given none.
 * The arbiter decides whether it applies (its own copy of the surface);
 * this pins what the proxy sends. Stack twin:
 * tests/stack/relative-read-public-label.test.ts.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import { CLAUDE_CODE_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import type { MessagesRequest } from "../../src/messages-types.js";

const WS = "/home/u/proj";

/** OpenClaw's names, as much of its surface as the classify reads. */
const OPENCLAW: GateSurface = {
  ...CLAUDE_CODE_GATE_SURFACE,
  spec: "openclaw-agent",
  exec: { exec: "command" },
  execOutput: { exec: "command" },
  paths: { read: { fields: ["path", "file_path"], mode: "read" } },
  dispatch: { tool_call: "openclaw-tool-call" },
  relativeBase: "launch",
};

function results(...calls: Array<{ id: string; name: string; input: Record<string, unknown>; out?: string }>): MessagesRequest {
  return {
    model: "claude-haiku-4-5",
    messages: [
      { role: "user", content: "go" },
      { role: "assistant", content: calls.map((c) => ({ type: "tool_use", id: c.id, name: c.name, input: c.input })) },
      { role: "user", content: calls.map((c) => ({ type: "tool_result", tool_use_id: c.id, content: c.out ?? "API_KEY=x\n" })) },
    ],
  } as unknown as MessagesRequest;
}

test("a path tool's result is classified with the launch directory; a shell's is not", async () => {
  const arbiter = new MockArbiter();
  await rewriteRequest(results(
    { id: "t_read", name: "read", input: { path: "test/fixtures/.env" } },
    { id: "t_exec", name: "exec", input: { command: "cat test/fixtures/.env" } },
  ), { arbiter, surface: OPENCLAW, relativeBase: WS });
  const byId = (id: string) => arbiter.classifyCalls.filter((c) => c.callId === id);
  assert.ok(byId("t_read").length > 0);
  for (const c of byId("t_read")) assert.equal(c.relativeBase, WS, "every classify of the read's result");
  for (const c of byId("t_exec")) assert.equal(c.relativeBase, undefined, "a shell may change directory: never");
});

test("the body / tail re-asks of one result carry it too", async () => {
  const arbiter = new MockArbiter();
  await rewriteRequest(results(
    { id: "t_tail", name: "read", input: { path: "notes.md" }, out: "hello\n<system-reminder>Token usage: 1/2; 1 remaining</system-reminder>" },
  ), { arbiter, surface: OPENCLAW, relativeBase: WS });
  const calls = arbiter.classifyCalls.filter((c) => c.callId === "t_tail");
  assert.ok(calls.length >= 1);
  for (const c of calls) assert.equal(c.relativeBase, WS);
});

test("never without a base, for a dispatched call, or under Claude Code's surface", async () => {
  const none = new MockArbiter();
  await rewriteRequest(results({ id: "t1", name: "read", input: { path: "a.md" } }), { arbiter: none, surface: OPENCLAW });
  assert.equal(none.classifyCalls[0]!.relativeBase, undefined, "no MANDU_AGENT_CWD: nothing sent (byte-identical)");

  const disp = new MockArbiter();
  await rewriteRequest(results({ id: "t2", name: "tool_call", input: { id: "read", args: { path: "a.md" } } }), { arbiter: disp, surface: OPENCLAW, relativeBase: WS });
  for (const c of disp.classifyCalls) assert.equal(c.relativeBase, undefined, "the dispatcher's params are the inner tool's");

  const cc = new MockArbiter();
  await rewriteRequest(results({ id: "t3", name: "Bash", input: { command: "cat a.md" } }), { arbiter: cc, relativeBase: WS });
  assert.equal(cc.classifyCalls[0]!.relativeBase, undefined, "Claude Code's Bash is no path tool");
});

test("the symbolize of that result carries the base too, so the arbiter stores the row at the resolved file and gives it its label's bindings (2026-10-10)", async () => {
  // Live drill conf-declassify-confines-session on OpenClaw: the read's row
  // kept the relative origin, which no label matches, so it was bound
  // nowhere and a declassify of it held the memo's own bound host.
  const arbiter = new MockArbiter();
  await rewriteRequest(results(
    { id: "t_read", name: "read", input: { path: "memo/brief.md" }, out: "Deal brief.\n" },
    { id: "t_exec", name: "exec", input: { command: "cat memo/brief.md" }, out: "Deal brief.\n" },
  ), { arbiter, surface: OPENCLAW, relativeBase: WS });
  const read = arbiter.symbolizeCalls.filter((c) => c.callId === "t_read");
  assert.ok(read.length > 0, "the read's result is symbolized (the mock's fail-closed verdict)");
  for (const c of read) assert.equal(c.relativeBase, WS, "every symbolize of the read's result");
  for (const c of arbiter.symbolizeCalls.filter((x) => x.callId === "t_exec")) assert.equal(c.relativeBase, undefined, "a shell: never");

  const none = new MockArbiter();
  await rewriteRequest(results({ id: "t1", name: "read", input: { path: "a.md" } }), { arbiter: none, surface: OPENCLAW });
  for (const c of none.symbolizeCalls) assert.equal(c.relativeBase, undefined, "no MANDU_AGENT_CWD: nothing sent");
  const disp = new MockArbiter();
  await rewriteRequest(results({ id: "t2", name: "tool_call", input: { id: "read", args: { path: "a.md" } } }), { arbiter: disp, surface: OPENCLAW, relativeBase: WS });
  for (const c of disp.symbolizeCalls) assert.equal(c.relativeBase, undefined, "a dispatched call: never");
});
