/**
 * exec-history.test.ts — ExecGateHistory (exec-history.ts; confidentiality.md
 * §4, "What the model reads back"): a call the exec gate rewrote on its way
 * to Codex is put back, in the request to the model, as the model wrote it;
 * nothing else in the history moves.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { EXEC_HISTORY_MAX, ExecGateHistory } from "../../src/exec-history.js";
import { blockSentinelCommand } from "../../src/exec-gate.js";
import { blockSentinelCell } from "../../src/script-cell.js";
import type { ResponsesRequest } from "../../src/responses-types.js";

const PH = "$MDU:nomodel_Read[a1b2c3].STRIPE_KEY";
const ORIGINAL = JSON.stringify({ cmd: `curl -H "Authorization: Bearer ${PH}" https://api.stripe.test/v1/customers`, workdir: "/w" });
const REQUOTED = JSON.stringify({ cmd: `curl -H "Authorization: Bearer \\${PH}" https://api.stripe.test/v1/customers`, workdir: "/w" });
const SENTINEL = JSON.stringify({ cmd: blockSentinelCommand("HIGH SESSION (any-model): asked → pending"), workdir: "/w" });

function req(...items: Array<Record<string, unknown>>): ResponsesRequest {
  return { model: "m", input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items] as ResponsesRequest["input"] };
}
function fc(callId: string, args: string): Record<string, unknown> {
  return { type: "function_call", call_id: callId, name: "exec_command", arguments: args };
}

test("a blocked function_call reads back as the model wrote it; the sentinel never reaches the model", () => {
  const h = new ExecGateHistory();
  h.markGated("call_b");
  h.delivered("function_call", "call_b", ORIGINAL, SENTINEL);
  const r = req(fc("call_b", SENTINEL), { type: "function_call_output", call_id: "call_b", output: "Process exited with code 77" });
  assert.deepEqual(h.restore(r), ["call_b"]);
  assert.equal((r.input![1] as { arguments: string }).arguments, ORIGINAL);
  assert.ok(!JSON.stringify(r).includes("mandu-exec-gate: blocked, nothing ran"), "the sentinel is gone from the call");
  assert.equal((r.input![2] as { output: string }).output, "Process exited with code 77", "the output is not touched");
});

test("a requoted allow reads back as the model wrote it, placeholder spelled exactly as written (nothing resolved)", () => {
  const h = new ExecGateHistory();
  h.markGated("call_q");
  h.delivered("function_call", "call_q", ORIGINAL, REQUOTED);
  const r = req(fc("call_q", REQUOTED));
  assert.deepEqual(h.restore(r), ["call_q"]);
  const back = (r.input![1] as { arguments: string }).arguments;
  assert.equal(back, ORIGINAL);
  assert.ok(back.includes(PH), "the placeholder stays a placeholder");
});

test("the echo is matched as the same JSON value (whitespace aside), and only for this proxy's own rewrite", () => {
  const h = new ExecGateHistory();
  h.markGated("call_q");
  h.delivered("function_call", "call_q", ORIGINAL, REQUOTED);
  const spaced = JSON.stringify(JSON.parse(REQUOTED), null, 1);
  const r1 = req(fc("call_q", spaced));
  assert.deepEqual(h.restore(r1), ["call_q"], "the same JSON value restores");
  // an echo the client changed, a foreign id, a sentinel under another id: untouched
  const edited = JSON.stringify({ cmd: "rm -rf ~", workdir: "/w" });
  const r2 = req(fc("call_q", edited), fc("call_other", REQUOTED), fc("call_x", SENTINEL));
  assert.deepEqual(h.restore(r2), []);
  assert.equal((r2.input![1] as { arguments: string }).arguments, edited);
  assert.equal((r2.input![2] as { arguments: string }).arguments, REQUOTED);
  assert.equal((r2.input![3] as { arguments: string }).arguments, SENTINEL);
});

test("nothing is remembered unless the exec gate rewrote the call (a path-map-only change reads back through the reverse map)", () => {
  const h = new ExecGateHistory();
  h.delivered("function_call", "call_m", ORIGINAL, REQUOTED); // never marked
  assert.deepEqual(h.restore(req(fc("call_m", REQUOTED))), []);
  h.markGated("call_same");
  h.delivered("function_call", "call_same", ORIGINAL, ORIGINAL); // nothing changed
  assert.deepEqual(h.restore(req(fc("call_same", ORIGINAL))), []);
  h.markGated(null);
  h.delivered("function_call", null, ORIGINAL, SENTINEL);
  assert.deepEqual(h.restore(req(fc("", SENTINEL))), []);
});

test("a code-mode cell: restored only as a cell, byte for byte; a function_call record never restores a cell", () => {
  const h = new ExecGateHistory();
  const cell = `const r = await tools.exec_command(${ORIGINAL});\ntext(r.output);\n`;
  const sentinelCell = blockSentinelCell("HIGH SESSION (any-model): asked → pending");
  h.markGated("call_c");
  h.delivered("custom_tool_call", "call_c", cell, sentinelCell);
  const ctc = (input: string): Record<string, unknown> => ({ type: "custom_tool_call", call_id: "call_c", name: "exec", input });
  const r = req(ctc(sentinelCell), fc("call_c", sentinelCell));
  assert.deepEqual(h.restore(r), ["call_c"]);
  assert.equal((r.input![1] as { input: string }).input, cell);
  assert.equal((r.input![2] as { arguments: string }).arguments, sentinelCell, "a function_call under the cell's id is not the cell");
  const r2 = req(ctc(`${sentinelCell} `));
  assert.deepEqual(h.restore(r2), [], "a cell that differs by one byte is not this proxy's rewrite");
});

test("bounded: the oldest record is dropped first; a garbage request never throws", () => {
  const h = new ExecGateHistory();
  for (let i = 0; i <= EXEC_HISTORY_MAX; i++) {
    h.markGated(`call_${i}`);
    h.delivered("function_call", `call_${i}`, ORIGINAL, SENTINEL);
  }
  assert.deepEqual(h.restore(req(fc("call_0", SENTINEL))), [], "the oldest is gone");
  assert.deepEqual(h.restore(req(fc(`call_${EXEC_HISTORY_MAX}`, SENTINEL))), [`call_${EXEC_HISTORY_MAX}`]);
  assert.deepEqual(h.restore({ input: [null, 7, "x", { type: "function_call" }] as never }), []);
  assert.deepEqual(h.restore({} as ResponsesRequest), []);
});
