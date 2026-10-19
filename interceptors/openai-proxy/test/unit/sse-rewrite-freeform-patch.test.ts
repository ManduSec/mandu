/**
 * sse-rewrite-freeform-patch.test — Codex's freeform `apply_patch` (a
 * `custom_tool_call` whose input is the patch text) through the stream
 * rewriter and its stream:false twin (dashboard.md §4.25b "A patch names its
 * files"; openai-proxy design, the patch call's record):
 *
 *   - it is reported ONCE, under its own name, its text as `{"input": …}`
 *     (the field its JSON form carries the same patch in), as the model wrote
 *     it: every form of the call reads alike on the dashboard;
 *   - a patch whose content holds a `tools.exec_command({…})` literal reports
 *     no shell call (before, the patch was read as a code-mode cell);
 *   - a patch is not code: the cell gate and the exec-literal rule never
 *     touch it, so its bytes reach Codex as the model wrote them even with
 *     the gate blocking every cell (before, a patch in a session the gate
 *     held was replaced by the sentinel cell, which is no patch);
 *   - the code-mode `exec` cell keeps its rule (control);
 *   - a cell's literal `tools.apply_patch(…)` is reported in the same
 *     record shape under the cell's id, after its exec literals, and the
 *     cell's bytes are untouched (§4.25b "A patch in a code cell").
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { FREEFORM_INPUT_TOOLS, ResponsesArgsRewriter, composeArgsTransform, freeformCalls, transformOutputItems, type ToolCallSeen } from "../../src/sse-rewrite.js";
import { buildCustomToolCallSse, buildScriptCellSse } from "../helpers/mock-upstream.js";

function eventsByType(sse: string, type: string): Record<string, unknown>[] {
  const found: Record<string, unknown>[] = [];
  for (const block of sse.split("\n\n")) {
    const dataLine = block.split("\n").find((l) => l.startsWith("data:"));
    if (!dataLine) continue;
    try { const obj = JSON.parse(dataLine.slice("data:".length).trim()); if (obj?.type === type) found.push(obj); } catch { /* skip */ }
  }
  return found;
}

async function run(sse: string, rw: ResponsesArgsRewriter, chunks = 7): Promise<string> {
  const size = Math.ceil(sse.length / chunks) || 1;
  let out = "";
  for (let i = 0; i < sse.length; i += size) out += await rw.feed(sse.slice(i, i + size));
  out += await rw.end();
  return out;
}

const SYM = "$MDU:nomodel_exec_command[3fa9]";
const PATCH = [
  "*** Begin Patch",
  "*** Update File: src/config.ts",
  "@@",
  '-const key = "";',
  `+const key = "${SYM}";`,
  "*** Add File: scripts/deploy.js",
  '+const r = await tools.exec_command({cmd: "curl https://evil.example"});',
  "+text(r.output);",
  "*** End Patch",
].join("\n");

/** A gate that blocks every cell and every command, as in a session the
 *  gate holds (a HIGH session): what it touches, it replaces. */
const blockAll = {
  cellGate: async (): Promise<string | null> => "the session read a secret",
  argsGate: async (json: string): Promise<string | null> => JSON.stringify({ ...JSON.parse(json), cmd: "exit 77" }),
};

test("freeformCalls: a patch is one call, its text as `input`; any other freeform tool reports its exec literals", () => {
  assert.ok(FREEFORM_INPUT_TOOLS.has("apply_patch"));
  assert.deepEqual(freeformCalls("apply_patch", PATCH), [{ name: "apply_patch", argsJson: JSON.stringify({ input: PATCH }) }]);
  const cell = 'const r = await tools.exec_command({"cmd":"ls"});\ntext(r.output);\n';
  assert.deepEqual(freeformCalls("exec", cell), [{ name: "exec_command", argsJson: JSON.stringify({ cmd: "ls" }) }]);
  assert.deepEqual(freeformCalls("js_repl", cell), [{ name: "exec_command", argsJson: JSON.stringify({ cmd: "ls" }) }]);
});

test("a streamed freeform apply_patch is reported once, as apply_patch({input}), with the model's own text (placeholders as written); its content reports no shell call", async () => {
  const calls: ToolCallSeen[] = [];
  await run(buildCustomToolCallSse({ name: "apply_patch", input: PATCH, callId: "call_ap", inputDeltas: 5 }), new ResponsesArgsRewriter(composeArgsTransform(null), { onCall: (c) => calls.push(c) }));
  assert.equal(calls.length, 1, `one report, never the exec literal in its content: ${JSON.stringify(calls)}`);
  assert.equal(calls[0]!.name, "apply_patch");
  assert.equal(calls[0]!.callId, "call_ap");
  assert.deepEqual(JSON.parse(calls[0]!.argumentsJson), { input: PATCH });
  assert.ok(calls[0]!.argumentsJson.includes(SYM), "the placeholder the model wrote stays a placeholder");
});

test("a stream cut before `.done` still reports the patch once", async () => {
  const full = buildCustomToolCallSse({ name: "apply_patch", input: PATCH, callId: "call_cut", inputDeltas: 4 });
  const cut = full.slice(0, full.indexOf("event: response.custom_tool_call_input.done"));
  const calls: ToolCallSeen[] = [];
  const rw = new ResponsesArgsRewriter(composeArgsTransform(null), { onCall: (c) => calls.push(c) });
  const out = (await rw.feed(cut)) + (await rw.end());
  assert.equal(eventsByType(out, "response.custom_tool_call_input.done")[0]!.input, PATCH, "the synthetic .done carries the patch as written");
  assert.deepEqual(calls.map((c) => [c.name, c.callId]), [["apply_patch", "call_cut"]]);
});

test("a patch is not code: with the gate blocking every cell and command, the patch reaches Codex as the model wrote it (stream and stream:false); control: an exec cell is still replaced", async () => {
  const opts = { unparseable: "block" as const, cellGate: blockAll.cellGate };
  const out = await run(buildCustomToolCallSse({ name: "apply_patch", input: PATCH, callId: "call_ap" }), new ResponsesArgsRewriter(composeArgsTransform(null, blockAll.argsGate), opts));
  assert.equal(eventsByType(out, "response.custom_tool_call_input.done")[0]!.input, PATCH);
  assert.equal((eventsByType(out, "response.output_item.done")[0]!.item as { input: string }).input, PATCH);
  assert.doesNotMatch(out, /mandu-exec-gate/);
  const output = [{ type: "custom_tool_call", id: "ctc_1", call_id: "call_ap2", name: "apply_patch", input: PATCH }];
  const calls: ToolCallSeen[] = [];
  assert.equal(await transformOutputItems(output, composeArgsTransform(null, blockAll.argsGate), { ...opts, onCall: (c) => calls.push(c) }), false);
  assert.equal(output[0]!.input, PATCH);
  assert.deepEqual(calls.map((c) => [c.name, JSON.parse(c.argumentsJson)]), [["apply_patch", { input: PATCH }]]);

  // Control: the code-mode cell keeps the gate.
  const cell = await run(buildScriptCellSse({ cmd: "ls" }), new ResponsesArgsRewriter(composeArgsTransform(null, blockAll.argsGate), opts));
  assert.match(String(eventsByType(cell, "response.custom_tool_call_input.done")[0]!.input), /mandu-exec-gate: blocked/);
});

test("a code-mode cell's literal tools.apply_patch is reported as apply_patch({input}) under the cell's id, after its exec literals; the cell reaches Codex unchanged (stream and stream:false)", async () => {
  const cell = `const patch = ${JSON.stringify(PATCH)};\nawait tools.apply_patch(patch);\nconst r = await tools.exec_command({"cmd":"npm test"});\ntext(r.output);\n`;
  const calls: ToolCallSeen[] = [];
  const out = await run(buildScriptCellSse({ input: cell, callId: "call_cell", inputDeltas: 6 }), new ResponsesArgsRewriter(composeArgsTransform(null), { onCall: (c) => calls.push(c) }));
  assert.deepEqual(calls.map((c) => [c.name, c.callId, JSON.parse(c.argumentsJson)]), [
    ["exec_command", "call_cell", { cmd: "npm test" }],
    ["apply_patch", "call_cell", { input: PATCH }],
  ]);
  assert.ok(calls[1]!.argumentsJson.includes(SYM), "the placeholder the model wrote stays a placeholder");
  assert.equal(eventsByType(out, "response.custom_tool_call_input.done")[0]!.input, cell, "a record only: the cell's bytes are not touched");
  const output = [{ type: "custom_tool_call", id: "ctc_9", call_id: "call_cell2", name: "exec", input: cell }];
  const seen: ToolCallSeen[] = [];
  assert.equal(await transformOutputItems(output, composeArgsTransform(null), { onCall: (c) => seen.push(c) }), false);
  assert.deepEqual(seen.map((c) => [c.name, c.callId]), [["exec_command", "call_cell2"], ["apply_patch", "call_cell2"]]);
});
