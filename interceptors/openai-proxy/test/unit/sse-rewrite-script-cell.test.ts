/**
 * sse-rewrite-script-cell.test — the codex ≥ 0.154 wire through the stream
 * rewriter: a `custom_tool_call` exec cell's input is buffered across deltas,
 * every `tools.exec_command({…})` literal goes through the SAME ArgsTransform
 * as a function_call's arguments (exec gate → forward path-map), the rewritten
 * cell lands consistently in `.done`, `.output_item.done` and
 * `.completed`, a stream cut before `.done` still flushes the transformed
 * cell, and every assembled call is reported ONCE through `onCall`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { ResponsesArgsRewriter, composeArgsTransform, transformOutputItems, type ToolCallSeen } from "../../src/sse-rewrite.js";
import { ViewMap } from "../../src/view-map.js";
import { buildExecCommandSse, buildScriptCellSse, scriptCellFor } from "../helpers/mock-upstream.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";
const makeMap = (): ViewMap => new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });

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

test("a script cell's cmd AND workdir are forward-mapped in every payload-bearing event, as one collapsed delta", async () => {
  const sse = buildScriptCellSse({ cmd: `cat ${HUMAN}/vendor/notes.txt`, workdir: HUMAN, inputDeltas: 5 });
  const calls: ToolCallSeen[] = [];
  const out = await run(sse, new ResponsesArgsRewriter(composeArgsTransform(makeMap()), { onCall: (c) => calls.push(c) }));
  const expected = scriptCellFor({ cmd: `cat ${AGENT}/vendor/notes.txt`, workdir: AGENT, yield_time_ms: 10000, max_output_tokens: 2000 });
  assert.equal(eventsByType(out, "response.custom_tool_call_input.done")[0]!.input, expected);
  assert.equal((eventsByType(out, "response.output_item.done")[0]!.item as { input: string }).input, expected);
  assert.equal((eventsByType(out, "response.completed")[0]!.response as { output: Array<{ input: string }> }).output[0]!.input, expected);
  const deltas = eventsByType(out, "response.custom_tool_call_input.delta");
  assert.equal(deltas.length, 1, "the deltas were buffered and re-emitted as ONE");
  assert.equal(deltas[0]!.delta, expected);
  assert.ok(!out.includes(HUMAN), "the HumanView path is nowhere in the delivered stream");
  // reported once, as the shell call the cell runs, with the model's ORIGINAL arguments
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.name, "exec_command");
  assert.equal(calls[0]!.callId, "call_1");
  assert.equal(JSON.parse(calls[0]!.argumentsJson).cmd, `cat ${HUMAN}/vendor/notes.txt`);
});

test("an unchanged cell relays its events byte-verbatim (rule 3) and is still reported once", async () => {
  const sse = buildScriptCellSse({ cmd: "echo hi", inputDeltas: 3 });
  const calls: ToolCallSeen[] = [];
  const out = await run(sse, new ResponsesArgsRewriter(composeArgsTransform(makeMap()), { onCall: (c) => calls.push(c) }));
  // the three deltas collapse into one (buffering is unconditional), the rest is verbatim
  assert.equal(eventsByType(out, "response.custom_tool_call_input.delta").length, 1);
  assert.equal(eventsByType(out, "response.custom_tool_call_input.done")[0]!.input, scriptCellFor({ cmd: "echo hi", yield_time_ms: 10000, max_output_tokens: 2000 }));
  assert.equal(calls.length, 1);
});

test("a stream cut before `.done` flushes the TRANSFORMED cell as a synthetic delta + done", async () => {
  const full = buildScriptCellSse({ cmd: `ls ${HUMAN}`, inputDeltas: 4 });
  const cut = full.slice(0, full.indexOf("event: response.custom_tool_call_input.done"));
  const rw = new ResponsesArgsRewriter(composeArgsTransform(makeMap()));
  const out = (await rw.feed(cut)) + (await rw.end());
  const done = eventsByType(out, "response.custom_tool_call_input.done");
  assert.equal(done.length, 1, "a synthetic .done closes the item");
  assert.equal(done[0]!.input, scriptCellFor({ cmd: `ls ${AGENT}`, yield_time_ms: 10000, max_output_tokens: 2000 }));
  assert.ok(!out.includes(HUMAN));
});

test("the exec gate runs on the literal: a blocked command becomes the sentinel INSIDE the cell; a non-literal cell becomes the sentinel cell under `block`", async () => {
  const gate = async (json: string): Promise<string | null> => {
    const o = JSON.parse(json) as { cmd: string };
    return o.cmd.includes("$MDU:") ? JSON.stringify({ ...o, cmd: "echo 'mandu-exec-gate: blocked — symbol' 1>&2; exit 77" }) : null;
  };
  const sym = "$MDU:web_fetch[a1b2].text";
  const out = await run(buildScriptCellSse({ cmd: `bash -c ${sym}` }), new ResponsesArgsRewriter(composeArgsTransform(null, gate), { unparseable: "block" }));
  const input = eventsByType(out, "response.custom_tool_call_input.done")[0]!.input as string;
  assert.match(input, /exit 77/);
  assert.ok(!out.includes(sym), "the symbol never survives in the delivered stream");
  assert.match(input, /^const r = await tools\.exec_command\(/, "still the model's cell around the gated literal");

  const evasive = `const s = "${sym}"; const r = await tools.exec_command({cmd: "bash -c " + s});\ntext(r.output);\n`;
  const out2 = await run(buildScriptCellSse({ input: evasive }), new ResponsesArgsRewriter(composeArgsTransform(null, gate), { unparseable: "block" }));
  const input2 = eventsByType(out2, "response.custom_tool_call_input.done")[0]!.input as string;
  assert.match(input2, /mandu-exec-gate: blocked/);
  assert.ok(!out2.includes(sym), "the evasive cell's own bytes never reach codex");
  // `keep` (no gate): rule 3 leaves the evasive cell alone
  const out3 = await run(buildScriptCellSse({ input: evasive }), new ResponsesArgsRewriter(composeArgsTransform(null, gate), { unparseable: "keep" }));
  assert.equal(eventsByType(out3, "response.custom_tool_call_input.done")[0]!.input, evasive);
});

test("the classic function_call wire is reported through the same onCall, once per item, with its own name", async () => {
  const calls: ToolCallSeen[] = [];
  await run(buildExecCommandSse({ cmd: "echo x", argDeltas: 3 }), new ResponsesArgsRewriter(composeArgsTransform(makeMap()), { onCall: (c) => calls.push(c) }));
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.name, "exec_command");
  assert.equal(calls[0]!.argumentsJson, JSON.stringify({ cmd: "echo x" }));
});

test("transformOutputItems (the stream:false twin) maps a cell's literals and reports the calls", async () => {
  const output = [
    { type: "message", role: "assistant", content: [] },
    { type: "custom_tool_call", id: "ctc_9", call_id: "call_9", name: "exec", input: scriptCellFor({ cmd: `cat ${HUMAN}/a`, workdir: HUMAN }) },
    { type: "function_call", id: "fc_9", call_id: "call_8", name: "exec_command", arguments: JSON.stringify({ cmd: `ls ${HUMAN}` }) },
  ];
  const calls: ToolCallSeen[] = [];
  const changed = await transformOutputItems(output, composeArgsTransform(makeMap()), { onCall: (c) => calls.push(c) });
  assert.ok(changed);
  assert.equal((output[1] as { input: string }).input, scriptCellFor({ cmd: `cat ${AGENT}/a`, workdir: AGENT }));
  assert.equal((output[2] as { arguments: string }).arguments, JSON.stringify({ cmd: `ls ${AGENT}` }));
  assert.deepEqual(calls.map((c) => [c.callId, c.name]), [["call_9", "exec_command"], ["call_8", "exec_command"]]);
});

test("a cell replaced WHOLE by the sentinel cell is reported with its own call id and the notice (stream and stream:false; the !545 leftover)", async () => {
  const keep = async (): Promise<string | null> => null;
  const evasive = 'const c = "ls"; const r = await tools.exec_command({cmd: c + " -la"});\ntext(r.output);\n';
  const told: Array<[string | null, string]> = [];
  const onCellBlocked = (id: string | null, n: string): void => { told.push([id, n]); };
  await run(buildScriptCellSse({ input: evasive, callId: "call_cell7" }), new ResponsesArgsRewriter(keep, { unparseable: "block", onCellBlocked }));
  assert.equal(told.length, 1, "reported once across the payload-bearing snapshots");
  assert.equal(told[0]![0], "call_cell7");
  assert.match(told[0]![1], /^mandu-exec-gate: blocked, nothing ran: /);
  told.length = 0;
  const output = [{ type: "custom_tool_call", id: "ctc_8", call_id: "call_cell8", name: "exec", input: evasive }];
  assert.ok(await transformOutputItems(output, keep, { unparseable: "block", onCellBlocked }));
  assert.deepEqual(told.map((t) => t[0]), ["call_cell8"]);
  // an untouched cell reports nothing
  told.length = 0;
  await run(buildScriptCellSse({ cmd: "echo hi" }), new ResponsesArgsRewriter(keep, { unparseable: "block", onCellBlocked }));
  assert.deepEqual(told, []);
});
