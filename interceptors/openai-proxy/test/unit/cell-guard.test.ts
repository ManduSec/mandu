/**
 * cell-guard.test — plan 10 §11.18, "The cell guard" (2026-10-11). Pins:
 *   - the guard's text: one canonical prelude per keep list, after a pragma
 *     line; splitGuardedCell accepts exactly that text (a tampered guard, a
 *     non-identifier name, a guard not at the head: refused); the model's
 *     own code comes back unchanged;
 *   - the guard RUNS as claimed (node's own V8, the same engine codex 0.162
 *     embeds; the real codex is the drill suite's codex-cell-tools-guard):
 *     every tool the keep list leaves out throws whatever way it is reached,
 *     a kept one still works, it cannot be restored, and `store` / `load`
 *     keep the guarded keys apart;
 *   - cellGuardKeep: codex's own tools plus each named tool the arbiter maps;
 *     no guard when the arbiter does not mask an unmapped tool (the axis off)
 *     or an ask fails;
 *   - the stream rewriter delivers a refused cell guarded (every snapshot
 *     the same), an identified cell, a patch and a js_repl cell as written;
 *   - the request side: a guarded cell is not masked for what its text may
 *     reach while every kept tool is mapped; a kept tool that is not, an
 *     `import`, an unisolated battery, or no guard: the text rule.
 * Axes: confidentiality ON (the mock arbiter answers as `secrets` does).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";

import { guardCell, guardPrelude, splitGuardedCell, writtenToolNames } from "../../src/cell-guard.js";
import { cellGuardKeep, rewriteRequest } from "../../src/rewrite-request.js";
import { ResponsesArgsRewriter, composeArgsTransform } from "../../src/sse-rewrite.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { buildCustomToolCallSse } from "../helpers/mock-upstream.js";

const KEEP = ["exec_command", "write_stdin"];
const EMPTY_TAINT = { level: null, files: [], apps: [], rule: "secret" as const, mask: [], root: null, denied: [] };
const UNMAPPED = (tool: string) => ({ ...EMPTY_TAINT, level: "no-model", evidence: "unmapped" as const, why: `Mandu has no mapping for the tool ${tool}, so its whole result is hidden from the AI: list it under \`mapped_tools:\` in policy.yaml` });

test("the guard's text: canonical per keep list, after a pragma, split back exactly", () => {
  assert.equal(guardPrelude(["write_stdin", "exec_command", "exec_command"]), guardPrelude(KEEP), "sorted and deduplicated");
  const body = "const r = await tools[n]({});\ntext(r)";
  const g = guardCell(body, KEEP);
  assert.ok(g.startsWith("/* mandu: nested tools Mandu has not mapped are switched off in this cell */"));
  assert.deepEqual(splitGuardedCell(g), { keep: KEEP, body });
  const pragma = "// @exec: {\"yield_time_ms\": 10000}\n";
  const gp = guardCell(pragma + body, KEEP);
  assert.ok(gp.startsWith(pragma + "/* mandu:"), "the pragma stays first");
  assert.deepEqual(splitGuardedCell(gp), { keep: KEEP, body: pragma + body });
  // refused: a tampered guard, a name that is no identifier, a guard not first, no guard
  assert.equal(splitGuardedCell(g.replace("O.preventExtensions(t);", "")), null);
  assert.equal(splitGuardedCell(g.replace("\"exec_command\"", "\"exec_command\\\"\"")), null);
  assert.equal(splitGuardedCell(guardPrelude(KEEP).replace("[\"exec_command\",\"write_stdin\"]", "[\"a b\"]") + body), null);
  assert.equal(splitGuardedCell(`text(1);\n${g}`), null);
  assert.equal(splitGuardedCell(body), null);
  assert.equal(splitGuardedCell(42), null);
});

test("writtenToolNames: the names a cell's text writes", () => {
  assert.deepEqual(writtenToolNames('await tools.exec_command({}); await tools?.view_image({}); await tools["read_mcp_resource"]({}); const x = "mcp__remote__get";').sort(),
    ["exec_command", "mcp__remote__get", "read_mcp_resource", "view_image"]);
  assert.deepEqual(writtenToolNames("ALL_TOOLS.map(t => t.name); my_tools.x()"), []);
});

/** Run a guarded cell in a fresh V8 context shaped like codex 0.162's
 *  (a `tools` object of data properties, `store` / `load` on a key map). */
function runCell(src: string): { calls: string[]; stored: Map<string, unknown>; out: unknown[]; error: string | null; done: Promise<void> } {
  const calls: string[] = [];
  const stored = new Map<string, unknown>([["k", "stored by an unguarded cell"]]);
  const out: unknown[] = [];
  const tools: Record<string, unknown> = {};
  for (const n of ["exec_command", "write_stdin", "read_mcp_resource", "list_mcp_resources", "mcp__remote__get"]) tools[n] = (args: unknown) => { calls.push(n); return { tool: n, args }; };
  const ctx = vm.createContext({
    tools, text: (v: unknown) => out.push(v),
    store: (k: string, v: unknown) => { if (typeof v === "function") throw new Error(); stored.set(k, v); },
    load: (k: string) => stored.get(k),
  });
  let error: string | null = null;
  const done = (async () => {
    try { await vm.runInContext(`(async () => {\n${src}\n})()`, ctx); } catch (e) { error = String((e as Error).message); }
  })();
  return { calls, stored, out, get error() { return error; }, done } as never;
}

test("the guard runs as claimed: every reach to a tool it switched off throws; kept tools work; it cannot be undone; store / load keep the guarded keys", async () => {
  const reaches = [
    "await tools.read_mcp_resource({})",
    "await tools.mcp__remote__get({})",
    "await tools[[\"mcp\", \"remote\", \"get\"].join(\"__\")]({})",
    "await globalThis.tools.list_mcp_resources({})",
    "await (0, eval)(\"tools\").read_mcp_resource({})",
    "await [][\"con\" + \"structor\"][\"con\" + \"structor\"](\"return tools.mcp__remote__get\")()({})",
    "await Function(\"return this\")().tools.read_mcp_resource({})",
    "await (() => { try { delete tools.read_mcp_resource } catch {} return tools.read_mcp_resource })()({})",
    "await (() => { try { Object.defineProperty(tools, \"read_mcp_resource\", { value: (a) => a }) } catch {} return tools.read_mcp_resource })()({})",
    "await (() => { try { tools.read_mcp_resource = (a) => a } catch {} return tools.read_mcp_resource })()({})"
  ];
  for (const r of reaches) {
    const c = runCell(guardCell(`text(${r})`, KEEP));
    await c.done;
    assert.deepEqual(c.calls, [], `${r}: no switched-off tool ran`);
    assert.ok(c.error === null || /switched off inside code cells|is not a function|Cannot/.test(c.error), `${r}: ${c.error}`);
  }
  const kept = runCell(guardCell("text(JSON.stringify(await tools.exec_command({ cmd: \"ls\" })))", KEEP));
  await kept.done;
  assert.deepEqual(kept.calls, ["exec_command"], "a kept tool runs");
  const add = runCell(guardCell("tools.extra = () => 1; text(typeof tools.extra)", KEEP));
  await add.done;
  assert.ok(add.error !== null || add.out[0] === "undefined", "no tool can be added after the guard");
  const twice = runCell(guardCell(guardCell("text(\"twice ok\")", KEEP), KEEP));
  await twice.done;
  assert.deepEqual([twice.error, twice.out], [null, ["twice ok"]], "a cell that repeats the guard runs");
  const kv = runCell(guardCell("text(String(load(\"k\"))); store(\"k\", 7); text(String(load(\"k\")))", KEEP));
  await kv.done;
  assert.deepEqual(kv.out, ["undefined", "7"], "a guarded load never reads an unguarded cell's key");
  assert.equal(kv.stored.get("k"), "stored by an unguarded cell");
  assert.equal(kv.stored.get("mandu:k"), 7);
  // fail closed: a tool the guard cannot switch off stops the cell before its code
  const frozen = vm.createContext({ tools: Object.freeze({ read_mcp_resource: () => "raw" }), text: () => {}, store: () => {}, load: () => {} });
  await assert.rejects(vm.runInContext(`(async () => {\n${guardCell("globalThis.ran = true", KEEP)}\n})()`, frozen), /cannot switch off read_mcp_resource/);
  assert.equal((frozen as { ran?: boolean }).ran, undefined, "the model's code did not run");
});

test("cellGuardKeep: codex's own tools and the named ones the arbiter maps; no guard with the axis off or an ask that fails", async () => {
  const mapped = new Set(["mcp__mandu_policy__mandu_policy_read"]);
  const arbiter = new MockArbiter({
    classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock" }),
    callTaintFn: (r) => (mapped.has(String(r.unmappedTool)) ? EMPTY_TAINT : UNMAPPED(String(r.unmappedTool))),
  });
  const keep = (await cellGuardKeep(arbiter, "await tools.mcp__mandu_policy__mandu_policy_read({}); await tools.mcp__remote__get({}); await tools.read_mcp_resource({})", "s"))!;
  for (const k of ["exec_command", "write_stdin", "apply_patch", "view_image", "mcp__mandu_policy__mandu_policy_read"]) assert.ok(keep.includes(k), k);
  for (const k of ["mcp__remote__get", "read_mcp_resource", "list_mcp_resources"]) assert.ok(!keep.includes(k), k);
  const off = new MockArbiter({ classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock" }), callTaintFn: () => EMPTY_TAINT });
  assert.equal(await cellGuardKeep(off, "text(1)", "s"), null, "the axis off: no guard");
  const broken = new MockArbiter({ classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock" }), callTaintFn: () => { throw new Error("down"); } });
  assert.equal(await cellGuardKeep(broken, "text(1)", "s"), null, "an ask that fails: no guard (the request side keeps the text rule)");
});

test("the stream rewriter delivers a refused cell guarded in every snapshot; an identified cell, a patch and a js_repl cell as written", async () => {
  const guard = async (src: string): Promise<string | null> => (src.includes("tools[") ? guardCell(src, KEEP) : null);
  const rw = () => new ResponsesArgsRewriter(composeArgsTransform(null), { cellGuard: guard, cellsIsolated: true });
  const feedAll = async (r: ResponsesArgsRewriter, sse: string): Promise<string> => (await r.feed(sse)) + (await r.end());
  const refused = "text(await tools[n]({}))";
  const out = await feedAll(rw(), buildCustomToolCallSse({ name: "exec", input: refused, inputDeltas: 3 }));
  const inputs = [...out.matchAll(/"input":"((?:[^"\\]|\\.)*)"/g)].map((m) => JSON.parse(`"${m[1]}"`) as string).filter((s) => s !== "");
  assert.ok(inputs.length >= 3, "the .done, .output_item.done and .completed snapshots");
  for (const s of inputs) assert.equal(s, guardCell(refused, KEEP));
  for (const [name, input] of [["apply_patch", "*** Begin Patch\n*** Add File: tools[x].md\n+x\n*** End Patch"], ["js_repl", refused]] as const) {
    const o = await feedAll(rw(), buildCustomToolCallSse({ name, input }));
    assert.ok(!o.includes("mandu: nested tools"), `${name}: not guarded`);
  }
});

const ISOLATED_EXEC = { type: "custom", name: "exec", description: "Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." };
const BATTERY = { type: "additional_tools", tools: [{ type: "namespace", name: "functions", tools: [ISOLATED_EXEC, { type: "function", name: "wait" }] }] };
const ENVELOPE = "Script completed\nWall time 0.0 seconds\nOutput:\n";
const forwarded = (req: ResponsesRequest, callId: string): string =>
  JSON.stringify((req.input as Array<Record<string, unknown>>).find((i) => /_output$/.test(String(i["type"])) && i["call_id"] === callId)!["output"]);

test("the request side: a guarded cell is not masked for what its text may reach while its keep list holds; otherwise the text rule", async () => {
  const cells: Array<[string, string]> = [
    ["g_load", guardCell("text(String(load(\"k\")))", KEEP)],
    ["g_dyn", guardCell("text((await tools[\"exec_\" + \"command\"]({ cmd: \"ls\" })).output)", KEEP)],
    ["g_named", guardCell("text(JSON.stringify(await tools.read_mcp_resource({})))", KEEP)],
    ["g_forged", guardCell("text(String(load(\"k\")))", [...KEEP, "read_mcp_resource"])],
    ["g_import", guardCell("import \"x\";\ntext(String(load(\"k\")))", KEEP)],
    ["g_stale", guardCell("text(\"plain\")", [...KEEP, "stale_tool"])],
    ["t_load", "text(String(load(\"k\")))"],
  ];
  const items = [BATTERY, ...cells.flatMap(([id, input]) => [
    { type: "custom_tool_call", call_id: id, name: "exec", input },
    { type: "custom_tool_call_output", call_id: id, output: [{ type: "input_text", text: ENVELOPE }, { type: "input_text", text: `out-of-${id}` }] },
  ])];
  const arbiter = new MockArbiter({
    classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock" }),
    callTaintFn: (r) => (r.builtin === true || r.unmappedTool === undefined ? EMPTY_TAINT : UNMAPPED(String(r.unmappedTool))),
  });
  const { request } = await rewriteRequest({ model: "m", input: structuredClone(items) } as unknown as ResponsesRequest, { arbiter, sessionKey: "s", skipPromptInjection: true });
  for (const id of ["g_load", "g_dyn", "g_named"]) assert.ok(forwarded(request, id).includes(`out-of-${id}`), `${id}: the guard holds, not masked for its text`);
  for (const id of ["g_forged", "g_import", "g_stale", "t_load"]) assert.ok(!forwarded(request, id).includes(`out-of-${id}`), `${id}: no trusted guard, the text rule masks it`);
  // no isolation sentence: no guard is trusted
  const unisolated = [{ type: "additional_tools", tools: [{ type: "namespace", name: "functions", tools: [{ type: "custom", name: "exec", description: "Run code." }] }] }, ...items.slice(1)];
  const u = (await rewriteRequest({ model: "m", input: unisolated } as unknown as ResponsesRequest, { arbiter, sessionKey: "s", skipPromptInjection: true })).request;
  assert.ok(!forwarded(u, "g_load").includes("out-of-g_load"), "an unisolated battery keeps the text rule");
});
