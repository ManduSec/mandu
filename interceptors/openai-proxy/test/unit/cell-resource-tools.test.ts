/**
 * cell-resource-tools.test — plan 10 §11.18, a cell's resource tools
 * (2026-10-11). codex-cli 0.162 declares `read_mcp_resource`,
 * `list_mcp_resources` and `list_mcp_resource_templates` as nested tools of
 * every code-mode `exec` cell. The direct call is masked whole (no mapping);
 * a cell calling one got only the cell rule (the session's raw reads), so in
 * a session that read nothing a resource reached the model raw through a
 * cell. Pins:
 *   - cellResourceTools: what a cell's source may call (named in any
 *     spelling; any way to a tool by a name it does not write, or to a value
 *     an earlier cell stored), and what does not count (a cell that only
 *     writes `tools.exec_command`, an `ALL_TOOLS` listing);
 *   - the wire: such a cell, its `wait` continuation and its `load` partner
 *     are asked about each resource tool exactly as the direct call is, and
 *     masked whole on the arbiter's `unmapped`; an identified cell is not
 *     asked; `mapped_tools:` (the arbiter answering empty) lets it through;
 *     an ask that throws masks.
 * Axes: confidentiality ON (the mock arbiter answers as `secrets` does).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { CODEX_RESOURCE_TOOLS, cellResourceTools } from "../../src/cell-resource-tools.js";
import { buildCorrelationMap, rewriteRequest } from "../../src/rewrite-request.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const ISOLATED_EXEC = { type: "custom", name: "exec", description: "Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." };
const BATTERY = { type: "additional_tools", tools: [{ type: "namespace", name: "functions", tools: [ISOLATED_EXEC, { type: "function", name: "wait" }] }] };
const EMPTY_TAINT = { level: null, files: [], apps: [], rule: "secret" as const, mask: [], root: null, denied: [] };
const ENVELOPE = "Script completed\nWall time 0.0 seconds\nOutput:\n";
/** A registered secret's bytes as an MCP `blob` (base64): no value
 *  fingerprint matches it. */
const BLOB = Buffer.from("db.internal:5432:*:app:Pg-CELLRES-a8d4e2b7\n").toString("base64");
const RESOURCE = JSON.stringify({ server: "res", uri: "res://pg", contents: [{ uri: "res://pg", mimeType: "application/octet-stream", blob: BLOB }] });

const unmappedWhy = (tool: string) => `Mandu has no mapping for the tool ${tool}, so its whole result is hidden from the AI: list it under \`mapped_tools:\` in policy.yaml`;
const UNMAPPED = (tool: string) => ({ ...EMPTY_TAINT, level: "no-model", evidence: "unmapped" as const, why: unmappedWhy(tool) });

const forwarded = (req: ResponsesRequest, callId: string): string =>
  JSON.stringify((req.input as Array<Record<string, unknown>>).find((i) => /_output$/.test(String(i["type"])) && i["call_id"] === callId)!["output"]);

const cell = (id: string, input: string, out = RESOURCE) => [
  { type: "custom_tool_call", call_id: id, name: "exec", input },
  { type: "custom_tool_call_output", call_id: id, output: [{ type: "input_text", text: ENVELOPE }, { type: "input_text", text: out }] },
];

test("cellResourceTools: a resource tool named in any spelling is that tool", () => {
  for (const [src, tools] of [
    ['text(JSON.stringify(await tools.read_mcp_resource({server: "res", uri: "res://pg"})))', ["read_mcp_resource"]],
    ['text(JSON.stringify(await tools.list_mcp_resources({})))', ["list_mcp_resources"]],
    ['text(JSON.stringify(await tools?.list_mcp_resource_templates({server: "res"})))', ["list_mcp_resource_templates"]],
    ['const r = await tools["read_mcp_resource"]({server: "res", uri: "res://pg"}); text(r.contents[0].blob)', ["read_mcp_resource"]],
    // a renamed one (a codex release) counts by its spelling
    ['text(await tools.mcp_resource_read({id: "pg"}))', ["mcp_resource_read"]],
    // an MCP tool it names (2026-10-11): asked as its direct call is (an
    // unregistered server's is masked whole; Mandu's own and a clean
    // registered server's are not)
    ['const p = await tools.mcp__remote__search({q: "x"}); text(p.content.map(c => c.text).join(""))', ["mcp__remote__search"]],
    ['const p = await tools["mcp__mandu_policy__mandu_policy_read"]({}); text(JSON.stringify(p).slice(0, 100))', ["mcp__mandu_policy__mandu_policy_read"]],
    // two in one cell
    ['const l = await tools.list_mcp_resources({}); const r = await tools.read_mcp_resource({server: "res", uri: l.resources[0].uri}); text(r)', ["list_mcp_resources", "read_mcp_resource"]],
  ] as Array<[string, string[]]>) {
    assert.deepEqual(cellResourceTools(src)?.tools, tools, src);
    assert.match(cellResourceTools(src)!.why, /^calls /, src);
  }
});

test("cellResourceTools: a way to a tool by a name the cell does not write, or to a stored value, is every resource tool", () => {
  for (const src of [
    'const n = ["read", "mcp", "resource"].join("_"); text(await tools[n]({server: "res", uri: "res://pg"}))',
    'const { read_mcp_resource: r } = tools; text(await r({}))',
    'const t = tools; text(await t.list_mcp_resources({}))',
    'for (const k of Object.keys(tools)) text(k)',
    'text(await globalThis["to" + "ols"]["read_" + "mcp_resource"]({}))',
    'text(await (0, eval)("tools").list_mcp_resources({}))',
    'const F = (() => 0).constructor; text(await F("return tools")().list_mcp_resources({}))',
    'text(await Reflect.get(tools, "x")({}))',
    'text(await \\u0074ools.anything({}))',
    'text(await tools["read_mcp_\\x72esource"]({}))',
    'text(load("k"))',
    'text(await import("data:text/javascript,export default 1"))',
  ]) {
    const r = cellResourceTools(src);
    assert.ok(r, src);
    for (const t of CODEX_RESOURCE_TOOLS) assert.ok(r!.tools.includes(t), `${src}: ${t}`);
  }
  assert.match(cellResourceTools('text(load("k"))')!.why, /`load`/);
  assert.match(cellResourceTools("text(await tools[n]({}))")!.why, /`tools` other than by a written tool name/);
});

test("cellResourceTools: a cell that writes only other tools' names, or reads only the listing, calls none", () => {
  for (const src of [
    'const r = await tools.exec_command({cmd: "ls"});\ntext(r.output);',
    'for (const f of ["a", "b"]) { const r = await tools.exec_command({cmd: `wc -l ${f}`}); text(r.output.split("\\n")[0]); }',
    'const r = await tools["exec_command"]({cmd: "ls"}); text(r.output.toUpperCase())',
    'text(JSON.stringify(ALL_TOOLS.filter(t => /policy/.test(t.name))))',
    'store("k", 1); text("stored")',
    'const download = 1; const loader = 2; text(String(download + loader))',
    "",
  ]) assert.equal(cellResourceTools(src), null, src);
  assert.equal(cellResourceTools(undefined), null);
});

test("§11.18 wire: each resource tool a cell may call is asked as the direct call is; the cell is masked whole on `unmapped`", async () => {
  const asked: Array<[unknown, unknown, unknown]> = [];
  const arbiter = new MockArbiter({
    classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock: integrity off" }),
    // a session that read nothing: the cell (a built-in) has nothing to mask;
    // a tool with no mapping is `unmapped`
    callTaintFn: (r) => { asked.push([r.callId, r.unmappedTool, r.builtin]); return r.builtin === true || r.unmappedTool === undefined ? EMPTY_TAINT : UNMAPPED(String(r.unmappedTool)); },
  });
  const items = [
    BATTERY,
    ...cell("c_read", 'text(JSON.stringify(await tools.read_mcp_resource({server: "res", uri: "res://pg"})))'),
    ...cell("c_list", "text(JSON.stringify(await tools.list_mcp_resources({})))", JSON.stringify({ resources: [{ server: "res", uri: "res://pg", name: BLOB }] })),
    ...cell("c_tpl", "text(JSON.stringify(await tools.list_mcp_resource_templates({})))", JSON.stringify({ resourceTemplates: [{ server: "res", uriTemplate: "res://{x}", name: BLOB }] })),
    ...cell("c_dyn", 'const n = ["read", "mcp", "resource"].join("_"); text(JSON.stringify(await tools[n]({server: "res", uri: "res://pg"})))'),
    // the store/load pair: the storing cell prints nothing; its partner prints the value
    ...cell("c_store", 'store("k", (await tools.read_mcp_resource({server: "res", uri: "res://pg"})).contents[0].blob); text("stored")', "stored"),
    ...cell("c_load", 'text(load("k"))', BLOB),
    // a yielded cell, and its `wait` continuation (§11.13 path (b))
    { type: "custom_tool_call", call_id: "c_y", name: "exec", input: 'yield_control(); text(JSON.stringify(await tools.read_mcp_resource({server: "res", uri: "res://pg"})))' },
    { type: "custom_tool_call_output", call_id: "c_y", output: [{ type: "input_text", text: "Script running with cell ID 7\nWall time 0.1 seconds\nOutput:\n" }] },
    { type: "function_call", call_id: "w_y", name: "wait", arguments: JSON.stringify({ cell_id: "7" }) },
    { type: "function_call_output", call_id: "w_y", output: `Script completed\nWall time 0.1 seconds\nOutput:\n${RESOURCE}` },
    // controls: an identified cell and an unidentified exec cell that names no resource tool
    ...cell("c_exact", 'const r = await tools.exec_command({"cmd":"ls"});\ntext(r.output);\n', "README.md"),
    ...cell("c_loop", 'for (const f of ["a"]) { const r = await tools.exec_command({cmd: `ls ${f}`}); text(r.output.trim()); }', "a"),
  ];
  const { request } = await rewriteRequest({ model: "m", input: items } as unknown as ResponsesRequest, { arbiter, sessionKey: "s", skipPromptInjection: true });
  // MASTER (before 2026-10-11): each raw (the cell rule alone, a session that read nothing)
  for (const id of ["c_read", "c_list", "c_tpl", "c_dyn", "c_load", "w_y"]) {
    const out = forwarded(request, id);
    assert.ok(!out.includes(BLOB), `${id}: CONFIDENTIALITY VIOLATION: a cell carried an MCP resource to the model raw: ${out.slice(0, 300)}`);
    assert.match(out, /this cell .*mapped_tools/, `${id}: the note says why and the way out`);
  }
  assert.match(forwarded(request, "c_read"), /this cell calls read_mcp_resource/);
  assert.match(forwarded(request, "c_load"), /reads a value an earlier cell stored/);
  assert.ok(forwarded(request, "c_exact").includes("README.md"), "an identified cell is not asked about resource tools");
  assert.ok(forwarded(request, "c_loop").includes("\"a\""), "a cell that names no resource tool keeps the cell rule");
  const resourceAsks = asked.filter(([, tool]) => typeof tool === "string" && CODEX_RESOURCE_TOOLS.includes(tool as string));
  assert.deepEqual(resourceAsks.filter(([id]) => String(id).startsWith("c_read")), [["c_read#read_mcp_resource", "read_mcp_resource", undefined]], "asked under its own id, not as a built-in");
  assert.ok(resourceAsks.some(([id]) => id === "c_y#read_mcp_resource"), "the wait continuation is asked under the yielded cell's id");
  assert.ok(!asked.some(([id]) => String(id).startsWith("c_exact#") || String(id).startsWith("c_loop#")), "the controls are not asked about resource tools");
});

test("§11.18 wire: `mapped_tools:` lets a cell's resource read through; an ask that throws masks; an unisolated cell is read as well", async () => {
  const items = [BATTERY, ...cell("c_read", 'text(JSON.stringify(await tools.read_mcp_resource({server: "res", uri: "res://pg"})))')];
  const mapped = new MockArbiter({
    classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock" }),
    callTaintFn: () => EMPTY_TAINT, // the person listed the resource tools under mapped_tools:
  });
  const ok = (await rewriteRequest({ model: "m", input: structuredClone(items) } as unknown as ResponsesRequest, { arbiter: mapped, sessionKey: "s", skipPromptInjection: true })).request;
  assert.ok(forwarded(ok, "c_read").includes(BLOB), "a mapped resource tool's cell reaches the model as the direct call would");
  const broken = new MockArbiter({
    classifyFn: (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock" }),
    callTaintFn: (r) => { if (r.unmappedTool === "read_mcp_resource") throw new Error("socket closed"); return EMPTY_TAINT; },
  });
  const thrown = (await rewriteRequest({ model: "m", input: structuredClone(items) } as unknown as ResponsesRequest, { arbiter: broken, sessionKey: "s", skipPromptInjection: true })).request;
  assert.ok(!forwarded(thrown, "c_read").includes(BLOB), "an ask that throws masks (fail-closed)");
  // with no isolation sentence no cell is identified, and an exact-looking one is read too
  const map = buildCorrelationMap([
    { type: "custom_tool_call", call_id: "x", name: "exec", input: 'const r = await tools.exec_command({"cmd":"ls"}); const s = await tools.list_mcp_resources({}); text(r.output)' },
    { type: "custom_tool_call", call_id: "y", name: "js_repl", input: "await codex.tool(\"read_mcp_resource\", {})" },
    { type: "custom_tool_call", call_id: "p", name: "apply_patch", input: "*** Begin Patch\n*** Add File: read_mcp_resource.md\n+x\n*** End Patch" },
  ] as never, { isolatedCells: false });
  assert.deepEqual(map.get("x")!.resourceTools?.tools, ["list_mcp_resources"]);
  assert.deepEqual(map.get("y")!.resourceTools?.tools, ["read_mcp_resource"], "js_repl carries code too");
  assert.equal(map.get("p")!.resourceTools, undefined, "a patch is not code");
});
