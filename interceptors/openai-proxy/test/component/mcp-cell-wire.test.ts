/**
 * mcp-cell-wire (proxy e2e, Codex) — plan 10 §11.13 through the REAL
 * OpenAiProxy with a mock arbiter:
 *
 *   - a code-mode cell that is nothing but one literal call to a Mandu policy
 *     tool asks the arbiter EXACTLY what the namespaced function_call to the
 *     same tool asks (tool name, params, no taint ask), and its result reaches
 *     the upstream as that call's does;
 *   - a third-party MCP tool with a command, in a cell, takes §11.12's
 *     `unmappedTool` ask under its own name, as the namespaced call does;
 *   - an `ALL_TOOLS` listing, bare or filtered (codex-cli 0.160's tool
 *     search), is classified as `exec` with no input and no taint ask;
 *   - every cell that does not qualify (an alias, a second call, or ANY cell
 *     when the request's `exec` tool does not say each cell is a fresh
 *     isolate) is classified as `exec` with its source as `code` and asked
 *     about as `unmappedTool: "exec"`, so a session in which a reader read a
 *     secret raw masks its output whole (the fail-closed side, raise-only).
 *
 * Axes: `secrets`, stated through the mock: classify answers TRUSTED (integrity
 * OFF) with no level unless the test gives one, and callTaint answers as the
 * real arbiter does with the confidentiality axis ON.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { OpenAiProxy } from "../../src/proxy.js";
import type { CallTaintWire, ClassifyRequest } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

const READ = "mcp__mandu_policy__mandu_policy_read";
const POLICY_TEXT = "{\"tool\":\"mandu_policy_read\",\"law\":{\"pendingAskCount\":0}}";
const READER_SECRET = "4411-5522-6633-7744";
const ENVELOPE = "Script completed\nWall time 0.1 seconds\nOutput:\n";
const EMPTY: CallTaintWire = { level: null, files: [], apps: [], rule: "secret", mask: [], root: null, denied: [] };
/** The session answer of §11.12: a listed reader read a secret raw. */
const SESSION_TAINT: CallTaintWire = { ...EMPTY, level: "no-model", files: ["/h/.pgpass"], apps: ["psql"], evidence: "session" };

/** The code-mode battery as codex 0.159.1 sends it (`additional_tools`). */
function battery(isolated: boolean): Record<string, unknown> {
  return {
    type: "additional_tools", role: "developer",
    tools: [{
      type: "namespace", name: "functions",
      tools: [
        { type: "custom", name: "exec", description: isolated ? "Run JavaScript code\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." : "Run JavaScript code in a REPL." },
        { type: "function", name: "wait" },
      ],
    }],
  };
}

function cellTurn(cell: string, output: string, callId: string, isolated = true): string {
  return JSON.stringify({
    model: "gpt-6.1-sol", stream: true, instructions: "You are Codex.",
    input: [
      battery(isolated),
      { type: "message", role: "user", content: [{ type: "input_text", text: "set up Mandu" }] },
      { type: "custom_tool_call", call_id: callId, name: "exec", input: cell },
      { type: "custom_tool_call_output", call_id: callId, output: [{ type: "input_text", text: ENVELOPE }, { type: "input_text", text: output }] },
    ],
  });
}

function fnTurn(namespace: string, name: string, args: Record<string, unknown>, output: string, callId: string): string {
  return JSON.stringify({
    model: "gpt-6.1-sol", stream: true, instructions: "You are Codex.",
    input: [
      battery(true),
      { type: "message", role: "user", content: [{ type: "input_text", text: "set up Mandu" }] },
      { type: "function_call", call_id: callId, namespace, name, arguments: JSON.stringify(args) },
      { type: "function_call_output", call_id: callId, output: `Wall time: 0.1 seconds\nOutput:\n${output}` },
    ],
  });
}

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
    req.end(body);
  });
}

async function run(arbiter: MockArbiter, body: string): Promise<string> {
  const up = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter, upstream: up.fetcher, sessionKey: "codex-cell", log: () => {} });
  const port = await proxy.listen(0);
  try {
    assert.equal((await call(port, body)).status, 200);
    return up.requests[0]!.bodyText;
  } finally { await proxy.close(); }
}

/** The forwarded tool-output text of the one tool call in a forwarded body. */
function outputOf(body: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" || i["type"] === "custom_tool_call_output")!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

const trusted = () => ({ trust: "TRUSTED" as const, category: null, reason: "mock: integrity off" });
/** The classify requests for tool outputs (the handling prompt is not one). */
const toolAsks = (a: MockArbiter): Array<Pick<ClassifyRequest, "tool" | "params">> =>
  a.classifyCalls.filter((c) => c.boundary === "model_context").map((c) => ({ tool: c.tool, params: c.params }));

test("a policy-tool cell asks the arbiter exactly what the namespaced call asks, and its result reaches the model as that call's does", async () => {
  const asked: Array<Record<string, unknown>> = [];
  // Even a session where a reader read a secret raw: both wires ask about the
  // tool as an MCP server (§11.13 path (c)), and the arbiter answers empty for
  // Mandu's own tools (mapped), so neither is masked. The mock answers so.
  const mk = () => new MockArbiter({ classifyFn: trusted, callTaintFn: (r) => { asked.push({ ...r }); return r.unmappedTool?.startsWith("mcp__mandu_") ? EMPTY : SESSION_TAINT; } });
  const viaFn = mk();
  const fn = await run(viaFn, fnTurn("mcp__mandu_policy", "mandu_policy_read", {}, POLICY_TEXT, "call_fn"));
  const viaCell = mk();
  const cell = await run(viaCell, cellTurn(`const r = await tools.${READ}({});\ntext(r.content[0].text);`, POLICY_TEXT, "call_cell"));
  assert.deepEqual(toolAsks(viaCell).map((a) => a.tool), [READ]);
  assert.deepEqual(toolAsks(viaFn).map((a) => a.tool), [READ, READ], "the namespaced call asks for its body and its header");
  assert.deepEqual(toolAsks(viaCell)[0]!.params, toolAsks(viaFn)[0]!.params, "same params on both wires");
  assert.deepEqual(asked.map((a) => [a["unmappedTool"], a["command"]]), [[READ, undefined], [READ, undefined]], "one bare ask per wire, the same on both");
  assert.ok(outputOf(fn).endsWith(POLICY_TEXT), "control: the namespaced result is forwarded raw");
  assert.equal(outputOf(cell), ENVELOPE + POLICY_TEXT, "the cell's result is forwarded raw as well, nothing symbolized");

  // A propose whose edit names `.env`: the arguments ride as the namespaced
  // call's do (the policy tool's input is not scanned, §11.11), not the
  // cell's source text.
  const propose = new MockArbiter({ classifyFn: trusted });
  await run(propose, cellTurn(`// lock .env\ntext(await tools.mcp__mandu_policy__mandu_policy_propose({edits: [{op: "lock-path", path: ".env", level: "no-model"}]}));`, "Applied.", "call_p"));
  assert.deepEqual(toolAsks(propose), [{ tool: "mcp__mandu_policy__mandu_policy_propose", params: { edits: [{ op: "lock-path", path: ".env", level: "no-model" }] } }]);
});

test("a secret verdict on the tool masks the cell's result, as it masks the namespaced call's", async () => {
  const secret = new MockArbiter({ classifyFn: (r) => ({ ...trusted(), ...(r.tool === "mcp__fs__read_file" ? { confidentiality: "no-model" } : {}) }) });
  const out = await run(secret, cellTurn(`text(await tools.mcp__fs__read_file({path: ".env"}));`, "API_KEY=AKIA-CELL-SECRET", "call_rf"));
  assert.ok(!out.includes("AKIA-CELL-SECRET"), "CONFIDENTIALITY VIOLATION: a secret tool result reached the model through a cell");
  assert.deepEqual(toolAsks(secret)[0], { tool: "mcp__fs__read_file", params: { path: ".env" } });
});

test("a third-party command tool in a cell takes the §11.12 ask under its own name, as the namespaced call does", async () => {
  const asked: Array<Record<string, unknown>> = [];
  const arbiter = new MockArbiter({ classifyFn: trusted, callTaintFn: (r) => { asked.push({ ...r }); return SESSION_TAINT; } });
  const cell = await run(arbiter, cellTurn(`text(await tools.mcp__box__run_command({command: "dbdump cards"}));`, READER_SECRET, "call_box"));
  const fn = await run(arbiter, fnTurn("mcp__box", "run_command", { command: "dbdump cards" }, READER_SECRET, "call_boxfn"));
  assert.deepEqual(asked, [
    { callId: "call_box", command: "dbdump cards", sessionKey: "codex-cell", unmappedTool: "mcp__box__run_command" },
    { callId: "call_boxfn", command: "dbdump cards", sessionKey: "codex-cell", unmappedTool: "mcp__box__run_command" },
  ]);
  assert.ok(!cell.includes(READER_SECRET) && !fn.includes(READER_SECRET), "the session answer masks both");
});

test("an ALL_TOOLS listing, bare or filtered, is `exec` with no input and no taint ask; one that reads anything else is not", async () => {
  const listing = "[{\"name\":\"mcp__mandu_policy__mandu_policy_read\",\"description\":\"Read the rules\"}]";
  // the bare listing, and the filtered search codex-cli 0.160 asks for ("To
  // find one, filter `ALL_TOOLS` by `name` and `description`")
  for (const src of [
    "text(ALL_TOOLS);",
    "text(JSON.stringify(ALL_TOOLS.filter(t => /mandu|policy/i.test(t.name + \" \" + t.description)), null, 2));",
    "const hits = ALL_TOOLS.filter((t) => t.name.toLowerCase().includes(\"policy\"));\ntext(hits.map((t) => `${t.name}: ${t.description}`).join(\"\\n\"));",
  ]) {
    const asked: unknown[] = [];
    const arbiter = new MockArbiter({ classifyFn: trusted, callTaintFn: (r) => { asked.push(r); return SESSION_TAINT; } });
    const out = await run(arbiter, cellTurn(src, listing, "call_ls"));
    assert.deepEqual(toolAsks(arbiter), [{ tool: "exec", params: {} }], src);
    assert.equal(asked.length, 0, `a listing runs no process: ${src}`);
    assert.equal(outputOf(out), ENVELOPE + listing, `the listing reaches the model, even in a session with a raw read: ${src}`);
  }

  // a listing-shaped cell that reads something besides ALL_TOOLS (`load`, a
  // tool) keeps the fail-closed handling
  for (const src of [
    "text(ALL_TOOLS.filter(t => load(\"k\")));",
    "text(ALL_TOOLS.map(t => tools.mcp__box__get_rows({})));",
  ]) {
    const asked: unknown[] = [];
    const tainted = new MockArbiter({ classifyFn: trusted, callTaintFn: (r) => { asked.push(r); return SESSION_TAINT; } });
    const out = await run(tainted, cellTurn(src, READER_SECRET, "call_ls2"));
    assert.ok(toolAsks(tainted).every((a) => a.tool === "exec" && (a.params as { code?: string }).code === src), src);
    assert.equal(asked.length, 1, `asked about as an unmapped tool: ${src}`);
    assert.ok(!out.includes(READER_SECRET), `CONFIDENTIALITY VIOLATION: masked whole in a session with a raw read: ${src}`);
  }
});

test("cells that do not qualify keep the fail-closed handling, now as an unmapped tool (§11.12)", async () => {
  const cases: Array<[string, string, boolean]> = [
    ["alias", `const t = tools; text(await t.${READ}({}));`, true],
    ["computed exec", `text((await tools["exec_command"]({cmd: "psql -c 'select 1'"})).output);`, true],
    ["two calls", `text(await tools.${READ}({})); text(await tools.mcp__box__run_command({command: "id"}));`, true],
    ["load", `text(load("rows"));`, true],
    ["not isolated", `text(await tools.${READ}({}));`, false],
  ];
  for (const [label, src, isolated] of cases) {
    const asked: Array<Record<string, unknown>> = [];
    const tainted = new MockArbiter({ classifyFn: trusted, callTaintFn: (r) => { asked.push({ ...r }); return SESSION_TAINT; } });
    const out = await run(tainted, cellTurn(src, READER_SECRET, `call_${label.replace(/\W/g, "_")}`, isolated));
    assert.ok(toolAsks(tainted).length > 0 && toolAsks(tainted).every((a) => a.tool === "exec" && (a.params as { code?: string }).code === src), label);
    assert.deepEqual(asked.map((a) => [a["unmappedTool"], a["command"]]), [["exec", src]], `${label}: asked as unmappedTool`);
    assert.ok(!out.includes(READER_SECRET), `CONFIDENTIALITY VIOLATION (${label}): a reader's output reached the model through a cell`);
    assert.match(out, /\[mandu:secret\] masked: plan 10 §11\.12: exec runs a command/, label);

    // control: a session with no raw read forwards the same cell raw
    const clean = new MockArbiter({ classifyFn: trusted, callTaintFn: () => EMPTY });
    const raw = await run(clean, cellTurn(src, READER_SECRET, `call_c_${label.replace(/\W/g, "_")}`, isolated));
    assert.ok(raw.includes(READER_SECRET), `${label}: control, no taint ⇒ raw`);
  }
});
