/**
 * codex-cell-tools-guard — plan 10 §11.18, "The cell guard" and "An MCP tool
 * in a cell" (2026-10-11), over the REAL components: the real ArbiterServer
 * in `secrets`, the real openai-proxy over HTTP in its PRODUCTION wiring
 * (`new ArbiterClientAdapter(new ArbiterClient(sock), new ArbiterClient(human))`),
 * only the model upstream canned, in a session where nothing read a secret
 * raw. The MCP server `remote` is not registered (a remote server, a
 * connector): Mandu has no mapping for its tools, so its direct call is
 * masked whole.
 *
 * (1) The gap: a cell the §11.13 grammar refuses that calls
 *     `tools.mcp__remote__get` and transforms the result reached the model
 *     raw (the cell rule alone), while the namespaced call was masked whole.
 *     Now the cell's text rule asks about every MCP tool it names, as the
 *     direct call is. Red on master.
 * (2) The guard, delivered: the proxy puts its run-time guard at the head of
 *     every code cell the grammar cannot identify (the model's cell as the
 *     SSE carries it to codex); the keep list holds codex's own tools and the
 *     mapped tools the cell names (Mandu's policy tool), never `remote`'s, a
 *     resource tool, or a tool the cell does not name. An identified cell
 *     and a cell with the axis off are delivered as written.
 * (3) Narrowed: a guarded cell (its text exactly the proxy's guard, every
 *     kept tool still mapped) is not masked for what its text may reach: a
 *     `load`, a computed `tools` name. A guard whose keep list names an
 *     unmapped tool (a forged one), and the same cells unguarded, keep the
 *     text rule (masked).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { guardCell, splitGuardedCell } from "../../interceptors/openai-proxy/src/cell-guard.js";
import { MockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { responsesCustomToolTurn, sseChunk } from "../lib/model-wire.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

// one value per case: a value masked once is registered, and the value
// backstop would then mask a later case by value, not by its rule
const ROW = `remote-row-${process.pid}-4be0d1`;
const DIRECT_ROW = `direct-${process.pid}-77aa01`;
const ENVELOPE = "Script completed\nWall time 0.0 seconds\nOutput:\n";
const MCP_HEADER = "Wall time: 0.1 seconds\nOutput:";
const BATTERY = {
  type: "additional_tools", role: "developer",
  tools: [{
    type: "namespace", name: "functions",
    tools: [
      { type: "custom", name: "exec", description: "Run JavaScript code to orchestrate/compose tool calls\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." },
      { type: "function", name: "wait" },
    ],
  }],
};
const NAMED = "const r = await tools.mcp__remote__get({});\ntext(r.content.map((c) => c.text).join(\"\"))";
const COMPUTED = "const n = \"exec_\" + \"command\";\nconst r = await tools[n]({ cmd: \"ls\" });\ntext(r.output)";
const LOAD = "text(String(load(\"k\")))";
const POLICY = "const p = await tools.mcp__mandu_policy__mandu_policy_read({});\ntext(JSON.stringify(p).slice(0, 200))";
const EXACT = "const r = await tools.exec_command({\"cmd\":\"ls\"});\ntext(r.output);\n";

function turn(...items: unknown[]): unknown {
  return { model: "gpt-6.1-sol", stream: true, instructions: "You are Codex.", input: [BATTERY, { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }, ...items] };
}
const cellItems = (id: string, src: string, out: string) => [
  { type: "custom_tool_call", call_id: id, name: "exec", input: src },
  { type: "custom_tool_call_output", call_id: id, output: [{ type: "input_text", text: ENVELOPE }, { type: "input_text", text: out }] },
];
function outputIn(body: string, id: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => /_output$/.test(String(i["type"])) && i["call_id"] === id)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}
/** The cell input the proxy delivered to codex in an SSE body. */
function deliveredInput(sse: string): string {
  let input: string | null = null;
  for (const block of sse.split("\n\n")) {
    const data = block.split("\n").find((l) => l.startsWith("data: "));
    if (!data) continue;
    const d = JSON.parse(data.slice(6)) as Record<string, unknown>;
    if (d["type"] === "response.custom_tool_call_input.done") input = d["input"] as string;
  }
  assert.ok(input !== null, "the proxy delivered the cell");
  return input!;
}

async function rig(confidentiality: boolean) {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cell-guard-"));
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality, integrity: false, // `secrets` (or `off`), stated
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const session = `cell-guard-${process.pid}-${confidentiality ? "on" : "off"}`;
  let upstream = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  /** POST a turn; the model answers `sse`. Returns what reached the model and what reached codex. */
  const send = async (body: unknown, sse = "event: response.completed\ndata: {}\n\n"): Promise<{ toModel: string; toAgent: string }> => {
    upstream = new MockUpstream({ sse });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
    const toAgent = await res.text();
    assert.equal(res.status, 200, toAgent);
    return { toModel: upstream.requests[0]!.bodyText, toAgent };
  };
  const modelCell = (id: string, src: string): string => responsesCustomToolTurn(id, "exec", src).map(([e, d]) => sseChunk(e, d)).join("");
  const close = async (): Promise<void> => {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  };
  return { send, modelCell, close };
}

test("an unregistered server's MCP tool in a refused cell, the cell guard delivered, and the guarded cells narrowed (secrets axes, real arbiter, production adapter)", async () => {
  const r = await rig(true);
  try {
    // (1) the gap: the namespaced call and the refused cell, same answer
    const fn = await r.send(turn(
      { type: "function_call", call_id: "f1", namespace: "mcp__remote", name: "get", arguments: "{}" },
      { type: "function_call_output", call_id: "f1", output: [{ type: "input_text", text: MCP_HEADER }, { type: "input_text", text: DIRECT_ROW }] },
    ));
    assert.ok(!outputIn(fn.toModel, "f1").includes(DIRECT_ROW), "control: the direct call is masked whole (§11.18)");
    const cell = await r.send(turn(...cellItems("c1", NAMED, ROW)));
    // MASTER: raw (the cell rule alone, a session that read nothing)
    assert.ok(!outputIn(cell.toModel, "c1").includes(ROW), "CONFIDENTIALITY VIOLATION: an unregistered server's tool reached the model raw through a cell");
    assert.match(outputIn(cell.toModel, "c1"), /this cell calls mcp__remote__get.*no mapping for the tool mcp__remote__get/);

    // (2) the guard, as the proxy delivers each cell to codex
    const g1 = deliveredInput((await r.send(turn(), r.modelCell("g1", NAMED))).toAgent);
    const s1 = splitGuardedCell(g1);
    assert.ok(s1, `a refused cell is delivered with the guard: ${g1.slice(0, 120)}`);
    assert.equal(s1!.body, NAMED, "the model's code follows the guard unchanged");
    for (const own of ["exec_command", "write_stdin", "apply_patch", "view_image"]) assert.ok(s1!.keep.includes(own), `codex's own ${own} is kept`);
    for (const off of ["mcp__remote__get", "read_mcp_resource", "list_mcp_resources", "list_mcp_resource_templates"]) assert.ok(!s1!.keep.includes(off), `${off} is switched off`);
    const g2 = splitGuardedCell(deliveredInput((await r.send(turn(), r.modelCell("g2", POLICY))).toAgent));
    assert.ok(g2 && g2.keep.includes("mcp__mandu_policy__mandu_policy_read"), "a mapped tool the cell names (Mandu's own) is kept");
    assert.equal(deliveredInput((await r.send(turn(), r.modelCell("g3", EXACT))).toAgent), EXACT, "an identified cell is delivered as written");
    const pragma = "// @exec: {\"yield_time_ms\": 1000}\n" + LOAD;
    const g4 = deliveredInput((await r.send(turn(), r.modelCell("g4", pragma))).toAgent);
    assert.ok(g4.startsWith("// @exec: {\"yield_time_ms\": 1000}\n/* mandu:"), "the pragma stays the first line, the guard after it");

    // (3) narrowed: the guarded cells' outputs (what codex would answer)
    const guardedLoad = guardCell(LOAD, s1!.keep);
    const guardedComputed = guardCell(COMPUTED, s1!.keep);
    const forged = guardCell(LOAD, [...s1!.keep, "mcp__remote__get"]);
    const out = (await r.send(turn(
      ...cellItems("n_load", guardedLoad, "util-load-ok"),
      ...cellItems("n_dyn", guardedComputed, "README.md"),
      ...cellItems("t_forged", forged, "forged-keep"),
      ...cellItems("t_load", LOAD, "plain-load"),
      ...cellItems("t_dyn", COMPUTED, "plain-dyn"),
    ))).toModel;
    assert.ok(outputIn(out, "n_load").includes("util-load-ok"), "a guarded `load` reaches the model (the guard keeps its keys)");
    assert.ok(outputIn(out, "n_dyn").includes("README.md"), "a guarded computed tools name reaches the model (the guard switched the rest off)");
    for (const id of ["t_forged", "t_load", "t_dyn"]) {
      assert.match(outputIn(out, id), /\$MDU:.*mapped_tools/s, `${id}: no trusted guard, the text rule masks it`);
    }
  } finally {
    await r.close();
  }
});

test("with the confidentiality axis off the proxy delivers the cell as the model wrote it (off axes, real arbiter)", async () => {
  const r = await rig(false);
  try {
    assert.equal(deliveredInput((await r.send(turn(), r.modelCell("g1", NAMED))).toAgent), NAMED);
  } finally {
    await r.close();
  }
});
