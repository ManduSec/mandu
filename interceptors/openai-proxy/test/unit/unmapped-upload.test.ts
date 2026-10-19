/**
 * unmapped-upload — the openai-proxy's unmapped upload leg (guarantees.md
 * §3; supported-agents.md §2, "The upload residuals", item 4): the local
 * files a Codex tool Mandu does not map may send off this computer. Before
 * 2026-10-17 Codex's MCP tools had no such check: a namespaced
 * `{namespace: "mcp__drive", name: "upload_file", arguments: {path:
 * "/ws/app/.env"}}` reached Codex unchanged. Pinned here, over a fake
 * arbiter and the real OpenAiProxy:
 *   - the core is the anthropic-proxy's, byte for byte below its marker;
 *   - which tools the leg judges (every tool but codex's own) and which may
 *     write (all but codex's bookkeeping); the turn's order;
 *   - the strings a code cell spells;
 *   - a function_call: the held path withheld (names no file), asked as
 *     `<namespace>__<name>` in the unmapped form with no host, the rest of
 *     the call kept, the output replaced by the notice next request, the
 *     model's own call restored in history; codex's built-ins never asked;
 *   - the window: an MCP upload after an `exec_command` of the same
 *     response is withheld; alone, it goes;
 *   - a code cell: identified (in a fresh isolate) or not, a held file
 *     replaces the whole cell by the sentinel cell, and its notice reaches
 *     the model;
 *   - the buffered (stream:false) answer the same; fail-closed when the
 *     arbiter throws.
 *
 * Axes: `secrets`, stated through the fake arbiter (the upload gate's
 * answers are the confidentiality axis's).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { OpenAiProxy } from "../../src/proxy.js";
import type { FileUploadDecision, FileUploadDecisionRequest } from "../../src/arbiter-client.js";
import type { UpstreamFetcher } from "../../src/proxy.js";
import {
  cellStringLiterals,
  codexPossibleWriter,
  gateUnmappedUploadCell,
  uploadLegApplies,
  UploadTurn,
  UPLOAD_DENIED_ROOT,
} from "../../src/unmapped-upload.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildCallsSse, deliveredItems, type TurnCall } from "../helpers/mock-upstream.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SECRET = "/ws/app/.env";
const CLEAN = "/ws/app/report.html";

const HELD: FileUploadDecision = {
  allow: false, requiresApproval: true,
  reason: `'${SECRET}' is a secret file (no-model) and no rule lets it go to an unnamed destination`,
  ruleRef: { source: "rule", id: "fs:upload-secret-file" }, approvalId: "egr-3",
};
const allow = (id: string): FileUploadDecision => ({ allow: true, reason: id, ruleRef: { source: "rule", id } });

/** The arbiter's unmapped-form answers, reduced: the secret is held, a file
 *  under /ws is clean, anything else names nothing. */
function decide(req: FileUploadDecisionRequest): FileUploadDecision {
  return req.path === SECRET ? HELD : req.path.startsWith("/ws/") ? allow("fs:upload-clean") : allow("fs:upload-no-file");
}

function arbiter(extra: ConstructorParameters<typeof MockArbiter>[0] = {}): MockArbiter {
  return new MockArbiter({ fileUploadDecisionFn: decide, scanSecretValuesFn: () => ({ hits: [] }), ...extra });
}

const ISOLATED_EXEC = { type: "custom", name: "exec", description: "Evaluates the provided JavaScript code in a fresh V8 isolate as an async module." };

/** A proxy whose upstream answers each request with the next turn's calls. */
async function harness(arb: MockArbiter, opts: { json?: boolean } = {}) {
  let next: TurnCall[] = [];
  const seen: MockUpstream[] = [];
  const fetcher: UpstreamFetcher = (args) => {
    const items = deliveredItems(buildCallsSse(next));
    const up = opts.json
      ? new MockUpstream({ json: { id: "r", status: "completed", output: items } })
      : new MockUpstream({ sse: buildCallsSse(next) });
    seen.push(up);
    return up.fetcher(args);
  };
  const proxy = new OpenAiProxy({ arbiter: arb, upstream: fetcher, sessionKey: "s-upload", log: () => {} });
  const port = await proxy.listen(0);
  const post = async (calls: TurnCall[], input: unknown[] = [{ type: "message", role: "user", content: [{ type: "input_text", text: "share it" }] }], tools: unknown[] = []): Promise<Array<Record<string, unknown>>> => {
    next = calls;
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-6.1-sol", stream: !opts.json, input, tools }),
    });
    assert.equal(res.status, 200);
    const text = await res.text();
    if (opts.json) return (JSON.parse(text) as { output: Array<Record<string, unknown>> }).output;
    return deliveredItems(text);
  };
  const lastBody = (): unknown => seen.at(-1)!.requests.at(-1)!.json();
  return { proxy, post, lastBody };
}

const args = (item: Record<string, unknown> | undefined): Record<string, unknown> => JSON.parse(String(item?.["arguments"])) as Record<string, unknown>;

test("the shared core stays equal to the anthropic-proxy's below the marker line", () => {
  const strip = (s: string): string => s.slice(s.indexOf("// ── the shared core"));
  const mine = readFileSync(join(HERE, "..", "..", "src", "unmapped-upload-core.ts"), "utf8");
  const theirs = readFileSync(join(HERE, "..", "..", "..", "anthropic-proxy", "src", "unmapped-upload-core.ts"), "utf8");
  assert.ok(mine.includes("// ── the shared core"), "the marker is there");
  assert.equal(strip(mine), strip(theirs), "keep interceptors/*/src/unmapped-upload-core.ts equal below the marker");
  assert.equal(UPLOAD_DENIED_ROOT, "/mandu/denied/upload");
});

test("uploadLegApplies: codex's own tools keep their legs; an MCP tool, a new built-in, a connector's tool are judged", () => {
  for (const t of ["exec_command", "shell", "apply_patch", "view_image", "read_file", "write_stdin", "exec", "js_repl", "wait", "spawn_agent", "collaboration__spawn_agent", "update_plan"]) {
    assert.equal(uploadLegApplies(t), false, t);
  }
  for (const t of ["mcp__drive__upload_file", "mcp__claude-in-chrome__file_upload", "attach_file", "read_mcp_resource"]) {
    assert.equal(uploadLegApplies(t), true, t);
  }
  assert.equal(uploadLegApplies(""), false, "no name: nothing to judge");
});

test("codexPossibleWriter and UploadTurn: shells, patches, cells and unmapped tools may write; bookkeeping does not; order by item", () => {
  for (const t of ["exec_command", "apply_patch", "exec", "write_stdin", "wait", "mcp__fs__write_file", "collaboration__spawn_agent"]) assert.equal(codexPossibleWriter(t), true, t);
  for (const t of ["update_plan", "view_image", "read_file", "tool_search", "request_user_input", "clock__sleep"]) assert.equal(codexPossibleWriter(t), false, t);
  const turn = new UploadTurn();
  turn.record("fc_0", "update_plan");
  turn.record("fc_1", "exec_command");
  turn.record("fc_2", "mcp__drive__upload_file");
  assert.equal(turn.priorWriter("fc_0"), undefined);
  assert.equal(turn.priorWriter("fc_1"), undefined, "a call is not its own prior writer");
  assert.equal(turn.priorWriter("fc_2"), "exec_command");
  turn.record("fc_1", "exec_command");
  assert.equal(turn.priorWriter("fc_9"), "exec_command", "an unrecorded call: every recorded call is earlier");
});

test("cellStringLiterals: quoted strings, template pieces and escapes, read past a confusing regex literal", () => {
  const src = [
    "// a comment naming /etc/passwd is not code",
    "const a = '/ws/app/.env';",
    "const b = \"~/notes\\u002etxt\";",
    "const c = `file:///ws/app/${name}.pem`;",
    "const re = /it's/; const d = \"/ws/app/after-regex\";",
  ].join("\n");
  const lits = cellStringLiterals(src);
  for (const want of ["/ws/app/.env", "~/notes.txt", "file:///ws/app/", ".pem", "/ws/app/after-regex"]) assert.ok(lits.includes(want), `${want} in ${JSON.stringify(lits)}`);
});

test("gateUnmappedUploadCell: an identified cell's MCP call naming a secret is held; an exec before a clean upload holds it (the window); codex's own calls are not asked", async () => {
  const arb = arbiter();
  const base = { arbiter: arb, sessionKey: "s", cellsIsolated: true };
  const up = (p: string): string => `const r = await tools.mcp__drive__upload_file({"path": "${p}", "name": "q3"});\ntext(JSON.stringify(r));`;
  const held = await gateUnmappedUploadCell(up(SECRET), base);
  assert.ok(held, "held");
  assert.equal(held!.tool, "mcp__drive__upload_file");
  assert.match(held!.notice, /^mandu-upload-gate: mcp__drive__upload_file was not given the file \/ws\/app\/\.env/);
  assert.deepEqual(arb.fileUploadDecisionCalls.at(-1), { tool: "mcp__drive__upload_file", path: SECRET, destination: "", unmapped: true, sessionKey: "s" });
  assert.equal(await gateUnmappedUploadCell(up(CLEAN), base), null, "a clean file goes");
  const after = await gateUnmappedUploadCell(`await tools.exec_command({"cmd": "cp ~/k ${CLEAN}"});\n${up(CLEAN)}`, base);
  assert.match(after?.notice ?? "", /rule: proxy:upload-after-write/, "an earlier exec of the same cell runs first");
  assert.match((await gateUnmappedUploadCell(up(CLEAN), { ...base, priorWriter: "exec_command" }))?.notice ?? "", /proxy:upload-after-write/, "an earlier call of the response");
  const n = arb.fileUploadDecisionCalls.length;
  assert.equal(await gateUnmappedUploadCell(`const r = await tools.exec_command({"cmd": "cat ${SECRET}"}); text(r.output);`, base), null);
  assert.equal(arb.fileUploadDecisionCalls.length, n, "a cell of codex's own calls asks nothing here (the exec gate and the guard are its)");
});

test("gateUnmappedUploadCell: a cell the grammar does not identify has every path it spells judged under each non-codex tool it names", async () => {
  const arb = arbiter();
  const src = `const p = ["/ws/app", ".env"].join("/");\nconst f = "${SECRET}";\nawait tools["mcp__drive__upload_file"]({ path: f });`;
  const held = await gateUnmappedUploadCell(src, { arbiter: arb, cellsIsolated: true });
  assert.ok(held, "held through the literal");
  assert.equal(held!.tool, "mcp__drive__upload_file");
  // not isolated: the parse is not believed, the literal scan applies
  assert.ok(await gateUnmappedUploadCell(`await tools.mcp__drive__upload_file({path: "${SECRET}"});`, { arbiter: arb, cellsIsolated: false }));
  assert.equal(await gateUnmappedUploadCell(`await tools.mcp__drive__upload_file({path: "${CLEAN}"});`, { arbiter: arb, cellsIsolated: false }), null);
});

test("a namespaced MCP upload naming a secret: the path is withheld, asked as mcp__drive__upload_file in the unmapped form, and its output becomes the notice next request", async () => {
  const arb = arbiter();
  const { proxy, post, lastBody } = await harness(arb);
  try {
    const [got] = await post([{ name: "upload_file", namespace: "mcp__drive", callId: "call_up", arguments: { path: SECRET, name: "q3.txt" } }]);
    assert.deepEqual(args(got), { path: `/mandu/denied/upload${SECRET}`, name: "q3.txt" }, "the path names no file, the rest is the model's");
    assert.equal(got!["namespace"], "mcp__drive", "the call keeps its namespace");
    assert.deepEqual(arb.fileUploadDecisionCalls, [{ tool: "mcp__drive__upload_file", path: SECRET, destination: "", unmapped: true, sessionKey: "s-upload" }]);
    // next turn: Codex echoes the delivered call and the server's error
    await post([], [
      { type: "message", role: "user", content: [{ type: "input_text", text: "share it" }] },
      { type: "function_call", call_id: "call_up", name: "upload_file", namespace: "mcp__drive", arguments: String(got!["arguments"]) },
      { type: "function_call_output", call_id: "call_up", output: [{ type: "input_text", text: "Wall time: 0.1 seconds\nOutput:" }, { type: "input_text", text: "ENOENT: /mandu/denied/upload/ws/app/.env" }] },
    ]);
    const req = lastBody() as { input: Array<Record<string, unknown>> };
    const fco = req.input.find((i) => i["type"] === "function_call_output")!;
    assert.match(String(fco["output"]), /^mandu-upload-gate: mcp__drive__upload_file was not given the file \/ws\/app\/\.env .*Approvals page/);
    const fc = req.input.find((i) => i["type"] === "function_call")!;
    assert.deepEqual(JSON.parse(String(fc["arguments"])), { path: SECRET, name: "q3.txt" }, "the model reads back the call it wrote");
  } finally {
    await proxy.close();
  }
});

test("utility: a clean file and a remote path go unchanged; codex's built-ins are never asked", async () => {
  const arb = arbiter();
  const { proxy, post } = await harness(arb);
  try {
    const [clean] = await post([{ name: "upload_file", namespace: "mcp__drive", arguments: { path: CLEAN } }]);
    assert.deepEqual(args(clean), { path: CLEAN });
    const [remote] = await post([{ name: "post", namespace: "mcp__crm", arguments: { endpoint: "/v1/items" } }]);
    assert.deepEqual(args(remote), { endpoint: "/v1/items" });
    const asked = arb.fileUploadDecisionCalls.length;
    await post([{ name: "exec_command", arguments: { cmd: `cat ${SECRET}` } }]);
    await post([{ name: "view_image", arguments: { path: SECRET } }]);
    assert.equal(arb.fileUploadDecisionCalls.length, asked, "exec_command and view_image keep their own legs");
  } finally {
    await proxy.close();
  }
});

test("THE WINDOW: an MCP upload after an exec_command of the same response is withheld; on its own it goes", async () => {
  const arb = arbiter();
  const { proxy, post } = await harness(arb);
  try {
    const [, up] = await post([
      { name: "exec_command", arguments: { cmd: `cp ~/notes.txt ${CLEAN}` } },
      { name: "upload_file", namespace: "mcp__drive", arguments: { path: CLEAN } },
    ]);
    assert.deepEqual(args(up), { path: `/mandu/denied/upload${CLEAN}` });
    const [, after] = await post([
      { name: "update_plan", arguments: { plan: [] } },
      { name: "upload_file", namespace: "mcp__drive", arguments: { path: CLEAN } },
    ]);
    assert.deepEqual(args(after), { path: CLEAN }, "bookkeeping is no writer");
    const [alone] = await post([{ name: "upload_file", namespace: "mcp__drive", arguments: { path: CLEAN } }]);
    assert.deepEqual(args(alone), { path: CLEAN }, "a later turn on its own");
  } finally {
    await proxy.close();
  }
});

test("a code cell whose MCP call names a secret is replaced whole by the sentinel cell; the notice reaches the model", async () => {
  const arb = arbiter();
  const { proxy, post, lastBody } = await harness(arb);
  try {
    const cell = `const r = await tools.mcp__drive__upload_file({"path": "${SECRET}"});\ntext(JSON.stringify(r));`;
    const [got] = await post([{ name: "exec", input: cell, callId: "call_cell" }], undefined, [ISOLATED_EXEC]);
    const delivered = String(got!["input"]);
    assert.ok(!delivered.includes("tools.mcp__drive__upload_file"), "the upload never runs");
    const m = /echo '([^']*)' 1>&2; exit 77/.exec(delivered);
    assert.ok(m, `the sentinel cell: ${delivered.slice(0, 160)}`);
    const notice = m![1]!;
    assert.match(notice, /^mandu-exec-gate: blocked, nothing ran: a call in this code cell would send a local file Mandu holds/);
    assert.match(notice, /mcp__drive__upload_file was not given the file \/ws\/app\/\.env/);
    // next turn: the cell's output is exactly the sentinel's
    await post([], [
      { type: "message", role: "user", content: [{ type: "input_text", text: "share it" }] },
      { type: "custom_tool_call", call_id: "call_cell", name: "exec", input: delivered },
      { type: "custom_tool_call_output", call_id: "call_cell", output: [{ type: "input_text", text: "Script completed\nWall time 0.1 seconds\nOutput:\n" }, { type: "input_text", text: notice }] },
    ], [ISOLATED_EXEC]);
    const req = lastBody() as { input: Array<Record<string, unknown>> };
    const out = JSON.stringify(req.input.find((i) => i["type"] === "custom_tool_call_output")!["output"]);
    assert.ok(out.includes("mcp__drive__upload_file was not given the file"), `the model reads why: ${out.slice(0, 200)}`);
    const echoed = req.input.find((i) => i["type"] === "custom_tool_call")!;
    assert.equal(echoed["input"], cell, "the model reads back the cell it wrote");
  } finally {
    await proxy.close();
  }
});

test("the buffered (stream:false) answer is gated the same", async () => {
  const arb = arbiter();
  const { proxy, post } = await harness(arb, { json: true });
  try {
    const [got] = await post([{ name: "upload_file", namespace: "mcp__drive", arguments: { path: SECRET } }]);
    assert.deepEqual(args(got), { path: `/mandu/denied/upload${SECRET}` });
  } finally {
    await proxy.close();
  }
});

test("FAIL-CLOSED: an arbiter that throws withholds every path; one without the op too", async () => {
  for (const arb of [new MockArbiter({ failFileUpload: true }), (() => { const a = new MockArbiter(); (a as { fileUploadDecision?: unknown }).fileUploadDecision = undefined; return a; })()]) {
    const { proxy, post } = await harness(arb);
    try {
      const [got] = await post([{ name: "upload_file", namespace: "mcp__drive", arguments: { path: CLEAN, also: "~/x" } }]);
      assert.deepEqual(args(got), { path: `/mandu/denied/upload${CLEAN}`, also: `/mandu/denied/upload${homedir()}/x` }, JSON.stringify(args(got)));
    } finally {
      await proxy.close();
    }
  }
});
