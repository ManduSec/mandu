/**
 * codex-mcp-cell — plan 10 §11.13 over the REAL components: the real
 * ArbiterServer in `secrets`, the real OpenAiProxy, the PRODUCTION adapter
 * (`new ArbiterClientAdapter(new ArbiterClient(sock))`), only the model
 * upstream canned. Codex's code mode (codex-cli 0.159.1) wraps every MCP call
 * in an `exec` script cell; the battery below carries the `exec` description
 * codex sends (each cell "in a fresh V8 isolate").
 *
 * (a) A cell that is one literal call to a Mandu policy tool is classified as
 *     that tool: its result reaches the model as the namespaced call's does
 *     (raw), even when a comment in the cell names `.env` (the 2026-10-01
 *     observation: that comment masked the result before, through the
 *     §11.11 scan of the cell's source). An `ALL_TOOLS` listing, bare or
 *     filtered (codex-cli 0.160's tool search, which reached the model
 *     masked in a session with a raw read), reaches the model as it is.
 * (b) The security-invariant oracle: no un-symbolized secret reaches the
 *     model. A cell that reads `.env` through `exec_command`; a cell whose
 *     exec the literal scanner cannot see (`tools["exec_command"]`) in a
 *     session where a listed reader read a secret raw; a third-party MCP
 *     command tool in a cell and as a namespaced call (header and all) in
 *     that session; and a qualifying cell whose tool argument names `.env` —
 *     the canary never appears in the forwarded request.
 *
 * The guard's records are written as the guard writes them
 * (`taintProcessSecret`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const CANARY = "sk-live-CELLCANARY-7f3a9c";
// one value per masked case: a value masked once is a registered secret, and
// the value backstop would then mask a later case by value, not by its rule
const C2 = "sk-live-CELLTWO-1a2b3c", C3 = "psql-row-3b81e0aa", C4 = "psql-row-4c92f1bb", C5 = "psql-row-5da302cc", C6 = "psql-row-6eb413dd";
const POLICY_TEXT = JSON.stringify({ tool: "mandu_policy_read", law: { pendingAskCount: 0, locked: [".env"] } });
const ENVELOPE = "Script completed\nWall time 0.1 seconds\nOutput:\n";
const MCP_HEADER = "Wall time: 0.1 seconds\nOutput:";

/** Tool-search cells as a model writes them on codex-cli 0.160, whose
 *  `exec` description says "To find one, filter `ALL_TOOLS` by `name` and
 *  `description`" (the deferred MCP tools are not listed). */
const FILTERED_LISTINGS = [
  "text(JSON.stringify(ALL_TOOLS.filter(t => /mandu|policy/i.test(t.name + \" \" + t.description))));",
  "const hits = ALL_TOOLS.filter((t) => t.name.toLowerCase().includes(\"mandu\") || (t.description ?? \"\").toLowerCase().includes(\"policy\"));\n" +
    "text(JSON.stringify(hits.map((t) => ({ name: t.name, description: t.description })), null, 2));",
  "text(ALL_TOOLS.filter(t => /policy/.test(`${t.name} ${t.description}`)).map(t => `${t.name}: ${t.description}`).join(\"\\n\"));",
];

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

function cellTurn(callId: string, cell: string, output: string): unknown {
  return {
    model: "gpt-6.1-sol", stream: true, instructions: "You are Codex.",
    input: [
      BATTERY,
      { type: "message", role: "user", content: [{ type: "input_text", text: "set up Mandu for this repo" }] },
      { type: "custom_tool_call", call_id: callId, name: "exec", input: cell },
      { type: "custom_tool_call_output", call_id: callId, output: [{ type: "input_text", text: ENVELOPE }, { type: "input_text", text: output }] },
    ],
  };
}

function fnTurn(callId: string, namespace: string, name: string, args: Record<string, unknown>, output: string): unknown {
  return {
    model: "gpt-6.1-sol", stream: true, instructions: "You are Codex.",
    input: [
      BATTERY,
      { type: "message", role: "user", content: [{ type: "input_text", text: "set up Mandu for this repo" }] },
      { type: "function_call", call_id: callId, namespace, name, arguments: JSON.stringify(args) },
      { type: "function_call_output", call_id: callId, output: [{ type: "input_text", text: MCP_HEADER }, { type: "input_text", text: output }] },
    ],
  };
}

/** The forwarded tool output of the one call in a forwarded body. */
function outputOf(body: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "function_call_output" || i["type"] === "custom_tool_call_output")!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("a policy-tool cell reaches the model as the namespaced call does; no secret reaches it through any cell (secrets axes, real arbiter, production adapter)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-mcp-cell-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const guard = new ArbiterClient(socketPath); await guard.connect(); // what the guard writes
  const real: RealArbiterClient = new ArbiterClient(socketPath); await real.connect();
  const session = `codex-mcp-cell-${process.pid}`;
  const proxy = new OpenAiProxy({ arbiter: new ArbiterClientAdapter(real), upstream: (args) => upstream.fetcher(args), sessionKey: session, log: () => {} });
  let upstream = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const port = await proxy.listen(0);
  const send = async (body: unknown): Promise<string> => {
    upstream = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    assert.equal(res.status, 200, await res.text());
    return upstream.requests[0]!.bodyText;
  };
  try {
    // ── (a) utility: the policy tool's result, both wires ──────────────────
    const fn = await send(fnTurn("call_fn", "mcp__mandu_policy", "mandu_policy_read", {}, POLICY_TEXT));
    assert.equal(outputOf(fn), MCP_HEADER + POLICY_TEXT, "control: the namespaced call's result is forwarded raw");
    for (const cell of [
      "text(await tools.mcp__mandu_policy__mandu_policy_read({}));",
      "const r = await tools.mcp__mandu_policy__mandu_policy_read({});\ntext(r.content[0].text);",
      // the observed shape: the model's own words in the source name `.env`
      "// rg found .env; look up what Mandu protects\nconst r = await tools.mcp__mandu_policy__mandu_policy_read({});\ntext(JSON.stringify(r));",
    ]) {
      const out = outputOf(await send(cellTurn("call_cell", cell, POLICY_TEXT)));
      assert.equal(out, ENVELOPE + POLICY_TEXT, `the cell's result is the tool's, forwarded raw: ${cell}`);
    }
    // control: the same comment in a cell the grammar refuses keeps the
    // fail-closed §11.11 scan of the source (masked by what it names)
    const refused = outputOf(await send(cellTurn("call_alias", "// rg found .env\nconst t = tools; text(await t.mcp__mandu_policy__mandu_policy_read({}));", POLICY_TEXT)));
    assert.ok(!refused.includes(POLICY_TEXT), "a refused cell keeps today's handling");
    // a bare listing reaches the model
    const listing = JSON.stringify([{ name: "mcp__mandu_policy__mandu_policy_read", description: "Read the rules in force" }]);
    assert.equal(outputOf(await send(cellTurn("call_ls", "text(ALL_TOOLS);", listing))), ENVELOPE + listing);

    // ── (b) the oracle: no un-symbolized secret reaches the model ──────────
    const leaks: string[] = [];
    const check = (label: string, body: string, canary = CANARY): void => { if (body.includes(canary)) leaks.push(label); };
    // 1. a cell that reads .env through exec_command (path-derived no-model)
    check("exec_command cat .env", await send(cellTurn("call_env", "const r = await tools.exec_command({\"cmd\":\"cat .env\"});\ntext(r.output);", `API_KEY=${CANARY}\n`)));
    // 2. a qualifying cell whose tool argument names .env (§11.11 on the tool's args)
    check("mcp read_file .env", await send(cellTurn("call_rf", "text(await tools.mcp__fs__read_file({path: \".env\"}));", `API_KEY=${C2}`)), C2);
    // a listed reader read a secret raw in this session (the guard's record)
    await guard.taintProcessSecret({ procKey: "cx-psql-1", path: join(tmp, ".pgpass"), level: "no-model", app: "psql", session });
    // 3. an exec the literal scanner cannot see, so no tree: the session answers
    check("computed exec", await send(cellTurn("call_cx", "text((await tools[\"exec_command\"]({cmd: \"psql -c 'select key from creds'\"})).output);", C3)), C3);
    // 4. a third-party MCP command tool in a qualifying cell (§11.12 under its own name)
    check("mcp run_command cell", await send(cellTurn("call_rc", "text(await tools.mcp__box__run_command({command: \"psql -c 'select key from creds'\"}));", C4)), C4);
    // 5. the same tool as a namespaced call, with codex's real MCP header
    check("mcp run_command namespaced", await send(fnTurn("call_rcfn", "mcp__box", "run_command", { command: "psql -c 'select key from creds'" }, C5)), C5);
    // 6. a listing-shaped cell that also reads a stored value: not a listing
    check("listing with load", await send(cellTurn("call_ld", "text(ALL_TOOLS.filter(t => /policy/.test(t.name)).map(t => load(\"rows\")));", C6)), C6);
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a secret reached the model through these");

    // and the policy cell is still forwarded raw in the tainted session: it
    // runs no command, exactly as the namespaced call
    assert.equal(outputOf(await send(cellTurn("call_cell2", "text(await tools.mcp__mandu_policy__mandu_policy_read({}));", POLICY_TEXT))), ENVELOPE + POLICY_TEXT);
    // codex-cli 0.160 leaves the deferred MCP tools out of the `exec`
    // description and tells the model to "filter ALL_TOOLS by name and
    // description": the search cell is a filtered listing, and in this
    // tainted session it reached the model masked (the 0.160 tour, "the
    // tool-discovery result was hidden from me"). It reads ALL_TOOLS only.
    for (const cell of FILTERED_LISTINGS) {
      assert.equal(outputOf(await send(cellTurn("call_ls2", cell, listing))), ENVELOPE + listing, `a filtered listing reaches the model: ${cell}`);
    }
  } finally {
    await proxy.close();
    guard.close(); real.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
