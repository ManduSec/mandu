/**
 * codex-cell-resource-tools — plan 10 §11.18, a cell's resource tools
 * (2026-10-11), over the REAL components: the real ArbiterServer in
 * `secrets` (a policy file labels `.pgpass`, registered as the launcher
 * registers a labelled file at launch), the real openai-proxy over HTTP in
 * its PRODUCTION wiring (`new ArbiterClientAdapter(new ArbiterClient(sock),
 * new ArbiterClient(human))`), only the model upstream canned.
 *
 * codex-cli 0.162's code mode declares `read_mcp_resource`,
 * `list_mcp_resources` and `list_mcp_resource_templates` as nested tools of
 * every `exec` cell, even with no MCP server configured. The wire below is
 * what codex 0.162.0 sent, read off a recording Responses server with a
 * stdio MCP server serving `.pgpass` as a text resource and as a base64
 * `blob` (each cell's output: the runtime's envelope, then the cell's text).
 * The direct call is masked whole (§11.18); a cell calling one had only the
 * cell rule, so in a session where nothing read a secret raw:
 *
 *   - the text read was caught by the value backstop alone (a registered
 *     file's line, verbatim): the control;
 *   - the blob read (the registered secret, base64) reached the model RAW:
 *     no value fingerprint matches base64. A server the guard does not run
 *     (a remote server, a connector, or any server under the `gated`
 *     posture) can hold such a copy;
 *   - the listing and the template listing (a server's own text) were raw;
 *   - a cell reaching the tool by a computed name, and a `store` / `load`
 *     pair (the reading cell prints nothing; the next cell prints the stored
 *     value), were raw.
 *
 * Now each is masked whole, as the direct call is, with the note naming the
 * tool and `mapped_tools:`; a cell that names no resource tool keeps the
 * cell rule (raw in a clean session). Red with the cell's resource asks
 * removed (`withResourceTools` in rewrite-request.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { MockUpstream } from "../../interceptors/openai-proxy/test/helpers/mock-upstream.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const PGPASS = `db.internal:5432:*:app:Pg-${process.pid}-c3e1a9f4`;
const BLOB = Buffer.from(`${PGPASS}\n`).toString("base64");
const LISTED = "res-listed-name-7d2e90";
const ENVELOPE = "Script completed\nWall time 0.0 seconds\nOutput:\n";
/** codex 0.162's `exec` description, as far as the proxy reads it. */
const BATTERY = {
  type: "additional_tools", role: "developer",
  tools: [{
    type: "namespace", name: "functions",
    tools: [
      { type: "custom", name: "exec", description: "Run JavaScript code to orchestrate/compose tool calls\n- Evaluates the provided JavaScript code in a fresh V8 isolate as an async module.\n- All nested tools are available on the global `tools` object, for example `await tools.exec_command(...)`." },
      { type: "function", name: "wait" },
    ],
  }],
};
/** A resource read's result as the cell printed it (`text(JSON.stringify(r))`
 *  of codex's string result: a JSON string of the JSON). */
const printed = (o: unknown): string => JSON.stringify(JSON.stringify(o));
const TEXT_READ = printed({ server: "res", uri: "res://pg", contents: [{ uri: "res://pg", mimeType: "text/plain", text: `${PGPASS}\n` }] });
const BLOB_READ = printed({ server: "res", uri: "res://pg-blob", contents: [{ uri: "res://pg-blob", mimeType: "application/octet-stream", blob: BLOB }] });
const LIST = printed({ resources: [{ server: "res", uri: "res://pg", name: LISTED, mimeType: "text/plain" }] });
const TEMPLATES = printed({ resourceTemplates: [{ server: "res", uriTemplate: "res://file/{name}", name: LISTED }] });

const CELLS: Array<{ id: string; src: string; out: string; leaks: string[] }> = [
  { id: "c_text", src: 'text(JSON.stringify(await tools.read_mcp_resource({server: "res", uri: "res://pg"})))', out: TEXT_READ, leaks: [PGPASS] },
  { id: "c_blob", src: 'text(JSON.stringify(await tools.read_mcp_resource({server: "res", uri: "res://pg-blob"})))', out: BLOB_READ, leaks: [BLOB, PGPASS] },
  { id: "c_list", src: "text(JSON.stringify(await tools.list_mcp_resources({})))", out: LIST, leaks: [LISTED] },
  { id: "c_tpl", src: "text(JSON.stringify(await tools.list_mcp_resource_templates({})))", out: TEMPLATES, leaks: [LISTED] },
  { id: "c_dyn", src: 'const n = ["read", "mcp", "resource"].join("_");\ntext(JSON.stringify(await tools[n]({server: "res", uri: "res://pg-blob"})))', out: BLOB_READ, leaks: [BLOB] },
  { id: "c_store", src: 'const r = JSON.parse(await tools.read_mcp_resource({server: "res", uri: "res://pg-blob"}));\nstore("k", r.contents[0].blob);\ntext("stored")', out: "stored", leaks: [] },
  { id: "c_load", src: 'text(load("k"))', out: BLOB, leaks: [BLOB] },
];

function turn(...items: unknown[]): unknown {
  return {
    model: "gpt-6.1-sol", stream: true, instructions: "You are Codex.",
    input: [BATTERY, { type: "message", role: "user", content: [{ type: "input_text", text: "read the resources" }] }, ...items],
  };
}
const cellItems = (id: string, src: string, out: string) => [
  { type: "custom_tool_call", call_id: id, name: "exec", input: src },
  { type: "custom_tool_call_output", call_id: id, output: [{ type: "input_text", text: ENVELOPE }, { type: "input_text", text: out }] },
];
function outputIn(body: string, id: string): string {
  const item = (JSON.parse(body).input as Array<Record<string, unknown>>).find((i) => i["type"] === "custom_tool_call_output" && i["call_id"] === id)!;
  const o = item["output"];
  return typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join("");
}

test("a code-mode cell calling an MCP resource tool reaches the model masked whole, as the direct call does, in a session that read nothing (secrets axes, real arbiter, production adapter)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cell-res-"));
  const pgpass = join(tmp, ".pgpass");
  writeFileSync(pgpass, `${PGPASS}\n`, { mode: 0o600 });
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${pgpass}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {},
    confidentiality: true, integrity: false, // the `secrets` mode axes, stated
  });
  await server.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const session = `cell-res-${process.pid}`;
  const reg = await (await open(sock)).registerSecret({ path: pgpass, sessionKey: session });
  assert.ok(reg.symbol, `the labelled file is registered, as at launch: ${reg.reason}`);
  let upstream = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
  const proxy = new OpenAiProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(human)), upstream: (a) => upstream.fetcher(a), sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const send = async (body: unknown): Promise<string> => {
    upstream = new MockUpstream({ sse: "event: response.completed\ndata: {}\n\n" });
    const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, { method: "POST", headers: { "content-type": "application/json", "x-mandu-session-id": session }, body: JSON.stringify(body) });
    assert.equal(res.status, 200, await res.text());
    return upstream.requests[0]!.bodyText;
  };
  try {
    // controls first, before any masked result registers a value: a cell
    // that names no resource tool keeps the cell rule (raw in a session that
    // read nothing), and so does an identified exec cell
    const loop = await send(turn(...cellItems("c_loop", 'for (const f of ["src"]) { const r = await tools.exec_command({cmd: `ls ${f}`}); text(r.output.trim()); }', "index.ts")));
    assert.ok(outputIn(loop, "c_loop").includes("index.ts"), "a cell that names no resource tool reaches the model as before");
    const exact = await send(turn(...cellItems("c_exact", 'const r = await tools.exec_command({"cmd":"ls"});\ntext(r.output);\n', "README.md")));
    assert.ok(outputIn(exact, "c_exact").includes("README.md"), "an identified cell reaches the model as before");

    // the oracle, one request per cell (the order a model would go in)
    const leaks: string[] = [];
    const unnoted: string[] = [];
    let history: unknown[] = [];
    for (const c of CELLS) {
      history = [...history, ...cellItems(c.id, c.src, c.out)];
      const body = await send(turn(...history));
      for (const l of c.leaks) if (body.includes(l)) leaks.push(`${c.id}: ${l === BLOB ? "the base64 blob" : l === PGPASS ? "the .pgpass line" : "the listed name"}`);
      if (!/this cell .*mapped_tools/.test(outputIn(body, c.id))) unnoted.push(c.id);
    }
    // MASTER (before 2026-10-11): c_blob, c_list, c_tpl, c_dyn and c_load leaked
    assert.deepEqual(leaks, [], "CONFIDENTIALITY VIOLATION: a cell carried an MCP resource to the model raw");
    assert.deepEqual(unnoted, [], "each is masked with the note naming the tool and the way out");
    assert.match(outputIn(await send(turn(...history)), "c_text"), /this cell calls read_mcp_resource/);
  } finally {
    await proxy.close();
    for (const c of clients) c.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
