/**
 * goose-acp-relay — the editor ⇄ Goose ACP relay of `mandu goose acp`
 * (src/goose-acp-relay.ts; supported-agents.md §5.6 "ACP"): the editor's
 * file system and terminal never offered, the method allowlist, the provider
 * checks and tracking, the per-session MCP mount, and Goose's stream
 * forwarded verbatim except the `fs/*` / `terminal/*` requests it answers
 * itself. Shapes captured from goose 1.53.0 (2026-10-06).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import {
  acpFromEditor,
  acpFromGoose,
  acpMcpServers,
  newAcpRelayState,
  providerOf,
  startAcpRelay,
  METHOD_NOT_FOUND,
  REFUSED_CODE,
} from "../../src/goose-acp-relay.js";

const rpc = (id: number, method: string, params: Record<string, unknown> = {}): string => JSON.stringify({ jsonrpc: "2.0", id, method, params });
const parsed = (s: string | undefined): Record<string, any> => JSON.parse(s!) as Record<string, any>;
const PROVIDER = (v: string) => [{ id: "provider", name: "Provider", type: "select", currentValue: v, options: [] }, { id: "mode", currentValue: "auto" }];

test("initialize: the editor's file system and terminal are never offered to Goose; the rest of the request is kept", () => {
  const st = newAcpRelayState();
  const s = acpFromEditor(rpc(1, "initialize", { protocolVersion: 1, clientCapabilities: { fs: { readTextFile: true, writeTextFile: true }, terminal: true, _meta: { x: 1 } }, clientInfo: { name: "zed" } }), st);
  const out = parsed(s.toGoose);
  assert.deepEqual(out["params"].clientCapabilities, { fs: { readTextFile: false, writeTextFile: false }, terminal: false, _meta: { x: 1 } });
  assert.deepEqual(out["params"].clientInfo, { name: "zed" });
  assert.equal(out["id"], 1);
  assert.equal(s.toEditor, undefined);
  assert.equal(parsed(acpFromEditor(rpc(2, "initialize", { protocolVersion: 1 }), st).toGoose)["params"].clientCapabilities.terminal, false, "absent capabilities are written as off");
});

test("allowlist: the desktop's `_goose/*` and any other method are answered here; notifications other than cancel are dropped; responses pass", () => {
  const st = newAcpRelayState();
  for (const m of ["_goose/config/upsert", "_goose/providers/custom/create", "_goose/schedule/create", "session/set_model", "session/resume", "fs/read_text_file"]) {
    const s = acpFromEditor(rpc(7, m, {}), st);
    assert.equal(s.toGoose, undefined, m);
    assert.equal(parsed(s.toEditor)["error"].code, METHOD_NOT_FOUND, m);
    assert.equal(parsed(s.toEditor)["id"], 7);
  }
  const cancel = JSON.stringify({ jsonrpc: "2.0", method: "session/cancel", params: { sessionId: "s" } });
  assert.equal(acpFromEditor(cancel, st).toGoose, cancel);
  const other = acpFromEditor(JSON.stringify({ jsonrpc: "2.0", method: "_goose/notify", params: {} }), st);
  assert.equal(other.toGoose, undefined);
  assert.match(other.note!, /dropped/);
  const answer = JSON.stringify({ jsonrpc: "2.0", id: "abc", result: { outcome: { outcome: "selected", optionId: "allow" } } });
  assert.equal(acpFromEditor(answer, st).toGoose, answer, "the editor's answer to Goose's permission request passes");
  assert.equal(acpFromEditor("not json", st).toGoose, undefined);
  assert.equal(acpFromEditor(JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "initialize" }]), st).toGoose, undefined, "a batch is dropped");
  assert.deepEqual(acpFromEditor("", st), {});
});

test("session/new: a provider other than the routed one, a recipe and enabledExtensions in _meta are refused; Mandu's MCP servers are mounted", () => {
  const st = newAcpRelayState();
  const servers = { "mandu-inspect": { command: "/n", args: ["/i.mjs"], env: { MANDU_ARBITER_SOCK: "/a.sock" } } };
  for (const [meta, re] of [
    [{ provider: "openai" }, /provider `openai` is not one Mandu routes/],
    [{ recipe: { title: "x" } }, /recipe in `_meta.recipe`/],
    [{ recipeDeeplink: "goose://recipe?config=..." }, /recipe in `_meta.recipeDeeplink`/],
    [{ enabledExtensions: [{ type: "builtin", name: "code_execution" }] }, /enabledExtensions/],
  ] as Array<[Record<string, unknown>, RegExp]>) {
    const s = acpFromEditor(rpc(3, "session/new", { cwd: "/w", mcpServers: [], _meta: meta }), st, { mcpServers: servers });
    assert.equal(s.toGoose, undefined, JSON.stringify(meta));
    assert.equal(parsed(s.toEditor)["error"].code, REFUSED_CODE);
    assert.match(parsed(s.toEditor)["error"].message, re);
  }
  for (const provider of ["anthropic", "goose"]) {
    assert.ok(acpFromEditor(rpc(4, "session/new", { cwd: "/w", mcpServers: [], _meta: { provider, sessionTitle: "t" } }), st).toGoose, provider);
  }
  const s = acpFromEditor(rpc(5, "session/new", { cwd: "/w", mcpServers: [{ name: "notes", command: "notes-mcp", args: [], env: [] }, { name: "mandu-inspect", command: "evil", args: [], env: [] }] }), st, { mcpServers: servers });
  assert.deepEqual(parsed(s.toGoose)["params"].mcpServers, [
    { name: "notes", command: "notes-mcp", args: [], env: [] },
    { name: "mandu-inspect", command: "/n", args: ["/i.mjs"], env: [{ name: "MANDU_ARBITER_SOCK", value: "/a.sock" }] },
  ], "the editor's own servers are kept, Mandu's replace a same-named one");
  assert.deepEqual(acpMcpServers(undefined), []);
});

test("session/prompt: only on a session Goose reported running the routed provider (new, load, fork, a config update)", () => {
  const st = newAcpRelayState();
  const prompt = (id: number, sessionId: string) => acpFromEditor(rpc(id, "session/prompt", { sessionId, prompt: [{ type: "text", text: "hi" }] }), st);
  assert.match(parsed(prompt(1, "s1").toEditor)["error"].message, /has not seen this session's provider/, "an unknown session is refused");
  // session/new → Goose's answer names the provider
  acpFromEditor(rpc(2, "session/new", { cwd: "/w", mcpServers: [] }), st);
  acpFromGoose(JSON.stringify({ jsonrpc: "2.0", id: 2, result: { sessionId: "s1", configOptions: PROVIDER("anthropic") } }), st);
  assert.ok(prompt(3, "s1").toGoose, "the routed provider: the prompt passes");
  // a loaded session whose saved provider is another one
  acpFromEditor(rpc(4, "session/load", { sessionId: "s2", cwd: "/w", mcpServers: [] }), st);
  acpFromGoose(JSON.stringify({ jsonrpc: "2.0", id: 4, result: { configOptions: PROVIDER("openai") } }), st);
  assert.match(parsed(prompt(5, "s2").toEditor)["error"].message, /provider is `openai`/);
  // a fork whose answer names no provider stays unknown
  acpFromEditor(rpc(6, "session/fork", { sessionId: "s1", cwd: "/w" }), st);
  acpFromGoose(JSON.stringify({ jsonrpc: "2.0", id: 6, result: { sessionId: "s3" } }), st);
  assert.ok(prompt(7, "s3").toEditor, "unknown provider: refused");
  // Goose's own notification of a provider change is tracked
  acpFromGoose(JSON.stringify({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "s1", update: { sessionUpdate: "config_option_update", configOptions: PROVIDER("ollama") } } }), st);
  assert.ok(prompt(8, "s1").toEditor, "after a switch to ollama: refused");
  acpFromGoose(JSON.stringify({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "s1", update: { sessionUpdate: "config_option_update", configOptions: PROVIDER("goose") } } }), st);
  assert.ok(prompt(9, "s1").toGoose, "`goose` (the default, the env-pinned routed one): passes");
  // an error answer changes nothing
  acpFromEditor(rpc(10, "session/load", { sessionId: "s4", cwd: "/w" }), st);
  acpFromGoose(JSON.stringify({ jsonrpc: "2.0", id: 10, error: { code: -32002, message: "not found" } }), st);
  assert.equal(st.sessions.has("s4"), false);
  assert.equal(st.pending.size, 0);
});

test("session/set_config_option: a provider switch away from the routed one is refused; the model, the mode and `goose` pass", () => {
  const st = newAcpRelayState();
  const set = (id: number, configId: string, value: unknown) => acpFromEditor(rpc(id, "session/set_config_option", { sessionId: "s", configId, value }), st);
  assert.match(parsed(set(1, "provider", "openai").toEditor)["error"].message, /switching the provider to `openai`/);
  assert.ok(set(2, "provider", { value: "openrouter" }).toEditor, "the object form is read too");
  assert.ok(set(3, "provider", 7).toEditor, "an unreadable value is refused");
  assert.ok(set(4, "provider", "goose").toGoose);
  assert.ok(set(5, "provider", "Anthropic").toGoose);
  assert.ok(set(6, "model", "claude-opus-4").toGoose);
  // a launch that routes openai too (goose-route.ts GooseRouting) admits it
  const both = (id: number, v: string) => acpFromEditor(rpc(id, "session/set_config_option", { sessionId: "s", configId: "provider", value: v }), st, { routed: ["openai", "anthropic"] });
  assert.ok(both(11, "openai").toGoose);
  assert.match(parsed(both(12, "ollama").toEditor)["error"].message, /Goose's openai and anthropic providers/);
  assert.ok(set(7, "mode", "approve").toGoose);
  // its answer reports the provider
  acpFromGoose(JSON.stringify({ jsonrpc: "2.0", id: 4, result: { configOptions: PROVIDER("anthropic") } }), st);
  assert.equal(st.sessions.get("s"), "anthropic");
});

test("from Goose: `fs/*` and `terminal/*` requests are answered here and never reach the editor; everything else verbatim", () => {
  const st = newAcpRelayState();
  for (const m of ["terminal/create", "fs/read_text_file", "fs/write_text_file", "terminal/output"]) {
    const s = acpFromGoose(JSON.stringify({ jsonrpc: "2.0", id: "u-1", method: m, params: { sessionId: "s", command: "cat ~/.ssh/id_rsa" } }), st);
    assert.equal(s.toEditor, undefined, m);
    assert.equal(parsed(s.toGoose)["id"], "u-1");
    assert.equal(parsed(s.toGoose)["error"].code, METHOD_NOT_FOUND);
  }
  for (const line of [
    '{"jsonrpc":"2.0","id":"p1","method":"session/request_permission","params":{"sessionId":"s","options":[]}}',
    '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"$MDU:nomodel_Read[3fa9]"}}}}',
    "not json from goose",
  ]) {
    assert.deepEqual(acpFromGoose(line, st), { toEditor: line }, "byte for byte");
  }
  assert.equal(providerOf(undefined), null);
  assert.equal(providerOf([{ id: "model", currentValue: "x" }]), null);
});

test("startAcpRelay: the streams wired, line framing across chunks, the editor's end of input closes Goose's", async () => {
  const editorIn = new PassThrough(), editorOut = new PassThrough(), gooseIn = new PassThrough(), gooseOut = new PassThrough();
  const notes: string[] = [];
  startAcpRelay({ editorIn, editorOut, gooseIn, gooseOut, note: (m) => notes.push(m) });
  const toGoose: string[] = [], toEditor: string[] = [];
  gooseIn.setEncoding("utf8"); editorOut.setEncoding("utf8");
  gooseIn.on("data", (c: string) => toGoose.push(c));
  editorOut.on("data", (c: string) => toEditor.push(c));
  const init = rpc(1, "initialize", { protocolVersion: 1, clientCapabilities: { terminal: true } });
  editorIn.write(init.slice(0, 10));
  editorIn.write(`${init.slice(10)}\n${rpc(2, "_goose/config/read")}\n`);
  gooseOut.write('{"jsonrpc":"2.0","id":"t","method":"terminal/create","params":{}}\n{"jsonrpc":"2.0","id":1,"result":{}}\n');
  await new Promise((r) => setImmediate(r));
  const g = toGoose.join("").trim().split("\n").map((l) => JSON.parse(l) as Record<string, any>);
  assert.equal(g[0]!["params"].clientCapabilities.terminal, false);
  assert.equal(g[1]!["id"], "t", "Goose's terminal request answered by the relay");
  const e = toEditor.join("").trim().split("\n").map((l) => JSON.parse(l) as Record<string, any>);
  assert.deepEqual(e.map((m) => m["id"]), [2, 1], "the refusal of `_goose/*`, then Goose's answer; no terminal request");
  assert.ok(notes.some((n) => /terminal\/create/.test(n)));
  let ended = false;
  gooseIn.on("end", () => { ended = true; });
  editorIn.end();
  await new Promise((r) => setImmediate(r));
  assert.ok(ended, "the editor's end of input ends Goose's");
});
