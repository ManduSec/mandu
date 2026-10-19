/**
 * goose-acp-display.test.ts — `mandu goose acp`'s editor-bound display pass
 * over the PRODUCTION wiring (supported-agents.md §5.6 "Recipes, review and
 * ACP"; launcher/src/goose-acp-display.ts): the real ACP relay
 * (`startAcpRelay`) with the real resolver (`humanPlaneDesymbolizer`, one
 * NDJSON call per string over the human-plane socket) against a real
 * ArbiterServer on the `secrets` axes holding a registered secret.
 *
 *   (a) the editor (the human view) reads the ORIGINAL in every display
 *       field of Goose's messages: the reply text, a tool call's output, a
 *       permission request's command; the line's ids, methods and framing
 *       are Goose's, and a human turn replayed by a load keeps its symbol;
 *   (b) THE INVARIANT on the model's side: nothing the relay writes toward
 *       Goose (the editor's prompt, a permission answer, the relay's own
 *       refusal of an `fs/*` request) is desymbolized: no original goes
 *       toward the model through the relay;
 *   (c) the human plane: given the DATA socket in its place the pass
 *       resolves nothing (the data socket refuses `desymbolize`), so the
 *       editor reads the symbols;
 *   (d) the arbiter gone: every line passes as Goose wrote it, in order
 *       (utility-only, nothing leaks).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { startAcpRelay } from "../../launcher/src/goose-acp-relay.js";
import { humanPlaneDesymbolizer } from "../../launcher/src/goose-acp-display.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // the confidentiality axis mints the secret symbol

const ORIGINAL = "ghp_AcpDisplay0123456789abcdefghijklmnopq";

interface Rig { sock: string; humanSock: string; symbol: string; server: ArbiterServer; dir: string }

async function startRig(): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-acp-display-"));
  const sock = join(dir, "arbiter.sock");
  const humanSock = humanSockIn(dir);
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"), log: () => {} });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  try {
    const r = await client.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: ORIGINAL }] });
    const symbol = r.vars[0]?.twin;
    assert.ok(symbol && symbol.startsWith("$MDU:"), `the token is masked: ${r.vars[0]?.reason}`);
    return { sock, humanSock, symbol, server, dir };
  } finally {
    client.close();
  }
}

/** One relay over PassThrough streams; Goose's lines in, what each side read out. */
async function relayRun(desymbolize: ReturnType<typeof humanPlaneDesymbolizer> | null, symbol: string): Promise<{ toEditor: string[]; toGoose: string; editorLines: Record<string, string> }> {
  const editorIn = new PassThrough(), editorOut = new PassThrough(), gooseIn = new PassThrough(), gooseOut = new PassThrough();
  const relay = startAcpRelay({ editorIn, editorOut, gooseIn, gooseOut, note: () => {}, desymbolize });
  let toEditor = "", toGoose = "";
  editorOut.setEncoding("utf8"); gooseIn.setEncoding("utf8");
  editorOut.on("data", (c: string) => (toEditor += c));
  gooseIn.on("data", (c: string) => (toGoose += c));
  const editorLines = {
    newSession: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "session/new", params: { cwd: "/w", mcpServers: [] } }),
    prompt: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "session/prompt", params: { sessionId: "s", prompt: [{ type: "text", text: `What is ${symbol}?` }] } }),
    permission: JSON.stringify({ jsonrpc: "2.0", id: "perm-1", result: { outcome: { outcome: "selected", optionId: "allow_once" } } }),
  };
  editorIn.write(`${editorLines.newSession}\n`);
  await new Promise((r) => setImmediate(r));
  const update = (u: Record<string, unknown>): string => JSON.stringify({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "s", update: u } });
  gooseOut.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { sessionId: "s", configOptions: [{ id: "provider", currentValue: "anthropic" }] } })}\n`);
  editorIn.write(`${editorLines.prompt}\n`);
  await new Promise((r) => setImmediate(r));
  gooseOut.write([
    update({ sessionUpdate: "user_message_chunk", content: { type: "text", text: `What is ${symbol}?` } }),
    JSON.stringify({ jsonrpc: "2.0", id: "perm-1", method: "session/request_permission", params: { sessionId: "s", toolCall: { toolCallId: "toolu_1", kind: "other", status: "pending", title: `shell · echo ${symbol}`, rawInput: { command: `echo ${symbol}` } }, options: [{ optionId: "allow_once", name: "allow_once", kind: "allow_once" }] } }),
    JSON.stringify({ jsonrpc: "2.0", id: "fs-1", method: "fs/read_text_file", params: { sessionId: "s", path: "/w/.env" } }),
    update({ sessionUpdate: "tool_call_update", toolCallId: "toolu_1", status: "completed", content: [{ type: "content", content: { type: "text", text: `${symbol}\n` } }], rawOutput: { stdout: symbol, exit_code: 0 } }),
    update({ sessionUpdate: "agent_message_chunk", content: { type: "text", text: `The token is ${symbol}.` }, messageId: "m" }),
    JSON.stringify({ jsonrpc: "2.0", id: 2, result: { stopReason: "end_turn" } }),
  ].join("\n") + "\n");
  editorIn.write(`${editorLines.permission}\n`);
  gooseOut.end();
  await relay.drained();
  editorIn.end();
  await new Promise((r) => setImmediate(r));
  return { toEditor: toEditor.trim().split("\n"), toGoose, editorLines };
}

const kinds = (lines: string[]): unknown[] => lines.map((l) => { const m = JSON.parse(l) as Record<string, any>; return m["method"] === "session/update" ? m["params"].update.sessionUpdate : (m["method"] ?? m["id"]); });

test("(a)+(b) the editor reads originals in every display field; nothing toward Goose is desymbolized", async () => {
  const rig = await startRig();
  try {
    const { toEditor, toGoose, editorLines } = await relayRun(humanPlaneDesymbolizer(rig.humanSock), rig.symbol);
    assert.deepEqual(kinds(toEditor), [1, "user_message_chunk", "session/request_permission", "tool_call_update", "agent_message_chunk", 2], "Goose's lines in order; the fs request never reaches the editor");
    const [, user, perm, tool, reply] = toEditor.map((l) => JSON.parse(l) as Record<string, any>);
    assert.equal(reply!["params"].update.content.text, `The token is ${ORIGINAL}.`);
    assert.equal(tool!["params"].update.content[0].content.text, `${ORIGINAL}\n`);
    assert.equal(tool!["params"].update.rawOutput.stdout, ORIGINAL);
    assert.equal(perm!["params"].toolCall.rawInput.command, `echo ${ORIGINAL}`);
    assert.equal(perm!["id"], "perm-1", "Goose's request id kept");
    assert.equal(user!["params"].update.content.text, `What is ${rig.symbol}?`, "a human turn keeps its symbol (an editor may resend it)");
    // (b) the model's side
    assert.ok(toGoose.includes(editorLines.prompt), "the editor's prompt reaches Goose byte for byte");
    assert.ok(toGoose.includes(editorLines.permission), "the permission answer byte for byte");
    assert.ok(toGoose.includes('"id":"fs-1"'), "the relay answered the fs request itself");
    assert.ok(!toGoose.includes(ORIGINAL), "INVARIANT: no original is written toward Goose (the model's side)");
  } finally {
    await rig.server.close();
    rmSync(rig.dir, { recursive: true, force: true });
  }
});

test("(c) the data socket in place of the human plane resolves nothing: the editor reads the symbols", async () => {
  const rig = await startRig();
  try {
    const { toEditor, toGoose } = await relayRun(humanPlaneDesymbolizer(rig.sock), rig.symbol);
    const all = toEditor.join("\n");
    assert.ok(!all.includes(ORIGINAL), "the data socket refuses `desymbolize`");
    assert.ok(all.includes(`The token is ${rig.symbol}.`));
    assert.ok(!toGoose.includes(ORIGINAL));
  } finally {
    await rig.server.close();
    rmSync(rig.dir, { recursive: true, force: true });
  }
});

test("(d) the arbiter gone: every line as Goose wrote it, in order; nothing raw anywhere", async () => {
  const rig = await startRig();
  await rig.server.close();
  try {
    const { toEditor, toGoose } = await relayRun(humanPlaneDesymbolizer(rig.humanSock), rig.symbol);
    assert.deepEqual(kinds(toEditor), [1, "user_message_chunk", "session/request_permission", "tool_call_update", "agent_message_chunk", 2]);
    const all = toEditor.join("\n") + toGoose;
    assert.ok(!all.includes(ORIGINAL));
    assert.ok(toEditor.join("\n").includes(`The token is ${rig.symbol}.`), "the symbol stays (utility-only)");
  } finally {
    rmSync(rig.dir, { recursive: true, force: true });
  }
});
