/**
 * goose-acp-display — the editor-bound display pass of `mandu goose acp`
 * (src/goose-acp-display.ts; supported-agents.md §5.6 "Recipes, review and
 * ACP"): the human-display strings of Goose's messages desymbolized, every
 * other byte of the line kept, the framing and escaping intact, the order
 * kept, any failure a passthrough, and nothing toward Goose touched. Shapes
 * captured from goose 1.53.0 (2026-10-07).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import {
  AcpEditorWriter,
  acpDisplayStrings,
  desymbolizeAcpLine,
  humanPlaneDesymbolizer,
  BACKOFF_MS,
  type Desymbolize,
} from "../../src/goose-acp-display.js";
import { startAcpRelay } from "../../src/goose-acp-relay.js";
import { parse } from "../../src/parse.js";
import { testRuntimeDir } from "../lib/test-runtime.js";

const SYM = "$MDU:nomodel_file[abc123]";
const ORIGINAL = "sk-live-ORIGINAL-9931";
/** The arbiter's deep desymbolize, mocked: known tokens → originals,
 *  unknown ones stay literal. Records every text it was asked. */
function mock(values: Record<string, string> = { [SYM]: ORIGINAL }): Desymbolize & { asked: string[] } {
  const asked: string[] = [];
  const f = (async (text: string) => {
    asked.push(text);
    return text.replace(/\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/g, (m) => values[m] ?? m);
  }) as Desymbolize & { asked: string[] };
  f.asked = asked;
  return f;
}
const update = (u: Record<string, unknown>): string => JSON.stringify({ jsonrpc: "2.0", method: "session/update", params: { sessionId: "20261007_1", update: u } });
const lineOf = (s: string): Record<string, any> => JSON.parse(s) as Record<string, any>;

test("agent_message_chunk / agent_thought_chunk: the text resolves; the line keeps every other byte, its ids and its method", async () => {
  for (const kind of ["agent_message_chunk", "agent_thought_chunk"]) {
    const line = update({ sessionUpdate: kind, content: { type: "text", text: `Done: ${SYM}.` }, messageId: "m", _meta: { goose: { created: 1791359439, messageId: SYM } } });
    const out = await desymbolizeAcpLine(line, mock());
    assert.equal(lineOf(out).params.update.content.text, `Done: ${ORIGINAL}.`, kind);
    assert.equal(lineOf(out).params.update._meta.goose.messageId, SYM, "_meta is not display text");
    // only the one span changed: every other byte as Goose wrote it
    assert.equal(out, line.replace(`"Done: ${SYM}."`, `"Done: ${ORIGINAL}."`));
  }
});

test("tool_call / tool_call_update: title, content text, diff, rawInput / rawOutput strings, Goose's live output; locations, ids and keys untouched", async () => {
  const call = update({ sessionUpdate: "tool_call", toolCallId: SYM, title: `shell · cat ${SYM}`, rawInput: { command: `echo ${SYM}`, nested: [{ v: SYM }, 3, true, null] }, locations: [{ path: `/w/${SYM}`, line: 1 }] });
  const c = lineOf(await desymbolizeAcpLine(call, mock())).params.update;
  assert.equal(c.title, `shell · cat ${ORIGINAL}`);
  assert.deepEqual(c.rawInput, { command: `echo ${ORIGINAL}`, nested: [{ v: ORIGINAL }, 3, true, null] });
  assert.equal(c.toolCallId, SYM, "an id is not display text");
  assert.equal(c.locations[0].path, `/w/${SYM}`, "a path is not display text");
  const upd = update({
    sessionUpdate: "tool_call_update", toolCallId: "toolu_1", status: "completed",
    content: [{ type: "content", content: { type: "text", text: `token=${SYM}` } }, { type: "diff", path: `/w/${SYM}`, oldText: "a", newText: `b ${SYM}` }, { type: "terminal", terminalId: SYM }],
    rawOutput: { stdout: `token=${SYM}`, stderr: "", exit_code: 0 },
    _meta: { toolNotification: { type: "live_output", params: { sequence: 1, chunks: [{ stream: "stdout", output: `token=${SYM}\n` }], truncated: false } } },
  });
  const u = lineOf(await desymbolizeAcpLine(upd, mock())).params.update;
  assert.equal(u.content[0].content.text, `token=${ORIGINAL}`);
  assert.equal(u.content[1].newText, `b ${ORIGINAL}`);
  assert.equal(u.content[1].path, `/w/${SYM}`);
  assert.equal(u.content[2].terminalId, SYM);
  assert.equal(u.rawOutput.stdout, `token=${ORIGINAL}`);
  assert.equal(u.rawOutput.exit_code, 0);
  assert.equal(u._meta.toolNotification.params.chunks[0].output, `token=${ORIGINAL}\n`);
  assert.equal(u._meta.toolNotification.params.chunks[0].stream, "stdout");
});

test("plan entries, session titles, a permission request's tool call and session/list's titles resolve; resource blocks too", async () => {
  const plan = lineOf(await desymbolizeAcpLine(update({ sessionUpdate: "plan", entries: [{ content: `rotate ${SYM}`, priority: "high", status: "pending" }] }), mock()));
  assert.equal(plan.params.update.entries[0].content, `rotate ${ORIGINAL}`);
  const info = lineOf(await desymbolizeAcpLine(update({ sessionUpdate: "session_info_update", title: `Title ${SYM}` }), mock()));
  assert.equal(info.params.update.title, `Title ${ORIGINAL}`);
  const perm = JSON.stringify({ jsonrpc: "2.0", id: "bde80d0c", method: "session/request_permission", params: { sessionId: "s", toolCall: { toolCallId: "toolu_1", kind: "other", status: "pending", title: `shell · cat ${SYM}`, rawInput: { command: `cat ${SYM}` } }, options: [{ optionId: "allow_once", name: SYM, kind: "allow_once" }] } });
  const p = lineOf(await desymbolizeAcpLine(perm, mock()));
  assert.equal(p.id, "bde80d0c");
  assert.equal(p.params.toolCall.rawInput.command, `cat ${ORIGINAL}`);
  assert.equal(p.params.options[0].name, SYM, "an option is Goose's own, not display text from the model");
  const list = JSON.stringify({ jsonrpc: "2.0", id: 4, result: { sessions: [{ sessionId: "s", cwd: "/w", title: `Title ${SYM}` }] } });
  assert.equal(lineOf(await desymbolizeAcpLine(list, mock(), { answers: "session/list" })).result.sessions[0].title, `Title ${ORIGINAL}`);
  assert.equal(await desymbolizeAcpLine(list, mock()), list, "an answer the relay cannot place is left alone");
  const res = lineOf(await desymbolizeAcpLine(update({ sessionUpdate: "agent_message_chunk", content: { type: "resource", resource: { uri: `file:///${SYM}`, text: `x ${SYM}` } } }), mock()));
  assert.equal(res.params.update.content.resource.text, `x ${ORIGINAL}`);
  assert.equal(res.params.update.content.resource.uri, `file:///${SYM}`);
});

test("user_message_chunk (a load replays the human's turns), unknown updates, responses and errors stay as Goose wrote them", async () => {
  const lines = [
    update({ sessionUpdate: "user_message_chunk", content: { type: "text", text: `Read notes ${SYM}` } }),
    update({ sessionUpdate: "available_commands_update", availableCommands: [{ name: "x", description: SYM }] }),
    update({ sessionUpdate: "config_option_update", configOptions: [{ id: "provider", currentValue: SYM }] }),
    JSON.stringify({ jsonrpc: "2.0", id: 3, result: { stopReason: "end_turn", note: SYM } }),
    JSON.stringify({ jsonrpc: "2.0", id: 3, error: { code: -1, message: SYM } }),
  ];
  for (const l of lines) {
    const d = mock();
    assert.equal(await desymbolizeAcpLine(l, d), l);
    assert.deepEqual(d.asked, [], "nothing asked of the arbiter");
  }
});

test("escapes and unicode: the resolved value is re-escaped, the line stays one line, the bytes around the span are kept", async () => {
  const value = 'multi\nline "quoted" \\back\\ tab\t é 漢字 🔑   end';
  const text = `pre "q" \\ é 漢字 🔑 ${SYM} post\n`;
  const line = update({ sessionUpdate: "agent_message_chunk", content: { type: "text", text } });
  const out = await desymbolizeAcpLine(line, mock({ [SYM]: value }));
  assert.ok(!out.includes("\n"), "the framing: one line");
  assert.equal(lineOf(out).params.update.content.text, `pre "q" \\ é 漢字 🔑 ${value} post\n`);
  // A line Goose wrote with \u escapes keeps them outside the patched span.
  const escaped = `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"\\u0073","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"\\u00e9 ${SYM}"}}}}`;
  const o2 = await desymbolizeAcpLine(escaped, mock());
  assert.ok(o2.startsWith(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"\\u0073"`), o2);
  assert.equal(lineOf(o2).params.update.content.text, `é ${ORIGINAL}`);
  // A Markdown-escaped token (a model repeating it) resolves too.
  const md = update({ sessionUpdate: "agent_message_chunk", content: { type: "text", text: "key: \\$MDU:nomodel\\_file[abc123]" } });
  assert.equal(lineOf(await desymbolizeAcpLine(md, mock())).params.update.content.text, `key: ${ORIGINAL}`);
  // An unknown symbol stays exactly as written (no unescape leaks into the line).
  const unknown = update({ sessionUpdate: "agent_message_chunk", content: { type: "text", text: "\\$MDU:other\\_x[ffff]" } });
  assert.equal(await desymbolizeAcpLine(unknown, mock()), unknown);
});

test("failure is a passthrough: no resolver, a refusal, a non-string answer, a deadline, a malformed or duplicate-key line", async () => {
  const line = update({ sessionUpdate: "agent_message_chunk", content: { type: "text", text: SYM } });
  assert.equal(await desymbolizeAcpLine(line, null), line);
  const diags: string[] = [];
  assert.equal(await desymbolizeAcpLine(line, async () => { throw new Error("refused on the data plane"); }, { onDiagnostic: (d) => diags.push(d) }), line);
  assert.equal(await desymbolizeAcpLine(line, async () => 42 as unknown as string, { onDiagnostic: (d) => diags.push(d) }), line);
  assert.equal(await desymbolizeAcpLine(line, () => new Promise<string>(() => {}), { deadlineMs: 20, onDiagnostic: (d) => diags.push(d) }), line);
  const bad = `${line.slice(0, -1)}`;
  assert.equal(await desymbolizeAcpLine(bad, mock(), { onDiagnostic: (d) => diags.push(d) }), bad);
  const dup = `{"method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"${SYM}","text":"x"}}}}`;
  assert.equal(await desymbolizeAcpLine(dup, mock(), { onDiagnostic: (d) => diags.push(d) }), dup);
  assert.deepEqual(diags, ["failed", "failed", "deadline", "malformed", "malformed"]);
  assert.deepEqual(acpDisplayStrings("not json"), null);
  assert.deepEqual(acpDisplayStrings(update({ sessionUpdate: "plan", entries: [{ content: "a" }, { content: 1 }] })), ["a"]);
});

test("AcpEditorWriter: the order is kept behind a slow resolution; a missed deadline backs off for a while and says so once", async () => {
  const out: string[] = [];
  const notes: string[] = [];
  let release!: () => void;
  const slow = new Promise<void>((r) => { release = r; });
  let t = 1_000;
  let calls = 0;
  const desym: Desymbolize = async (text) => { calls++; if (calls === 1) await slow; return text.replace(SYM, ORIGINAL); };
  const w = new AcpEditorWriter((l) => out.push(l), desym, (m) => notes.push(m), () => t, 50);
  const a = update({ sessionUpdate: "agent_message_chunk", content: { type: "text", text: SYM } });
  w.push(a);
  w.push('{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}');
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(out.length, 2, "the deadline passed: both written");
  assert.equal(out[0], a, "the slow line passed unresolved");
  assert.equal(lineOf(out[1]!).id, 3, "in order");
  release();
  // backing off: the next symbol line is not even asked
  w.push(a);
  await w.drained();
  assert.equal(out[2], a);
  assert.equal(calls, 1);
  t += BACKOFF_MS + 1;
  w.push(a);
  w.push(a, undefined, false);
  await w.drained();
  assert.equal(lineOf(out[3]!).params.update.content.text, ORIGINAL, "asked again after the back-off");
  assert.equal(out[4], a, "resolve=false writes the line as it is");
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /shows the `\$MDU:` symbol instead/);
});

test("startAcpRelay: Goose's lines resolve for the editor (split across chunks, in order); nothing toward Goose is ever desymbolized", async () => {
  const editorIn = new PassThrough(), editorOut = new PassThrough(), gooseIn = new PassThrough(), gooseOut = new PassThrough();
  const d = mock();
  const relay = startAcpRelay({ editorIn, editorOut, gooseIn, gooseOut, note: () => {}, desymbolize: d });
  const toGoose: string[] = [], toEditor: string[] = [];
  gooseIn.setEncoding("utf8"); editorOut.setEncoding("utf8");
  gooseIn.on("data", (c: string) => toGoose.push(c));
  editorOut.on("data", (c: string) => toEditor.push(c));
  // The editor sends a prompt carrying a symbol, a list, and a refused method.
  const prompt = JSON.stringify({ jsonrpc: "2.0", id: 9, method: "session/prompt", params: { sessionId: "s", prompt: [{ type: "text", text: `about ${SYM}` }] } });
  editorIn.write(`${JSON.stringify({ jsonrpc: "2.0", id: 6, method: "session/new", params: { cwd: "/w", mcpServers: [] } })}\n${JSON.stringify({ jsonrpc: "2.0", id: 7, method: "session/list", params: {} })}\n${JSON.stringify({ jsonrpc: "2.0", id: 8, method: "_goose/x", params: { v: SYM } })}\n`);
  await new Promise((r) => setImmediate(r));
  // Goose: the session (on the routed provider), a chunk split mid-token,
  // the list's answer, an fs request.
  gooseOut.write(`${JSON.stringify({ jsonrpc: "2.0", id: 6, result: { sessionId: "s", configOptions: [{ id: "provider", currentValue: "anthropic" }] } })}\n`);
  const chunk = update({ sessionUpdate: "agent_message_chunk", content: { type: "text", text: `Done: ${SYM}` } });
  const cut = chunk.indexOf("abc1");
  gooseOut.write(chunk.slice(0, cut));
  gooseOut.write(`${chunk.slice(cut)}\n{"jsonrpc":"2.0","id":7,"result":{"sessions":[{"sessionId":"s","title":"T ${SYM}"}]}}\n`);
  gooseOut.write(`{"jsonrpc":"2.0","id":"f1","method":"fs/read_text_file","params":{"path":"${SYM}"}}\n`);
  await new Promise((r) => setImmediate(r));
  editorIn.write(`${prompt}\n`);
  // The editor answers a permission request: passes as it is.
  const answer = JSON.stringify({ jsonrpc: "2.0", id: "p1", result: { outcome: { outcome: "selected", optionId: "allow_once" }, _meta: { note: SYM } } });
  editorIn.write(`${answer}\n`);
  gooseOut.end();
  await relay.drained();
  await new Promise((r) => setImmediate(r));
  const e = toEditor.join("").trim().split("\n").map((l) => lineOf(l));
  assert.deepEqual(e.map((m) => m["id"] ?? m["method"]), [8, 6, "session/update", 7], "the refusal, then Goose's lines in order; no fs request");
  assert.equal(e[2]!["params"].update.content.text, `Done: ${ORIGINAL}`, "split across chunks, resolved");
  assert.equal(e[3]!["result"].sessions[0].title, `T ${ORIGINAL}`, "session/list's titles");
  assert.ok(JSON.stringify(e[0]).includes("_goose/x"), "the relay's refusal is its own text");
  const g = toGoose.join("");
  assert.ok(g.includes(prompt), "the editor's prompt reaches Goose byte for byte, its symbol a symbol");
  assert.ok(g.includes(answer), "the permission answer byte for byte");
  assert.ok(!g.includes(ORIGINAL), "no original ever goes toward Goose");
  assert.ok(d.asked.every((t) => !t.includes("about ")), "the editor's lines are never sent to desymbolize");
});

test("humanPlaneDesymbolizer: the `desymbolize` op on the socket it was given, its `text` answer; a bad answer throws", async () => {
  const seen: Array<[string, string, Record<string, unknown>]> = [];
  const call = (async (sock: string, op: string, args: Record<string, unknown>) => { seen.push([sock, op, args]); return { text: "orig" }; }) as never;
  assert.equal(await humanPlaneDesymbolizer("/run/h.sock", call)(SYM), "orig");
  assert.deepEqual(seen, [["/run/h.sock", "desymbolize", { text: SYM }]]);
  const bad = (async () => ({})) as never;
  await assert.rejects(() => humanPlaneDesymbolizer("/run/h.sock", bad)(SYM));
});

test("parse: `goose acp` turns the byte-stream filter off and the display pass on; the reply filter's switch turns both off", () => {
  const ENV = { HOME: "/home/u", XDG_RUNTIME_DIR: testRuntimeDir() }; // a private dir, never another account's /run/user/<uid> (test-organization.md §8.7)
  assert.equal(parse(["goose", "acp"], ENV).acpDisplay, true);
  assert.equal(parse(["goose", "acp"], ENV).replyFilter, false);
  assert.equal(parse(["--no-reply-filter", "goose", "acp"], ENV).acpDisplay, false);
  assert.equal(parse(["goose", "acp"], { ...ENV, MANDU_REPLY_FILTER: "0" }).acpDisplay, false);
  assert.equal(parse(["goose", "session"], ENV).acpDisplay, undefined);
});
