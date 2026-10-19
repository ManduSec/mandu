import assert from "node:assert/strict";
import { test } from "node:test";
import { StructuredReplyFilter, type StructuredDiagnostic, type StructuredOptions } from "../../src/structured-filter.js";
import { replyOutputFormat, parseReplyInvocation } from "../../src/output-format.js";
const SYM = "$MDU:Read[ab12].result";
const RAW = 'Notes: "quoted" \\ path\nnext\trow\r\n雪 😀';
const resolver = { desymbolize: async (text: string) => text.replaceAll(SYM, RAW) };
const result = (text = SYM): string => JSON.stringify({ type: "result", result: text });
async function filter(input: string, format: "json" | "stream-json" = "stream-json", opts: StructuredOptions = {}): Promise<string> {
  const f = new StructuredReplyFilter(resolver, format, opts);
  return await f.write(input) + await f.flush();
}
test("explicit format selection honors delimiter and known option values", () => {
  for (const format of ["json", "stream-json"] as const) {
    assert.equal(replyOutputFormat(["/bin/claude", "-p", "prompt", "--output-format", format]), format);
    assert.equal(replyOutputFormat(["claude", `--output-format=${format}`, "-p"]), format);
  }
  for (const cmd of [["claude", "-p", "--", "--output-format", "json"], ["claude", "--system-prompt", "--output-format", "json"], ["claude", "--output-format", "text"], ["node", "claude", "--output-format", "json"]]) assert.equal(replyOutputFormat(cmd), "text");
  for (const cmd of [["claude", "--output-format", "yaml"], ["claude", "--output-format"], ["claude", "--output-format", "json", "--output-format=stream-json"]]) assert.equal(replyOutputFormat(cmd), "passthrough");
});
test("optional CLI values never consume the following format option or delimiter", () => {
  for (const flag of ["--cloud", "--debug", "-d", "--from-pr", "--prompt-suggestions", "--remote-control", "--resume", "-r", "--teleport", "--worktree", "-w"]) {
    assert.equal(replyOutputFormat(["claude", flag, "--output-format", "stream-json", "-p", "prompt"]), "stream-json", flag);
    assert.equal(replyOutputFormat(["claude", flag, "session-or-filter", "--output-format=json", "-p"]), "json", flag);
    assert.equal(replyOutputFormat(["claude", flag, "--", "--output-format", "json"]), "text", flag);
    assert.equal(replyOutputFormat(["claude", flag, "-p", "--output-format", "json"]), "json", flag);
  }
  assert.equal(replyOutputFormat(["claude", "--resume=session", "--output-format", "json"]), "json");
});
test("all chunk splits preserve framing, JSON escapes and multiline Unicode originals", async () => {
  const source = ' \t' + result('prefix "\\\n雪 ' + SYM) + '\r\n' + result() + '\n';
  for (let split = 0; split <= source.length; split++) {
    const f = new StructuredReplyFilter(resolver, "stream-json");
    const out = await f.write(source.slice(0, split)) + await f.write(source.slice(split)) + await f.flush();
    const lines = out.trim().split('\n');
    assert.equal(lines.length, 2);
    assert.equal(JSON.parse(lines[0]!).result, 'prefix "\\\n雪 ' + RAW);
    assert.equal(JSON.parse(lines[1]!).result, RAW);
    assert.ok(out.startsWith(' \t') && out.includes('\r\n'));
  }
});
test("only human spans change; metadata, identifiers and numeric bytes are lossless", async () => {
  const source = `{ "type":"assistant", "uuid":"${SYM}", "count":900719925474099312345, "ratio":1.00e+003, "message":{"role":"assistant","id":"${SYM}","content":[{"type":"text","text":"${SYM}","result_symbol":"${SYM}"},{"type":"tool_use","id":"${SYM}","input":{"text":"${SYM}"}},{"type":"thinking","thinking":"${SYM}"}]}, "escaped":"\\u0061" }\r\n`;
  const expected = source.replace(`"text":"${SYM}"`, `"text":${JSON.stringify(RAW)}`);
  assert.equal(await filter(source), expected);
  assert.equal(JSON.parse(expected).message.content[1].input.text, SYM);
});
test("JSON buffers pretty documents/verbose arrays through EOF and preserves unknown members", async () => {
  const records = [{ type: "system", session_id: SYM }, { type: "result", result: SYM, structured_output: { text: SYM }, is_error: false, cost: 0 }];
  const input = '\n' + JSON.stringify(records, null, 2) + '\n';
  const f = new StructuredReplyFilter(resolver, "json");
  assert.equal(await f.write(input), "");
  assert.equal(await f.flush(false), "");
  const out = await f.flush();
  assert.equal(out, input.replace(`"result": "${SYM}"`, `"result": ${JSON.stringify(RAW)}`));
  assert.equal(JSON.parse(out)[1].is_error, false);
  assert.equal(JSON.parse(out)[1].structured_output.text, SYM);
});
test("unknown schemas, partial deltas and mismatched fields pass through", async () => {
  const cases = [
    { type: "user", message: { role: "user", content: [{ type: "text", text: SYM }] } },
    { type: "stream_event", event: { type: "content_block_delta", delta: { type: "text_delta", text: SYM } } },
    { type: "future", result: SYM }, { type: "result", result_symbol: SYM }, { type: "result", result: { text: SYM } },
    { type: "assistant", message: { role: "user", content: [{ type: "text", text: SYM }] } },
    { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: 1 }] } },
    [{ type: "result", result: SYM }],
  ];
  for (const record of cases) { const input = JSON.stringify(record) + '\n'; assert.equal(await filter(input), input); }
});
test("no symbols and unknown symbols preserve original escape spelling with no resolution event", async () => {
  const events: string[] = [];
  for (const input of [result('plain \\ text'), result('$MDU:Read[ffff].unknown'), '{"type":"result","result":"\\u0061"}\n']) {
    assert.equal(await filter(input, "stream-json", { onResolve: (a) => { events.push(a); } }), input);
  }
  assert.deepEqual(events, []);
});
test("malformed, truncated and duplicate-key records pass through then resume at next LF", async () => {
  const malformed = [
    '{"type":"result","result":"' + SYM + '"', '{"type":"result","result":"' + SYM + '",}',
    '{"type":"result","result":"' + SYM + '","result":"second"}',
    '{"type":"result","result":"' + SYM + '","r\\u0065sult":"second"}',
    '{"type":"result","result":"bad\\q' + SYM + '"}',
    '{"type":"result","result":"' + SYM + '","number":01}',
    '{"type":"result","result":"' + SYM + '","bool":truefalse}', result() + ' prose',
  ];
  for (const input of malformed) {
    const diagnostics: StructuredDiagnostic[] = [];
    assert.equal(await filter(input + '\n' + result(), "stream-json", { onDiagnostic: (r) => { diagnostics.push(r); } }), input + '\n' + result(RAW));
    assert.deepEqual(diagnostics, ["malformed-record"]);
  }
});
test("byte limit handles multibyte UTF-8, fragmented oversized records and recovery", async () => {
  const first = result('雪'.repeat(30) + SYM) + '\r\n';
  const diagnostics: StructuredDiagnostic[] = [];
  const f = new StructuredReplyFilter(resolver, "stream-json", { maxRecordBytes: 100, onDiagnostic: (r) => { diagnostics.push(r); } });
  let out = "";
  for (const char of first + result() + '\n') { out += await f.write(char); assert.ok(f.pending <= 100); }
  assert.equal(out + await f.flush(), first + result(RAW) + '\n');
  assert.deepEqual(diagnostics, ["record-limit"]);
});
test("oversized JSON stays passthrough through EOF", async () => {
  const input = result('x'.repeat(200) + SYM) + '\n' + result();
  const f = new StructuredReplyFilter(resolver, "json", { maxRecordBytes: 64 });
  let out = "";
  for (let i = 0; i < input.length; i += 17) out += await f.write(input.slice(i, i + 17));
  assert.equal(out + await f.flush(), input);
});
test("depth, value-count, human-field and output bounds retain originals", async () => {
  const cases = [
    '{"type":"result","result":"' + SYM + '","metadata":' + '['.repeat(65) + '0' + ']'.repeat(65) + '}',
    '{"type":"result","result":"' + SYM + '","metadata":[' + Array(20001).fill('0').join(',') + ']}',
    JSON.stringify({ type: "assistant", message: { role: "assistant", content: Array.from({ length: 129 }, () => ({ type: "text", text: SYM })) } }),
  ];
  for (const input of cases) assert.equal(await filter(input), input);
  assert.equal(await filter(result(), "json", { maxOutputBytes: 30 }), result());
});
test("resolver failure is atomic across fields and diagnostics omit exception content", async () => {
  let calls = 0;
  const diagnostics: StructuredDiagnostic[] = [];
  const input = JSON.stringify({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text: SYM }, { type: "text", text: SYM }] } });
  const f = new StructuredReplyFilter({ desymbolize: async () => { if (++calls === 2) throw new Error('private fixture error'); return RAW; } }, "json", { onDiagnostic: (r) => { diagnostics.push(r); } });
  assert.equal(await f.write(input) + await f.flush(), input);
  assert.deepEqual(diagnostics, ["resolution-failed"]);
});
test("resolver deadlines and observability exceptions preserve output", async () => {
  const f = new StructuredReplyFilter({ desymbolize: () => new Promise(() => {}) }, "json", { resolutionTimeoutMs: 5 });
  assert.equal(await f.write(result()) + await f.flush(), result());
  assert.equal(await filter(result(), "json", { onResolve: () => { throw new Error(); } }), result(RAW));
});
test("resolution events retain complete valid serialized before/after records", async () => {
  const events: [string, string][] = [];
  const source = result() + '\r\n';
  const output = await filter(source, "stream-json", { onResolve: (a, b) => { events.push([a, b]); } });
  assert.deepEqual(events, [[source, output]]);
  assert.equal(JSON.parse(events[0]![0]).result, SYM);
  assert.equal(JSON.parse(events[0]![1]).result, RAW);
});


test("launcher format is consumed before delimiter and cannot enter child argv", () => {
  assert.deepEqual(parseReplyInvocation(["--mandu-output-format=stream-json", "--", "supervisor", "--", "claude"]), { cmd: ["supervisor", "--", "claude"], outputFormat: "stream-json" });
  assert.deepEqual(parseReplyInvocation(["--mandu-output-format=unknown", "--", "supervisor"]), { cmd: ["supervisor"], outputFormat: "passthrough" });
  assert.deepEqual(parseReplyInvocation(["--", "claude", "--mandu-output-format=json"]), { cmd: ["claude", "--mandu-output-format=json"] });
  assert.deepEqual(parseReplyInvocation(["claude", "-p"]), { cmd: ["claude", "-p"] });
});
