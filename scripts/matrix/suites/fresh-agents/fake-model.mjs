#!/usr/bin/env node
// fake-model.mjs — a scripted stand-in for the model API, for the fresh-agents
// VM suite (docs/design/testing/os-test-matrix.md §10.14). Standalone on purpose:
// the guest has no checkout, so this file needs nothing but Node.
//
// It sits where api.anthropic.com / api.openai.com would, BEHIND the installed
// Mandu's context proxy (MANDU_UPSTREAM=http://127.0.0.1:<port>):
//
//     real agent ──► mandu anthropic-proxy / openai-proxy ──► fake-model
//
// so every request body it captures is exactly what the privileged model would
// have been given. The script is one agentic turn: the agent's first request
// that advertises the target tool gets a tool call reading --file; the request
// that carries that tool's result gets a closing text turn; anything else (title
// calls, quota probes, warmups) gets a short ACK; Claude Code's auto-mode
// classifier gets an allowing verdict. The suite then greps the
// capture file: the tool result must be there (the agent really ran the tool)
// and the planted canary must not be anywhere in it.
//
// Wire shapes are ported from the checkout's live-test fakes
// (tests/lib/fake-anthropic.ts, fake-responses.ts, and
// interceptors/openai-proxy/test/helpers/mock-upstream.ts buildScriptCellSse
// for codex ≥ 0.154's custom_tool_call `exec` cell).
//
// Usage: node fake-model.mjs --agent claude|opencode|openclaw|codex \
//          --file <abs path to read> --capture <ndjson out> --port-file <path>
//          [--claude-tool Bash]
import http from "node:http";
import { appendFileSync, writeFileSync } from "node:fs";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const AGENT = args.agent;
const FILE = args.file;
const CAPTURE = args.capture;
const DONE_TEXT = "MANDU_FAKE_DONE: the file came back; I only describe its shape.";
if (!AGENT || !FILE || !CAPTURE || !args["port-file"]) {
  console.error("usage: fake-model.mjs --agent <a> --file <path> --capture <file> --port-file <file>");
  process.exit(2);
}

// ── Anthropic Messages ───────────────────────────────────────────────────────
// --claude-tool Bash: Claude Code reads the file with a shell `cat` instead,
// which runs through Mandu's AgentShell exec box (a nested bwrap).
const TOOL = {
  claude: args["claude-tool"] === "Bash" ? { name: "Bash", input: { command: `cat ${FILE}`, description: "Read the file" } } : { name: "Read", input: { file_path: FILE } },
  opencode: { name: "read", input: { filePath: FILE } },
  openclaw: { name: "read", input: { path: FILE } },
};
const msgStart = (id) => ["message_start", { type: "message_start", message: { id, type: "message", role: "assistant", model: "claude-fake-mandu", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } } }];
function anthropicText(text) {
  return [
    msgStart("msg_fake_text"),
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}
function anthropicToolUse(name, input) {
  return [
    msgStart("msg_fake_tool"),
    ["content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_fake_1", name, input: {} } }],
    ["content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(input) } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "tool_use", stop_sequence: null }, usage: { output_tokens: 1 } }],
    ["message_stop", { type: "message_stop" }],
  ];
}
// A non-streaming request (`stream` absent or false) gets the same turn as one
// Message JSON: Claude Code's auto-mode classifier asks without streaming, and
// an SSE answer to it parses as no verdict at all.
function anthropicJson(events) {
  const msg = structuredClone(events[0][1].message);
  for (const [e, d] of events) {
    if (e === "content_block_start") msg.content[d.index] = structuredClone(d.content_block);
    if (e === "content_block_delta" && d.delta.type === "text_delta") msg.content[d.index].text += d.delta.text;
    if (e === "content_block_delta" && d.delta.type === "input_json_delta") msg.content[d.index].input = JSON.parse(d.delta.partial_json);
    if (e === "message_delta") Object.assign(msg, d.delta);
  }
  return msg;
}
// Claude Code's auto-mode classifier. Under Mandu, whose launch sets
// CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1, Claude Code fetches no feature
// flags and starts in permission mode `auto` unless a mode is chosen
// (os-test-matrix.md §10.14.1 item 9; a Mandu since 0.2.0-beta.6 chooses
// `default` for a launch that picks none, supported-agents.md §2). Before an action that needs a permission (a Bash command, even one
// --allowedTools names) it asks the model for a verdict, `<severity>N` with N
// below 50 allowing it, and stops at `</severity>`. Detected by that stop
// sequence, never by prompt text. The scripted verdict allows: the leg tests
// Mandu's gates, and Anthropic's classifier is not under test.
const isClassifier = (j) => Array.isArray(j.stop_sequences) && j.stop_sequences.includes("</severity>");
function anthropicVerdict() {
  const ev = anthropicText("<severity>5");
  ev[4] = ["message_delta", { type: "message_delta", delta: { stop_reason: "stop_sequence", stop_sequence: "</severity>" }, usage: { output_tokens: 1 } }];
  return ev;
}
const hasToolResult = (j) => (j.messages ?? []).some((m) => Array.isArray(m.content) && m.content.some((b) => b?.type === "tool_result"));
const advertises = (j, name) => (j.tools ?? []).some((t) => t?.name === name);

// ── OpenAI Responses (codex) ─────────────────────────────────────────────────
function responsesText(t) {
  const m = { type: "message", id: "msg_f", status: "completed", role: "assistant", content: [{ type: "output_text", text: t, annotations: [] }] };
  return [
    ["response.created", { type: "response.created", response: { id: "r", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { type: "message", id: "msg_f", status: "in_progress", role: "assistant", content: [] } }],
    ["response.content_part.added", { type: "response.content_part.added", item_id: "msg_f", output_index: 0, content_index: 0, part: { type: "output_text", text: "" } }],
    ["response.output_text.delta", { type: "response.output_text.delta", item_id: "msg_f", output_index: 0, content_index: 0, delta: t }],
    ["response.output_text.done", { type: "response.output_text.done", item_id: "msg_f", output_index: 0, content_index: 0, text: t }],
    ["response.content_part.done", { type: "response.content_part.done", item_id: "msg_f", output_index: 0, content_index: 0, part: { type: "output_text", text: t } }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: m }],
    ["response.completed", { type: "response.completed", response: { id: "r", status: "completed", output: [m], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}
// codex ≥ 0.154: the shell is a custom_tool_call `exec` whose input is a JS cell.
function responsesExecCell(cmd) {
  const input = `const r = await tools.exec_command(${JSON.stringify({ cmd, yield_time_ms: 10000, max_output_tokens: 2000 })});\ntext(r.output);`;
  const item = { type: "custom_tool_call", id: "ctc_1", call_id: "call_1", name: "exec", input, status: "completed" };
  return [
    ["response.created", { type: "response.created", response: { id: "r2", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { ...item, input: "", status: undefined } }],
    ["response.custom_tool_call_input.delta", { type: "response.custom_tool_call_input.delta", item_id: "ctc_1", output_index: 0, delta: input }],
    ["response.custom_tool_call_input.done", { type: "response.custom_tool_call_input.done", item_id: "ctc_1", output_index: 0, input }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item }],
    ["response.completed", { type: "response.completed", response: { id: "r2", status: "completed", output: [item], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}
// Older codex: a plain function_call to exec_command.
function responsesFnCall(cmd) {
  const a = JSON.stringify({ cmd });
  const fc = { type: "function_call", id: "fc_1", call_id: "call_1", name: "exec_command", arguments: a, status: "completed" };
  return [
    ["response.created", { type: "response.created", response: { id: "r2", status: "in_progress", output: [] } }],
    ["response.output_item.added", { type: "response.output_item.added", output_index: 0, item: { ...fc, arguments: "" } }],
    ["response.function_call_arguments.delta", { type: "response.function_call_arguments.delta", item_id: "fc_1", output_index: 0, delta: a }],
    ["response.function_call_arguments.done", { type: "response.function_call_arguments.done", item_id: "fc_1", output_index: 0, arguments: a }],
    ["response.output_item.done", { type: "response.output_item.done", output_index: 0, item: fc }],
    ["response.completed", { type: "response.completed", response: { id: "r2", status: "completed", output: [fc], usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } }],
  ];
}
// Match on input[].type, never on body substrings: codex's tool descriptions
// mention "custom_tool_call_output" themselves.
const inputTypes = (j) => new Set((Array.isArray(j.input) ? j.input : []).map((i) => i?.type));
const codexHasResult = (j) => { const t = inputTypes(j); return t.has("custom_tool_call_output") || t.has("function_call_output"); };
const codexHasExecCell = (j) => {
  const all = [...(j.tools ?? []), ...(Array.isArray(j.input) ? j.input.filter((i) => i?.type === "additional_tools").flatMap((i) => i.tools ?? []) : [])];
  const flat = all.flatMap((t) => (t?.type === "namespace" ? [t, ...(t.tools ?? [])] : [t]));
  return { cell: flat.some((t) => t?.name === "exec" && t?.type === "custom"), fn: flat.some((t) => t?.name === "exec_command") };
};

// The text of the LAST tool result in a request, whichever wire: what the
// oracles check for a symbol. Grepping the whole body would be vacuous, since
// Mandu's handling prompt carries example $MDU: tokens of its own.
const partsText = (c) => (typeof c === "string" ? c : Array.isArray(c) ? c.map((p) => (typeof p?.text === "string" ? p.text : "")).join("\n") : "");
function lastToolResult(j) {
  let last = null;
  for (const m of j.messages ?? []) for (const b of Array.isArray(m.content) ? m.content : []) if (b?.type === "tool_result") last = partsText(b.content);
  for (const i of Array.isArray(j.input) ? j.input : []) if (i?.type === "custom_tool_call_output" || i?.type === "function_call_output") last = partsText(i.output);
  return last;
}

// ── server ───────────────────────────────────────────────────────────────────
let toolCallSent = false;
function sse(res, events) {
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  for (const [e, d] of events) res.write(`event: ${e}\ndata: ${JSON.stringify(d)}\n\n`);
  res.end();
}
function decide(url, j) {
  if (url.includes("/v1/messages")) {
    if (isClassifier(j)) return ["classifier", anthropicVerdict()];
    if (hasToolResult(j)) return ["tool-result", anthropicText(DONE_TEXT)];
    const t = TOOL[AGENT];
    if (t && !toolCallSent && advertises(j, t.name)) { toolCallSent = true; return ["tool-call", anthropicToolUse(t.name, t.input)]; }
    return ["ack", anthropicText("ok")];
  }
  if (url.includes("/responses")) {
    if (codexHasResult(j)) return ["tool-result", responsesText(DONE_TEXT)];
    const s = codexHasExecCell(j);
    if (!toolCallSent && (s.cell || s.fn)) {
      toolCallSent = true;
      return ["tool-call", s.cell ? responsesExecCell(`cat ${FILE}`) : responsesFnCall(`cat ${FILE}`)];
    }
    return ["ack", responsesText("ok")];
  }
  return [null, null];
}
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const url = req.url ?? "";
    if (url.includes("count_tokens")) { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"input_tokens":10}'); }
    let j = {};
    try { j = JSON.parse(body || "{}"); } catch { /* not JSON: captured raw, answered as ACK below */ }
    const [kind, events] = req.method === "POST" ? decide(url, j) : [null, null];
    const toolResult = kind === "tool-result" ? lastToolResult(j) : undefined;
    appendFileSync(CAPTURE, JSON.stringify({ t: Date.now(), method: req.method, url, kind, toolResult, body }) + "\n");
    // The Anthropic wire answers a non-streaming request with one Message JSON.
    if (events && url.includes("/v1/messages") && j.stream !== true) {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify(anthropicJson(events)));
    }
    if (events) return sse(res, events);
    // models lists and other GETs: an empty, well-formed answer
    res.writeHead(200, { "content-type": "application/json" });
    res.end(url.includes("/models") ? '{"data":[],"models":[]}' : "{}");
  });
});
server.listen(0, "127.0.0.1", () => {
  writeFileSync(args["port-file"], String(server.address().port));
});
for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => server.close(() => process.exit(0)));
