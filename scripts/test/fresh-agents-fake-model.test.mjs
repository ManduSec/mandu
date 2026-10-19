// fresh-agents-fake-model.test.mjs — the scripted model the fresh-agents VM
// suite puts behind the installed mandu (scripts/matrix/suites/fresh-agents/
// fake-model.mjs; docs/design/testing/os-test-matrix.md §10.14). Its capture file
// IS the suite's oracle, so what it answers and what it records are pinned
// here, per wire: a tool call to the agent's read tool on the first request
// that advertises it, a closing turn on the tool result, an allowing verdict
// to Claude Code's auto-mode classifier, an ACK otherwise (one Message JSON
// when the request does not stream), and
// `toolResult` holding ONLY the tool result's text (the handling prompt's own
// example $MDU: tokens must never satisfy the symbol check).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const FAKE = join(dirname(fileURLToPath(import.meta.url)), "..", "matrix", "suites", "fresh-agents", "fake-model.mjs");

async function withFake(agent, fn, extra = []) {
  const dir = mkdtempSync(join(tmpdir(), "fake-model-test-"));
  const cap = join(dir, "cap.ndjson"), portFile = join(dir, "port");
  const child = spawn(process.execPath, [FAKE, "--agent", agent, "--file", "/home/u/.aws/credentials", "--capture", cap, "--port-file", portFile, ...extra], { stdio: "ignore" });
  try {
    // The port, once the file holds it: the fake writes it in place, so the
    // file can exist empty for a moment (a loaded CI guest read port 0 there).
    const portIn = () => (existsSync(portFile) ? Number(readFileSync(portFile, "utf8")) : 0);
    for (let i = 0; i < 100 && !(portIn() > 0); i++) await new Promise((r) => setTimeout(r, 30));
    const port = portIn();
    assert.ok(port > 0, "the fake model wrote its port");
    const post = async (path, body) => (await fetch(`http://127.0.0.1:${port}${path}`, { method: "POST", body: JSON.stringify(body) })).text();
    const records = () => readFileSync(cap, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    await fn(post, records);
  } finally {
    child.kill(); rmSync(dir, { recursive: true, force: true });
  }
}

const SYSTEM_WITH_EXAMPLE = "Tokens like $MDU:nomodel_Read[3fa9] are opaque.";

test("anthropic wire (claude): Read call once, closing turn on the result, toolResult is the result only", async () => {
  await withFake("claude", async (post, records) => {
    const ack = await post("/v1/messages", { stream: true, system: SYSTEM_WITH_EXAMPLE, messages: [{ role: "user", content: "title?" }] });
    assert.match(ack, /"text":"ok"/, "a request that advertises no Read gets an ACK");
    const call = await post("/v1/messages", { stream: true, system: SYSTEM_WITH_EXAMPLE, tools: [{ name: "Read" }], messages: [{ role: "user", content: "go" }] });
    assert.match(call, /"name":"Read"/);
    assert.match(call, /\\"file_path\\":\\"\/home\/u\/\.aws\/credentials\\"/);
    const again = await post("/v1/messages", { stream: true, tools: [{ name: "Read" }], messages: [{ role: "user", content: "go" }] });
    assert.doesNotMatch(again, /"tool_use"/, "the tool call is issued once");
    await post("/v1/messages", { stream: true, system: SYSTEM_WITH_EXAMPLE, messages: [
      { role: "user", content: "go" },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t", content: [{ type: "text", text: "key = $MDU:nomodel_Read[e865].default.k" }] }] },
    ] });
    const r = records();
    assert.deepEqual(r.map((x) => x.kind), ["ack", "tool-call", "ack", "tool-result"]);
    assert.equal(r[3].toolResult, "key = $MDU:nomodel_Read[e865].default.k");
    assert.equal(r[1].toolResult, undefined);
  });
});

test("anthropic wire: a tool result WITHOUT a symbol yields a symbol-free toolResult even when the prompt has example tokens", async () => {
  await withFake("opencode", async (post, records) => {
    await post("/v1/messages", { stream: true, system: SYSTEM_WITH_EXAMPLE, messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "t", content: "aws_secret_access_key = RAW" }] }] });
    const [rec] = records();
    assert.equal(rec.kind, "tool-result");
    assert.equal(rec.toolResult, "aws_secret_access_key = RAW");
    assert.doesNotMatch(rec.toolResult, /\$MDU:/, "the example token in the system prompt is not the tool result");
  });
});

test("per-agent read tool shapes: opencode read.filePath, openclaw read.path", async () => {
  await withFake("opencode", async (post) => {
    assert.match(await post("/v1/messages", { stream: true, tools: [{ name: "read" }], messages: [] }), /\\"filePath\\"/);
  });
  await withFake("openclaw", async (post) => {
    assert.match(await post("/v1/messages", { stream: true, tools: [{ name: "read" }], messages: [] }), /\\"path\\"/);
  });
});

test("responses wire (codex ≥ 0.154): an exec cell running cat, then the custom_tool_call_output parts as toolResult", async () => {
  await withFake("codex", async (post, records) => {
    const at = { type: "additional_tools", tools: [{ type: "namespace", name: "functions", tools: [{ type: "custom", name: "exec" }] }] };
    const cell = await post("/v1/responses", { input: [at, { type: "message", role: "user", content: [{ type: "input_text", text: "go" }] }] });
    assert.match(cell, /response\.custom_tool_call_input\.done/);
    assert.match(cell, /tools\.exec_command/);
    assert.match(cell, /cat \/home\/u\/\.aws\/credentials/);
    // The tool DESCRIPTIONS mention custom_tool_call_output: structure decides, not substrings.
    await post("/v1/responses", { instructions: "custom_tool_call_output is how results come back", input: [at] });
    await post("/v1/responses", { input: [at, { type: "custom_tool_call_output", call_id: "call_1", output: [{ type: "input_text", text: "Script completed\n" }, { type: "input_text", text: "$MDU:nomodel_exec_command[e7a1]" }] }] });
    const r = records();
    assert.deepEqual(r.map((x) => x.kind), ["tool-call", "ack", "tool-result"]);
    assert.equal(r[2].toolResult, "Script completed\n\n$MDU:nomodel_exec_command[e7a1]");
  });
});

test("responses wire (older codex): a plain function_call to exec_command when no exec cell is offered", async () => {
  await withFake("codex", async (post) => {
    const out = await post("/v1/responses", { tools: [{ type: "function", name: "exec_command" }], input: [] });
    assert.match(out, /"type":"function_call"/);
    assert.match(out, /exec_command/);
  });
});

test("anthropic wire (claude --claude-tool Bash): a Bash `cat` of the file instead of Read, only where Bash is advertised", async () => {
  await withFake("claude", async (post, records) => {
    const noBash = await post("/v1/messages", { stream: true, tools: [{ name: "Read" }], messages: [{ role: "user", content: "go" }] });
    assert.doesNotMatch(noBash, /"tool_use"/, "Read alone is not what this leg asks for");
    const call = await post("/v1/messages", { stream: true, tools: [{ name: "Read" }, { name: "Bash" }], messages: [{ role: "user", content: "go" }] });
    assert.match(call, /"name":"Bash"/);
    assert.match(call, /\\"command\\":\\"cat \/home\/u\/\.aws\/credentials\\"/);
    assert.deepEqual(records().map((x) => x.kind), ["ack", "tool-call"]);
  }, ["--claude-tool", "Bash"]);
});

test("anthropic wire: Claude Code's auto-mode classifier (stop at </severity>) gets an allowing verdict, as JSON when not streaming", async () => {
  // Under Mandu, Claude Code starts in permission mode `auto` and asks this
  // before a Bash command (os-test-matrix.md §10.14.1 item 9). Its request does
  // not stream; an SSE answer, or a text with no <severity>, is no verdict,
  // and the command is denied.
  await withFake("claude", async (post, records) => {
    const classifier = { model: "claude-sonnet-5", max_tokens: 64, stop_sequences: ["</severity>"],
      system: [{ type: "text", text: "You are a security monitor for autonomous AI coding agents." }],
      messages: [{ role: "user", content: [{ type: "text", text: "<transcript>\n{\"Bash\":\"cat /home/u/.aws/credentials\"}\n</transcript>\n" }] }] };
    const verdict = JSON.parse(await post("/v1/messages?beta=true", classifier));
    assert.equal(verdict.type, "message");
    assert.equal(verdict.stop_reason, "stop_sequence");
    assert.equal(verdict.stop_sequence, "</severity>");
    const severity = Number(/^<severity>(\d+)$/.exec(verdict.content[0].text)?.[1]);
    assert.ok(severity < 50, `an allowing verdict (below 50), got ${verdict.content[0].text}`);
    const streamed = await post("/v1/messages", { ...classifier, stream: true });
    assert.match(streamed, /event: message_start/, "a streaming classifier request gets SSE");
    assert.match(streamed, /<severity>5/);
    // A classifier request is never the scripted tool call or its result,
    // even when it advertises the tool or quotes a tool result.
    await post("/v1/messages", { ...classifier, tools: [{ name: "Read" }] });
    const call = await post("/v1/messages", { stream: true, tools: [{ name: "Read" }], messages: [{ role: "user", content: "go" }] });
    assert.match(call, /"name":"Read"/);
    assert.deepEqual(records().map((x) => x.kind), ["classifier", "classifier", "classifier", "tool-call"]);
  });
});

test("anthropic wire: a non-streaming request gets one Message JSON (tool call and text alike)", async () => {
  await withFake("claude", async (post) => {
    const ack = JSON.parse(await post("/v1/messages", { messages: [{ role: "user", content: "title?" }] }));
    assert.deepEqual(ack.content, [{ type: "text", text: "ok" }]);
    assert.equal(ack.stop_reason, "end_turn");
    const call = JSON.parse(await post("/v1/messages", { stream: false, tools: [{ name: "Read" }], messages: [{ role: "user", content: "go" }] }));
    assert.equal(call.stop_reason, "tool_use");
    assert.deepEqual(call.content[0], { type: "tool_use", id: "toolu_fake_1", name: "Read", input: { file_path: "/home/u/.aws/credentials" } });
  });
});
