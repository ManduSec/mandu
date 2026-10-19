/**
 * reply-media-route (proxy e2e) — the `MEDIA:` reply gate (reply-media.ts;
 * supported-agents.md §2.1, "Files named in the reply") on every response
 * route of the REAL AnthropicProxy, over a mock arbiter: the Messages SSE
 * and JSON answers, and an OpenClaw provider routed through the OpenAI wire
 * (Chat Completions SSE, Responses SSE and JSON). In an OpenClaw session a
 * held file's line reaches the agent as a notice, asked as tool `MEDIA` with
 * no host, with an `fs_action` deny event; a clean one passes untouched; a
 * session whose agent attaches nothing its reply names (Claude Code) is not
 * read. The real-arbiter oracle is tests/stack/openclaw-media-lines.test.ts.
 *
 * Axes: `secrets`, stated through the mock arbiter's upload answers.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import type { GateSurface } from "../../src/gate-surface.js";
import type { FileUploadDecisionRequest } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream, buildTextSse } from "../helpers/mock-upstream.js";

type Json = Record<string, unknown>;

const SECRET = "/home/u/proj/.env";
const BASE: Omit<GateSurface, "spec"> = {
  exec: { exec: "command" }, execOutput: { exec: "command" }, net: {}, paths: {},
  dispatch: {}, refuse: {}, refuseArgs: {}, stdin: {}, patch: {}, upload: {},
};
const OPENCLAW: GateSurface = { spec: "openclaw-agent", ...BASE, replyMedia: "openclaw-media-lines", relativeBase: "launch" };
const CLAUDE: GateSurface = { spec: "claude-code", ...BASE, replyMedia: null };

function send(port: number, path: string, body: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "x-mandu-session-id": "s-1", "content-length": String(data.length) } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

async function withProxy(
  surface: GateSurface,
  up: MockUpstream,
  fn: (port: number, arbiter: MockArbiter, calls: FileUploadDecisionRequest[]) => Promise<void>,
): Promise<void> {
  const calls: FileUploadDecisionRequest[] = [];
  const arbiter = new MockArbiter({
    gateSurfaceFn: () => surface,
    fileUploadDecisionFn: (req) => {
      calls.push(req);
      return req.path === SECRET
        ? { allow: false, requiresApproval: true, reason: "secret file", ruleRef: { source: "rule", id: "fs:upload-secret-file" }, approvalId: "egr-7" }
        : { allow: true, reason: "clean", ruleRef: { source: "rule", id: "fs:upload-clean" } };
    },
  });
  const proxy = new AnthropicProxy({
    arbiter, sessionKey: "s-1", log: () => {}, agentCwd: "/home/u/proj",
    upstream: up.fetcher,
    openaiUpstreams: { deepseek: "https://deepseek.invalid/v1", openai: "https://openai.invalid/v1" },
    openaiFetcher: () => up.fetcher,
  });
  const port = await proxy.listen(0);
  try { await fn(port, arbiter, calls); } finally { await proxy.close(); }
}

const messages = (stream: boolean): Json => ({ model: "claude-sonnet-5", stream, messages: [{ role: "user", content: "send it" }] });

function anthropicText(sse: string): string {
  let t = "";
  for (const raw of sse.split("\n\n")) {
    const line = raw.split("\n").find((l) => l.startsWith("data: "));
    if (!line) continue;
    const d = JSON.parse(line.slice(6)) as Json;
    const delta = d["delta"] as Json | undefined;
    if (d["type"] === "content_block_delta" && delta?.["type"] === "text_delta") t += delta["text"] as string;
  }
  return t;
}

test("Messages SSE in an OpenClaw session: the held file's line becomes a notice (asked as MEDIA, no host, an fs_action deny), a clean one passes, the rest streams as written", async () => {
  const text = `Here you go.\nMEDIA: ${SECRET}\nMEDIA: ./chart.png\nBye`;
  const up = new MockUpstream({ sse: buildTextSse(text, { deltas: text.length }), chunkInto: 11 });
  await withProxy(OPENCLAW, up, async (port, arbiter, calls) => {
    const r = await send(port, "/v1/messages", messages(true));
    assert.equal(r.status, 200);
    const got = anthropicText(r.body);
    assert.match(got, /^Here you go\.\n\[mandu\] attachment not sent, nothing was uploaded: .*\(rule: fs:upload-secret-file\)\nMEDIA: \.\/chart\.png\nBye$/);
    assert.deepEqual(calls.map((c) => [c.tool, c.path, c.destination]), [["MEDIA", SECRET, ""], ["MEDIA", "/home/u/proj/chart.png", ""]]);
    const deny = arbiter.emittedEvents.filter((e) => e.kind === "fs_action" && JSON.stringify(e).includes("MEDIA.reply"));
    assert.equal(deny.length, 1, "one deny event per held file");
    assert.match(JSON.stringify(deny[0]), /egr-7/);
  });
});

test("Messages JSON in an OpenClaw session: the answer's text block is gated the same way", async () => {
  const up = new MockUpstream({ json: { id: "m", type: "message", role: "assistant", content: [{ type: "text", text: `MEDIA: ${SECRET}` }], stop_reason: "end_turn" } });
  await withProxy(OPENCLAW, up, async (port) => {
    const r = await send(port, "/v1/messages", messages(false));
    const obj = JSON.parse(r.body) as { content: Array<{ text: string }> };
    assert.match(obj.content[0]!.text, /^\[mandu\] attachment not sent/);
  });
});

test("a session whose agent attaches nothing its reply names (Claude Code) is relayed as written", async () => {
  const text = `MEDIA: ${SECRET}\nSocial media: 3`;
  const sse = buildTextSse(text, { deltas: 5 });
  const up = new MockUpstream({ sse });
  await withProxy(CLAUDE, up, async (port, _a, calls) => {
    const r = await send(port, "/v1/messages", messages(true));
    assert.equal(anthropicText(r.body), text);
    assert.equal(calls.length, 0);
  });
});

test("an OpenClaw provider on the OpenAI wire: Chat Completions SSE, Responses SSE (deltas and every complete text) and a Responses JSON answer", async () => {
  const env = { id: "c1", object: "chat.completion.chunk", created: 1, model: "m" };
  const pieces = ["Config:\nME", "DIA: /home/u", "/proj/.env"];
  let chat = `data: ${JSON.stringify({ ...env, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] })}\n\n`;
  for (const p of pieces) chat += `data: ${JSON.stringify({ ...env, choices: [{ index: 0, delta: { content: p }, finish_reason: null }] })}\n\n`;
  chat += `data: ${JSON.stringify({ ...env, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`;
  await withProxy(OPENCLAW, new MockUpstream({ sse: chat, chunkInto: 5 }), async (port) => {
    const r = await send(port, "/_mandu/openai/deepseek/chat/completions", { model: "deepseek-chat", stream: true, messages: [{ role: "user", content: "hi" }] });
    assert.equal(r.status, 200);
    const text = r.body.split("\n\n").filter((e) => e.startsWith("data: {"))
      .map((e) => (((JSON.parse(e.slice(6)) as Json)["choices"] as Json[])[0]!["delta"] as Json)["content"]).filter((t): t is string => typeof t === "string").join("");
    assert.match(text, /^Config:\n\[mandu\] attachment not sent/);
    assert.ok(r.body.endsWith("data: [DONE]\n\n"));
  });

  const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;
  const full = pieces.join("");
  const msg = { type: "message", id: "msg_1", role: "assistant", content: [{ type: "output_text", text: full }] };
  const resp = ev("response.output_item.added", { output_index: 0, item: { ...msg, content: [] } })
    + pieces.map((p) => ev("response.output_text.delta", { item_id: "msg_1", output_index: 0, content_index: 0, delta: p })).join("")
    + ev("response.output_text.done", { item_id: "msg_1", output_index: 0, content_index: 0, text: full })
    + ev("response.output_item.done", { output_index: 0, item: msg })
    + ev("response.completed", { response: { id: "r1", output: [msg] } });
  await withProxy(OPENCLAW, new MockUpstream({ sse: resp }), async (port) => {
    const r = await send(port, "/_mandu/openai/openai/responses", { model: "gpt-5", stream: true, input: "hi" });
    assert.equal(r.status, 200);
    assert.ok(!r.body.includes(`MEDIA: ${SECRET}`), "no event still names the file");
    assert.equal(r.body.match(/\[mandu\] attachment not sent/g)?.length, 4, "the delta, the .done text, the item, response.completed");
  });

  await withProxy(OPENCLAW, new MockUpstream({ json: { id: "r1", object: "response", output: [msg] } }), async (port) => {
    const r = await send(port, "/_mandu/openai/openai/responses", { model: "gpt-5", input: "hi" });
    assert.equal(r.status, 200);
    assert.match(r.body, /\[mandu\] attachment not sent/);
    assert.ok(!r.body.includes(`MEDIA: ${SECRET}`));
  });
});
