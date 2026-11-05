/**
 * openai-text-calls (proxy e2e) — a tool call the model WRITES in its reply
 * text on an OpenClaw session's OpenAI-family route, through the REAL
 * AnthropicProxy at /_mandu/openai/<provider> (model-wires.md, "Tool calls
 * written as text"; src/text-calls.ts).
 *
 * OpenClaw's LM Studio and xAI providers (and any provider plugin that uses
 * its plain-text tool-call compat layer) RUN such a call; no gate sees it.
 * Pinned, for a provider of ANY id (the stop is keyed on the agent, not the
 * provider): the reply is ended with the error event before the agent holds
 * the whole call, over Chat Completions (streamed and buffered) and the
 * Responses API; on an agent the arbiter did not name (the union surface)
 * too; an OpenCode session's same reply relays unchanged (OpenCode runs no
 * such call); a plain reply relays unchanged.
 *
 * The real-arbiter version is tests/stack/openai-text-calls.test.ts; the
 * real OpenClaw, the plugin lane's text-call legs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";

import { AnthropicProxy } from "../../src/proxy.js";
import type { GateSurface } from "../../src/gate-surface.js";
import { UNION_GATE_SURFACE } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { MockUpstream } from "../helpers/mock-upstream.js";

type Json = Record<string, unknown>;

const OPENCLAW: GateSurface = { ...UNION_GATE_SURFACE, spec: "openclaw-agent" };
const OPENCODE: GateSurface = { ...UNION_GATE_SURFACE, spec: "opencode" };

function send(port: number, path: string, body: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), authorization: "Bearer sk-test-not-real" } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

async function withRig(surface: GateSurface, provider: string, up: MockUpstream, fn: (port: number) => Promise<void>): Promise<void> {
  const proxy = new AnthropicProxy({
    arbiter: new MockArbiter({ gateSurfaceFn: () => surface }),
    sessionKey: "s-1",
    log: () => {},
    upstream: async () => { throw new Error("the Anthropic upstream was called"); },
    openaiUpstreams: { [provider]: `https://${provider}.invalid/v1` },
    openaiFetcher: () => up.fetcher,
  });
  const port = await proxy.listen(0);
  try { await fn(port); } finally { await proxy.close(); }
}

const TOOLS = [{ type: "function", function: { name: "exec", parameters: { type: "object" } } }];
const chatRequest = (stream = true): Json => ({ model: "m", stream, messages: [{ role: "user", content: "touch the file" }], tools: TOOLS });
const CALL = "[tool:exec] {\"command\":\"touch /tmp/mandu-text-call-ran\"}";
const env = { id: "c1", object: "chat.completion.chunk", created: 1, model: "m" };
const chatTextSse = (...pieces: string[]): string =>
  pieces.map((p) => `data: ${JSON.stringify({ ...env, choices: [{ index: 0, delta: { content: p }, finish_reason: null }] })}\n\n`).join("")
  + `data: ${JSON.stringify({ ...env, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\ndata: [DONE]\n\n`;

for (const provider of ["lmstudio", "xai", "my-local-box"]) {
  test(`Chat (stream), provider "${provider}" on an OpenClaw session: a text call ends the reply before the agent holds it`, async () => {
    const up = new MockUpstream({ sse: chatTextSse("Sure.\n[tool:ex", CALL.slice("[tool:ex".length)), chunkInto: 5 });
    await withRig(OPENCLAW, provider, up, async (port) => {
      const r = await send(port, `/_mandu/openai/${provider}/chat/completions`, chatRequest());
      assert.equal(r.status, 200);
      assert.match(r.body, /mandu_fail_closed[^\n]*tool call in its reply text/);
      assert.ok(!r.body.includes("touch /tmp/mandu-text-call-ran"), "the call's payload never reached the agent");
      assert.ok(!r.body.includes("[DONE]"), "the reply never finished");
    });
  });
}

test("Chat (buffered), an OpenClaw session: a message carrying a text call is a 502, never relayed", async () => {
  const up = new MockUpstream({ json: { id: "c1", object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content: `ok\n${CALL}` }, finish_reason: "stop" }] } });
  await withRig(OPENCLAW, "lmstudio", up, async (port) => {
    const r = await send(port, "/_mandu/openai/lmstudio/chat/completions", chatRequest(false));
    assert.equal(r.status, 502);
    assert.ok(!r.body.includes("touch /tmp"));
  });
});

test("Responses (stream), an OpenClaw session: a text call in the output text ends the reply before response.completed", async () => {
  const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`;
  const sse = ev("response.created", { response: { id: "resp_1", output: [] } })
    + ev("response.output_item.added", { output_index: 0, item: { id: "m1", type: "message", role: "assistant", content: [] } })
    + ev("response.output_text.delta", { item_id: "m1", output_index: 0, content_index: 0, delta: "<function=exec>" })
    + ev("response.output_text.delta", { item_id: "m1", output_index: 0, content_index: 0, delta: "<parameter=command>touch /tmp/x</parameter></function>" })
    + ev("response.completed", { response: { id: "resp_1", output: [{ id: "m1", type: "message", content: [{ type: "output_text", text: "<function=exec>…" }] }] } });
  const up = new MockUpstream({ sse });
  await withRig(OPENCLAW, "xai", up, async (port) => {
    const r = await send(port, "/_mandu/openai/xai/responses", { model: "grok", stream: true, input: "touch it", tools: [{ type: "function", name: "exec", parameters: {} }] });
    assert.match(r.body, /mandu_fail_closed[^\n]*tool call in its reply text/);
    assert.ok(!r.body.includes("response.completed"), "nothing after the error");
  });
});

test("an agent the arbiter did not name (the union surface) gets the stop too; an OpenCode session's reply, and a plain reply, relay unchanged", async () => {
  const up = new MockUpstream({ sse: chatTextSse(CALL) });
  await withRig(UNION_GATE_SURFACE, "lmstudio", up, async (port) => {
    assert.match((await send(port, "/_mandu/openai/lmstudio/chat/completions", chatRequest())).body, /mandu_fail_closed/);
  });
  const up2 = new MockUpstream({ sse: chatTextSse(CALL) });
  await withRig(OPENCODE, "lmstudio", up2, async (port) => {
    const r = await send(port, "/_mandu/openai/lmstudio/chat/completions", chatRequest());
    assert.equal(r.body, chatTextSse(CALL), "OpenCode runs no text call: relayed as sent");
  });
  const plain = chatTextSse("Done. See [1] and use [note] later.\n", "[1] a footnote");
  const up3 = new MockUpstream({ sse: plain });
  await withRig(OPENCLAW, "lmstudio", up3, async (port) => {
    assert.equal((await send(port, "/_mandu/openai/lmstudio/chat/completions", chatRequest())).body, plain);
  });
});
