/**
 * split-token-round-trip (proxy e2e, 2026-09-30) — a secret's `$MDU:` symbol,
 * echoed back by the model split at EVERY character boundary of the answer,
 * through the REAL AnthropicProxy on each wire it reads: the Messages API
 * (`/v1/messages`, sse-text-repack.ts) and the routed OpenAI wires
 * (`/_mandu/openai/<provider>/…` Chat Completions and Responses,
 * text-repack.ts, agent-e2e-harness.md §9).
 *
 * The round trip, per boundary:
 *   request   the agent sends a `.env` tool result (`secrets` shape:
 *             integrity off, the result labelled `no-model`); the provider
 *             must receive only its symbol, never the canary;
 *   answer    the provider echoes that symbol in two text deltas cut at the
 *             boundary, relayed to the proxy in one chunk or in 7-byte
 *             chunks (so frames tear at every offset too); the agent must
 *             receive the text byte-identical with the token WHOLE in one
 *             delta (no broken token), and never the canary (the proxy does
 *             not desymbolize the reply).
 * The OpenAI-wire repacker is shared verbatim with openai-proxy; its unit
 * suite is test/unit/text-repack.test.ts, the copies' parity
 * tests/stack/text-repack-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";

import { AnthropicProxy, type UpstreamFetcher } from "../../src/proxy.js";
import type { GateSurface } from "../../src/gate-surface.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { sseEvent } from "../helpers/mock-upstream.js";

type Json = Record<string, unknown>;

const CANARY = "SPLITTOKENCANARY7HX2";
const SECRET_BYTES = `API_TOKEN=${CANARY}`;
const SYMBOL_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/;

const OPENCLAW: GateSurface = {
  spec: "openclaw-agent",
  exec: { exec: "command" },
  execOutput: { exec: "command", process: "command" },
  net: {},
  paths: { read: { fields: ["path", "file_path"], mode: "read" } },
  dispatch: {},
  refuse: {},
  refuseArgs: {},
  stdin: {},
};

/** `secrets` as the arbiter answers it: integrity off (all TRUSTED), the
 *  .env read carries its level. */
function secretsArbiter(): MockArbiter {
  return new MockArbiter({
    gateSurfaceFn: () => OPENCLAW,
    classifyFn: (req) => JSON.stringify(req).includes(".env")
      ? { trust: "TRUSTED", category: null, reason: "mock: workspace .env", confidentiality: "no-model" }
      : { trust: "TRUSTED", category: null, reason: "mock: integrity off" },
  });
}

function send(port: number, path: string, body: Json): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": "s-1" } },
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

/** The data payloads of an SSE body, in order ([DONE] dropped). */
function payloads(sse: string): Json[] {
  return sse.split("\n\n").flatMap((e) => {
    const line = e.split("\n").find((l) => l.startsWith("data: "));
    return line && line !== "data: [DONE]" ? [JSON.parse(line.slice(6)) as Json] : [];
  });
}

interface Wire {
  name: string;
  path: string;
  request: Json;
  /** The provider's answer: `pieces` as consecutive text deltas. */
  answer: (pieces: string[], full: string) => string;
  texts: (sse: string) => string[];
}

const MESSAGES: Wire = {
  name: "messages",
  path: "/v1/messages",
  request: {
    model: "claude-opus-4", stream: true, max_tokens: 1024,
    messages: [
      { role: "user", content: "what is in .env?" },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_env", name: "Read", input: { file_path: "/workspace/.env" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_env", content: SECRET_BYTES }] },
    ],
  },
  answer: (pieces) => sseEvent("message_start", { type: "message_start", message: { id: "msg_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })
    + pieces.map((p) => sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: p } })).join("")
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" } })
    + sseEvent("message_stop", { type: "message_stop" }),
  texts: (sse) => payloads(sse).flatMap((p) => {
    const d = p["delta"] as Json | undefined;
    return p["type"] === "content_block_delta" && d?.["type"] === "text_delta" ? [d["text"] as string] : [];
  }),
};

const CHAT: Wire = {
  name: "routed chat",
  path: "/_mandu/openai/deepseek/chat/completions",
  request: {
    model: "deepseek-chat", stream: true,
    messages: [
      { role: "user", content: "what is in .env?" },
      { role: "assistant", content: null, tool_calls: [{ id: "call_env", type: "function", function: { name: "read", arguments: '{"path":".env"}' } }] },
      { role: "tool", tool_call_id: "call_env", content: SECRET_BYTES },
    ],
    tools: [{ type: "function", function: { name: "read", parameters: { type: "object" } } }],
  },
  answer: (pieces) => {
    const env = { id: "c1", object: "chat.completion.chunk", created: 1, model: "deepseek-chat" };
    const chunk = (delta: Json, finish: string | null = null): string =>
      `data: ${JSON.stringify({ ...env, choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
    return chunk({ role: "assistant", content: "" }) + pieces.map((p) => chunk({ content: p })).join("") + chunk({}, "stop") + "data: [DONE]\n\n";
  },
  texts: (sse) => payloads(sse).flatMap((p) => ((p["choices"] as Json[] | undefined) ?? [])
    .map((c) => (c["delta"] as Json | undefined)?.["content"]).filter((t): t is string => typeof t === "string")),
};

const RESPONSES: Wire = {
  name: "routed responses",
  path: "/_mandu/openai/openai/responses",
  request: {
    model: "gpt-5", stream: true,
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "what is in .env?" }] },
      { type: "function_call", call_id: "call_env", name: "read", arguments: '{"path":".env"}' },
      { type: "function_call_output", call_id: "call_env", output: SECRET_BYTES },
    ],
    tools: [{ type: "function", name: "read", parameters: { type: "object" } }],
  },
  answer: (pieces, full) => {
    let n = 0;
    const ev = (type: string, data: Json): string => `event: ${type}\ndata: ${JSON.stringify({ type, sequence_number: n++, ...data })}\n\n`;
    const msg = { type: "message", id: "msg_1", role: "assistant", content: [{ type: "output_text", text: full }] };
    return ev("response.created", { response: { id: "r1", output: [] } })
      + ev("response.output_item.added", { output_index: 0, item: { ...msg, content: [] } })
      + pieces.map((p) => ev("response.output_text.delta", { item_id: "msg_1", output_index: 0, content_index: 0, delta: p })).join("")
      + ev("response.output_text.done", { item_id: "msg_1", output_index: 0, content_index: 0, text: full })
      + ev("response.output_item.done", { output_index: 0, item: msg })
      + ev("response.completed", { response: { id: "r1", output: [msg] } });
  },
  texts: (sse) => payloads(sse).filter((p) => p["type"] === "response.output_text.delta").map((p) => p["delta"] as string),
};

for (const wire of [MESSAGES, CHAT, RESPONSES]) {
  for (const torn of [false, true]) {
    test(`${wire.name}: a secret's symbol echoed split at every boundary reaches the agent whole, never raw (${torn ? "7-byte chunks" : "one chunk"})`, async () => {
      // The fetcher plays the model: it reads the symbol the proxy forwarded
      // and answers with it, cut at the boundary under test.
      let cutAt = 1;
      const seen = { token: "", full: "" };
      const forwarded: string[] = [];
      const fetcher: UpstreamFetcher = async ({ body }) => {
        const sent = body.toString("utf8");
        forwarded.push(sent);
        const token = SYMBOL_RE.exec(sent)?.[0];
        assert.ok(token, `the provider received the secret's symbol: ${sent.slice(0, 400)}`);
        const full = `The file holds ${token} and nothing else.`;
        seen.token = token;
        seen.full = full;
        const sse = wire.answer([full.slice(0, cutAt), full.slice(cutAt)], full);
        const parts = torn ? (sse.match(/[\s\S]{1,7}/g) ?? []) : [sse];
        return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from(parts.map((p) => Buffer.from(p, "utf8"))) };
      };
      const proxy = new AnthropicProxy({
        arbiter: secretsArbiter(),
        sessionKey: "s-1",
        log: () => {},
        upstream: fetcher,
        openaiUpstreams: { deepseek: "https://deepseek.invalid/v1", openai: "https://openai.invalid/v1" },
        openaiFetcher: () => fetcher,
      });
      const port = await proxy.listen(0);
      try {
        // Learn the answer's length once, then walk every boundary inside it.
        const first = await send(port, wire.path, wire.request);
        assert.equal(first.status, 200, first.body);
        const len = seen.full.length;
        for (cutAt = 1; cutAt < len; cutAt++) {
          const r = await send(port, wire.path, wire.request);
          const { token, full } = seen;
          const at = `cut after ${JSON.stringify(full.slice(0, cutAt))}`;
          assert.equal(r.status, 200, r.body);
          assert.ok(!forwarded.at(-1)!.includes(CANARY), `CONFIDENTIALITY VIOLATION: the secret reached the provider (${at})`);
          assert.ok(!r.body.includes(CANARY), `the agent received the raw secret (${at})`);
          const texts = wire.texts(r.body);
          assert.equal(texts.join(""), full, `the text is byte-identical (${at})`);
          assert.equal(texts.filter((t) => t.includes(token)).length, 1, `the token is whole in one delta (${at}): ${JSON.stringify(texts)}`);
        }
      } finally {
        await proxy.close();
      }
    });
  }
}
