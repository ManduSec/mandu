/**
 * prompt-filter-ingress — `model-ingress/prompt` on the real path
 * (confidentiality-plan-15-prompt-filter.md §3, §11 phase 1): a registered
 * secret pasted into the human's prompt reaches the model only as its symbol,
 * through each REAL model proxy over HTTP, on each agent family's wire.
 *
 *   the agent's request ──► the REAL proxy over HTTP (production adapter:
 *       `new ArbiterClientAdapter(new ArbiterClient(sock))`)
 *     ──► a scripted fake model on loopback, which records every request.
 *
 * The values are registered as the launcher registers the environment
 * (`registerEnvSecrets` on a real ArbiterServer in `secrets`): a high-entropy
 * API key and `DB_PASSWORD=postgres`. Per agent family:
 *   - Claude Code: anthropic-proxy, Messages;
 *   - OpenClaw: anthropic-proxy, the routed Chat Completions wire (openai-wire.ts);
 *   - OpenCode: anthropic-proxy, the routed Chat Completions wire, text parts;
 *   - Codex: openai-proxy, the Responses wire and the Chat Completions wire.
 * The oracle, per family: no request the fake model received holds the key;
 * the key's own symbol (the one registration minted) is there instead;
 * `postgres` typed by the human reaches the model as typed (the prompt
 * floor), while the same value inside text the harness added (a
 * `<system-reminder>`, OpenClaw's sender header, Codex's AGENTS.md) is masked;
 * the human still reads the original: `desymbolize` on the human plane turns
 * the forwarded text back into what was typed. And fail-closed: with the
 * arbiter gone, nothing reaches the model.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { startScriptedAnthropic, type FakeAnthropic } from "../lib/fake-anthropic.js";
import { startScriptedResponses, type ScriptedFake } from "../lib/fake-responses.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const KEY = "sk-live-PromptCanary7Hq2Zx9Lw4Rt8Kd";
const WEAK = "postgres";
const ENVELOPE = "[Thu 2026-10-02 10:48 GMT+9] ";

interface Rig {
  sock: string;
  server: ArbiterServer;
  data: ArbiterClient;
  human: ArbiterClient;
  keySym: string;
  weakSym: string;
  stop(): Promise<void>;
}

async function boot(): Promise<Rig> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prompt-filter-"));
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({ socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await server.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  // The launcher's registration of the session's environment.
  const reg = await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }, { name: "DB_PASSWORD", value: WEAK }] });
  const keySym = reg.vars.find((v) => v.name === "STRIPE_API_KEY")!.symbol!;
  const weakSym = reg.vars.find((v) => v.name === "DB_PASSWORD")!.symbol!;
  assert.match(keySym, /^\$MDU:/, JSON.stringify(reg));
  assert.match(weakSym, /^\$MDU:/, JSON.stringify(reg));
  return {
    sock, server, data, human, keySym, weakSym,
    async stop() {
      data.close();
      human.close();
      await server.close().catch(() => {});
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

function post(port: number, path: string, body: unknown, session: string): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path, headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": session, authorization: "Bearer sk-test-not-real" } },
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

/** A Chat Completions model on loopback: records every request, answers "ok". */
async function startFakeChat(): Promise<{ origin: string; requests: string[]; close(): Promise<void> }> {
  const requests: string[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requests.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: "c1", object: "chat.completion", created: 1, model: "m", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }] }));
    });
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    requests,
    close: () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }),
  };
}

/** The common oracle over what the model received. */
async function assertPromptOracle(r: Rig, received: string[], typed: string, forwardedTyped: (body: string) => string, where: string): Promise<void> {
  assert.ok(received.length > 0, `${where}: the model was called`);
  for (const b of received) {
    assert.ok(!b.includes(KEY), `CONFIDENTIALITY VIOLATION (${where}): a registered key pasted into the prompt reached the model raw`);
  }
  const last = received[received.length - 1]!;
  assert.ok(last.includes(r.keySym), `${where}: the key reaches the model as its own symbol`);
  assert.ok(last.includes(r.weakSym), `${where}: postgres in text the harness added is masked`);
  const sent = forwardedTyped(last);
  assert.ok(sent.includes(`as ${WEAK}`), `${where}: postgres typed by the human reaches the model as typed (the prompt floor): ${sent}`);
  // The human still sees the original.
  assert.equal(await r.human.desymbolize(sent), typed, `${where}: the human plane restores what was typed`);
}

const typedText = `deploy with ${KEY} as ${WEAK}`;

test("model-ingress/prompt (Claude Code, Messages): a pasted registered key reaches the model only as its symbol; postgres as typed, masked in a reminder (secrets axes, the real proxy over HTTP)", async () => {
  const r = await boot();
  const session = `prompt-cc-${process.pid}`;
  await r.data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake: FakeAnthropic = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const body = {
      model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
      tools: [{ name: "Read", description: "read", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: [
        { type: "text", text: `<system-reminder>\nThe environment has DB_PASSWORD=${WEAK}\n</system-reminder>` },
        { type: "text", text: typedText },
      ] }],
    };
    for (let i = 0; i < 2; i++) {
      const res = await post(port, "/v1/messages", body, session);
      assert.equal(res.status, 200, res.body);
    }
    const received = fake.requests.filter((q) => q.url.includes("/v1/messages")).map((q) => q.body);
    await assertPromptOracle(r, received, typedText,
      (b) => ((JSON.parse(b) as { messages: Array<{ content: Array<{ text: string }> }> }).messages[0]!.content[1]!.text), "claude-code");
    assert.equal(received[0], received[1], "the resend is byte-identical (stable symbols; provider prompt caching keeps working)");
  } finally {
    await proxy.close();
    await fake.close();
    await r.stop();
  }
});

for (const agent of [
  { name: "OpenClaw", spec: "openclaw-agent", typed: (t: string) => `Sender (untrusted metadata):\n\`\`\`json\n{"id":"gateway-client","db":"${WEAK}"}\n\`\`\`\n\n${ENVELOPE}${t}`, cut: (s: string) => s.slice(s.lastIndexOf(ENVELOPE) + ENVELOPE.length) },
  { name: "OpenCode", spec: "opencode", typed: (t: string) => `<system-reminder>DB_PASSWORD=${WEAK}</system-reminder>\n${t}`, cut: (s: string) => s.slice(s.indexOf("\n") + 1) },
] as const) {
  test(`model-ingress/prompt (${agent.name}, the routed Chat Completions wire): the key reaches the model only as its symbol; the user text is written back (secrets axes)`, async () => {
    const r = await boot();
    const session = `prompt-${agent.spec}-${process.pid}`;
    await r.data.setSessionSpec({ sessionKey: session, spec: agent.spec });
    const fake = await startFakeChat();
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: "http://127.0.0.1:9", openaiUpstreams: { local: `${fake.origin}/v1` }, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    try {
      const body = {
        model: "local-model", stream: false,
        tools: [{ type: "function", function: { name: "read", parameters: { type: "object" } } }],
        messages: [{ role: "system", content: "you are an agent" }, { role: "user", content: agent.typed(typedText) }],
      };
      const res = await post(port, "/_mandu/openai/local/chat/completions", body, session);
      assert.equal(res.status, 200, res.body);
      await assertPromptOracle(r, fake.requests, typedText,
        (b) => agent.cut((JSON.parse(b) as { messages: Array<{ content: string }> }).messages[1]!.content), agent.name);
    } finally {
      await proxy.close();
      await fake.close();
      await r.stop();
    }
  });
}

test("model-ingress/prompt (Codex, Responses): the key reaches the model only as its symbol; postgres masked in AGENTS.md text (secrets axes, the real openai-proxy over HTTP)", async () => {
  const r = await boot();
  const session = `prompt-codex-${process.pid}`;
  const fake: ScriptedFake = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const msg = (text: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });
    const body = {
      model: "gpt-5", stream: true,
      tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
      input: [msg(`# AGENTS.md instructions for /w\n\nThe DB password is ${WEAK}.`), msg("<environment_context>\n  <cwd>/w</cwd>\n</environment_context>"), msg(typedText)],
    };
    const res = await post(port, "/v1/responses", body, session);
    assert.equal(res.status, 200, res.body);
    const received = fake.requests.filter((q) => q.url.includes("/responses")).map((q) => q.body);
    await assertPromptOracle(r, received, typedText,
      (b) => ((JSON.parse(b) as { input: Array<{ content: Array<{ text: string }> }> }).input[2]!.content[0]!.text), "codex responses");
  } finally {
    await proxy.close();
    await fake.close();
    await r.stop();
  }
});

test("model-ingress/prompt (Codex, Chat Completions): the user text is written back as symbols (secrets axes)", async () => {
  const r = await boot();
  const session = `prompt-codex-chat-${process.pid}`;
  const fake = await startFakeChat();
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const body = {
      model: "gpt-5", stream: false,
      tools: [{ type: "function", function: { name: "exec_command", parameters: { type: "object" } } }],
      messages: [
        { role: "system", content: "sys" },
        { role: "user", content: `# AGENTS.md instructions for /w\n\nThe DB password is ${WEAK}.` },
        { role: "user", content: typedText },
      ],
    };
    const res = await post(port, "/v1/chat/completions", body, session);
    assert.equal(res.status, 200, res.body);
    await assertPromptOracle(r, fake.requests, typedText,
      (b) => ((JSON.parse(b) as { messages: Array<{ content: string }> }).messages[2]!.content), "codex chat");
  } finally {
    await proxy.close();
    await fake.close();
    await r.stop();
  }
});

test("model-ingress/prompt FAIL CLOSED: with the arbiter gone, neither proxy sends the prompt (secrets axes)", async () => {
  const r = await boot();
  const fakeA = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const fakeR = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const a = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: fakeA.origin, log: () => {} });
  const o = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fakeR.origin, log: () => {} });
  const pa = await a.listen(0);
  const po = await o.listen(0);
  try {
    await r.server.close();
    const ra = await post(pa, "/v1/messages", { model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: {} }], messages: [{ role: "user", content: typedText }] }, "fc-a");
    assert.notEqual(ra.status, 200);
    const ro = await post(po, "/v1/responses", { model: "gpt-5", stream: true, tools: [{ type: "function", name: "exec_command", parameters: {} }], input: [{ type: "message", role: "user", content: [{ type: "input_text", text: typedText }] }] }, "fc-o");
    assert.notEqual(ro.status, 200);
    assert.ok(!fakeA.requests.some((q) => q.body.includes(KEY)) && !fakeR.requests.some((q) => q.body.includes(KEY)), "CONFIDENTIALITY VIOLATION: the prompt went to the model with the arbiter down");
  } finally {
    await a.close();
    await o.close();
    await fakeA.close();
    await fakeR.close();
    await r.stop();
  }
});
