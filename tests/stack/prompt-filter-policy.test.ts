/**
 * prompt-filter-policy — `model-ingress/prompt` under a `prompt_filters:`
 * policy, on the real path (confidentiality-plan-15-prompt-filter.md §4, §6,
 * §7, §11 phase 2): what the person's policy says about their prompt holds
 * through each REAL model proxy over HTTP, on each agent family's wire.
 *
 *   the agent's request ──► the REAL proxy over HTTP (production adapter:
 *       `new ArbiterClientAdapter(new ArbiterClient(sock))`)
 *     ──► a scripted fake model on loopback, which records every request.
 *
 * The policy (a real ArbiterServer in `secrets`, a policy document and the
 * person's pack directory): `key-shapes` on (a GitHub token nobody
 * registered: the default `redact`), a pack `acme-dlp` on (a check-valid
 * payment card: `block`; the codename `falcon`: `mask`). Per agent family:
 *   - Claude Code: anthropic-proxy, Messages;
 *   - OpenClaw and OpenCode: anthropic-proxy, the routed Chat Completions wire;
 *   - Codex: openai-proxy, Responses and Chat Completions.
 * The oracle, per family: the model never receives the token, the card or
 * the codename; it receives `[redacted: secret.shape.github-token]` and the
 * codename's symbol; the human plane turns that symbol back into what was
 * typed. A prompt holding the card is refused with a 400 the agent shows
 * (the reason names the category, never the card) and nothing reaches the
 * model; the next turn, which resends the refused message, reaches it with
 * `[blocked: pii.payment-card]` (§13.3). A side call that quotes the prompt
 * (a title request, no tools) carries `[redacted: pii.payment-card]`. And
 * fail-closed (§4.4): a pack the policy turns on but that cannot be loaded
 * refuses the prompt rather than send it unchecked.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { startScriptedAnthropic, type FakeAnthropic } from "../lib/fake-anthropic.js";
import { startScriptedResponses, type ScriptedFake } from "../lib/fake-responses.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const CARD = "4111 1111 1111 1111";
const CODENAME = "falcon";
const REDACTED = "[redacted: secret.shape.github-token]";
const ENVELOPE = "[Thu 2026-10-02 10:48 GMT+9] ";

const PACK = `pack: acme-dlp
version: 1
patterns:
  - id: card
    category: pii.payment-card
    regex: '\\b(?:\\d[ -]?){13,19}\\b'
    check: luhn
keywords:
  - category: acme.codename
    words: [${CODENAME}]
`;

const POLICY: PolicyFileConfig = {
  version: 1,
  prompt_filters: {
    filters: { "key-shapes": "on", "acme-dlp": "on" },
    actions: { "pii.payment-card": "block", "acme.codename": "mask" },
  },
};

interface Rig {
  data: ArbiterClient;
  human: ArbiterClient;
  stop(): Promise<void>;
}

async function boot(policy: PolicyFileConfig = POLICY): Promise<Rig> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prompt-policy-"));
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), PACK);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyDocument: policy, policyPollMs: 0,
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  return {
    data, human,
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

const typed = `push ${GH} for ${CODENAME} today`;
const typedCard = `and pay ${CARD}, now`;

/** The oracle over what the model received for `typed`. */
async function assertPolicyOracle(r: Rig, received: string[], forwarded: (body: string) => string, where: string): Promise<void> {
  assert.ok(received.length > 0, `${where}: the model was called`);
  for (const b of received) {
    assert.ok(!b.includes(GH), `CONFIDENTIALITY VIOLATION (${where}): an unregistered key the policy redacts reached the model`);
    assert.ok(!new RegExp(`\\b${CODENAME}\\b`).test(b), `CONFIDENTIALITY VIOLATION (${where}): the masked codename reached the model`);
    assert.ok(!b.includes(CARD), `CONFIDENTIALITY VIOLATION (${where}): a blocked card reached the model`);
  }
  const sent = forwarded(received[received.length - 1]!);
  assert.ok(sent.includes(REDACTED), `${where}: the token is redacted: ${sent}`);
  const sym = /\$MDU:[A-Za-z0-9_]+\[[0-9a-f]+\]/.exec(sent)?.[0];
  assert.ok(sym, `${where}: the codename reaches the model as a symbol: ${sent}`);
  // The human reads the original of what was masked; a redaction stores nothing.
  assert.equal(await r.human.desymbolize(sent), `push ${REDACTED} for ${CODENAME} today`, `${where}: the human plane restores the masked codename`);
}

test("prompt_filters (Claude Code, Messages): a token is redacted, a codename masked; a card never reaches the model (secrets axes, the real proxy over HTTP)", async () => {
  const r = await boot();
  const session = `pf-cc-${process.pid}`;
  await r.data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake: FakeAnthropic = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const body = (text: string) => ({
      model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
      tools: [{ name: "Read", description: "read", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: [{ type: "text", text: "<system-reminder>\nctx\n</system-reminder>" }, { type: "text", text }] }],
    });
    const ok = await post(port, "/v1/messages", body(typed), session);
    assert.equal(ok.status, 200, ok.body);
    const received = () => fake.requests.filter((q) => q.url.includes("/v1/messages")).map((q) => q.body);
    await assertPolicyOracle(r, received(), (b) => ((JSON.parse(b) as { messages: Array<{ content: Array<{ text: string }> }> }).messages[0]!.content[1]!.text), "claude-code");
    const n = received().length;
    const blocked = await post(port, "/v1/messages", body(typedCard), session);
    assert.equal(blocked.status, 400, `a prompt holding a card the policy blocks is refused: ${blocked.body}`);
    assert.match(blocked.body, /invalid_request_error/);
    assert.match(blocked.body, /Mandu blocked this prompt: it contains pii\.payment-card \(acme-dlp\)/);
    assert.ok(!blocked.body.includes(CARD));
    assert.equal(received().length, n, "nothing was sent to the model for it");
    // The agent keeps the refused message; the next turn carries it safe.
    const next = {
      ...body(typedCard),
      messages: [...body(typedCard).messages, { role: "assistant", content: [{ type: "text", text: "(error)" }] }, { role: "user", content: [{ type: "text", text: "never mind, say hi" }] }],
    };
    const ok2 = await post(port, "/v1/messages", next, session);
    assert.equal(ok2.status, 200, ok2.body);
    const sent = (JSON.parse(received().at(-1)!) as { messages: Array<{ content: Array<{ text: string }> }> }).messages[0]!.content[1]!.text;
    assert.equal(sent, "and pay [blocked: pii.payment-card], now");
    // A side call (no tools: Claude Code's title request) quoting the prompt.
    const title = await post(port, "/v1/messages", { model: "claude-haiku-4-5", stream: false, max_tokens: 32, messages: [{ role: "user", content: `Write a 5-word title for: ${typedCard}` }] }, session);
    assert.equal(title.status, 200, title.body);
    assert.ok(received().at(-1)!.includes("and pay [redacted: pii.payment-card], now"), received().at(-1));
    for (const b of received()) assert.ok(!b.includes(CARD), "CONFIDENTIALITY VIOLATION: the card reached the model");
  } finally {
    await proxy.close();
    await fake.close();
    await r.stop();
  }
});

for (const agent of [
  { name: "OpenClaw", spec: "openclaw-agent", typed: (t: string) => `Sender (untrusted metadata):\n\`\`\`json\n{"id":"gateway-client"}\n\`\`\`\n\n${ENVELOPE}${t}`, cut: (s: string) => s.slice(s.lastIndexOf(ENVELOPE) + ENVELOPE.length) },
  { name: "OpenCode", spec: "opencode", typed: (t: string) => `<system-reminder>ctx</system-reminder>\n${t}`, cut: (s: string) => s.slice(s.indexOf("\n") + 1) },
] as const) {
  test(`prompt_filters (${agent.name}, the routed Chat Completions wire): redact and mask written back; a card never reaches the model (secrets axes)`, async () => {
    const r = await boot();
    const session = `pf-${agent.spec}-${process.pid}`;
    await r.data.setSessionSpec({ sessionKey: session, spec: agent.spec });
    const fake = await startFakeChat();
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: "http://127.0.0.1:9", openaiUpstreams: { local: `${fake.origin}/v1` }, sessionKey: session, log: () => {} });
    const port = await proxy.listen(0);
    try {
      const body = (t: string) => ({
        model: "local-model", stream: false,
        tools: [{ type: "function", function: { name: "read", parameters: { type: "object" } } }],
        messages: [{ role: "system", content: "you are an agent" }, { role: "user", content: agent.typed(t) }],
      });
      const res = await post(port, "/_mandu/openai/local/chat/completions", body(typed), session);
      assert.equal(res.status, 200, res.body);
      await assertPolicyOracle(r, fake.requests, (b) => agent.cut((JSON.parse(b) as { messages: Array<{ content: string }> }).messages[1]!.content), agent.name);
      const n = fake.requests.length;
      const blocked = await post(port, "/_mandu/openai/local/chat/completions", body(typedCard), session);
      assert.equal(blocked.status, 400, blocked.body);
      assert.match(blocked.body, /pii\.payment-card/);
      assert.equal(fake.requests.length, n, "nothing was sent to the model for it");
      const again = await post(port, "/_mandu/openai/local/chat/completions", { ...body(typedCard), messages: [...body(typedCard).messages, { role: "assistant", content: "?" }, { role: "user", content: agent.typed("say hi") }] }, session);
      assert.equal(again.status, 200, again.body);
      assert.ok(fake.requests.at(-1)!.includes("and pay [blocked: pii.payment-card], now"));
      assert.ok(!fake.requests.some((b) => b.includes(CARD)), "CONFIDENTIALITY VIOLATION: the card reached the model");
    } finally {
      await proxy.close();
      await fake.close();
      await r.stop();
    }
  });
}

test("prompt_filters (Codex, Responses and Chat Completions): redact and mask written back; a card never reaches the model (secrets axes, the real openai-proxy)", async () => {
  const r = await boot();
  const session = `pf-codex-${process.pid}`;
  const fake: ScriptedFake = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const chat = await startFakeChat();
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const chatProxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: chat.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const chatPort = await chatProxy.listen(0);
  try {
    const msg = (text: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });
    const body = (t: string) => ({
      model: "gpt-5", stream: true,
      tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
      input: [msg("<environment_context>\n  <cwd>/w</cwd>\n</environment_context>"), msg(t)],
    });
    const res = await post(port, "/v1/responses", body(typed), session);
    assert.equal(res.status, 200, res.body);
    const received = () => fake.requests.filter((q) => q.url.includes("/responses")).map((q) => q.body);
    await assertPolicyOracle(r, received(), (b) => ((JSON.parse(b) as { input: Array<{ content: Array<{ text: string }> }> }).input[1]!.content[0]!.text), "codex responses");
    const n = received().length;
    const blocked = await post(port, "/v1/responses", body(typedCard), session);
    assert.equal(blocked.status, 400, blocked.body);
    assert.match(blocked.body, /invalid_request_error/);
    assert.equal(received().length, n, "nothing was sent to the model for it");
    const again = await post(port, "/v1/responses", { ...body(typedCard), input: [...body(typedCard).input, msg("say hi")] }, session);
    assert.equal(again.status, 200, again.body);
    assert.ok(received().at(-1)!.includes("and pay [blocked: pii.payment-card], now"));
    assert.ok(!received().some((b) => b.includes(CARD)), "CONFIDENTIALITY VIOLATION: the card reached the model");

    const chatBody = (t: string) => ({
      model: "gpt-5", stream: false,
      tools: [{ type: "function", function: { name: "exec_command", parameters: { type: "object" } } }],
      messages: [{ role: "system", content: "sys" }, { role: "user", content: "<environment_context>\n  <cwd>/w</cwd>\n</environment_context>" }, { role: "user", content: t }],
    });
    const c = await post(chatPort, "/v1/chat/completions", chatBody(typed), session);
    assert.equal(c.status, 200, c.body);
    await assertPolicyOracle(r, chat.requests, (b) => ((JSON.parse(b) as { messages: Array<{ content: string }> }).messages[2]!.content), "codex chat");
  } finally {
    await proxy.close();
    await chatProxy.close();
    await fake.close();
    await chat.close();
    await r.stop();
  }
});

test("prompt_filters FAIL CLOSED (§4.4): a pack the policy turns on but that cannot be loaded refuses the prompt on both proxies (secrets axes)", async () => {
  const r = await boot({ version: 1, prompt_filters: { filters: { "acme-dlp": "on", "missing-pack": "on" } } });
  const fakeA = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const fakeR = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const sa = `pf-fc-a-${process.pid}`;
  await r.data.setSessionSpec({ sessionKey: sa, spec: "claude-code" });
  const a = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: fakeA.origin, sessionKey: sa, log: () => {} });
  const o = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fakeR.origin, log: () => {} });
  const pa = await a.listen(0);
  const po = await o.listen(0);
  try {
    const ra = await post(pa, "/v1/messages", { model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: {} }], messages: [{ role: "user", content: typed }] }, sa);
    assert.notEqual(ra.status, 200);
    assert.match(ra.body, /missing-pack/, "the refusal names the filter that could not run");
    const ro = await post(po, "/v1/responses", { model: "gpt-5", stream: true, tools: [{ type: "function", name: "exec_command", parameters: {} }], input: [{ type: "message", role: "user", content: [{ type: "input_text", text: typed }] }] }, "pf-fc-o");
    assert.notEqual(ro.status, 200);
    assert.ok(!fakeA.requests.some((q) => q.body.includes(GH)) && !fakeR.requests.some((q) => q.body.includes(GH)), "CONFIDENTIALITY VIOLATION: the prompt went to the model unchecked");
    assert.equal(fakeA.requests.filter((q) => q.url.includes("/v1/messages")).length, 0);
  } finally {
    await a.close();
    await o.close();
    await fakeA.close();
    await fakeR.close();
    await r.stop();
  }
});
