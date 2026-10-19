/**
 * prompt-filter-plugin — `model-ingress/prompt` with a classifier PLUGIN, on
 * the real path (confidentiality-plan-15-prompt-filter.md §4.3, §5, §11
 * phase 3).
 *
 *   the agent's request ──► the REAL proxy over HTTP (production adapter:
 *       `new ArbiterClientAdapter(new ArbiterClient(sock))`)
 *     ──► a REAL ArbiterServer (secrets) running a plugin pack pinned to node
 *         and the test plugin (arbiter/test/fixtures/prompt-plugin), which
 *         asks a FAKE local classifier (a `local: true` models: entry on
 *         loopback) which words to find
 *     ──► a scripted fake provider model on loopback, which records every
 *         request.
 *
 * Two plugins: the test plugin, and Mandu's REFERENCE classifier
 * (arbiter/prompt-filter/plugins/local-classifier.mjs, installed by the pack
 * its generator writes). The plugin runs under the test stand-in guard
 * (this lane has no kernel guarantee); tests/sandbox/prompt-plugin-confine.test.ts
 * proves the real confinement. Per proxy (anthropic-proxy for Claude Code,
 * Messages; openai-proxy for Codex, Responses), per plugin:
 *   - the codename the classifier names reaches the provider only as a
 *     symbol (`acme.codename: mask`), and the human plane restores it;
 *   - a REGISTERED value in the same prompt reaches neither the provider
 *     (the floor masks it) nor the classifier (a plugin never reads one);
 *   - fail-closed (§4.4): a plugin that cannot answer in time refuses the
 *     prompt, and nothing reaches the provider;
 *   - a long prompt (the reference classifier reads it in chunks of 6000
 *     characters): a phrase the first cut falls inside is still found, on
 *     both proxies (the chunks overlap; P0 item 13).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { startScriptedResponses } from "../lib/fake-responses.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "arbiter", "test", "fixtures", "prompt-plugin");
const PLUGIN = join(FIX, "fake-plugin.mjs");
const NODE = realpathSync(process.execPath);
const sha = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");

const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb4R";
const CODENAME = "Osprey";
const typed = `deploy ${CODENAME} with ${KEY} please`;

interface Rig {
  data: ArbiterClient;
  human: ArbiterClient;
  classifierSaw: string[];
  stop(): Promise<void>;
}

const GENERATOR = join(FIX, "..", "..", "..", "prompt-filter", "plugins", "local-classifier-pack.mjs");

async function boot(o: { sleep?: number; reference?: boolean; phrase?: string } = {}): Promise<Rig> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-prompt-plugin-"));
  const classifierSaw: string[] = [];
  const classifier = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      classifierSaw.push(body);
      res.setHeader("content-type", "application/json");
      // The reference classifier asks for {findings: [{category, text}]};
      // the test plugin for a list of {word, category}.
      const content = o.reference
        ? JSON.stringify({ findings: body.includes(o.phrase ?? CODENAME) ? [{ category: "acme.codename", text: o.phrase ?? CODENAME }] : [] })
        : JSON.stringify([{ word: CODENAME, category: "acme.codename" }]);
      res.end(JSON.stringify({ choices: [{ message: { content } }] }));
    });
  });
  await new Promise<void>((ok) => classifier.listen(0, "127.0.0.1", ok));
  const port = (classifier.address() as AddressInfo).port;
  const packs = join(tmp, "prompt-filters");
  mkdirSync(packs);
  if (o.reference) {
    const gen = spawnSync(process.execPath, [GENERATOR, "--id", "acme-cls", "--categories", "acme.codename", "--deadline-ms", "5000"], { encoding: "utf8" });
    assert.equal(gen.status, 0, gen.stderr);
    writeFileSync(join(packs, "acme.yaml"), gen.stdout);
  } else writeFileSync(join(packs, "acme.yaml"), [
    "pack: acme-cls", "version: 1", "plugin:",
    `  exec: ${NODE}`, `  sha256: "${sha(NODE)}"`,
    `  script: ${PLUGIN}`, `  script_sha256: "${sha(PLUGIN)}"`,
    `  args: ${JSON.stringify(o.sleep ? ["--sleep", String(o.sleep), "--model"] : ["--model"])}`,
    "  endpoint: required", "  deadline_ms: 1500",
    "categories:", "  - { category: acme.codename, level: no-model }", "",
  ].join("\n"));
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\nmodels:\n  - name: ollama\n    url: http://127.0.0.1:${port}\n    wire: openai-chat\n    model: llama3.2\n    local: true\nprompt_filters:\n  filters:\n    acme-cls: { on: true, endpoint: ollama }\n  actions:\n    acme.codename: mask\n`);
  const sock = join(tmp, "arbiter.sock");
  const humanSock = join(tmp, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null,
    promptPlugins: {
      netGuard: join(FIX, "fake-guard.sh"), landlockApply: null, bwrap: null, dir: join(tmp, "plugins"),
      probe: async () => ({ guard: true, landlock: false, seccomp: false, namespaces: false, notes: ["the stack lane's stand-in guard"] }),
    },
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  return {
    data, human, classifierSaw,
    async stop() {
      data.close();
      human.close();
      await server.close().catch(() => {});
      classifier.close();
      resetCurrentPolicyForTests();
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

async function oracle(r: Rig, received: string[], sent: string, where: string): Promise<void> {
  assert.ok(received.length > 0, `${where}: the model was called`);
  for (const b of received) {
    assert.ok(!b.includes(KEY), `CONFIDENTIALITY VIOLATION (${where}): a registered value reached the provider model raw`);
    assert.ok(!b.includes(CODENAME), `CONFIDENTIALITY VIOLATION (${where}): the codename the classifier found reached the provider model`);
  }
  assert.ok(r.classifierSaw.length > 0, `${where}: the plugin asked its local classifier`);
  for (const b of r.classifierSaw) assert.ok(!b.includes(KEY), `CONFIDENTIALITY VIOLATION (${where}): a registered value reached the classifier model`);
  assert.ok(r.classifierSaw.some((b) => b.includes(CODENAME)), `${where}: the classifier read the prompt (it is cleared for it)`);
  assert.match(sent, /^deploy \$MDU:[^ ]+ with \$MDU:[^ ]+ please$/, `${where}: both reach the provider as symbols: ${sent}`);
  assert.equal(await r.human.desymbolize(sent), typed, `${where}: the human plane restores what was typed`);
}

for (const reference of [false, true]) {
const which = reference ? "the reference classifier" : "the test plugin";

test(`a classifier plugin (${which}; Claude Code, Messages, the real anthropic-proxy): the codename it finds and a registered value reach the provider only as symbols; the classifier never reads the registered value (secrets axes)`, async () => {
  const r = await boot({ reference });
  const session = `pp-cc-${process.pid}`;
  await r.data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const res = await post(port, "/v1/messages", {
      model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
      tools: [{ name: "Read", description: "read", input_schema: { type: "object" } }],
      messages: [{ role: "user", content: [{ type: "text", text: "<system-reminder>\nctx\n</system-reminder>" }, { type: "text", text: typed }] }],
    }, session);
    assert.equal(res.status, 200, res.body);
    const received = fake.requests.filter((q) => q.url.includes("/v1/messages")).map((q) => q.body);
    const sent = (JSON.parse(received.at(-1)!) as { messages: Array<{ content: Array<{ text: string }> }> }).messages[0]!.content[1]!.text;
    await oracle(r, received, sent, "claude-code");
  } finally {
    await proxy.close();
    await fake.close();
    await r.stop();
  }
});

test(`a classifier plugin (${which}; Codex, Responses, the real openai-proxy): the same oracle (secrets axes)`, async () => {
  const r = await boot({ reference });
  const fake = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const proxy = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fake.origin, sessionKey: `pp-codex-${process.pid}`, log: () => {} });
  const port = await proxy.listen(0);
  try {
    const msg = (text: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });
    const res = await post(port, "/v1/responses", {
      model: "gpt-5", stream: true,
      tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
      input: [msg("<environment_context>\n  <cwd>/w</cwd>\n</environment_context>"), msg(typed)],
    }, `pp-codex-${process.pid}`);
    assert.equal(res.status, 200, res.body);
    const received = fake.requests.filter((q) => q.url.includes("/responses")).map((q) => q.body);
    const sent = (JSON.parse(received.at(-1)!) as { input: Array<{ content: Array<{ text: string }> }> }).input[1]!.content[0]!.text;
    await oracle(r, received, sent, "codex");
  } finally {
    await proxy.close();
    await fake.close();
    await r.stop();
  }
});

}

test("a long prompt: the phrase the reference classifier's first 6000-character cut falls inside reaches neither provider (both proxies; secrets axes)", async () => {
  const PHRASE = "Project Heron";
  // 10-character words: the first cut lands on the space inside the phrase.
  const long = `${"lorem ips ".repeat(599)}${PHRASE} ${"tail word ".repeat(400)}`;
  const at = long.indexOf(PHRASE);
  assert.ok(at < 6000 && at + PHRASE.length > 6000, "the phrase straddles the first cut");
  const r = await boot({ reference: true, phrase: PHRASE });
  const fakeA = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const fakeR = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const sa = `pp-long-a-${process.pid}`;
  await r.data.setSessionSpec({ sessionKey: sa, spec: "claude-code" });
  const a = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: fakeA.origin, sessionKey: sa, log: () => {} });
  const o = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fakeR.origin, sessionKey: `pp-long-o-${process.pid}`, log: () => {} });
  const pa = await a.listen(0);
  const po = await o.listen(0);
  try {
    const ra = await post(pa, "/v1/messages", { model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: {} }], messages: [{ role: "user", content: [{ type: "text", text: long }] }] }, sa);
    assert.equal(ra.status, 200, ra.body);
    const ro = await post(po, "/v1/responses", { model: "gpt-5", stream: true, tools: [{ type: "function", name: "exec_command", parameters: {} }], input: [{ type: "message", role: "user", content: [{ type: "input_text", text: long }] }] }, `pp-long-o-${process.pid}`);
    assert.equal(ro.status, 200, ro.body);
    const sentA = fakeA.requests.filter((q) => q.url.includes("/v1/messages")).map((q) => q.body);
    const sentR = fakeR.requests.filter((q) => q.url.includes("/responses")).map((q) => q.body);
    assert.ok(sentA.length > 0 && sentR.length > 0, "both providers were called");
    for (const b of [...sentA, ...sentR]) {
      assert.ok(!b.includes(PHRASE), "CONFIDENTIALITY VIOLATION: a phrase across the classifier's chunk cut reached the provider model raw");
    }
    const text = (JSON.parse(sentA.at(-1)!) as { messages: Array<{ content: Array<{ text: string }> }> }).messages[0]!.content[0]!.text;
    assert.match(text, /lorem ips \$MDU:[^ ]+ tail word/, "the phrase reaches the provider as one symbol");
    assert.equal(await r.human.desymbolize(text), long, "the human plane restores what was typed");
    assert.ok(r.classifierSaw.length >= 2, "the classifier read the prompt in more than one chunk");
  } finally {
    await a.close();
    await o.close();
    await fakeA.close();
    await fakeR.close();
    await r.stop();
  }
});

test("FAIL CLOSED (§4.4): a plugin that misses its deadline refuses the prompt on both proxies; nothing reaches the provider (secrets axes)", async () => {
  const r = await boot({ sleep: 5000 });
  const fakeA = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const fakeR = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const sa = `pp-fc-a-${process.pid}`;
  await r.data.setSessionSpec({ sessionKey: sa, spec: "claude-code" });
  const a = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(r.data), upstreamOrigin: fakeA.origin, sessionKey: sa, log: () => {} });
  const o = new OpenAiProxy({ arbiter: new OpenAiProxyArbiterAdapter(r.data), upstreamOrigin: fakeR.origin, log: () => {} });
  const pa = await a.listen(0);
  const po = await o.listen(0);
  try {
    const ra = await post(pa, "/v1/messages", { model: "claude-sonnet-4-5", stream: true, max_tokens: 64, tools: [{ name: "Read", input_schema: {} }], messages: [{ role: "user", content: typed }] }, sa);
    assert.notEqual(ra.status, 200);
    assert.match(ra.body, /acme-cls/, "the refusal names the filter that could not run");
    const ro = await post(po, "/v1/responses", { model: "gpt-5", stream: true, tools: [{ type: "function", name: "exec_command", parameters: {} }], input: [{ type: "message", role: "user", content: [{ type: "input_text", text: typed }] }] }, "pp-fc-o");
    assert.notEqual(ro.status, 200);
    assert.ok(!fakeA.requests.some((q) => q.body.includes(CODENAME) || q.body.includes(KEY)), "CONFIDENTIALITY VIOLATION: the prompt went to the model unchecked");
    assert.ok(!fakeR.requests.some((q) => q.body.includes(CODENAME) || q.body.includes(KEY)), "CONFIDENTIALITY VIOLATION: the prompt went to the model unchecked");
    assert.equal(fakeA.requests.filter((q) => q.url.includes("/v1/messages")).length, 0);
    assert.equal(fakeR.requests.filter((q) => q.url.includes("/responses")).length, 0);
  } finally {
    await a.close();
    await o.close();
    await fakeA.close();
    await fakeR.close();
    await r.stop();
  }
});
