/**
 * openclaw-plugin-reply — a chat reply from a resident OpenClaw Gateway
 * attached to Mandu, over the REAL components
 * (docs/design/agents/openclaw-plugin.md §3.1, §3.5, §3.6).
 *
 * The stack, real except OpenClaw and the model:
 *   - a real ArbiterServer on the `secrets` axes with a registered secret
 *     (an environment variable's value), the session `openclaw:main` bound
 *     to the `openclaw-agent` spec, as `mandu serve` binds an attachment;
 *   - the real anthropic-proxy in its production wiring for that session (the
 *     proxy the installer routes `openclaw.json` to), in front of a scripted
 *     model that answers with the placeholder it was shown;
 *   - the Mandu OpenClaw plugin registered through its real registrar with
 *     the attachment config `mandu openclaw install` writes, on a fake
 *     OpenClaw api; its arbiter connection is the production one (the real
 *     IPC client on the DATA socket, nothing injected).
 *
 * The oracle (the confidentiality invariant, a chat destination):
 *   1. the model never received the secret (the proxy masked the tool result);
 *   2. the reply the Gateway sends to an UNBOUND chat keeps the placeholder
 *      and never carries the secret (no release op decides a chat today);
 *   3. a reply that does carry the value (a model that was given it) is
 *      cancelled, and neither the cancel reason nor any event holds it;
 *   4. with the arbiter gone, the reply still goes out with its placeholder
 *      only (the hook fails open, which leaves placeholders);
 *   5. the tamper policy refuses `mandu serve stop` through the same plugin.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { registerInspectPlugin } from "../../interceptors/openclaw-inspect-plugin/src/register.js";
import type { OpenClawPluginApiLike } from "../../interceptors/openclaw-inspect-plugin/src/openclaw-api.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality invariant suite pins `secrets`

const KEY = `sk-live-ocp${process.pid}e2e9c4b7a1d3f5e8`;
const SESSION = "openclaw:main";

function post(port: number, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": SESSION } },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

/** The assistant text OpenClaw would assemble from the proxy's SSE. */
function sseText(sse: string): string {
  let out = "";
  for (const line of sse.split("\n")) {
    if (!line.startsWith("data: ")) continue;
    try {
      const ev = JSON.parse(line.slice(6)) as { type?: string; delta?: { type?: string; text?: string } };
      if (ev.type === "content_block_delta" && ev.delta?.type === "text_delta") out += ev.delta.text ?? "";
    } catch { /* not JSON */ }
  }
  return out;
}

type Handler = (event: unknown, ctx: unknown) => unknown;

test("a reply to an unbound chat keeps the placeholder and never carries the secret; a reply with the value is cancelled (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ocp-reply-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const setup = new ArbiterClient(socketPath);
  await setup.connect();
  const human = new ArbiterClient(humanSockIn(tmp));
  await human.connect();
  const proxyClient = new ArbiterClient(socketPath);
  await proxyClient.connect();
  let proxy: AnthropicProxy | null = null;
  try {
    const reg = await setup.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }], sessionKey: SESSION });
    const sym = reg.vars[0]!.symbol!;
    assert.match(sym, /^\$MDU:/);
    assert.equal((await setup.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent", requestedBy: "openclaw-plugin-reply e2e" })).bound, "openclaw-agent");

    // ── the model turn, through the session's proxy ──────────────────────────
    const up = new MockUpstream({ sse: buildTextSse(`Your Stripe key is ${sym}. I kept it as Mandu's placeholder.`) });
    proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(proxyClient), upstream: up.fetcher, sessionKey: SESSION, log: () => {} });
    const port = await proxy.listen(0);
    const r = await post(port, JSON.stringify({
      model: "claude-haiku-4-5",
      stream: true,
      messages: [
        { role: "user", content: "What is my Stripe key? Send it to me here." },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_ocp_1", name: "exec", input: { command: "cat .env" } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ocp_1", content: `STRIPE_API_KEY=${KEY}\n` }] },
      ],
    }));
    assert.equal(r.status, 200, r.body);
    const modelSaw = up.requests.map((q) => JSON.stringify(q.json())).join("\n");
    assert.ok(!modelSaw.includes(KEY), "(1) CONFIDENTIALITY VIOLATION: the model received the secret");
    const replyText = sseText(r.body);
    assert.ok(replyText.includes(sym), `the Gateway's reply text carries the placeholder: ${replyText}`);

    // ── the plugin, as `mandu openclaw install` configures it ────────────────
    const hooks = new Map<string, Handler>();
    const logs: string[] = [];
    const api: OpenClawPluginApiLike = {
      id: "mandu-inspect",
      pluginConfig: { arbiterSock: socketPath, scopeId: SESSION, attachment: true, agentId: "main", manduPaths: [join(tmp, "mandu-home")] },
      logger: { info: (m) => logs.push(m), warn: (m) => logs.push(m), error: (m) => logs.push(m) },
      registerTool: () => {},
      on: (name: string, h: (e: never, c: never) => unknown) => { hooks.set(name, h as Handler); },
    };
    // No U-LLM transport in a test (cliAvailable false): the attachment keeps
    // its hooks and drops inspect_symbol. The arbiter connection is the real one.
    registerInspectPlugin(api, { env: { HOME: tmp }, cliAvailable: () => false });
    const send = hooks.get("message_sending")!;
    const ctx = { channelId: "telegram", accountId: "bot", conversationId: "4242", sessionKey: "agent:main:telegram:4242" };

    // (2) an unbound chat: the placeholder goes out, the secret never does.
    const res = await send({ to: "4242", content: replyText }, ctx) as { content?: string; cancel?: boolean } | undefined;
    const outgoing = res?.content ?? replyText;
    assert.notEqual(res?.cancel, true, "a placeholder is no leak: the reply is sent");
    assert.ok(outgoing.includes(sym), "the placeholder stays in the reply");
    assert.ok(!outgoing.includes(KEY), "(2) CONFIDENTIALITY VIOLATION: a reply to an unbound chat carried the secret");

    // (3) a reply carrying the value is cancelled.
    const leak = await send({ to: "4242", content: `Sure: ${KEY}` }, ctx) as { cancel?: boolean; cancelReason?: string };
    assert.equal(leak?.cancel, true, "(3) a reply with the secret's value must be cancelled");
    assert.ok(!String(leak.cancelReason).includes(KEY));

    // (5) the tamper policy, through the same plugin.
    const tool = hooks.get("before_tool_call")!;
    const blocked = tool({ toolName: "exec", params: { command: "mandu serve stop" }, toolCallId: "toolu_ocp_2" }, { agentId: "main", sessionKey: ctx.sessionKey }) as { block?: boolean };
    assert.equal(blocked?.block, true);

    // The events: claims under openclaw:main, no value anywhere.
    let evs: Array<Record<string, any>> = [];
    for (let i = 0; i < 50 && evs.length < 3; i++) {
      evs = (await human.events(SESSION, 0)) as unknown as Array<Record<string, any>>;
      evs = evs.filter((e) => e.emitter === "openclaw-plugin");
      if (evs.length < 3) await new Promise((res2) => setTimeout(res2, 20));
    }
    assert.equal(evs.length, 3, `kept + cancelled + tamper events: ${JSON.stringify(evs)}`);
    for (const e of evs) {
      assert.equal(e.claimed, true);
      assert.equal(e.openclaw.sessionKey, ctx.sessionKey);
    }
    assert.deepEqual(evs.map((e) => e.policy.ruleRef.id).sort(), ["openclaw:reply:fingerprint", "openclaw:reply:unbound", "openclaw:tamper:mandu-service"]);
    assert.ok(!JSON.stringify(evs).includes(KEY), "no event carries the secret");
    assert.ok(!logs.join("\n").includes(KEY), "no plugin log line carries the secret");

    // (4) the arbiter gone: the reply still goes out with its placeholder only.
    await proxy.close();
    proxy = null;
    proxyClient.close();
    setup.close();
    human.close();
    await server.close();
    const hold = setTimeout(() => {}, 10_000);
    const after = await send({ to: "4242", content: replyText }, ctx) as { content?: string } | undefined;
    clearTimeout(hold);
    const out2 = after?.content ?? replyText;
    assert.ok(out2.includes(sym) && !out2.includes(KEY), "(4) with no arbiter the reply keeps its placeholder");
  } finally {
    if (proxy) await proxy.close().catch(() => {});
    proxyClient.close();
    setup.close();
    human.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ── a reply about a command output the proxy masked whole ─────────────────────
// (openclaw-plugin.md §3.5, the reply scope; live 2026-10-26, demo-notion-token).
// On Route 1 the commands run on the Gateway's host, so no recorder binds a
// call's tree and a path-rule output row keeps every line as a fingerprint.
// The model never sees that output (only its placeholder), so a reply that
// repeats an ordinary line of it (a page title the model also read elsewhere)
// goes out; a reply with the secret, bare or inside the output's line, does not
// (the token's value is a registered one, as the drill's launch scan makes it).
const NOTION = `secret_OcpReplyScope${process.pid}Wq2Zx6Ln3Rt7`;
const TITLE = "Created the page: Team sync, 16 October (14 lines)";

test("a whole-masked command output: a reply repeating its ordinary line is sent; one with the secret, bare or in its line, is cancelled (secrets axes, explicit)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ocp-reply-scope-"));
  const ws = join(tmp, "ws");
  mkdirSync(join(ws, "notes-app"), { recursive: true });
  const env = join(ws, "notes-app", ".env");
  writeFileSync(env, `NOTION_TOKEN='${NOTION}'\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${env}`, "    level: no-model", "    bindings: [api.notion.com]", ""].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  const setup = new ArbiterClient(socketPath);
  await setup.connect();
  const proxyClient = new ArbiterClient(socketPath);
  await proxyClient.connect();
  const human = new ArbiterClient(humanSockIn(tmp));
  await human.connect();
  let proxy: AnthropicProxy | null = null;
  try {
    assert.equal((await setup.setSessionSpec({ sessionKey: SESSION, spec: "openclaw-agent", requestedBy: "openclaw-plugin-reply e2e" })).bound, "openclaw-agent");
    // the labelled file's value is registered (the launch's scan, as in the drill)
    const reg = await human.registerSecret({ path: env, sessionKey: SESSION });
    assert.ok(typeof reg.symbol === "string", JSON.stringify(reg));
    const output = `${TITLE}\nposted with token ${NOTION} to the notes page\n`;
    const up = new MockUpstream({ sse: buildTextSse(`Added the notes to Notion as a new page: **${TITLE}**.`) });
    proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(proxyClient), upstream: up.fetcher, sessionKey: SESSION, log: () => {} });
    const port = await proxy.listen(0);
    const r = await post(port, JSON.stringify({
      model: "claude-haiku-4-5",
      stream: true,
      messages: [
        { role: "user", content: "Show me notes-app/.env, then put my meeting notes into Notion." },
        // OpenClaw's `read` runs in the Gateway on Route 1: the proxy alone masks it
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_ocp_r0", name: "read", input: { path: env } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ocp_r0", content: `NOTION_TOKEN='${NOTION}'\n` }] },
        { role: "assistant", content: [{ type: "tool_use", id: "toolu_ocp_s1", name: "exec", input: { command: `. ${env} && sh ${join(ws, "notes-app", "add-page.sh")}` } }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_ocp_s1", content: output }] },
      ],
    }));
    assert.equal(r.status, 200, r.body);
    const modelSaw = up.requests.map((q) => JSON.stringify(q.json())).join("\n");
    assert.ok(!modelSaw.includes(NOTION), "CONFIDENTIALITY VIOLATION: the model received the token");
    assert.ok(!modelSaw.includes("16 October"), `the proxy masked the command's whole output (the premise): ${modelSaw.slice(-600)}`);
    // the whole-file read says what its symbol is (confidentiality.md §7, "A protected file read whole")
    assert.ok(modelSaw.includes(`masked: ${env} is a protected file that no AI model may read`), `the read's note: ${modelSaw.slice(0, 1500)}`);

    const hooks = new Map<string, Handler>();
    const api: OpenClawPluginApiLike = {
      id: "mandu-inspect",
      pluginConfig: { arbiterSock: socketPath, scopeId: SESSION, attachment: true, agentId: "main", manduPaths: [join(tmp, "mandu-home")] },
      logger: { info: () => {}, warn: () => {}, error: () => {} },
      registerTool: () => {},
      on: (name: string, h: (e: never, c: never) => unknown) => { hooks.set(name, h as Handler); },
    };
    registerInspectPlugin(api, { env: { HOME: tmp }, cliAvailable: () => false });
    const send = hooks.get("message_sending")!;
    const ctx = { channelId: "telegram", conversationId: "77", sessionKey: "agent:main:telegram:77" };

    const harmless = sseText(r.body);
    assert.ok(harmless.includes(TITLE), harmless);
    const ok = await send({ to: "77", content: harmless }, ctx) as { cancel?: boolean } | undefined;
    assert.notEqual(ok?.cancel, true, "a reply repeating an ordinary line of the masked output is no leak: it is sent");

    const bare = await send({ to: "77", content: `The token is ${NOTION}.` }, ctx) as { cancel?: boolean; cancelReason?: string };
    assert.equal(bare?.cancel, true, "CONFIDENTIALITY VIOLATION: a reply with the token went to the chat");
    assert.ok(!String(bare.cancelReason).includes(NOTION));
    const inLine = await send({ to: "77", content: `It printed: posted with token ${NOTION} to the notes page` }, ctx) as { cancel?: boolean };
    assert.equal(inLine?.cancel, true, "CONFIDENTIALITY VIOLATION: a reply with the output's line carrying the token went to the chat");
  } finally {
    if (proxy) await proxy.close().catch(() => {});
    proxyClient.close();
    setup.close();
    human.close();
    await server.close().catch(() => {});
    rmSync(tmp, { recursive: true, force: true });
  }
});
