/**
 * prompt-filter-ask-openclaw-opencode — OpenClaw's and OpenCode's own `ask`
 * e2e (confidentiality-plan-15-prompt-filter.md §7, phase 3; §13.6 items 13,
 * 14, 16): a prompt the policy asks about is HELD in the real anthropic-proxy
 * until the human answers on the admin channel, on every wire these two
 * agents use as the launcher wires them today:
 *
 *   - the Anthropic Messages wire (`/v1/messages`), their default: both speak
 *     genuine Anthropic Messages (OpenCode through `@ai-sdk/anthropic`), with
 *     the session's gate surface naming the agent (`openclaw-agent`,
 *     `opencode`) so the proxy cuts the prompt by THAT agent's segmenter
 *     rules: OpenClaw's sender header and wall-clock envelope are the
 *     harness's, the text after the envelope the human's; OpenCode's typed
 *     part is the human's;
 *   - the anthropic-proxy's routed Chat Completions wire
 *     (`/_mandu/openai/<id>/chat/completions`, agent-e2e-harness.md §9), where
 *     an OpenAI-family provider of either agent goes.
 *
 *   the agent's request ──► the REAL AnthropicProxy over HTTP (production
 *       wiring: `new ArbiterClientAdapter(new ArbiterClient(sock),
 *       new ArbiterClient(humanSock))`, its `filterPrompt` counted)
 *     ──► a scripted fake model on loopback, which records every request.
 *
 * Per agent and wire, with a real ArbiterServer in `secrets` (a pack finds the
 * code name `falconridgeproject`, `acme.codename: ask`; the environment
 * registers a key the same message carries):
 *   - while held NOTHING reaches the model; an answer from the data or the
 *     human socket is refused and releases nothing;
 *   - "send as written": the code name as typed, the registered key ONLY as
 *     its symbol;
 *   - "send masked": the model receives neither;
 *   - "cancel": a 400 the agent shows, nothing sent, and the next turn
 *     carries the message masked: a cancelled span never reaches the model;
 *   - the agent hanging up while held: the proxy stops asking at once, sends
 *     nothing, the hold stays pending, an answer given then releases nothing,
 *     and it decides the agent's retry.
 * OpenCode's title call (no tools) quoting the prompt is not held and never
 * carries the code name or the key raw while the main request waits.
 *
 * Mock upstream, no live model, no API key. The real agents' own runs
 * (`openclaw` / `opencode` binaries) are the drill suite's.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { stateAxes } from "../lib/axes.js";
import {
  boot, cancelled, CODENAME, countAsks, disconnectWhileHeld, ENVELOPE, heldThenAnswered, KEY, OPENCLAW_SENDER,
  pendingHold, post, postThenDrop, startFakeChat, typed, type Family, type Rig,
} from "../lib/prompt-hold-rig.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

type Agent = "OpenClaw" | "OpenCode";
const SPEC: Record<Agent, string> = { OpenClaw: "openclaw-agent", OpenCode: "opencode" };

/** The human's typed text as the agent puts it in a user turn. */
const wrapFor = (agent: Agent) => (agent === "OpenClaw"
  ? (t: string) => `${OPENCLAW_SENDER}${ENVELOPE}${t}`
  : (t: string) => t);

/** The agent on the Anthropic Messages wire (its default). */
async function messagesFamily(r: Rig, agent: Agent, session: string): Promise<Family> {
  await r.data.setSessionSpec({ sessionKey: session, spec: SPEC[agent] });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const { adapter, asks } = countAsks(new ArbiterClientAdapter(r.data, r.human));
  const proxy = new AnthropicProxy({ arbiter: adapter, upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const wrap = wrapFor(agent);
  const tools = agent === "OpenClaw"
    ? [{ name: "read", description: "Read a file", input_schema: { type: "object" } }, { name: "exec", description: "Run a command", input_schema: { type: "object" } }]
    : [{ name: "read", description: "Read a file", input_schema: { type: "object" } }, { name: "bash", description: "Run a command", input_schema: { type: "object" } }];
  const body = (text: string, history: string[] = []) => ({
    model: "claude-sonnet-4-5", stream: true, max_tokens: 1024,
    system: [{ type: "text", text: agent === "OpenClaw" ? "You are a personal assistant running inside OpenClaw." : "You are opencode, an interactive CLI tool." }],
    tools,
    messages: [
      ...history.flatMap((h) => [{ role: "user", content: [{ type: "text", text: wrap(h) }] }, { role: "assistant", content: [{ type: "text", text: "(error)" }] }]),
      { role: "user", content: [{ type: "text", text: wrap(text) }] },
    ],
  });
  const fam: Family = {
    name: `${agent} (Messages)`, session,
    send: (text, history) => post(port, "/v1/messages", body(text, history), session),
    sendThenDrop: (text, history) => postThenDrop(port, "/v1/messages", body(text, history), session),
    asks,
    received: () => fake.requests.filter((q) => q.url.includes("/v1/messages") && q.body.includes('"tools"')).map((q) => q.body),
    close: async () => { await proxy.close(); await fake.close(); },
  };
  if (agent === "OpenCode") {
    // OpenCode's title generator: a small-model call with no tools that
    // quotes the first message.
    fam.sideCall = async (text) => {
      const res = await post(port, "/v1/messages", {
        model: "claude-haiku-4-5", stream: false, max_tokens: 32,
        system: [{ type: "text", text: "You are a title generator. You output ONLY a thread title." }],
        messages: [{ role: "user", content: "Generate a title for this conversation:\n" }, { role: "user", content: text }],
      }, session);
      const title = fake.requests.filter((q) => !q.body.includes('"tools"')).at(-1)!.body;
      assert.ok(!title.includes(CODENAME) && !title.includes(KEY), `CONFIDENTIALITY VIOLATION: OpenCode's title call carried the code name or the key raw: ${title}`);
      return res;
    };
  }
  return fam;
}

/** The agent's OpenAI-family provider on the routed Chat Completions wire. */
async function chatFamily(r: Rig, agent: Agent, session: string): Promise<Family> {
  await r.data.setSessionSpec({ sessionKey: session, spec: SPEC[agent] });
  const fake = await startFakeChat();
  const { adapter, asks } = countAsks(new ArbiterClientAdapter(r.data, r.human));
  const proxy = new AnthropicProxy({ arbiter: adapter, upstreamOrigin: "http://127.0.0.1:9", openaiUpstreams: { local: `${fake.origin}/v1` }, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  // OpenCode's typed text on this wire, after a reminder part of its own.
  const wrap = agent === "OpenClaw" ? wrapFor(agent) : (t: string) => `<system-reminder>ctx</system-reminder>\n${t}`;
  const body = (t: string, history: string[] = []) => ({
    model: "local-model", stream: false,
    tools: [{ type: "function", function: { name: "read", parameters: { type: "object" } } }],
    messages: [
      { role: "system", content: "you are an agent" },
      ...history.flatMap((h) => [{ role: "user", content: wrap(h) }, { role: "assistant", content: "?" }]),
      { role: "user", content: wrap(t) },
    ],
  });
  const path = "/_mandu/openai/local/chat/completions";
  return {
    name: `${agent} (routed Chat Completions)`, session,
    send: (text, history) => post(port, path, body(text, history), session),
    sendThenDrop: (text, history) => postThenDrop(port, path, body(text, history), session),
    asks,
    received: () => fake.requests,
    close: async () => { await proxy.close(); await fake.close(); },
  };
}

for (const agent of ["OpenClaw", "OpenCode"] as const) {
  for (const wire of ["Messages", "routed Chat Completions"] as const) {
    test(`ask (${agent}, the ${wire} wire): held until the admin answers; send as written / masked / cancel; a hang-up while held stops the poll and sends nothing (secrets axes)`, async () => {
      const r = await boot();
      const session = `ask-${agent}-${wire === "Messages" ? "msg" : "chat"}-${process.pid}`;
      const f = wire === "Messages" ? await messagesFamily(r, agent, session) : await chatFamily(r, agent, session);
      try {
        await heldThenAnswered(r, f);
        await cancelled(r, f);
        await disconnectWhileHeld(r, f);
      } finally {
        await f.close();
        await r.stop();
      }
    });
  }
}

test("ask (OpenCode, Messages): its title call quoting the prompt is not held while the main request waits (secrets axes)", async () => {
  const r = await boot();
  const f = await messagesFamily(r, "OpenCode", `ask-opencode-title-${process.pid}`);
  try {
    const n = f.received().length;
    const p = f.send(typed(3));
    const id = await pendingHold(r, f.session, new Set());
    const t = await f.sideCall!(typed(3));
    assert.equal(t.status, 200, t.body);
    assert.equal(f.received().length, n, "the main request is still held");
    await r.admin.resolvePromptHold({ approvalId: id, answer: "mask", scope: "once" });
    assert.equal((await p).status, 200);
    assert.ok(!f.received().at(-1)!.includes(`${CODENAME} build 3`), "masked");
  } finally {
    await f.close();
    await r.stop();
  }
});
