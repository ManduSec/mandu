/**
 * prompt-filter-hold — `ask` and the Inbox hold on the real path
 * (confidentiality-plan-15-prompt-filter.md §7, phase 3; §13.5): a prompt the
 * policy asks about is HELD in the real proxy until the human answers on the
 * human plane, on each agent family's wire.
 *
 *   the agent's request ──► the REAL proxy over HTTP (production wiring:
 *       `new ArbiterClientAdapter(new ArbiterClient(sock), new ArbiterClient(humanSock))`)
 *     ──► a scripted fake model on loopback, which records every request.
 *
 * The policy (a real ArbiterServer in `secrets` with data, human and admin
 * sockets): a pack `acme-dlp` finds the code name `falcon` (level
 * `local-model`), `acme.codename: ask`; the session's environment registers
 * a key (the rig: tests/lib/prompt-hold-rig.ts). The typed prompt holds
 * both. Per family (Claude Code on Messages; Codex on the openai-proxy's
 * Responses and Chat Completions; OpenClaw and OpenCode, on Messages and the
 * anthropic-proxy's routed Chat Completions wire, have their own file,
 * prompt-filter-ask-openclaw-opencode.test.ts):
 *   - while held, NOTHING reaches the model; an answer from the data or the
 *     human socket is refused (only the admin channel, the dashboard's,
 *     answers), so the request stays held;
 *   - "send as written": the model receives the code name as typed, and the
 *     registered key ONLY as its symbol (a registered value never goes
 *     raw through the prompt filter, whatever the answer);
 *   - "send masked": the model receives neither.
 * Claude Code and Codex also: a title side call quoting the prompt is not
 * held and carries the code name redacted while the main request waits;
 * "cancel" is a 400 the agent shows, nothing sent, and the next turn carries
 * the message masked; no answer within the deadline sends it masked; and a
 * proxy with no human-plane client is never held (the default, masked).
 * On each of the three routes, the agent hanging up while held (plan 15
 * §13.6 item 13) stops the proxy's poll at once and sends nothing; the hold
 * stays pending, an answer given then releases nothing, and it decides the
 * agent's retry.
 * Under a LOCKED administrator's `ask` row (plan 15 §12, 2026-10-04) the hold
 * takes this message only: a session answer on either admin route is
 * refused while the request stays held, and the next message is held again;
 * on both proxies the session's own `prompt_filter` event names the finding
 * `onceOnly` (the arbiter's word, which the dashboard reads to offer no
 * session "let it through"), and a session let-through by its reference is
 * refused while once is taken.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter as OpenAiProxyArbiterAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { startScriptedResponses } from "../lib/fake-responses.js";
import { stateAxes } from "../lib/axes.js";
import {
  boot, CODENAME, countAsks, disconnectWhileHeld, heldThenAnswered, KEY, noRaw, pendingHold, post, postThenDrop,
  startFakeChat, typed, waitFor, type Family, type Rig,
} from "../lib/prompt-hold-rig.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default, stated

async function cancelTimeoutAndNoHumanPlane(r: Rig, f: Family, mkDataOnly: () => Promise<Family>): Promise<void> {
  const seen = new Set<string>();
  // The title side call while the main request is held: not held, redacted.
  if (f.sideCall) {
    const p = f.send(typed(3));
    const id = await pendingHold(r, f.session, seen);
    const t = await f.sideCall(typed(3));
    assert.equal(t.status, 200, t.body);
    await r.admin.resolvePromptHold({ approvalId: id, answer: "mask", scope: "once" });
    assert.equal((await p).status, 200);
  }
  // Cancel: a 400 the agent shows; nothing sent; the next turn carries it masked.
  const n = f.received().length;
  const p4 = f.send(typed(4));
  const id4 = await pendingHold(r, f.session, seen);
  await r.admin.resolvePromptHold({ approvalId: id4, answer: "cancel" });
  const c = await p4;
  assert.equal(c.status, 400, c.body);
  assert.match(c.body, /You cancelled this message in Mandu's Inbox/);
  assert.equal(f.received().length, n, `${f.name}: nothing was sent for a cancelled message`);
  const next = await f.send("say hi", [typed(4)]);
  assert.equal(next.status, 200, next.body);
  assert.ok(!f.received().at(-1)!.includes(`${CODENAME} build 4`), `${f.name}: the cancelled message is resent masked`);
  // A proxy with no human-plane client is never held: the default.
  const d = await mkDataOnly();
  try {
    const res = await d.send(typed(5));
    assert.equal(res.status, 200, res.body);
    assert.ok(!d.received().at(-1)!.includes(`${CODENAME} build 5`), `${f.name}: masked by default without the human plane`);
    noRaw(d.received(), `${f.name} (data socket only)`);
  } finally {
    await d.close();
  }
  for (const b of f.received()) {
    assert.ok(!b.includes(`${CODENAME} build 2`) && !b.includes(`${CODENAME} build 4`), `CONFIDENTIALITY VIOLATION (${f.name}): a span the human did not send as written reached the model`);
  }
  noRaw(f.received(), f.name);
}

// ── the families ──────────────────────────────────────────────────────────────
// OpenClaw and OpenCode, on both of their wires: prompt-filter-ask-openclaw-opencode.test.ts.

async function claudeCode(r: Rig, session: string, withHuman = true): Promise<Family> {
  await r.data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const { adapter, asks } = countAsks(new ArbiterClientAdapter(r.data, withHuman ? r.human : undefined));
  const proxy = new AnthropicProxy({ arbiter: adapter, upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const body = (text: string, history: string[] = []) => ({
    model: "claude-sonnet-4-5", stream: true, max_tokens: 256,
    tools: [{ name: "Read", description: "read", input_schema: { type: "object" } }],
    messages: [
      ...history.flatMap((h) => [{ role: "user", content: [{ type: "text", text: h }] }, { role: "assistant", content: [{ type: "text", text: "(error)" }] }]),
      { role: "user", content: [{ type: "text", text: "<system-reminder>\nctx\n</system-reminder>" }, { type: "text", text }] },
    ],
  });
  return {
    name: "Claude Code", session,
    send: (text, history) => post(port, "/v1/messages", body(text, history), session),
    sendThenDrop: (text, history) => postThenDrop(port, "/v1/messages", body(text, history), session),
    asks,
    received: () => fake.requests.filter((q) => q.url.includes("/v1/messages") && q.body.includes('"tools"')).map((q) => q.body),
    sideCall: async (text) => {
      const res = await post(port, "/v1/messages", { model: "claude-haiku-4-5", stream: false, max_tokens: 32, messages: [{ role: "user", content: `Write a 5-word title for: ${text}` }] }, session);
      const title = fake.requests.filter((q) => !q.body.includes('"tools"')).at(-1)!.body;
      // Redacted (ask on side-call text), or masked by the floor once the
      // default's own row exists: never raw, never held.
      assert.ok(!title.includes(CODENAME) && !title.includes(KEY), `CONFIDENTIALITY VIOLATION: the title side call carried the code name or the key raw: ${title}`);
      assert.match(title, /\[redacted: acme\.codename\]|\$MDU:localmodel_prompt_filter/, title);
      return res;
    },
    close: async () => { await proxy.close(); await fake.close(); },
  };
}

async function codex(r: Rig, session: string, withHuman = true): Promise<Family> {
  const fake = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const { adapter, asks } = countAsks(new OpenAiProxyArbiterAdapter(r.data, withHuman ? r.human : undefined));
  const proxy = new OpenAiProxy({ arbiter: adapter, upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const msg = (text: string) => ({ type: "message", role: "user", content: [{ type: "input_text", text }] });
  const body = (t: string, history: string[] = []) => ({
    model: "gpt-5", stream: true,
    tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
    input: [msg("<environment_context>\n  <cwd>/w</cwd>\n</environment_context>"), ...history.map(msg), msg(t)],
  });
  return {
    name: "Codex (Responses)", session,
    send: (text, history) => post(port, "/v1/responses", body(text, history), session),
    sendThenDrop: (text, history) => postThenDrop(port, "/v1/responses", body(text, history), session),
    asks,
    received: () => fake.requests.filter((q) => q.url.includes("/responses") && q.body.includes('"tools"')).map((q) => q.body),
    close: async () => { await proxy.close(); await fake.close(); },
  };
}

async function codexChat(r: Rig, session: string): Promise<Family> {
  const fake = await startFakeChat();
  const { adapter, asks } = countAsks(new OpenAiProxyArbiterAdapter(r.data, r.human));
  const proxy = new OpenAiProxy({ arbiter: adapter, upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const port = await proxy.listen(0);
  const body = (t: string, history: string[] = []) => ({
    model: "gpt-5", stream: false,
    tools: [{ type: "function", function: { name: "exec_command", parameters: { type: "object" } } }],
    messages: [{ role: "system", content: "sys" }, { role: "user", content: "<environment_context>\n  <cwd>/w</cwd>\n</environment_context>" },
      ...history.flatMap((h) => [{ role: "user", content: h }, { role: "assistant", content: "?" }]), { role: "user", content: t }],
  });
  return {
    name: "Codex (Chat Completions)", session,
    send: (text, history) => post(port, "/v1/chat/completions", body(text, history), session),
    sendThenDrop: (text, history) => postThenDrop(port, "/v1/chat/completions", body(text, history), session),
    asks,
    received: () => fake.requests,
    close: async () => { await proxy.close(); await fake.close(); },
  };
}

// ── the tests ─────────────────────────────────────────────────────────────────

test("ask (Claude Code, Messages): held until the human answers on the admin channel; send / mask / cancel; the title call is not held; no human plane, no hold (secrets axes)", async () => {
  const r = await boot();
  const session = `hold-cc-${process.pid}`;
  const f = await claudeCode(r, session);
  try {
    await heldThenAnswered(r, f);
    await cancelTimeoutAndNoHumanPlane(r, f, () => claudeCode(r, `hold-cc-data-${process.pid}`, false));
  } finally {
    await f.close();
    await r.stop();
  }
});

test("ask: the agent hanging up while held stops the poll and sends nothing, on Claude Code's Messages and Codex's Responses and Chat Completions; the hold stays for the retry (secrets axes)", async () => {
  const r = await boot();
  const fams = [
    await claudeCode(r, `hold-drop-cc-${process.pid}`),
    await codex(r, `hold-drop-codex-${process.pid}`),
    await codexChat(r, `hold-drop-codex-chat-${process.pid}`),
  ];
  try {
    for (const f of fams) await disconnectWhileHeld(r, f);
  } finally {
    for (const f of fams) await f.close();
    await r.stop();
  }
});

test("ask (Codex, Responses and Chat Completions): held until the human answers; send / mask / cancel; no human plane, no hold (secrets axes)", async () => {
  const r = await boot();
  const f = await codex(r, `hold-codex-${process.pid}`);
  const c = await codexChat(r, `hold-codex-chat-${process.pid}`);
  try {
    await heldThenAnswered(r, f);
    await cancelTimeoutAndNoHumanPlane(r, f, () => codex(r, `hold-codex-data-${process.pid}`, false));
    await heldThenAnswered(r, c);
  } finally {
    await f.close();
    await c.close();
    await r.stop();
  }
});

test("ask under a locked administrator's row (Claude Code): a session answer is refused while held, this message goes, the next message is held again (secrets axes)", async () => {
  const r = await boot(20_000, { lockedAsk: true });
  const f = await claudeCode(r, `hold-locked-${process.pid}`);
  try {
    const seen = new Set<string>();
    const n0 = f.received().length;
    const p1 = f.send(typed(1));
    const id1 = await pendingHold(r, f.session, seen);
    assert.equal((await r.human.promptHolds()).holds.find((h) => h.approvalId === id1)!.onceOnly, true, "the Inbox card: this message only");
    await assert.rejects(() => r.admin.resolvePromptHold({ approvalId: id1, answer: "send", scope: "session" }), /answer it for this message only/);
    await assert.rejects(() => r.admin.resolveEgressApproval(id1, true, "always"), /answer it for this message only/);
    await new Promise((res) => setTimeout(res, 700));
    assert.equal(f.received().length, n0, "a refused session answer releases nothing: still held");
    await r.admin.resolvePromptHold({ approvalId: id1, answer: "send", scope: "once" });
    const ok1 = await p1;
    assert.equal(ok1.status, 200, ok1.body);
    assert.ok(f.received().at(-1)!.includes(`deploy ${CODENAME} build 1 with $MDU:`), "this message, as written (the key as its symbol)");
    // The next message with the code name: held again, nothing sent meanwhile.
    const n1 = f.received().length;
    const p2 = f.send(typed(2), [typed(1)]);
    const id2 = await pendingHold(r, f.session, seen);
    assert.notEqual(id2, id1);
    assert.equal(f.received().length, n1, "the next message is held again");
    await r.admin.resolvePromptHold({ approvalId: id2, answer: "mask", scope: "once" });
    assert.equal((await p2).status, 200);
    assert.ok(!f.received().at(-1)!.includes(`${CODENAME} build 2`), "masked");
    noRaw(f.received(), f.name);
    // The proxy's event carries the arbiter's lock, which the dashboard reads
    // to offer no session let-through; the arbiter refuses one anyway.
    await lockedFindingEvent(r, f);
  } finally {
    await f.close();
    await r.stop();
  }
});

type PfEvent = { kind: string; claimed?: true; promptFilter?: { origin: string; turn?: string; findings: Array<{ category: string; ref?: string; onceOnly?: true; hold?: { state: string } }> } };

/** Plan 15 §12 (2026-10-04): the session's own `prompt_filter` event names
 *  the locked finding `onceOnly` (the arbiter's word, copied by the proxy);
 *  a session let-through by its reference is refused, once is not. */
async function lockedFindingEvent(r: Rig, f: Family): Promise<void> {
  const ev = await waitFor(`${f.name}: a prompt_filter event with the locked finding`, async () => {
    const events = (await r.human.events(f.session)) as unknown as PfEvent[];
    return events.find((e) => e.kind === "prompt_filter" && e.claimed !== true && e.promptFilter?.origin === "human"
      && e.promptFilter.findings.some((x) => x.category === "acme.codename" && x.hold?.state === "masked"));
  });
  const found = ev.promptFilter!.findings.find((x) => x.category === "acme.codename")!;
  assert.equal(found.onceOnly, true, `${f.name}: the event's finding says this message only`);
  assert.match(found.ref ?? "", /^[0-9a-f]{32}$/);
  assert.ok(!JSON.stringify(ev).includes(KEY) && !JSON.stringify(ev).includes(CODENAME), `${f.name}: the event never carries the value`);
  await assert.rejects(() => r.admin.letPromptFindingThrough({ session: f.session, category: found.category, ref: found.ref!, scope: "session" }), /answer it for this message only/);
  await r.admin.letPromptFindingThrough({ session: f.session, category: found.category, ref: found.ref!, turn: ev.promptFilter!.turn!, scope: "once" });
}

test("ask under a locked administrator's row (Codex, the openai-proxy): the event's finding says onceOnly; a session let-through is refused (secrets axes)", async () => {
  const r = await boot(20_000, { lockedAsk: true });
  const f = await codex(r, `hold-locked-codex-${process.pid}`);
  try {
    const p = f.send(typed(2));
    const id = await pendingHold(r, f.session, new Set());
    await assert.rejects(() => r.admin.resolvePromptHold({ approvalId: id, answer: "send", scope: "session" }), /answer it for this message only/);
    await r.admin.resolvePromptHold({ approvalId: id, answer: "mask", scope: "once" });
    assert.equal((await p).status, 200);
    await lockedFindingEvent(r, f);
    noRaw(f.received(), f.name);
  } finally {
    await f.close();
    await r.stop();
  }
});

test("ask: no answer within the deadline sends the default (masked) on both proxies, and the row waits in the Inbox (secrets axes)", async () => {
  const r = await boot(1_200);
  const a = await claudeCode(r, `hold-to-a-${process.pid}`);
  const o = await codex(r, `hold-to-o-${process.pid}`);
  try {
    for (const f of [a, o]) {
      const t0 = Date.now();
      const res = await f.send(typed(6));
      assert.equal(res.status, 200, res.body);
      assert.ok(Date.now() - t0 >= 1_000, `${f.name}: the request was held for the deadline`);
      const sent = f.received().at(-1)!;
      assert.ok(!sent.includes(`${CODENAME} build 6`), `${f.name}: no answer → masked: ${sent}`);
      noRaw(f.received(), f.name);
      // The resend goes at once (the deadline runs from the first sighting).
      const t1 = Date.now();
      assert.equal((await f.send("next", [typed(6)])).status, 200);
      assert.ok(Date.now() - t1 < 1_000, `${f.name}: a resend after the deadline is not held again`);
    }
    const pending = (await r.human.promptHolds()).holds;
    assert.equal(pending.length, 2, "the rows wait for an answer that applies to the next resend");
  } finally {
    await a.close();
    await o.close();
    await r.stop();
  }
});
