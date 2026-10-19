/**
 * prompt-filter-block — the anthropic-proxy's handling of the prompt
 * filter's phase-2 answers (src/prompt-filter.ts, src/rewrite-request.ts;
 * confidentiality-plan-15-prompt-filter.md §7).
 *
 * Proves, through rewriteRequest with a mock `filterPrompt` that answers as
 * the arbiter's policy does:
 *   - `redact` reaches the model as `[redacted: <category>]`;
 *   - `block` refuses the request the FIRST time its spans are seen
 *     (RewriteBlocked, still a RewriteRefusal, with the arbiter's reason and
 *     the report for the events); the same spans in a later request are
 *     forwarded with the arbiter's safe text (`[blocked: <category>]`), never
 *     raw, once the human has written after them (the agent's own retry of
 *     the same message is refused again); a new blocked span refuses again;
 *   - a token count forwards the safe text and does not count as the human
 *     having been told;
 *   - a block with NO safe text (a filter that could not run) refuses every
 *     time, even a token count;
 *   - without a ledger (a caller that keeps none) every block refuses;
 *   - the OpenAI-family shadow (OpenClaw, Chat Completions) blocks the same way.
 *
 * Axes: secrets (the mock answers as the arbiter does with confidentiality ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PromptBlockLedger, blockKeys } from "../../src/prompt-filter.js";
import { rewriteRequest, RewriteBlocked, RewriteRefusal } from "../../src/rewrite-request.js";
import { chatShadow } from "../../src/openai-wire.js";
import { UNION_GATE_SURFACE, type GateSurface } from "../../src/gate-surface.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import { policyFilter } from "../helpers/mock-prompt-filter.js";

const CARD = "4111 1111 1111 1111";
const TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const rules = [
  { needle: CARD, category: "pii.payment-card", action: "block" as const },
  { needle: TOKEN, category: "secret.shape.github-token", action: "redact" as const },
];

function conversation(...turns: string[]): MessagesRequest {
  return { model: "claude-sonnet-4-5", tools: [{ name: "Read" }], messages: turns.map((t) => ({ role: "user" as const, content: [{ type: "text" as const, text: t }] })) };
}
const textOf = (r: MessagesRequest, i: number): string => (r.messages[i]!.content as Array<{ text: string }>)[0]!.text;

test("redact reaches the model as [redacted: <category>]", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: policyFilter(rules) });
  const { request } = await rewriteRequest(conversation(`push ${TOKEN} now`), { arbiter, skipPromptInjection: true, sessionKey: "s" });
  assert.equal(textOf(request, 0), "push [redacted: secret.shape.github-token] now");
});

test("block: refused the first time with the arbiter's reason; the same spans later go as the safe text; a new one refuses again", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: policyFilter(rules) });
  const ledger = new PromptBlockLedger();
  const opts = { arbiter, skipPromptInjection: true, sessionKey: "s", promptBlockLedger: ledger };
  const first = `pay ${CARD} with ${TOKEN}`;
  await assert.rejects(rewriteRequest(conversation(first), opts), (e: unknown) => {
    assert.ok(e instanceof RewriteBlocked && e instanceof RewriteRefusal, "a block is a refusal");
    assert.match(e.message, /Mandu blocked this prompt: it contains pii\.payment-card \(acme-dlp\)/);
    assert.ok(!e.message.includes(CARD));
    assert.deepEqual(e.report.segments.map((s) => s.action), ["block"]);
    return true;
  });
  // The agent keeps the refused message and sends the next turn after it.
  const { request } = await rewriteRequest(conversation(first, "sorry, just say hi"), opts);
  assert.equal(textOf(request, 0), "pay [blocked: pii.payment-card] with [redacted: secret.shape.github-token]");
  assert.equal(textOf(request, 1), "sorry, just say hi");
  assert.ok(!JSON.stringify(request).includes(CARD) && !JSON.stringify(request).includes(TOKEN));
  // Another card (a different span) is refused on its own first sighting.
  await assert.rejects(rewriteRequest(conversation(first, "and 4012 8888 8888 1881 too"), {
    ...opts, arbiter: new MockArbiter({ filterPromptFn: policyFilter([...rules, { needle: "4012 8888 8888 1881", category: "pii.payment-card", action: "block" }]) }),
  }), RewriteBlocked);
  // The ledger keys are per session: another session is refused once too.
  await assert.rejects(rewriteRequest(conversation(first), { ...opts, sessionKey: "other" }), RewriteBlocked);
  assert.equal(blockKeys("s", first, [{ start: 4, end: 4 + CARD.length, category: "pii.payment-card", filterId: "acme-dlp", action: "block" }])[0]!.includes(CARD), false, "a key holds a hash, never the span");
});

test("a token count forwards the safe text and does not count as told", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: policyFilter(rules) });
  const ledger = new PromptBlockLedger();
  const turn = conversation(`pay ${CARD}`);
  const counted = await rewriteRequest(turn, { arbiter, skipPromptInjection: true, sessionKey: "s", promptBlockLedger: ledger, promptCountOnly: true });
  assert.equal(textOf(counted.request, 0), "pay [blocked: pii.payment-card]");
  await assert.rejects(rewriteRequest(turn, { arbiter, skipPromptInjection: true, sessionKey: "s", promptBlockLedger: ledger }), RewriteBlocked);
});

test("a block with no safe text refuses every time, even a token count; no ledger refuses every block", async () => {
  const noText = new MockArbiter({ filterPromptFn: policyFilter(rules, { noText: true }) });
  const ledger = new PromptBlockLedger();
  const turn = conversation(`pay ${CARD}`);
  for (let i = 0; i < 2; i++) {
    await assert.rejects(rewriteRequest(turn, { arbiter: noText, skipPromptInjection: true, sessionKey: "s", promptBlockLedger: ledger }), RewriteBlocked);
  }
  await assert.rejects(rewriteRequest(turn, { arbiter: noText, skipPromptInjection: true, sessionKey: "s", promptBlockLedger: ledger, promptCountOnly: true }), RewriteBlocked);
  const plain = new MockArbiter({ filterPromptFn: policyFilter(rules) });
  for (let i = 0; i < 2; i++) await assert.rejects(rewriteRequest(turn, { arbiter: plain, skipPromptInjection: true, sessionKey: "s" }), RewriteBlocked);
});

test("the OpenAI-family shadow (OpenClaw, Chat Completions) blocks, then writes the safe text back", async () => {
  const ENVELOPE = "[Thu 2026-08-06 10:48 GMT+9] ";
  const body = { model: "m", tools: [{ type: "function", function: { name: "read", parameters: {} } }], messages: [{ role: "user", content: `${ENVELOPE}pay ${CARD}` }] };
  const arbiter = new MockArbiter({ filterPromptFn: policyFilter(rules) });
  const ledger = new PromptBlockLedger();
  const surface = { ...UNION_GATE_SURFACE, spec: "openclaw" } as GateSurface;
  const s1 = chatShadow(structuredClone(body));
  await assert.rejects(rewriteRequest(s1.shadow, { arbiter, skipPromptInjection: true, sessionKey: "s", surface, promptBlockLedger: ledger }), RewriteBlocked);
  // the same message again, nothing after it: the agent's retry, refused again
  await assert.rejects(rewriteRequest(chatShadow(structuredClone(body)).shadow, { arbiter, skipPromptInjection: true, sessionKey: "s", surface, promptBlockLedger: ledger }), RewriteBlocked);
  const next = { ...body, messages: [...body.messages, { role: "assistant", content: "…" }, { role: "user", content: `${ENVELOPE}never mind` }] };
  const s2 = chatShadow(structuredClone(next));
  const { request } = await rewriteRequest(s2.shadow, { arbiter, skipPromptInjection: true, sessionKey: "s", surface, promptBlockLedger: ledger });
  const out = s2.apply(request) as { messages: Array<{ content: string }> };
  assert.equal(out.messages[0]!.content, `${ENVELOPE}pay [blocked: pii.payment-card]`);
});

test("block: the agent's own retry of the refused message (nothing the human wrote after it) is refused again, so the human sees the reason (Claude Code 2.1.289's beta-fallback retry, 2026-10-04)", async () => {
  const arbiter = new MockArbiter({ filterPromptFn: policyFilter(rules) });
  const ledger = new PromptBlockLedger();
  const opts = { arbiter, skipPromptInjection: true, sessionKey: "s", promptBlockLedger: ledger };
  const first = `pay ${CARD}`;
  for (let i = 0; i < 3; i++) await assert.rejects(rewriteRequest(conversation(first), opts), RewriteBlocked);
  // the human writes after it: the resend the reason asks for goes, safe
  const { request } = await rewriteRequest(conversation(first, "ok, without it then"), opts);
  assert.equal(textOf(request, 0), "pay [blocked: pii.payment-card]");
  assert.ok(!JSON.stringify(request).includes(CARD));
});
