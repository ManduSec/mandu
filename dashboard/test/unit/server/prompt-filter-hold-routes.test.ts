/**
 * prompt-filter-hold-routes — the Prompt filters panel's phase-3 routes
 * (server/prompt-filter-routes.ts; confidentiality-plan-15-prompt-filter.md
 * §7, §13.6): the held messages, the answer, and "let it through".
 *
 * Proves, over the real DashboardServer with a fake arbiter:
 *   - the findings rows carry the hold's state, a verdict that let a span
 *     through, the message's reference, and `canLet` only for a
 *     proxy-recorded finding on the human's own text with an opaque
 *     reference and an enforced action (never a registered value, never a
 *     claimed event);
 *   - `letThroughPlan` names the finding by event and index from the
 *     session's OWN events and refuses everything else (unknown, claimed,
 *     harness text, a registered value, once with no message reference);
 *   - GET holds needs the CSRF header and the admin session (the found text
 *     is the human's own words, human plane); the answer validates its
 *     answer and scope and forwards one object; a let-through forwards the
 *     finding's category, ref and turn, never anything the request body says
 *     about them;
 *   - a hold under a locked administrator's `ask` row is listed with
 *     `onceOnly`, and the arbiter's refusal of a session answer to it is a
 *     409 with its reason (plan 15 §12, 2026-10-04); so is a finding the
 *     arbiter marked `onceOnly` on its event, and its refusal of a session
 *     let-through is a 409 too (the route never pre-judges from the event).
 *
 * Axes: the fake answers as the arbiter does in `secrets` (enforcing).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, type PolicyDocArbiter } from "../../../src/server.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { isOnceOnlyRefusal, letThroughPlan, toFindingRows } from "../../../src/server/prompt-filter-routes.js";

const REF = "a".repeat(32);
const TURN = "b".repeat(32);
const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };

function pfEvent(id: string, detail: Record<string, unknown>, extra: Partial<ManduEvent> = {}): ManduEvent {
  return {
    id, sessionId: "s1", turn: 1, ts: `2026-10-03T10:00:0${id.slice(-1)}.000Z`, seq: 1, callId: null, parentId: null,
    kind: "prompt_filter", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: "prompt filter: …", original: null, differs: false, symbols: [] }, output: null, invariant: { violatedInvariant: false },
    promptFilter: { agent: "claude-code", segmentId: "m0.b0.p0", origin: "human", action: "rewrite", skipped: 0, enforcing: true, digest: { policy: "p", packs: "k" }, ...detail },
    ...extra,
  } as unknown as ManduEvent;
}

const EVENTS: ManduEvent[] = [
  pfEvent("e1", { turn: TURN, findings: [
    { filterId: "acme-dlp", category: "acme.ticket", action: "redact", start: 4, end: 14, ref: REF },
    { filterId: "registered-value", category: "secret.registered", action: "mask", symbol: "$MDU:nomodel_Env[f8d2].K", start: 20, end: 40 },
  ] }),
  pfEvent("e2", { findings: [{ filterId: "acme-dlp", category: "acme.codename", action: "ask", symbol: "$MDU:localmodel_prompt_filter[1]", start: 0, end: 6, ref: REF, let: "once", hold: { state: "sent", approvalId: "egr-1" } }], turn: TURN }),
  pfEvent("e3", { origin: "harness", findings: [{ filterId: "acme-dlp", category: "acme.ticket", action: "redact", start: 0, end: 4, ref: REF }] }),
  pfEvent("e4", { turn: TURN, findings: [{ filterId: "acme-dlp", category: "acme.ticket", action: "redact", start: 0, end: 4, ref: REF }] }, { claimed: true } as Partial<ManduEvent>),
  pfEvent("e5", { findings: [{ filterId: "acme-dlp", category: "acme.ticket", action: "redact", start: 0, end: 4, ref: REF }] }),
];

test("pure: findings rows carry hold, let and turn; canLet only where a let-through can apply", () => {
  const rows = toFindingRows(EVENTS);
  const by = (id: string) => rows.find((r) => r.eventId === id)!;
  assert.equal(by("e1").turn, TURN);
  assert.deepEqual(by("e1").findings.map((f) => [f.category, f.index, f.canLet]), [["acme.ticket", 0, true], ["secret.registered", 1, false]]);
  assert.deepEqual(by("e2").findings.map((f) => [f.let, f.hold, f.canLet]), [["once", "sent", false]], "already let through");
  assert.equal(by("e3").findings[0]!.canLet, false, "harness text is never let through");
  assert.equal(by("e4").findings[0]!.canLet, false, "a claimed event opens nothing");
});

test("pure: letThroughPlan takes the finding from the session's own events and refuses the rest", () => {
  assert.deepEqual(letThroughPlan(EVENTS, "e1", 0, "once"), { ok: true, category: "acme.ticket", ref: REF, turn: TURN });
  assert.deepEqual(letThroughPlan(EVENTS, "e1", 0, "session"), { ok: true, category: "acme.ticket", ref: REF });
  for (const [id, i, scope, status] of [
    ["nope", 0, "session", 404], ["e1", 5, "session", 404], ["e4", 0, "session", 404],
    ["e3", 0, "session", 409], ["e1", 1, "session", 409], ["e5", 0, "once", 409],
  ] as const) {
    const p = letThroughPlan(EVENTS, id, i, scope);
    assert.equal(p.ok, false, `${id}#${i}`);
    assert.equal((p as { status: number }).status, status, `${id}#${i}`);
  }
});

function source(): EventSource {
  return {
    async listSessions(): Promise<SessionRef[]> { return []; },
    async readEvents(id: string): Promise<ManduEvent[]> { return id === "s1" ? EVENTS : []; },
    subscribe(): () => void { return () => {}; },
    close(): void {},
  };
}

test("routes: holds gated like the packs; the answer and the let-through forward one object each", async () => {
  const calls: Array<[string, unknown]> = [];
  const arb = {
    async policyDocument() { throw new Error("unused"); },
    async applyPolicyDocument() { throw new Error("unused"); },
    async mintUserRule() { throw new Error("unused"); },
    async exportDbLabels() { throw new Error("unused"); },
    async promptHolds() {
      calls.push(["promptHolds", null]);
      return { timeoutMs: 30_000, holds: [{ approvalId: "egr-3", session: "s1", category: "acme.codename", filterId: "acme-dlp", span: "falcon", fallback: "mask", firstSeen: 1, lastSeen: 2, timeoutMs: 12_000 }] };
    },
    async resolvePromptHold(args: unknown) { calls.push(["resolvePromptHold", args]); return { approval: { id: "egr-3", status: "approved" } }; },
    async letPromptFindingThrough(args: unknown) { calls.push(["letPromptFindingThrough", args]); return { approval: { id: "egr-4", status: "approved" } }; },
  } as unknown as PolicyDocArbiter;
  const server = new DashboardServer({ source: source(), policyDocArbiter: arb, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}/api/prompt-filters`;
  const postJ = async (path: string, body: unknown) => {
    const r = await fetch(`${base}/${path}`, { method: "POST", headers: CSRF_ADMIN, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  try {
    assert.equal((await fetch(`${base}/holds`)).status, 403, "no CSRF header: refused");
    assert.equal((await fetch(`${base}/holds`, { headers: { "X-Mandu-Control": "1" } })).status, 403, "no admin session: refused");
    const h = await fetch(`${base}/holds`, { headers: CSRF_ADMIN });
    assert.equal(h.status, 200);
    const hb = (await h.json()) as { holds: Array<{ span: string; timeoutMs: number }> };
    assert.equal(hb.holds[0]!.span, "falcon");

    assert.equal((await postJ("holds/answer", { approvalId: "egr-3", answer: "allow" })).status, 400);
    assert.equal((await postJ("holds/answer", { approvalId: "egr-3", answer: "send", scope: "forever" })).status, 400);
    const ok = await postJ("holds/answer", { approvalId: "egr-3", answer: "cancel" });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.deepEqual(calls.at(-1), ["resolvePromptHold", { approvalId: "egr-3", answer: "cancel", scope: "once" }]);

    const lt = await postJ("let-through", { session: "s1", eventId: "e1", index: 0, scope: "once", category: "secret.registered", ref: "c".repeat(32) });
    assert.equal(lt.status, 200, JSON.stringify(lt.body));
    assert.deepEqual(calls.at(-1), ["letPromptFindingThrough", { session: "s1", category: "acme.ticket", ref: REF, turn: TURN, scope: "once" }],
      "the category and ref come from the session's own event, never from the body");
    assert.equal((await postJ("let-through", { session: "s1", eventId: "e1", index: 1, scope: "session" })).status, 409);
    assert.equal((await postJ("let-through", { session: "s1", eventId: "e1", index: 0 })).status, 400);
    // Without the global POST gate's header: refused before any arbiter call.
    const n = calls.length;
    const r = await fetch(`${base}/holds/answer`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approvalId: "egr-3", answer: "send" }) });
    assert.equal(r.status, 403);
    assert.equal(calls.length, n);
  } finally {
    await server.close();
  }
});

test("routes: a locked ask hold is listed this-message-only; a session answer the arbiter refuses is a 409 with its reason", async () => {
  const REFUSAL = "resolvePromptHold: your administrator set acme.codename to ask every time (/etc/mandu/policy.d/10-org.yaml), so it takes no answer for the session; answer it for this message only";
  const calls: unknown[] = [];
  const arb = {
    async policyDocument() { throw new Error("unused"); },
    async applyPolicyDocument() { throw new Error("unused"); },
    async mintUserRule() { throw new Error("unused"); },
    async exportDbLabels() { throw new Error("unused"); },
    async promptHolds() {
      return { timeoutMs: 30_000, holds: [
        { approvalId: "egr-3", session: "s1", category: "acme.codename", span: "falcon", fallback: "mask", firstSeen: 1, lastSeen: 2, timeoutMs: 12_000, onceOnly: true },
        { approvalId: "egr-4", session: "s1", category: "pii.email", firstSeen: 1, lastSeen: 2, timeoutMs: 12_000 },
      ] };
    },
    async resolvePromptHold(args: { scope?: string }) {
      calls.push(args);
      if (args.scope === "session") throw new Error(REFUSAL);
      return { approval: { id: "egr-3", status: "approved" } };
    },
  } as unknown as PolicyDocArbiter;
  const server = new DashboardServer({ source: source(), policyDocArbiter: arb, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}/api/prompt-filters`;
  try {
    const h = (await (await fetch(`${base}/holds`, { headers: CSRF_ADMIN })).json()) as { holds: Array<{ onceOnly: boolean }> };
    assert.deepEqual(h.holds.map((x) => x.onceOnly), [true, false]);
    const refused = await fetch(`${base}/holds/answer`, { method: "POST", headers: CSRF_ADMIN, body: JSON.stringify({ approvalId: "egr-3", answer: "send", scope: "session" }) });
    assert.equal(refused.status, 409);
    assert.match(((await refused.json()) as { error: string }).error, /this message only/);
    const once = await fetch(`${base}/holds/answer`, { method: "POST", headers: CSRF_ADMIN, body: JSON.stringify({ approvalId: "egr-3", answer: "send", scope: "once" }) });
    assert.equal(once.status, 200);
    assert.deepEqual(calls, [{ approvalId: "egr-3", answer: "send", scope: "session" }, { approvalId: "egr-3", answer: "send", scope: "once" }]);
    assert.equal(isOnceOnlyRefusal("unknown prompt hold: egr-9"), false);
  } finally {
    await server.close();
  }
});

test("a finding the arbiter marked onceOnly: listed onceOnly; a session let-through the arbiter refuses is a 409 with its reason, other refusals stay 422", async () => {
  const LOCKED: ManduEvent[] = [pfEvent("e7", { turn: TURN, findings: [
    { filterId: "acme-dlp", category: "acme.codename", action: "ask", symbol: "$MDU:localmodel_prompt_filter[2]", start: 0, end: 6, ref: REF, hold: { state: "masked", approvalId: "egr-5" }, onceOnly: true },
    { filterId: "acme-dlp", category: "acme.ticket", action: "redact", start: 8, end: 18, ref: "c".repeat(32) },
  ] })];
  const rows = toFindingRows(LOCKED);
  assert.deepEqual(rows[0]!.findings.map((f) => [f.category, f.canLet, f.onceOnly]), [["acme.codename", true, true], ["acme.ticket", true, false]]);
  // The route does not pre-judge from the event (the lock may have been
  // lifted since): the arbiter decides, and its once-only refusal is a 409.
  assert.deepEqual(letThroughPlan(LOCKED, "e7", 0, "session"), { ok: true, category: "acme.codename", ref: REF });
  const REFUSAL = "letPromptFindingThrough: your administrator set acme.codename to ask every time (/etc/mandu/policy.d/10-org.yaml), so it takes no answer for the session; answer it for this message only";
  const calls: Array<{ category: string; scope: string }> = [];
  const arb = {
    async policyDocument() { throw new Error("unused"); },
    async applyPolicyDocument() { throw new Error("unused"); },
    async mintUserRule() { throw new Error("unused"); },
    async exportDbLabels() { throw new Error("unused"); },
    async letPromptFindingThrough(args: { category: string; scope: string }) {
      calls.push(args);
      if (args.category === "acme.codename" && args.scope === "session") throw new Error(REFUSAL);
      if (args.category === "acme.ticket") throw new Error("letPromptFindingThrough: acme.ticket is set by your administrator (/etc/mandu/policy.d/10-org.yaml) as block; it cannot be let through");
      return { approval: { id: "egr-6", status: "approved" } };
    },
  } as unknown as PolicyDocArbiter;
  const src: EventSource = { ...source(), async readEvents(id: string) { return id === "s1" ? LOCKED : []; } };
  const server = new DashboardServer({ source: src, policyDocArbiter: arb, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const post = async (body: unknown) => {
    const r = await fetch(`http://127.0.0.1:${port}/api/prompt-filters/let-through`, { method: "POST", headers: CSRF_ADMIN, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as { error?: string } };
  };
  try {
    const refused = await post({ session: "s1", eventId: "e7", index: 0, scope: "session" });
    assert.equal(refused.status, 409);
    assert.match(refused.body.error ?? "", /ask every time .*answer it for this message only/);
    assert.equal((await post({ session: "s1", eventId: "e7", index: 0, scope: "once" })).status, 200, "once goes");
    assert.equal((await post({ session: "s1", eventId: "e7", index: 1, scope: "session" })).status, 422, "another refusal keeps its status");
    assert.deepEqual(calls.map((c) => [c.category, c.scope]), [["acme.codename", "session"], ["acme.codename", "once"], ["acme.ticket", "session"]]);
  } finally {
    await server.close();
  }
});
