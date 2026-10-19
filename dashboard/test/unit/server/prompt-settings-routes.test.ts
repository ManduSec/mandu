/**
 * prompt-settings-routes.test — the product page's Settings › Prompt filters
 * and the note's "Show what was hidden" (confidentiality-plan-15 §13.7;
 * dashboard.md §4.25y) over a real DashboardServer with a fake arbiter
 * surface and a fake event source.
 *
 * Pins:
 *   - GET /api/policy/prompt-filters is served only with the CSRF header AND
 *     the admin session, from the panel's own projection in the product's
 *     words; an arbiter predating plan 15 answers 501 and no arbiter 404,
 *     both in plain words;
 *   - POST /api/policy/prompt-filters/change needs the admin session (the
 *     global gate), accepts only the four ops the page offers (a switch is
 *     refused before the arbiter is asked), applies a tightening at once
 *     recorded as `settings`, answers a relaxation `confirm` with the rows
 *     as parts (the page's question) and applies it only with `expected`,
 *     and says a change the administrator locked is refused, naming who;
 *   - POST /api/prompt-filters/reveal {session, eventId, index} answers the
 *     original of a span the filter minted on its own in the human's text,
 *     and nothing else (a registered value, a merged span, a secret kind,
 *     harness text, a claimed event); never without the admin session.
 *
 * Axes: none is pinned (no arbiter; the fake answers as `secrets` would).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, type PolicyDocArbiter } from "../../../src/server.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { SETTINGS_REQUESTER, type PromptFiltersWire } from "../../../src/server/prompt-filter-routes.js";
import { READ_ONLY_SETTINGS } from "../../../src/view-model/prompt-settings.js";

const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };
const CSRF_ONLY = { "X-Mandu-Control": "1", "Content-Type": "application/json" };

const LOCK_FILE = "/etc/mandu/policy.d/10-org.yaml";
const FILTERS: PromptFiltersWire = {
  filters: [
    { id: "registered-value", kind: "built-in", on: true, setBy: "default", locked: false, onError: "block", onErrorSet: false, available: true, categories: [{ category: "secret.registered", action: "mask" }], origins: [] },
    { id: "acme-dlp", kind: "pack", on: true, setBy: "you", locked: false, onError: "block", onErrorSet: false, available: true, categories: [{ category: "acme.codename", action: "redact" }], origins: [] },
  ],
  actions: [
    { category: "secret.registered", action: "mask", setBy: "default", locked: false },
    { category: "secret.shape", action: "redact", setBy: "administrator", locked: true, file: LOCK_FILE },
  ],
  fallback: "redact",
  exceptions: [{ category: "pii.email", match: "*@example.com", setBy: "you", inForce: true }],
  signedOnly: false, packs: [], packProblems: [], conflicts: [], userPackDir: null,
  enforcing: true, digest: { policy: "p0", packs: "k0", values: "v0" }, registeredValues: 1,
};

const SYM = "$MDU:prompt_filter[1a2b3c4d]";
const REG = "$MDU:env_KEY[9f8e7d6c]";
const ORIGINAL = "falconridgeproject";

function pfEvent(id: string, over: Record<string, unknown>, findings: Array<Record<string, unknown>>, claimed = false): ManduEvent {
  return {
    id, sessionId: "s1", turn: 1, ts: "2026-10-03T10:00:00.000Z", seq: 1, callId: null, parentId: null,
    kind: "prompt_filter", view: "AgentView", boundary: "ingress", emitter: "anthropic-proxy", input: null, output: null,
    ...(claimed ? { claimed: true } : {}),
    promptFilter: { agent: "claude-code", segmentId: "m0.b0.p0", origin: "human", action: "rewrite", skipped: 0, enforcing: true, digest: { policy: "p", packs: "k" }, findings, ...over },
  } as unknown as ManduEvent;
}

const EVENTS: ManduEvent[] = [
  pfEvent("e-own", {}, [
    { filterId: "acme-dlp", category: "acme.codename", action: "mask", symbol: SYM, how: "keyword", start: 0, end: 5, ref: "a".repeat(32) },
    { filterId: "registered-value", category: "secret.registered", action: "mask", symbol: REG, how: "value", start: 6, end: 9 },
    { filterId: "acme-dlp", category: "acme.ticket", action: "mask", symbol: SYM, how: "merged", start: 10, end: 20, ref: "b".repeat(32) },
    { filterId: "key-shapes", category: "secret.shape.github-token", action: "mask", symbol: SYM, start: 21, end: 30, ref: "c".repeat(32) },
    { filterId: "acme-dlp", category: "acme.ticket", action: "redact", start: 31, end: 40, ref: "d".repeat(32) },
  ]),
  pfEvent("e-harness", { origin: "harness" }, [{ filterId: "acme-dlp", category: "acme.codename", action: "mask", symbol: SYM, start: 0, end: 5 }]),
  pfEvent("e-claimed", {}, [{ filterId: "acme-dlp", category: "acme.codename", action: "mask", symbol: SYM, start: 0, end: 5 }], true),
];

function source(asked: string[]): EventSource {
  return {
    async listSessions(): Promise<SessionRef[]> { return []; },
    async readEvents() { return EVENTS; },
    subscribe(): () => void { return () => {}; },
    close(): void {},
    async desymbolize(text: string) { asked.push(text); return text === SYM ? ORIGINAL : "?"; },
  };
}

function arbiter(over: Partial<PolicyDocArbiter> = {}) {
  const calls: Array<{ op: string; args: unknown }> = [];
  let relax = false;
  const a = {
    async policyDocument() { throw new Error("unused"); },
    async applyPolicyDocument() { throw new Error("unused"); },
    async mintUserRule() { throw new Error("unused"); },
    async exportDbLabels() { throw new Error("unused"); },
    async promptFilters() { return FILTERS; },
    async policyPreview(edits: unknown) {
      calls.push({ op: "policyPreview", args: edits });
      const e = (edits as Array<Record<string, unknown>>)[0]!;
      if (e["category"] === "secret.shape") {
        return { ok: false as const, problems: [`edits[0] (set-prompt-action): prompt_filters.actions.secret.shape: secret.shape is set by your administrator (${LOCK_FILE}) as redact; log would relax it`] };
      }
      relax = e["op"] === "add-prompt-exception" || e["action"] === "log";
      return {
        ok: true as const,
        relaxations: relax ? [{ facet: "prompt-filters", direction: "relax", subject: `prompt filter ${String(e["category"])}`, detail: "weaker" }] : [],
        tightenings: relax ? [] : [{ facet: "prompt-filters", direction: "tighten", subject: "x", detail: "y" }],
        perEdit: [{ loosens: relax }],
      };
    },
    async policyPropose(req: { edits: unknown; reason?: string; requestedBy?: string }) {
      calls.push({ op: "policyPropose", args: req });
      if (!relax) return { applied: true as const, changeId: "pc-1" };
      return { applied: false as const, proposalId: "pp-1", relaxes: [{ facet: "prompt-filters", subject: `prompt filter ${String(((req.edits as Array<Record<string, unknown>>)[0]!)["category"])}` }] };
    },
    async resolvePolicyProposal(id: string, verdict: string, by?: string) {
      calls.push({ op: "resolvePolicyProposal", args: { id, verdict, by } });
      return { proposal: { id }, changeId: "pc-2" };
    },
    ...over,
  } as unknown as PolicyDocArbiter;
  return { a, calls };
}

async function start(arb: PolicyDocArbiter | undefined, asked: string[] = []) {
  const server = new DashboardServer({ source: source(asked), policyDocArbiter: arb, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  return { base: `http://127.0.0.1:${port}`, close: () => server.close() };
}

const get = async (base: string, headers: Record<string, string> = CSRF_ADMIN) => {
  const r = await fetch(`${base}/api/policy/prompt-filters`, { headers });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
};
const change = async (base: string, body: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
  const r = await fetch(`${base}/api/policy/prompt-filters/change`, { method: "POST", headers, body: JSON.stringify(body) });
  return { status: r.status, body: (await r.json()) as Record<string, any> };
};

test("GET /api/policy/prompt-filters: only with the CSRF header and the admin session; the panel's projection in plain words", async () => {
  const { a } = arbiter();
  const h = await start(a);
  try {
    assert.equal((await get(h.base, {})).status, 403, "no CSRF header");
    assert.equal((await get(h.base, CSRF_ONLY)).status, 403, "no admin session");
    const r = await get(h.base);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const s = r.body["settings"];
    assert.equal(s.editable, true);
    assert.deepEqual(s.kinds.map((k: { category: string }) => k.category), ["secret.registered", "secret.shape", "acme.codename"]);
    const shape = s.kinds.find((k: { category: string }) => k.category === "secret.shape");
    assert.equal(shape.who, "Locked by your administrator (10-org.yaml).");
    assert.equal(shape.lockedBy, "10-org.yaml");
    assert.deepEqual(s.exceptions.map((x: { match: string }) => x.match), ["*@example.com"]);
  } finally {
    await h.close();
  }
});

test("GET: an arbiter predating plan 15 is 501 and no arbiter 404, in plain words", async () => {
  const { a } = arbiter({ promptFilters: undefined } as Partial<PolicyDocArbiter>);
  const h = await start(a);
  try {
    const r = await get(h.base);
    assert.equal(r.status, 501);
    assert.equal(r.body["error"], READ_ONLY_SETTINGS);
  } finally {
    await h.close();
  }
  const none = await start(undefined);
  try {
    const r = await get(none.base);
    assert.equal(r.status, 404);
    assert.doesNotMatch(String(r.body["error"]), /arbiter/i);
  } finally {
    await none.close();
  }
});

test("POST change: the admin session; only the page's four ops, before the arbiter is asked", async () => {
  const { a, calls } = arbiter();
  const h = await start(a);
  try {
    const edit = { op: "set-prompt-action", category: "acme.codename", action: "block" };
    assert.equal((await change(h.base, { edit }, {})).status, 403, "no CSRF header");
    assert.equal((await change(h.base, { edit }, CSRF_ONLY)).status, 403, "no admin session");
    for (const bad of [
      { op: "set-prompt-filter", filter: "registered-value", on: false },
      { op: "set-prompt-pattern", pack: "mine", pattern: {} },
      { op: "set-prompt-action", category: "acme.codename", action: "block", extra: 1 },
      "set-prompt-action",
    ]) {
      const r = await change(h.base, { edit: bad });
      assert.equal(r.status, 400, JSON.stringify(bad));
    }
    assert.equal(calls.length, 0, "nothing reached the arbiter");
  } finally {
    await h.close();
  }
});

test("POST change: a tightening applies at once as Settings'; a relaxation asks with parts, then applies with what was shown", async () => {
  const { a, calls } = arbiter();
  const h = await start(a);
  try {
    const up = await change(h.base, { edit: { op: "set-prompt-action", category: "acme.codename", action: "block" } });
    assert.equal(up.status, 200, JSON.stringify(up.body));
    assert.equal(up.body["applied"], true);
    const proposed = calls.find((c) => c.op === "policyPropose")!.args as { requestedBy: string; reason: string };
    assert.equal(proposed.requestedBy, SETTINGS_REQUESTER);
    assert.match(proposed.reason, /^Changed in Settings › Prompt filters \(set-prompt-action\)$/);

    calls.length = 0;
    const exc = { op: "add-prompt-exception", category: "pii.email", match: "*@corp.example" };
    const ask = await change(h.base, { edit: exc });
    assert.equal(ask.status, 200);
    assert.equal(ask.body["confirm"], true);
    assert.ok(Array.isArray(ask.body["rows"][0]) && ask.body["rows"][0].every((p: { kind: string; text: string }) => typeof p.text === "string"), "the rows are parts, as the page's question reads them");
    assert.ok(Array.isArray(ask.body["wouldLet"][0]));
    assert.ok(!calls.some((c) => c.op === "policyPropose"), "nothing applied before the person agreed");
    const agreed = await change(h.base, { edit: exc, expected: ask.body["expected"] });
    assert.equal(agreed.status, 200, JSON.stringify(agreed.body));
    assert.equal(agreed.body["applied"], true);
    assert.deepEqual(calls.filter((c) => c.op === "resolvePolicyProposal").map((c) => (c.args as { verdict: string }).verdict), ["approved"]);
  } finally {
    await h.close();
  }
});

test("POST change: a kind the administrator locked is refused, and the answer says who locked it", async () => {
  const { a, calls } = arbiter();
  const h = await start(a);
  try {
    const r = await change(h.base, { edit: { op: "set-prompt-action", category: "secret.shape", action: "log" } });
    assert.equal(r.status, 422, JSON.stringify(r.body));
    assert.deepEqual(r.body["problems"], [`secret.shape is set by your administrator (${LOCK_FILE}) as redact; log would relax it`]);
    assert.ok(!calls.some((c) => c.op === "policyPropose"), "nothing applied");
  } finally {
    await h.close();
  }
});

test("POST change: an arbiter without the write path is 501 in plain words", async () => {
  const { a } = arbiter({ policyPreview: undefined } as Partial<PolicyDocArbiter>);
  const h = await start(a);
  try {
    const r = await change(h.base, { edit: { op: "set-prompt-action", category: "acme.codename", action: "block" } });
    assert.equal(r.status, 501);
    assert.equal(r.body["error"], READ_ONLY_SETTINGS);
  } finally {
    await h.close();
  }
});

test("POST reveal by event and index: the filter's own mint in the human's text only; never without the admin session", async () => {
  const asked: string[] = [];
  const { a } = arbiter();
  const h = await start(a, asked);
  const reveal = async (body: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`${h.base}/api/prompt-filters/reveal`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as Record<string, any> };
  };
  try {
    assert.equal((await reveal({ session: "s1", eventId: "e-own", index: 0 }, CSRF_ONLY)).status, 403);
    assert.equal(asked.length, 0);
    const ok = await reveal({ session: "s1", eventId: "e-own", index: 0 });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.deepEqual(ok.body, { original: ORIGINAL }, "the original only: no symbol in the answer");
    assert.deepEqual(asked, [SYM]);
    for (const [eventId, index, status] of [
      ["e-own", 1, 409], // a registered value's own symbol
      ["e-own", 2, 409], // a span merged with another finding
      ["e-own", 3, 409], // a secret kind
      ["e-own", 4, 409], // a removal keeps nothing
      ["e-own", 9, 404],
      ["e-harness", 0, 409],
      ["e-claimed", 0, 404],
      ["no-such", 0, 404],
    ] as const) {
      const r = await reveal({ session: "s1", eventId, index });
      assert.equal(r.status, status, `${eventId}#${index}: ${JSON.stringify(r.body)}`);
    }
    assert.deepEqual(asked, [SYM], "nothing else was resolved");
    assert.equal((await reveal({ session: "s1", eventId: "e-own" })).status, 400, "an index is required");
  } finally {
    await h.close();
  }
});
