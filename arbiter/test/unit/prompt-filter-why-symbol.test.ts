/**
 * prompt-filter-why-symbol.test — the pure half of `whySymbol`
 * (`mandu why <symbol>`, confidentiality-plan-15-prompt-filter.md §13.8).
 * Mandu-new.
 *
 * Proves:
 *   - findings come from BELIEVED `prompt_filter` events only (a claimed one
 *     is the sender's word), one per message × category × filter, its first
 *     request's turn and the latest request's outcome, newest first;
 *   - only the event's `promptFilter` fields are copied: an event's panes
 *     (whose `original` can hold the value) never reach the answer;
 *   - the Inbox rows on file for those findings (message or session scope),
 *     and no other session's or category's;
 *   - the policy now: the deciding row, who set it, a lock, exceptions;
 *   - the source of a row (prompt filter, side call, a registered secret's
 *     path or variable name, other) and the session search order.
 *
 * Axes: secrets (stated).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { effectivePromptConfig } from "../../prompt-filter/policy.js";
import {
  WHY_SYMBOL_MAX_SESSIONS, WHY_SYMBOL_RE, whySymbol, whySymbolFindings, whySymbolPolicy, whySymbolSessions, whySymbolVerdicts,
  type WhySymbolEvent,
} from "../../prompt-filter/why-symbol.js";
import type { EgressApproval } from "../../policy/egress-approvals.js";
import type { SymbolEntry } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SYM = "$MDU:localmodel_prompt_filter[1a2b]";
const VALUE = "falconridgeproject";
const REF = "a".repeat(32);
const TURN = "b".repeat(32);
const TURN2 = "c".repeat(32);

function ev(over: Partial<WhySymbolEvent> & { findings?: unknown[]; turnRef?: string; detail?: Record<string, unknown> } = {}): WhySymbolEvent {
  const { findings, turnRef, detail, ...rest } = over;
  return {
    id: "e1", sessionId: "s1", ts: "2026-10-03T10:00:00.000Z", turn: 3, kind: "prompt_filter",
    // The panes: never read into the answer.
    ...({ input: { symbolized: `prompt filter: ... ${SYM}`, original: VALUE } } as object),
    promptFilter: {
      agent: "claude-code", segmentId: "m0", origin: "human", action: "rewrite", enforcing: true, skipped: 0,
      turn: turnRef ?? TURN,
      findings: findings ?? [{ filterId: "acme-dlp", category: "acme.codename", action: "mask", symbol: SYM, start: 7, end: 25, ref: REF }],
      digest: { policy: "p", packs: "k" },
      ...detail,
    },
    ...rest,
  };
}

function row(over: Partial<EgressApproval>): EgressApproval {
  return {
    id: "ea-1", symbol: `prompt:acme.codename#${REF}`, destination: `model:s1#turn:${TURN}`, status: "approved", reason: "r", count: 1,
    firstSeen: 1, lastSeen: 1, resolvedAt: 2, sessions: ["s1"], scope: "once", consumedAt: null, ...over,
  } as EgressApproval;
}

function entry(over: Partial<SymbolEntry> = {}): SymbolEntry {
  return {
    value: VALUE, tool: "prompt_filter", field: null, origin: null, session_key: "s1", call_id: null, created_at: Date.parse("2026-10-03T09:59:00Z"),
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null, confidentiality: "local-model", bindings: null, integrity: "trusted", ...over,
  };
}

test("WHY_SYMBOL_RE: a complete $MDU: name, a field path allowed; nothing else", () => {
  for (const ok of [SYM, "$MDU:nomodel_env[abcd1234]", "$MDU:Secret[ab12].STRIPE_KEY"]) assert.match(ok, WHY_SYMBOL_RE, ok);
  for (const bad of ["MDU:x[ab12]", "$MDU:x", "$MDU:x[zz12]", "$MDU:x[ab12] ", "$MDU:x[ab12]/etc", "/etc/passwd"]) assert.doesNotMatch(bad, WHY_SYMBOL_RE, bad);
});

test("findings: believed events only, one per message, first turn and latest outcome, never the value", () => {
  const events = [
    ev({ id: "e1", ts: "2026-10-03T10:00:00.000Z", turn: 3 }),
    // A resend of the same message (same turn reference) at a later request:
    // the latest outcome is the human's "let it through".
    ev({ id: "e2", ts: "2026-10-03T10:01:00.000Z", turn: 4, findings: [{ filterId: "acme-dlp", category: "acme.codename", action: "mask", symbol: SYM, start: 7, end: 25, ref: REF, let: "once" }], detail: { action: "pass" } }),
    // A claimed event (the data socket's word) naming the symbol: ignored.
    ev({ id: "e3", claimed: true, findings: [{ filterId: "forged", category: "forged.cat", action: "mask", symbol: SYM, start: 0, end: 1 }] }),
    // Another kind, another symbol: ignored.
    { ...ev({ id: "e4" }), kind: "tool_result" },
    ev({ id: "e5", findings: [{ filterId: "acme-dlp", category: "acme.codename", action: "mask", symbol: "$MDU:other[ffff]", start: 0, end: 1 }] }),
  ];
  const f = whySymbolFindings(SYM, events);
  assert.equal(f.length, 1);
  const [one] = f;
  assert.equal(one!.session, "s1");
  assert.equal(one!.turn, 3, "the first request that carried the message");
  assert.equal(one!.requests, 2);
  assert.equal(one!.let, "once", "the latest request's word");
  assert.equal(one!.segmentAction, "pass");
  assert.equal(one!.filterId, "acme-dlp");
  assert.equal(one!.category, "acme.codename");
  assert.equal(one!.ref, REF);
  assert.equal(one!.turnRef, TURN);
  assert.ok(!JSON.stringify(f).includes(VALUE), "never the value");
  assert.ok(!JSON.stringify(f).includes("forged"), "never a claimed event's word");
});

test("findings: two messages are two findings, newest first; an ask's hold is carried", () => {
  const f = whySymbolFindings(SYM, [
    ev({ id: "e1", ts: "2026-10-03T10:00:00.000Z" }),
    ev({ id: "e2", ts: "2026-10-03T11:00:00.000Z", turn: 9, turnRef: TURN2, findings: [{ filterId: "acme-dlp", category: "acme.codename", action: "ask", symbol: SYM, start: 0, end: 18, ref: REF, hold: { state: "timed-out", approvalId: "ea-9" } }] }),
  ]);
  assert.deepEqual(f.map((x) => x.turnRef), [TURN2, TURN]);
  assert.deepEqual(f[0]!.hold, { state: "timed-out", approvalId: "ea-9" });
  assert.equal(f[0]!.action, "ask");
});

test("findings: malformed details are skipped, not thrown", () => {
  const f = whySymbolFindings(SYM, [
    { kind: "prompt_filter", sessionId: "s1", promptFilter: null },
    { kind: "prompt_filter", sessionId: "s1", promptFilter: { findings: "x" } },
    { kind: "prompt_filter", sessionId: "", promptFilter: { findings: [{ symbol: SYM }] } },
    { kind: "prompt_filter", sessionId: "s1", promptFilter: { findings: [null, { symbol: SYM, category: 7 }] } },
  ]);
  assert.equal(f.length, 1, "the one with a session and the symbol");
  assert.equal(f[0]!.category, "");
  assert.equal(f[0]!.origin, "harness", "an unknown origin reads as the harness's (never offered a let-through)");
});

test("verdicts: the rows for those findings (message and session), no other", () => {
  const f = whySymbolFindings(SYM, [ev()]);
  const rows = [
    row({ id: "ea-1" }),
    row({ id: "ea-2", destination: "model:s1", scope: "always", status: "denied" }),
    row({ id: "ea-3", destination: `model:s1#turn:${TURN2}` }), // another message
    row({ id: "ea-4", destination: "model:s2" }), // another session
    row({ id: "ea-5", symbol: `prompt:other.cat#${REF}` }), // another category
    row({ id: "ea-6", symbol: "open:/usr/bin/cat#x", destination: "/home/u/.env" }), // not a prompt row
    row({ id: "ea-7", status: "pending" }),
  ];
  const v = whySymbolVerdicts(f, rows);
  assert.deepEqual(v.map((x) => [x.approvalId, x.scope, x.status]), [["ea-1", "message", "approved"], ["ea-2", "session", "denied"], ["ea-7", "message", "pending"]]);
});

test("policy: the deciding row, who set it, a lock, the exceptions in force", () => {
  const cfg = effectivePromptConfig(
    { actions: { acme: "redact", "acme.codename": "mask" }, exceptions: [{ category: "acme.codename", match: "*demo*" }] },
    [{ file: "/etc/mandu/policy.d/org.yaml", config: { actions: { "pii.payment-card": { action: "block", locked: true } } } }],
  );
  const [codename, card, other] = whySymbolPolicy(["acme.codename", "pii.payment-card", "x.y", "acme.codename"], cfg);
  assert.deepEqual(codename, { category: "acme.codename", action: "mask", row: "acme.codename", setBy: "you", locked: null, exceptions: 1 });
  assert.equal(card!.action, "block");
  assert.deepEqual(card!.locked, { action: "block", file: "/etc/mandu/policy.d/org.yaml" });
  assert.equal(card!.setBy, "administrator");
  assert.deepEqual(other, { category: "x.y", action: "redact", row: null, setBy: "default", locked: null, exceptions: 0 });
  assert.equal(card!.onceOnly, undefined, "a locked block is not a locked ask");
});

test("policy: a locked ask row says onceOnly with its file, even under a narrower row that decides the action (plan 15 §12, 2026-10-04)", () => {
  const ORG = "/etc/mandu/policy.d/org.yaml";
  const cfg = effectivePromptConfig(
    { actions: { "acme.codename": "block" } },
    [{ file: ORG, config: { actions: { acme: { action: "ask", locked: true }, "pii.email": { action: "ask", locked: false } } } }],
  );
  const [codename, token, email] = whySymbolPolicy(["acme.codename", "acme.token", "pii.email"], cfg);
  assert.equal(codename!.action, "block");
  assert.deepEqual(codename!.onceOnly, { file: ORG });
  assert.deepEqual(token!.onceOnly, { file: ORG });
  assert.equal(email!.onceOnly, undefined, "an unlocked administrator's ask keeps the session answer");
});

test("whySymbol: the source of a row; a secret's path or variable name, never another row's origin", () => {
  const base = { symbol: SYM, axis: true, events: [], rows: [], config: effectivePromptConfig(undefined), searched: 1 };
  const pf = whySymbol({ ...base, entry: entry() });
  assert.equal(pf.source, "prompt-filter");
  assert.equal(pf.level, "local-model");
  assert.equal(pf.session, "s1");
  assert.equal(pf.origin, null);
  assert.ok(!JSON.stringify(pf).includes(VALUE), "never the row's value");
  assert.equal(whySymbol({ ...base, entry: entry({ tool: "side_call", integrity: "untrusted" }) }).source, "side-call");
  const file = whySymbol({ ...base, entry: entry({ tool: "Read", origin: "/home/u/proj/.env", field: "STRIPE_KEY", confidentiality: "no-model" }) });
  assert.deepEqual([file.source, file.origin, file.field], ["secret", "/home/u/proj/.env", "STRIPE_KEY"]);
  const env = whySymbol({ ...base, entry: entry({ tool: "env", origin: "env:STRIPE_API_KEY", confidentiality: "no-model" }) });
  assert.deepEqual([env.source, env.origin], ["secret", "env:STRIPE_API_KEY"]);
  // A tool result from a URL: its origin is not a secret's name, not shown.
  const web = whySymbol({ ...base, entry: entry({ tool: "WebFetch", origin: "https://evil.example/?q=x", integrity: "untrusted", confidentiality: "public" }) });
  assert.deepEqual([web.source, web.origin], ["other", null]);
  const none = whySymbol({ ...base, entry: null });
  assert.deepEqual([none.known, none.source], [false, "unknown"]);
});

test("whySymbol: the filters named by the findings, with a pack's description", () => {
  const a = whySymbol({
    symbol: SYM, axis: true, entry: entry(), events: [ev()], rows: [], config: effectivePromptConfig(undefined), searched: 1,
    filters: [{ id: "acme-dlp", kind: "pack", description: "Acme's data-loss patterns" }, { id: "key-shapes", kind: "built-in" }],
  });
  assert.deepEqual(a.filters, [{ id: "acme-dlp", kind: "pack", description: "Acme's data-loss patterns" }]);
  assert.deepEqual(a.policy.map((p) => p.category), ["acme.codename"]);
});

test("sessions: the symbol's own, the hint, then the recent ones since the mint; the admin stream never", () => {
  const sessions = [
    { sessionId: "old", lastTs: "2026-10-01T00:00:00.000Z" },
    { sessionId: "s1", lastTs: "2026-10-03T10:00:00.000Z" },
    { sessionId: "recent", lastTs: "2026-10-03T12:00:00.000Z" },
    { sessionId: "arbiter-admin", lastTs: "2026-10-03T13:00:00.000Z" },
    { sessionId: "hint", lastTs: "2026-09-01T00:00:00.000Z" },
  ];
  assert.deepEqual(whySymbolSessions(entry(), "hint", sessions, new Set(["arbiter-admin"])), ["s1", "hint", "recent"]);
  assert.deepEqual(whySymbolSessions(entry(), "nope", sessions, new Set(["arbiter-admin"])), ["s1", "recent"], "a hint naming no session is dropped");
  const many = Array.from({ length: 100 }, (_, i) => ({ sessionId: `x${i}`, lastTs: `2026-10-03T1${i % 10}:00:00.000Z` }));
  assert.equal(whySymbolSessions(null, undefined, many, new Set()).length, WHY_SYMBOL_MAX_SESSIONS);
});
