/**
 * answered-day.test — dashboard.md §4.25 *Go to a day on Answered earlier*.
 * `answeredPage(…, q, before)` keeps the answers decided before `before`
 * (the start of the day after the one chosen, as the browser reckons it),
 * cut before the search and the page:
 *
 *   B1  only the answers whose moment is before the bound; the bound itself
 *       is out; `before` says the bound and every answer (`all`);
 *   B2  `total`, `next` and `after` count and page through the cut list;
 *   B3  the search holds with it, over the cut list, `query.all` every
 *       answer;
 *   B4  an answer not stamped (no `resolvedAt`) is cut by when it was last
 *       asked, the moment the list orders it by, so it never sits above the
 *       day; none is kept for want of a time;
 *   B5  a non-finite bound, or none, is no day; `answeredBefore` alone keeps
 *       the order.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { answeredBefore, answeredPage, type HomeAnswered } from "../../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import type { SessionRef } from "../../../src/event-source/contract.js";

const DAY = 86_400_000;
/** The bound: the start of the day after the chosen one. */
const BOUND = Date.parse("2026-10-21T00:00:00Z");

function verdict(over: Partial<VerdictEntry>): VerdictEntry {
  return {
    id: "egr-1", symbol: "$MDU:nomodel_Read[ab12cd34].STRIPE_KEY", destination: "api.stripe.com", source: { tool: "Read", origin: "/home/u/shop/.env" },
    status: "denied", reason: "r", count: 1, firstSeen: BOUND - 10 * DAY, lastSeen: BOUND - 10 * DAY, resolvedAt: BOUND - 10 * DAY,
    sessions: ["s-claude"],
    ...over,
  } as VerdictEntry;
}
function queueOf(verdicts: VerdictEntry[]) {
  const snapshot = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts,
  } as unknown as PolicySnapshot;
  return toPolicyPanelViewModel(snapshot).queue;
}
const BY_ID = new Map<string, Pick<SessionRef, "agent">>([["s-claude", { agent: "claude" }]]);
const page = (verdicts: VerdictEntry[], before: number | null, q: string | null = null, after: string | null = null, limit = 20) =>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  answeredPage(queueOf(verdicts), BY_ID as any, "/home/u", after, limit, q, before);
const ids = (rows: HomeAnswered[]) => rows.map((r) => r.id);

// Two answers after the day (one at the bound itself), three on it or before.
const FIVE = [
  verdict({ id: "after2", lastSeen: BOUND + 2 * DAY, resolvedAt: BOUND + 2 * DAY }),
  verdict({ id: "at", lastSeen: BOUND, resolvedAt: BOUND }),
  verdict({ id: "on", lastSeen: BOUND - 1, resolvedAt: BOUND - 1 }),
  verdict({ id: "before1", destination: "pastebin.com", lastSeen: BOUND - DAY, resolvedAt: BOUND - DAY }),
  verdict({ id: "before2", lastSeen: BOUND - 2 * DAY, resolvedAt: BOUND - 2 * DAY }),
];

test("B1: only the answers decided before the bound, the bound itself out; `before` says it and every answer", () => {
  const r = page(FIVE, BOUND);
  assert.deepEqual(ids(r.rows), ["on", "before1", "before2"]);
  assert.equal(r.total, 3);
  assert.equal(r.next, null);
  assert.deepEqual(r.before, { at: BOUND, all: 5 });
  assert.equal(r.query, undefined);
});

test("B2: total, next and after count and page through the cut list", () => {
  const first = page(FIVE, BOUND, null, null, 2);
  assert.deepEqual(ids(first.rows), ["on", "before1"]);
  assert.equal(first.total, 3, "the cut list, not every answer");
  assert.equal(first.next, "before1");
  const second = page(FIVE, BOUND, null, first.next, 2);
  assert.deepEqual(ids(second.rows), ["before2"]);
  assert.equal(second.next, null);
  // A cursor that is not in the cut list (an answer after the day) starts from its top.
  assert.deepEqual(ids(page(FIVE, BOUND, null, "after2", 2).rows), ["on", "before1"]);
});

test("B3: a search holds with the day, over the cut list", () => {
  const r = page(FIVE, BOUND, "pastebin");
  assert.deepEqual(ids(r.rows), ["before1"]);
  assert.equal(r.total, 1);
  assert.deepEqual(r.query, { text: "pastebin", all: 5 });
  assert.deepEqual(r.before, { at: BOUND, all: 5 });
});

test("B4: an answer not stamped is cut by when it was last asked, the moment it is ordered by", () => {
  const unstamped = [
    ...FIVE,
    verdict({ id: "old-asked-late", resolvedAt: undefined, lastSeen: BOUND + DAY }),
    verdict({ id: "old-asked-early", resolvedAt: undefined, lastSeen: BOUND - 3 * DAY }),
  ];
  const all = page(unstamped, null);
  assert.equal(ids(all.rows).indexOf("old-asked-late"), 1, "the list orders it by when it was last asked");
  const r = page(unstamped, BOUND);
  assert.deepEqual(ids(r.rows), ["on", "before1", "before2", "old-asked-early"], "asked after the day: out; before it: in, in its place");
  assert.deepEqual(r.before, { at: BOUND, all: 7 });
});

test("B5: no bound, or a non-finite one, is no day; answeredBefore keeps the order", () => {
  for (const b of [null, Number.NaN, Number.POSITIVE_INFINITY]) {
    const r = page(FIVE, b);
    assert.equal(r.total, 5, `before ${b}: every answer`);
    assert.equal(r.before, undefined);
  }
  const rows = [{ resolvedAt: 3, lastSeen: 3 }, { resolvedAt: null, lastSeen: 1 }, { resolvedAt: 2, lastSeen: 9 }];
  assert.deepEqual(answeredBefore(rows, 3), [rows[1], rows[2]]);
  assert.deepEqual(answeredBefore(rows, Number.NaN), rows);
});
