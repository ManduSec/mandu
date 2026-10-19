/**
 * history-stepped-in.test — dashboard.md §4.25ae *Only the sessions where
 * Mandu stepped in*: the pure rule History's switch keeps a row by
 * (`steppedIn`, read off the row the page draws) and the paging over the
 * kept rows (`historyPageWhere`): it keeps matches only, stops at `limit`
 * rows or at the scan budget, and its `next` lets the following read go on
 * past a long run of plain sessions; `buildHistoryViewModel` carries
 * `only.through`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { SessionRef } from "../../../src/event-source/contract.js";
import { buildHistoryViewModel, historyPageWhere, homeAgentRow, steppedIn, HISTORY_ONLY_STEPPED_IN, HISTORY_PAGE_MAX, HISTORY_SCAN_BUDGET, type HomeAgent, type HomeSessionFacts } from "../../../src/view-model/home.js";

const ref = (id: string, over: Partial<SessionRef> = {}): SessionRef => ({
  id, label: `task ${id}`, labelFrom: "prompt", eventCount: 3, firstTs: "2026-09-01T10:00:00.000Z", lastTs: "2026-09-01T10:05:00.000Z", violated: false, agent: "claude", status: "idle", ...over,
} as SessionRef);
const plain: Pick<HomeAgent, "secrets" | "untrusted" | "blocked" | "sent" | "waiting" | "holds"> = { secrets: { masked: 0, early: 0 }, untrusted: 0, blocked: 0, sent: 0, waiting: 0, holds: true };
const facts = (over: Partial<HomeSessionFacts> = {}): HomeSessionFacts => ({
  stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, blocked: 0, sent: 0, holds: true, violations: 0, cwd: null, ...over,
} as HomeSessionFacts);

test("steppedIn: each kind of count keeps a row, and a plain row is not kept", () => {
  assert.equal(HISTORY_ONLY_STEPPED_IN, "stepped-in");
  assert.equal(steppedIn(plain), false, "nothing on the counts line, nothing waiting, protection held");
  const kinds: Array<[string, Partial<typeof plain>]> = [
    ["a secret masked before the AI saw it", { secrets: { masked: 1, early: 0 } }],
    ["a secret read before it was marked", { secrets: { masked: 0, early: 2 } }],
    ["an untrusted item masked (where the level masks them)", { untrusted: 1 }],
    ["a step blocked", { blocked: 1 }],
    ["a send with a real value filled in", { sent: 3 }],
    ["a question still waiting", { waiting: 1 }],
    ["protection failed (a leak-check finding)", { holds: false }],
  ];
  for (const [what, over] of kinds) assert.equal(steppedIn({ ...plain, ...over }), true, what);
});

test("steppedIn over the row History draws: facts, the waiting count and the listing's verdict", () => {
  const row = (s: SessionRef, f: HomeSessionFacts | undefined, waiting = 0) => steppedIn(homeAgentRow(s, f, waiting, false));
  assert.equal(row(ref("a"), facts()), false);
  assert.equal(row(ref("a"), facts({ secrets: { masked: 1, early: 0 } })), true);
  assert.equal(row(ref("a"), facts({ blocked: 1 })), true);
  assert.equal(row(ref("a"), facts({ sent: 1 })), true);
  assert.equal(row(ref("a"), facts({ holds: false, violations: 1 })), true);
  assert.equal(row(ref("a"), facts(), 1), true, "a question it raised still waits");
  // An unreadable session (no facts): only the listing's verdict counts.
  assert.equal(row(ref("a"), undefined), false);
  assert.equal(row(ref("a", { violated: true }), undefined), true);
  // Flows alone (an item handed over as it is) are not a step-in.
  assert.equal(row(ref("a"), facts({ stats: { flows: 4, secret: 0, complete: 4, egressAllowed: 0, egressBlocked: 0, egressPending: 0 } })), false);
});

const ids = (r: { page: SessionRef[] }) => r.page.map((s) => s.id);
// Sessions s0 (newest) .. s<n-1>; `hits` the indexes that match.
const list = (n: number) => Array.from({ length: n }, (_, i) => ref(`s${i}`));
const by = (hits: number[]) => (s: SessionRef) => hits.includes(Number(s.id.slice(1)));

test("historyPageWhere keeps the matches only, in order, up to the limit", async () => {
  const all = list(10);
  const r = await historyPageWhere(all, null, 25, HISTORY_SCAN_BUDGET, by([1, 4, 7]));
  assert.deepEqual(ids(r), ["s1", "s4", "s7"]);
  assert.equal(r.next, null, "every session looked through");
  assert.equal(r.through, 10);
  const two = await historyPageWhere(all, null, 2, HISTORY_SCAN_BUDGET, by([1, 4, 7]));
  assert.deepEqual(ids(two), ["s1", "s4"]);
  assert.equal(two.next, "s4", "it stops at the limit; the next read goes on after the last row");
  assert.equal(two.through, 5);
  const rest = await historyPageWhere(all, two.next, 2, HISTORY_SCAN_BUDGET, by([1, 4, 7]));
  assert.deepEqual(ids(rest), ["s7"]);
  assert.equal(rest.next, null);
  assert.equal(rest.through, 10);
  // An async test, as the route counts each session as it goes.
  const slow = await historyPageWhere(all, null, 25, HISTORY_SCAN_BUDGET, async (s) => by([9])(s));
  assert.deepEqual(ids(slow), ["s9"]);
});

test("historyPageWhere stops at the scan budget, and next goes on past a long run of plain sessions", async () => {
  const all = list(500);
  const keep = by([3, 450, 451]);
  let looked = 0;
  const counting = (s: SessionRef) => { looked++; return keep(s); };
  const p1 = await historyPageWhere(all, null, 25, 200, counting);
  assert.deepEqual(ids(p1), ["s3"]);
  assert.equal(looked, 200, "one read never looks through more than the budget");
  assert.equal(p1.next, "s199", "the last session looked through, though not a match");
  assert.equal(p1.through, 200);
  const p2 = await historyPageWhere(all, p1.next, 25, 200, keep);
  assert.deepEqual(ids(p2), [], "a page of none: the run of plain sessions goes on");
  assert.equal(p2.next, "s399", "and it still pages on");
  assert.equal(p2.through, 400);
  const p3 = await historyPageWhere(all, p2.next, 25, 200, keep);
  assert.deepEqual(ids(p3), ["s450", "s451"]);
  assert.equal(p3.next, null, "the end");
  assert.equal(p3.through, 500);
  // A budget that ends exactly at the last session: no next page.
  const exact = await historyPageWhere(list(200), null, 25, 200, keep);
  assert.equal(exact.next, null);
});

test("historyPageWhere: an id no longer listed reads from the newest; the limit is clamped; the system logs stay out", async () => {
  const all = list(5);
  assert.deepEqual(ids(await historyPageWhere(all, "gone", 25, 200, () => true)), ["s0", "s1", "s2", "s3", "s4"]);
  assert.deepEqual(ids(await historyPageWhere(all, "s4", 25, 200, () => true)), [], "past the last");
  assert.equal((await historyPageWhere(all, "s4", 25, 200, () => true)).next, null);
  assert.equal((await historyPageWhere(list(300), null, 1000, 300, () => true)).page.length, HISTORY_PAGE_MAX);
  assert.equal((await historyPageWhere(all, null, 0, 200, () => true)).page.length, 1, "at least one row");
  const withLog = [ref("arbiter-admin"), ...all, ref("net-guard")];
  const seen: string[] = [];
  const r = await historyPageWhere(withLog, null, 25, 200, (s) => { seen.push(s.id); return true; });
  assert.deepEqual(seen, ["s0", "s1", "s2", "s3", "s4"], "a system log is never looked at");
  assert.deepEqual(ids(r), ["s0", "s1", "s2", "s3", "s4"]);
});

test("buildHistoryViewModel carries only.through when the read named the switch", () => {
  const vm = buildHistoryViewModel({ total: 9, page: [ref("a")], next: "a", facts: new Map([["a", facts({ blocked: 1 })]]), only: { through: 4 } });
  assert.deepEqual(vm.only, { through: 4 });
  assert.equal(vm.total, 9, "total still counts every session");
  assert.equal(vm.rows[0]!.blocked, 1);
  assert.equal("only" in buildHistoryViewModel({ total: 1, page: [], next: null, facts: new Map() }), false);
});
