/**
 * history-day.test — dashboard.md §4.25ae *Go to a day*: the pure cut
 * History's date box runs (`historyBefore`), the route's reading of
 * `?before=` (`historyBeforeParam`) and the view model carrying it
 * (`buildHistoryViewModel`'s `before`).
 *
 * The key is a session's last moment (`lastTs`, else `firstTs`): the moment
 * History is ordered by and an ended row's day heading names, so going to a
 * day lists exactly the rows under that day's heading and below. A session
 * that started before the bound and ended after it is cut. A session with no
 * time is kept (pinned: it sits at the list's end, undated). A non-finite
 * bound is no bound.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { SessionRef } from "../../../src/event-source/contract.js";
import { buildHistoryViewModel, historyBefore } from "../../../src/view-model/home.js";
import { historyBeforeParam } from "../../../src/server/home-routes.js";

const ref = (id: string, firstTs: string | null, lastTs: string | null): SessionRef => ({
  id, label: `task ${id}`, labelFrom: "prompt", eventCount: 3, firstTs, lastTs, violated: false, agent: "claude", status: "idle",
} as unknown as SessionRef);
const kept = (list: SessionRef[], ms: number) => historyBefore(list, ms).map((s) => s.id);

const BOUND = Date.parse("2026-10-21T00:00:00.000Z");
const LIST = [
  ref("ran-past", "2026-10-20T22:00:00.000Z", "2026-10-21T01:00:00.000Z"),
  ref("at-bound", "2026-10-20T23:00:00.000Z", "2026-10-21T00:00:00.000Z"),
  ref("last-ms", "2026-10-20T10:00:00.000Z", "2026-10-20T23:59:59.999Z"),
  ref("earlier", "2026-10-18T10:00:00.000Z", "2026-10-18T11:00:00.000Z"),
  ref("start-only", "2026-10-19T10:00:00.000Z", null),
  ref("start-only-after", "2026-10-22T10:00:00.000Z", null),
  ref("undated", null, null),
];

test("keeps the sessions whose last moment is before the bound, in order; at or after it is cut", () => {
  assert.deepEqual(kept(LIST, BOUND), ["last-ms", "earlier", "start-only", "undated"]);
});

test("the key is the last moment, not the start: a session that started before the day ended and ran past it is cut", () => {
  assert.ok(!kept(LIST, BOUND).includes("ran-past"), "started on the 20th, ended on the 21st: listed under the 21st, so not from the 20th back");
  assert.ok(kept(LIST, Date.parse("2026-10-22T00:00:00.000Z")).includes("ran-past"), "from the 21st back it is in");
});

test("a session with only a start is cut by its start; one with no time is kept", () => {
  assert.ok(kept(LIST, BOUND).includes("start-only"));
  assert.ok(!kept(LIST, BOUND).includes("start-only-after"));
  assert.ok(kept(LIST, BOUND).includes("undated"), "no time: kept, at the list's end");
  assert.deepEqual(kept([ref("x", "not a time", "nor this")], BOUND), ["x"], "an unreadable time is no time");
});

test("a non-finite bound is no bound; nothing before the first session keeps only the undated", () => {
  for (const ms of [NaN, Infinity, -Infinity]) assert.deepEqual(kept(LIST, ms), LIST.map((s) => s.id), String(ms));
  assert.deepEqual(kept(LIST, Date.parse("2026-01-01T00:00:00.000Z")), ["undated"]);
  assert.deepEqual(kept([], BOUND), []);
  const copy = historyBefore(LIST, NaN);
  assert.notEqual(copy, LIST, "a copy, never the list itself");
});

test("?before= reads as epoch ms; absent, empty or not a number is no day", () => {
  assert.equal(historyBeforeParam(String(BOUND)), BOUND);
  assert.equal(historyBeforeParam("0"), 0);
  for (const raw of [null, "", "  ", "abc", "Infinity", "NaN", "1e999"]) assert.equal(historyBeforeParam(raw), null, String(raw));
});

test("the view model carries `before` only when the read named a day", () => {
  const plain = buildHistoryViewModel({ total: 2, page: [], next: null, facts: new Map() });
  assert.equal("before" in plain, false);
  const cut = buildHistoryViewModel({ total: 2, page: [], next: null, facts: new Map(), before: { at: BOUND, all: 7 } });
  assert.deepEqual(cut.before, { at: BOUND, all: 7 });
  assert.equal(cut.total, 2, "total counts the sessions before the day");
});
