/**
 * session-neighbours.test — dashboard.md §4.25b *Newer and older sessions*:
 * the pure lookup the session page's Newer and Older links come from
 * (home.ts `sessionNeighbours`). The list is History's full list, newest
 * first; this session's neighbours are the rows just above and below it,
 * each named as its History row (the agent's name, `promptLabel` on one
 * line, null for a fallback label; its last moment, else its first). A
 * session not in the list (a drill or test run) has none: null.
 *
 * Axes: none (display only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { SessionRef } from "../../../src/event-source/contract.js";
import { sessionNeighbours } from "../../../src/view-model/home.js";

const ref = (id: string, over: Partial<SessionRef> = {}): SessionRef => ({
  id, label: `task ${id}`, labelFrom: "prompt", eventCount: 3, firstTs: "2026-10-20T09:00:00.000Z", lastTs: "2026-10-20T10:00:00.000Z",
  violated: false, agent: "claude", status: "idle", ...over,
} as unknown as SessionRef);

const LIST = [
  ref("s3", { lastTs: "2026-10-22T14:05:00.000Z", label: "Fix the login\n  test" }),
  ref("s2", { agent: "codex", lastTs: "2026-10-21T22:10:00.000Z", label: "What is in .env?" }),
  ref("s1", { label: "claude launch: 7 rung(s) live", labelFrom: "posture", lastTs: null, firstTs: "2026-10-20T08:00:00.000Z" }),
];

test("the middle session: Newer is the row above it, Older the row below, each named as its History row", () => {
  const n = sessionNeighbours(LIST, "s2");
  assert.deepEqual(n?.newer, { id: "s3", agent: "Claude Code", title: "Fix the login test", at: "2026-10-22T14:05:00.000Z" }, "the prompt on one line");
  assert.deepEqual(n?.older, { id: "s1", agent: "Claude Code", title: null, at: "2026-10-20T08:00:00.000Z" },
    "a fallback label has no title; no last moment: its first");
});

test("the newest has no Newer, the oldest no Older", () => {
  assert.equal(sessionNeighbours(LIST, "s3")?.newer, null);
  assert.equal(sessionNeighbours(LIST, "s3")?.older?.id, "s2");
  assert.equal(sessionNeighbours(LIST, "s1")?.older, null);
  assert.equal(sessionNeighbours(LIST, "s1")?.newer?.agent, "Codex CLI");
});

test("a session History does not list has none; one alone has neither", () => {
  assert.equal(sessionNeighbours(LIST, "drill-run"), null);
  assert.deepEqual(sessionNeighbours([ref("only")], "only"), { newer: null, older: null });
});
