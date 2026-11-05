/**
 * history-day.test — dashboard.md §4.25ae *Go to a day*, over the real
 * DashboardServer and a file source (product-only build): sessions on three
 * days, and one that started on the middle day and ended on the last.
 * `GET /api/home/history?before=<ms>` keeps the sessions whose last moment
 * is before the bound, newest first; `total`, `next` and Show more count
 * the cut list, and Show more goes on past the day to the oldest; the
 * session that ran past the bound is cut (it is listed under the day it
 * ended); with `q`, both hold; an unparseable `before` is no day.
 *
 * Axes: display only (the plain file source serves no posture); no arbiter
 * runs.
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { HistoryVM } from "../../src/view-model/home.js";

const DIR = mkdtempSync(join(tmpdir(), "mandu-history-day-"));
after(() => rmSync(DIR, { recursive: true, force: true }));

/** A session of two model calls, at `from` and `to`, its prompt `words`. */
function session(sid: string, from: string, to: string, words: string): void {
  const call = (i: number, ts: string) => JSON.stringify({
    id: `01J0000000000000000DAY${sid.slice(-2)}${i}`, sessionId: sid, turn: i, ts, seq: i, callId: null, parentId: null,
    kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: `▸ user\n${words}`, original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  });
  writeFileSync(join(DIR, `${sid}.ndjson`), `${call(0, from)}\n${call(1, to)}\n`);
}
session("sess-day1a", "2026-10-18T09:00:00.000Z", "2026-10-18T09:30:00.000Z", "Rename the parser helper.");
session("sess-day1b", "2026-10-18T15:00:00.000Z", "2026-10-18T15:30:00.000Z", "Fix the deploy script.");
session("sess-day2a", "2026-10-20T10:00:00.000Z", "2026-10-20T10:30:00.000Z", "Fix the deploy staging step.");
session("sess-span", "2026-10-20T20:00:00.000Z", "2026-10-22T08:00:00.000Z", "Migrate the database.");
session("sess-day3a", "2026-10-22T11:00:00.000Z", "2026-10-22T11:30:00.000Z", "Write the release notes.");
session("sess-day3b", "2026-10-22T16:00:00.000Z", "2026-10-22T16:30:00.000Z", "Fix the deploy docs.");

/** The end of Oct 20 as a browser in UTC sends it: the start of Oct 21. */
const OCT21 = Date.parse("2026-10-21T00:00:00.000Z");

const servers: DashboardServer[] = [];
after(async () => { for (const s of servers) await s.close(); });

async function serve(): Promise<(query: string) => Promise<HistoryVM>> {
  const server = new DashboardServer({ source: new FileEventSource(DIR), log: () => {} });
  servers.push(server);
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  return async (query) => {
    const res = await fetch(`${base}/api/home/history${query}`);
    assert.equal(res.status, 200, "signed out, the History read is open");
    return (await res.json()) as HistoryVM;
  };
}
const idsOf = (vm: HistoryVM) => vm.rows.map((r) => r.id);

test("?before= keeps the sessions whose last moment is before it, newest first; total counts them; the session that ran past it is cut", async () => {
  const read = await serve();
  const all = await read("?limit=100");
  assert.equal(all.total, 6);
  assert.equal(all.before, undefined, "no day, no `before`");
  assert.deepEqual(idsOf(all), ["sess-day3b", "sess-day3a", "sess-span", "sess-day2a", "sess-day1b", "sess-day1a"], "the plain list: by last moment");
  const cut = await read(`?before=${OCT21}&limit=100`);
  assert.deepEqual(idsOf(cut), ["sess-day2a", "sess-day1b", "sess-day1a"], "from Oct 20 back: exactly the rows below its heading in the plain list");
  assert.equal(cut.total, 3);
  assert.equal(cut.next, null);
  assert.deepEqual(cut.before, { at: OCT21, all: 6 }, "`all`: every session on record");
  assert.ok(!idsOf(cut).includes("sess-span"), "started on Oct 20, ended on Oct 22: cut");
  const none = await read(`?before=${Date.parse("2026-10-01T00:00:00.000Z")}`);
  assert.deepEqual(idsOf(none), []);
  assert.equal(none.total, 0);
  assert.equal(none.before?.all, 6, "the page tells nothing-before-the-day from an empty record");
});

test("next and Show more page through the cut list and go on past the day to the oldest", async () => {
  const read = await serve();
  const first = await read(`?before=${OCT21}&limit=1`);
  assert.deepEqual(idsOf(first), ["sess-day2a"]);
  assert.equal(first.total, 3);
  assert.equal(first.next, "sess-day2a");
  const second = await read(`?after=${first.next}&before=${OCT21}&limit=1`);
  assert.deepEqual(idsOf(second), ["sess-day1b"]);
  assert.equal(second.next, "sess-day1b");
  const last = await read(`?after=${second.next}&before=${OCT21}&limit=1`);
  assert.deepEqual(idsOf(last), ["sess-day1a"]);
  assert.equal(last.next, null, "the oldest: no more");
});

test("with q and only, every filter holds; an unparseable before is no day", async () => {
  const read = await serve();
  const both = await read(`?q=deploy&before=${OCT21}`);
  assert.deepEqual(idsOf(both), ["sess-day2a", "sess-day1b"], "the deploy sessions from Oct 20 back, not Oct 22's");
  assert.equal(both.total, 2);
  assert.equal(both.query?.all, 6);
  const switched = await read(`?only=stepped-in&before=${OCT21}`);
  assert.deepEqual(idsOf(switched), [], "Mandu stepped in on none of them");
  assert.equal(switched.total, 3, "total counts the cut list");
  for (const raw of ["", "abc", "Infinity"]) {
    const vm = await read(`?before=${raw}&limit=100`);
    assert.equal(vm.total, 6, `before=${raw} is no day`);
    assert.equal(vm.before, undefined);
  }
});
