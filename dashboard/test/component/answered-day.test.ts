/**
 * answered-day.test — dashboard.md §4.25 *Go to a day on Answered
 * earlier*, over the real DashboardServer and a file source whose policy
 * snapshot serves answers decided on three days (Oct 18, 20 and 22), one
 * answer not stamped and asked last on Oct 22, and one still waiting.
 * `GET /api/home/answered?before=<ms>` keeps the answers decided before the
 * bound, newest first; `total`, `next` and Show more count the cut list and
 * page on past the day to the oldest; the answer not stamped is cut by when
 * it was last asked; with `q`, both hold; an unparseable `before` is no day.
 *
 * Axes: the store serves the Secrets posture; display only, no arbiter runs.
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { rmSync } from "node:fs";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../src/policy-model.js";
import type { AnsweredPage } from "../../src/view-model/home.js";
import { tmpDir } from "../unit/tmp-dir.js";

const at = (iso: string) => Date.parse(iso);
const answer = (id: string, decided: string | null, over: Partial<VerdictEntry> = {}): VerdictEntry => ({
  id, symbol: `$MDU:nomodel_Read[ab12cd34].KEY_${id.replace(/\W/g, "_").toUpperCase()}`, destination: "api.stripe.com",
  source: { tool: "Read", origin: "/home/u/shop/.env" }, status: "denied", reason: "r", count: 1,
  firstSeen: at(decided ?? "2026-10-22T12:00:00Z") - 60_000, lastSeen: at(decided ?? "2026-10-22T12:00:00Z"),
  resolvedAt: decided === null ? null : at(decided), sessions: ["s-1"],
  ...over,
} as VerdictEntry);

const VERDICTS: VerdictEntry[] = [
  answer("egr-d22b", "2026-10-22T16:00:00Z"),
  answer("egr-d22a", "2026-10-22T11:00:00Z", { destination: "pastebin.com" }),
  answer("egr-nostamp", null),
  answer("egr-d20b", "2026-10-20T15:00:00Z", { destination: "pastebin.com" }),
  answer("egr-d20a", "2026-10-20T10:00:00Z"),
  answer("egr-d18b", "2026-10-18T15:00:00Z", { destination: "pastebin.com" }),
  answer("egr-d18a", "2026-10-18T09:00:00Z"),
  answer("egr-wait", null, { status: "pending", lastSeen: at("2026-10-19T12:00:00Z") }),
];

class QueueSource extends FileEventSource {
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true },
      usage: { rules: [], sensitivePaths: [] },
      verdicts: VERDICTS,
    } as unknown as PolicySnapshot;
  }
}

const events = tmpDir("mandu-answered-day-");
const mHome = tmpDir("mandu-answered-day-home-");
const server = new DashboardServer({ source: new QueueSource(events), configEnv: { MANDU_HOME: mHome }, fileBrowserHome: "/home/u", log: () => {} });
const base = `http://127.0.0.1:${await server.listen(0)}`;
after(async () => {
  await server.close();
  for (const d of [events, mHome]) rmSync(d, { recursive: true, force: true });
});

/** The end of Oct 20 as a browser in UTC sends it: the start of Oct 21. */
const OCT21 = at("2026-10-21T00:00:00.000Z");

async function read(query: string): Promise<AnsweredPage> {
  const res = await fetch(`${base}/api/home/answered${query}`);
  assert.equal(res.status, 200);
  return (await res.json()) as AnsweredPage;
}
const ids = (p: AnsweredPage) => p.rows.map((r) => r.id);

test("C1: ?before= keeps the answers decided before it, newest first; total, next and Show more count the cut list", async () => {
  const every = await read("");
  assert.deepEqual(ids(every), ["egr-d22b", "egr-nostamp", "egr-d22a", "egr-d20b", "egr-d20a", "egr-d18b", "egr-d18a"], "every answer, the one not stamped by when it was last asked");
  assert.equal(every.before, undefined);
  const first = await read(`?limit=2&before=${OCT21}`);
  assert.deepEqual(ids(first), ["egr-d20b", "egr-d20a"], "the day first, nothing newer");
  assert.equal(first.total, 4);
  assert.equal(first.next, "egr-d20a");
  assert.deepEqual(first.before, { at: OCT21, all: 7 });
  const more = await read(`?after=${first.next}&limit=2&before=${OCT21}`);
  assert.deepEqual(ids(more), ["egr-d18b", "egr-d18a"], "Show more goes on past the day to the oldest");
  assert.equal(more.next, null);
});

test("C2: a search holds with the day; an unparseable before is no day", async () => {
  const q = await read(`?q=pastebin&before=${OCT21}`);
  assert.deepEqual(ids(q), ["egr-d20b", "egr-d18b"]);
  assert.equal(q.total, 2);
  assert.deepEqual(q.query, { text: "pastebin", all: 7 });
  for (const bad of ["", "tuesday", "1e400x"]) {
    const r = await read(`?before=${encodeURIComponent(bad)}`);
    assert.equal(r.total, 7, `before=${bad}: every answer`);
    assert.equal(r.before, undefined);
  }
  const none = await read(`?before=${at("2026-10-01T00:00:00Z")}`);
  assert.deepEqual(ids(none), []);
  assert.deepEqual(none.before, { at: at("2026-10-01T00:00:00Z"), all: 7 }, "nothing before the day, and the page can tell it from an empty record");
});
