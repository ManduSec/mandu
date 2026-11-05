/**
 * agent-page-neighbours.test — dashboard.md §4.25b *Newer and older
 * sessions*, over the real DashboardServer and a file source (product-only
 * build): four recorded sessions with distinct last moments, a drill run
 * among them. `GET /api/home/agent?session=` carries `neighbours`, the
 * sessions just above (`newer`) and below (`older`) it in History's list,
 * cross-checked against `/api/home/history`'s rows: the newest has no
 * `newer`, the oldest no `older`; a drill run's page has none and is no
 * one's neighbour; a session with only the launcher's posture line (a
 * fallback label) is named with `title: null`; History's search does not
 * change the order (its filters do not apply). Signed out, the read is a
 * projection, and the neighbours are the same metadata History serves.
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
import type { AgentPageVM } from "../../src/view-model/agent-page-types.js";

const DIR = mkdtempSync(join(tmpdir(), "mandu-agent-neighbours-"));
after(() => rmSync(DIR, { recursive: true, force: true }));

let seq = 0;
const ev = (sid: string, ts: string, over: Record<string, unknown>) => JSON.stringify({
  id: `01J0000000000000000NB${String(++seq).padStart(5, "0")}`, sessionId: sid, turn: 0, ts, seq, callId: null, parentId: null,
  view: "AgentView", invariant: { violatedInvariant: false }, ...over,
});
/** A session of two model calls, at `from` and `to`, its prompt `words`. */
function session(sid: string, from: string, to: string, words: string): void {
  const call = (ts: string) => ev(sid, ts, {
    kind: "tllm_call", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: `▸ user\n${words}`, original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  });
  writeFileSync(join(DIR, `${sid}.ndjson`), `${call(from)}\n${call(to)}\n`);
}
session("sess-a-oldest", "2026-10-18T09:00:00.000Z", "2026-10-18T09:30:00.000Z", "Rename the parser helper.");
session("sess-b-middle", "2026-10-20T10:00:00.000Z", "2026-10-20T10:30:00.000Z", "Fix the deploy script.");
session("sess-c-newest", "2026-10-22T11:00:00.000Z", "2026-10-22T11:30:00.000Z", "Write the release notes.");
// A drill run between them in time: never in History, so no one's neighbour.
session("watch-20261021-1-scenario", "2026-10-21T08:00:00.000Z", "2026-10-21T08:30:00.000Z", "Drill prompt.");
// Only the launcher's posture line: a fallback label, older than every other.
writeFileSync(join(DIR, "sess-0-posture.ndjson"), ev("sess-0-posture", "2026-10-17T07:00:00.000Z", {
  kind: "launch_posture", boundary: "exec", emitter: "launcher",
  input: { symbolized: "claude launch: 7 rung(s) live", original: null, differs: false, symbols: [] },
}) + "\n");

const servers: DashboardServer[] = [];
after(async () => { for (const s of servers) await s.close(); });

async function serve() {
  const server = new DashboardServer({ source: new FileEventSource(DIR), log: () => {} });
  servers.push(server);
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const read = async <T>(path: string): Promise<T> => {
    const res = await fetch(`${base}${path}`);
    assert.equal(res.status, 200, `${path}: signed out, the read is served`);
    return (await res.json()) as T;
  };
  return {
    agent: (id: string) => read<AgentPageVM>(`/api/home/agent?session=${encodeURIComponent(id)}`),
    history: (q = "") => read<HistoryVM>(`/api/home/history?limit=100${q}`),
  };
}

test("the middle session's newer and older are the rows above and below it in History, named as its rows", async () => {
  const { agent, history } = await serve();
  const rows = (await history()).rows;
  const ids = rows.map((r) => r.id);
  assert.deepEqual(ids, ["sess-c-newest", "sess-b-middle", "sess-a-oldest", "sess-0-posture"], "History: newest first, no drill run");
  const vm = await agent("sess-b-middle");
  assert.equal(vm.found, true);
  const row = (id: string) => rows.find((r) => r.id === id)!;
  assert.deepEqual(vm.neighbours, {
    newer: { id: "sess-c-newest", agent: row("sess-c-newest").agent, title: row("sess-c-newest").title, at: row("sess-c-newest").lastAt },
    older: { id: "sess-a-oldest", agent: row("sess-a-oldest").agent, title: row("sess-a-oldest").title, at: row("sess-a-oldest").lastAt },
  }, "each named as its History row: agent, prompt label, last moment");
  assert.equal(vm.neighbours?.newer?.title, "Write the release notes.");
  assert.equal(vm.neighbours?.older?.at, "2026-10-18T09:30:00.000Z");
});

test("every listed session links the rows next to it; the newest has no newer, the oldest no older", async () => {
  const { agent, history } = await serve();
  const ids = (await history()).rows.map((r) => r.id);
  for (const [i, id] of ids.entries()) {
    const n = (await agent(id)).neighbours;
    assert.ok(n, `${id} is in History: it has neighbours`);
    assert.equal(n.newer?.id ?? null, ids[i - 1] ?? null, `${id}: newer`);
    assert.equal(n.older?.id ?? null, ids[i + 1] ?? null, `${id}: older`);
  }
});

test("a drill run's page has none; a fallback label gives title null; a missing session has none", async () => {
  const { agent, history } = await serve();
  const posture = (await history()).rows.find((r) => r.id === "sess-0-posture")!;
  assert.equal(posture.title, null, "History draws it with no prompt");
  const drill = await agent("watch-20261021-1-scenario");
  assert.equal(drill.found, true, "the drill's page opens (from an ask)");
  assert.equal(drill.neighbours, undefined, "not in History: neither link");
  const oldest = await agent("sess-a-oldest");
  assert.deepEqual(oldest.neighbours?.older, { id: "sess-0-posture", agent: posture.agent, title: null, at: "2026-10-17T07:00:00.000Z" }, "the posture line is no title");
  const missing = await agent("sess-nowhere");
  assert.equal(missing.found, false);
  assert.equal(missing.neighbours, undefined);
});

test("History's search does not change them: the full list's order", async () => {
  const { agent, history } = await serve();
  assert.deepEqual((await history("&q=deploy")).rows.map((r) => r.id), ["sess-b-middle"], "a search keeps one row");
  const n = (await agent("sess-b-middle")).neighbours;
  assert.equal(n?.newer?.id, "sess-c-newest");
  assert.equal(n?.older?.id, "sess-a-oldest");
});
