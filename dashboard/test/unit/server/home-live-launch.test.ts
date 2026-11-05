/**
 * home-live-launch.test — an agent quiet for longer than the listing's
 * five-minute recency window stays running while its `mandu` launch is
 * alive (dashboard.md §4.10.4, *A live launch keeps R*): `buildHome`,
 * `buildHistoryFor` and `buildAgentPageFor` over the `live` dep
 * (home-routes.ts `withLive`), and the server's wiring of
 * `liveLaunches` for the live tenant only.
 *
 * Pins:
 * - a session whose last event is 20 minutes old, with a question of its
 *   own still waiting: with its launch alive, its Home row is not idle
 *   (`waiting`: under Running now), the question carries no `askerEnded`
 *   (so its card keeps "tell the agent to try again"), History's row and
 *   the session page say running too;
 * - without the launch (the dep absent, or another session's launch alive):
 *   today's rule, the row idle, the question from a session that ended;
 * - a recorded exit outranks a live launch;
 * - `withLive` marks copies, never the source's own SessionRefs (a source
 *   caches them, and a kept mark would outlive the launch); a `live` read
 *   that throws is none;
 * - the server passes `liveLaunches` to the live tenant's Home and never to
 *   the test tenant's.
 *
 * Axes: the stub snapshot serves the `secrets` posture (stated); display
 * only, no arbiter runs.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildAgentPageFor, buildHistoryFor, buildHome, HomeFacts, withLive, type HomeDeps } from "../../../src/server/home-routes.js";
import { FileEventSource } from "../../../src/event-source.js";
import type { SessionRef } from "../../../src/event-source/contract.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import { DashboardServer } from "../../../src/server.js";

const MIN = 60_000;
const SID = "1793600000-4242";
const OTHER = "1793600500-4343";
// The real clock: the server case reads it (it has no clock seam).
const NOW = Date.now();
const QUIET_SINCE = new Date(NOW - 20 * MIN).toISOString();
const MANDU = mkdtempSync(join(tmpdir(), "mandu-home-live-mandu-"));
const dirs: string[] = [MANDU];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function event(sid: string, ts: string, seq: number, kind = "tllm_call"): string {
  return JSON.stringify({
    id: `01J0000000000000000000${String(seq).padStart(4, "0")}`, sessionId: sid, turn: 0, ts, seq, callId: null, parentId: null,
    kind, view: "AgentView", boundary: "model_context", emitter: kind === "session_exit" ? "launcher" : "anthropic-proxy",
    input: { symbolized: "▸ user\nDeploy the shop.", original: null, differs: false, symbols: [] },
    output: { symbolized: "I need to send the key.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  }) + "\n";
}

/** A record dir holding SID, quiet for 20 minutes. */
function records(): string {
  const dir = mkdtempSync(join(tmpdir(), "mandu-home-live-"));
  dirs.push(dir);
  writeFileSync(join(dir, `${SID}.ndjson`), event(SID, new Date(NOW - 22 * MIN).toISOString(), 0) + event(SID, QUIET_SINCE, 1));
  return dir;
}

/** A file source behind which an arbiter serves the `secrets` posture and
 *  one pending question SID asked. */
class Source extends FileEventSource {
  listed: SessionRef[] = [];
  override async listSessions(): Promise<SessionRef[]> {
    this.listed = await super.listSessions();
    return this.listed;
  }
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    const verdicts = [{
      id: "egr-1", symbol: "$MDU:nomodel_Read[1abc].STRIPE_KEY", destination: "api.stripe.com", status: "pending",
      reason: "secret symbol (no-model) at unbound destination", count: 1, firstSeen: NOW - 21 * MIN, lastSeen: NOW - 20 * MIN,
      resolvedAt: null, sessions: [SID],
    } as VerdictEntry];
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true }, // the `secrets` axes, stated
      usage: { rules: [], sensitivePaths: [] },
      verdicts,
    } as unknown as PolicySnapshot;
  }
}

function deps(source: Source, live?: HomeDeps["live"], now = NOW): HomeDeps {
  return {
    source, facts: new HomeFacts(source, "/home/u"), approvals: undefined, testRuns: [], watchRuns: [],
    env: { MANDU_HOME: MANDU }, home: "/home/u", now: () => now, ...(live ? { live } : {}),
  };
}

test("quiet 20 minutes with its launch alive: Home keeps it under Running now and its question live; History and its page agree", async () => {
  const source = new Source(records());
  const d = deps(source, () => new Set([SID]));
  const home = await buildHome(d);
  const row = home.agents.find((a) => a.id === SID);
  assert.ok(row, "the session has a Home row");
  assert.equal(row.state, "waiting", "running, waiting on its question: under Running now, not Earlier");
  const ask = home.waiting.find((a) => a.id === "egr-1");
  assert.ok(ask, "the question waits");
  assert.equal(ask.askerEnded, undefined, "its asker has not ended: the card keeps 'try again'");
  const history = await buildHistoryFor(d, null, 20);
  assert.notEqual(history.rows.find((r) => r.id === SID)?.state, "idle", "History lists it running");
  const page = await buildAgentPageFor(d, SID);
  assert.equal(page.running, true, "its page says it runs");
});

test("the control: no live launch (no dep, or another session's), the recency rule ends it as today", async () => {
  for (const [what, live] of [["no dep", undefined], ["another launch alive", () => new Set([OTHER])]] as const) {
    const source = new Source(records());
    const d = deps(source, live);
    const home = await buildHome(d);
    assert.equal(home.agents.find((a) => a.id === SID)?.state, "idle", `${what}: Earlier`);
    assert.equal(home.waiting.find((a) => a.id === "egr-1")?.askerEnded, true, `${what}: the question is from a session that has ended`);
    assert.equal((await buildHistoryFor(d, null, 20)).rows.find((r) => r.id === SID)?.state, "idle", what);
    assert.equal((await buildAgentPageFor(d, SID)).running, false, what);
  }
});

test("a recorded exit outranks a live launch", async () => {
  const dir = records();
  appendFileSync(join(dir, `${SID}.ndjson`), event(SID, new Date(NOW - 19 * MIN).toISOString(), 2, "session_exit"));
  const d = deps(new Source(dir), () => new Set([SID]));
  const home = await buildHome(d);
  assert.equal(home.agents.find((a) => a.id === SID)?.state, "idle", "the agent exited: Earlier");
  assert.equal(home.waiting.find((a) => a.id === "egr-1")?.askerEnded, true);
  assert.equal((await buildAgentPageFor(d, SID)).running, false);
});

test("withLive marks copies, never the source's own refs; a live read that throws is none", async () => {
  const source = new Source(records());
  await buildHome(deps(source, () => new Set([SID])));
  assert.ok(source.listed.length > 0);
  assert.ok(source.listed.every((s) => s.live === undefined), "the source's refs carry no mark");
  const refs: SessionRef[] = [{ id: SID, label: null, eventCount: 1, firstTs: null, lastTs: null, violated: false }, { id: OTHER, label: null, eventCount: 1, firstTs: null, lastTs: null, violated: false }];
  const marked = withLive(refs, new Set([SID]));
  assert.equal(marked[0]!.live, true);
  assert.notEqual(marked[0], refs[0], "a copy");
  assert.equal(marked[1], refs[1], "an unmarked one is passed as it is");
  assert.equal(refs[0]!.live, undefined);
  const thrown = await buildHome(deps(new Source(records()), () => { throw new Error("EACCES"); }));
  assert.equal(thrown.agents.find((a) => a.id === SID)?.state, "idle", "a read that throws: the recency rule alone");
});

test("the server passes liveLaunches to the live tenant's Home, never the test tenant's", async () => {
  // Real time: the record's last event is far older than five minutes.
  const live = new Source(records());
  const testSide = new Source(records());
  let reads = 0;
  const server = new DashboardServer({
    source: live, testTenant: { source: testSide }, log: () => {},
    configEnv: { MANDU_HOME: MANDU },
    liveLaunches: () => { reads += 1; return new Set([SID]); },
  });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  try {
    const state = async (q: string) => {
      const res = await fetch(`${base}/api/home${q}`);
      assert.equal(res.status, 200);
      return ((await res.json()) as { agents: { id: string; state: string }[] }).agents.find((a) => a.id === SID)?.state;
    };
    assert.notEqual(await state(""), "idle", "the live tenant: its launch keeps it running");
    assert.ok(reads >= 1, "read for the live tenant");
    const before = reads;
    assert.equal(await state("?tenant=test"), "idle", "the test tenant: the recency rule alone");
    assert.equal(reads, before, "never read for the test tenant");
  } finally {
    await server.close();
  }
});
