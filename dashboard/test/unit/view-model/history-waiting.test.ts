/**
 * history-waiting.test — dashboard.md §4.25ae *History says what waits for
 * you*: a History row counts the questions its session raised that still
 * wait, as Home's rows do (`rowContext`, shared by `buildHomeViewModel` and
 * `buildHistoryViewModel`).
 *
 *   - `rowContext` counts each pending ask once, on the session that raised
 *     it LAST; answered rows count nothing; a queue not known counts none;
 *     `masking` follows the integrity axis;
 *   - History's row of a running session with a question is `waiting`, an
 *     ended one stays `idle` with its count, one with none is unchanged;
 *   - Home's rows and History's rows of the same sessions agree.
 *
 * Axes: none (pure projections; the posture is the snapshot's).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildHistoryViewModel, buildHomeViewModel, rowContext, type HomeSessionFacts } from "../../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import type { SessionRef } from "../../../src/event-source/contract.js";

const NOW = Date.parse("2026-10-16T08:00:00Z");

function snapshot(verdicts: VerdictEntry[] | undefined, integrity = false): PolicySnapshot {
  return {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity, confidentiality: true },
    usage: { rules: [], sensitivePaths: [] },
    ...(verdicts ? { verdicts } : {}),
  } as PolicySnapshot;
}
function ask(id: string, sessions: string[], over: Partial<VerdictEntry> = {}): VerdictEntry {
  return {
    id, symbol: `$MDU:nomodel_Read[${id.replace(/\W/g, "")}].STRIPE_KEY`, destination: "api.stripe.com",
    status: "pending", reason: "secret symbol (no-model) at unbound destination", count: 1,
    firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, resolvedAt: null, sessions, ...over,
  } as VerdictEntry;
}
const ref = (id: string, status: "running" | "idle"): SessionRef => ({
  id, label: `task ${id}`, labelFrom: "prompt", eventCount: 3,
  firstTs: new Date(NOW - 30 * 60_000).toISOString(), lastTs: new Date(NOW - 60_000).toISOString(),
  violated: false, agent: "claude", status,
} as SessionRef);
const fact = (exited = false): HomeSessionFacts => ({
  stats: { flows: 1, secret: 1, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 },
  secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 0, sent: 0, holds: true, violations: 0, cwd: null, exited,
});

const RUN = "1791700000-11";
const ENDED = "1791700100-12";
const QUIET = "1791700200-13";
const SESSIONS = [ref(RUN, "running"), ref(ENDED, "idle"), ref(QUIET, "running")];
const FACTS = new Map<string, HomeSessionFacts>([[RUN, fact()], [ENDED, fact(true)], [QUIET, fact()]]);
const QUEUE: VerdictEntry[] = [
  ask("egr-1", [RUN]),
  // Raised by ENDED, then by RUN: it waits on RUN, the last to ask.
  ask("egr-2", [ENDED, RUN], { destination: "hooks.example.com" }),
  ask("egr-3", [ENDED], { destination: "paste.example" }),
  // Answered: waits on no one.
  ask("egr-4", [QUIET], { status: "denied", resolvedAt: NOW - 30_000 }),
  ask("egr-5", [QUIET], { status: "approved", scope: "once", resolvedAt: NOW - 20_000 } as Partial<VerdictEntry>),
  // Raised by no session on record: counted on no row.
  ask("egr-6", [], { destination: "gist.github.com" }),
];

test("rowContext counts each pending ask once, on the session that raised it last; answered asks and a queue not known count none", () => {
  const ctx = rowContext(toPolicyPanelViewModel(snapshot(QUEUE)));
  assert.deepEqual(ctx.waiting, new Map([[RUN, 2], [ENDED, 1]]));
  assert.equal(ctx.masking, false, "secrets: untrusted content is not masked");
  // No arbiter, or one that serves no queue: nothing is said to wait.
  assert.equal(rowContext(toPolicyPanelViewModel(null)).waiting.size, 0);
  assert.equal(rowContext(toPolicyPanelViewModel(snapshot(undefined))).waiting.size, 0);
  assert.equal(rowContext(toPolicyPanelViewModel(snapshot(QUEUE, true))).masking, true, "the integrity axis on: masking");
});

test("a History row says what waits for you: a running session with a question is waiting, an ended one keeps its count, one with none is unchanged", () => {
  const vm = buildHistoryViewModel({ total: 3, page: SESSIONS, next: null, facts: FACTS, ...rowContext(toPolicyPanelViewModel(snapshot(QUEUE))) });
  const row = (id: string) => vm.rows.find((r) => r.id === id)!;
  assert.deepEqual({ state: row(RUN).state, waiting: row(RUN).waiting }, { state: "waiting", waiting: 2 });
  assert.deepEqual({ state: row(ENDED).state, waiting: row(ENDED).waiting }, { state: "idle", waiting: 1 }, "an ended session is not brought back by its question");
  assert.deepEqual({ state: row(QUIET).state, waiting: row(QUIET).waiting }, { state: "running", waiting: 0 });
  // Without the panel's context (the page's read before this change), every
  // row said nothing waits.
  const bare = buildHistoryViewModel({ total: 3, page: SESSIONS, next: null, facts: FACTS });
  assert.deepEqual(bare.rows.map((r) => [r.state, r.waiting]), [["running", 0], ["idle", 0], ["running", 0]]);
});

test("Home's rows and History's rows of the same sessions agree on state, waiting and notice", () => {
  const panel = toPolicyPanelViewModel(snapshot(QUEUE));
  const home = buildHomeViewModel({ sessions: SESSIONS, facts: FACTS, panel, configuredMode: "secrets", nowMs: NOW, windowHours: 24, historyTotal: 3 });
  const history = buildHistoryViewModel({ total: 3, page: SESSIONS, next: null, facts: FACTS, ...rowContext(panel) });
  const pick = (r: { id: string; state: string; waiting: number; notice: string | null }) => ({ id: r.id, state: r.state, waiting: r.waiting, notice: r.notice });
  assert.deepEqual(history.rows.map(pick), home.agents.map(pick));
  assert.equal(home.window.waiting, 4, "Home's own count of the queue is unchanged");
});
