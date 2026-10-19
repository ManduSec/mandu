/**
 * tenant-classification.test — the dashboard classifies a session by its
 * TENANT STAMP first and by the session-id prefix only as the fallback
 * (docs/design/ui/policy-surface.md §2.7; the user's report that
 * launcher-driven live tests — golden-path, kernel-tier, TUI differential,
 * dev-rig sessions, all minted as `<sec>-<pid>` — landed in the LIVE section).
 *
 * Pins:
 *   - deriveTenant: the arbiter's summary hint wins, else the first stamped
 *     event, else undefined (garbage hints are ignored);
 *   - tenantedTags: a `test` tenant always carries the "test" tag (existing
 *     tag consumers keep working); a `live` tenant never does, even for an id
 *     that matches a test prefix; unstamped keeps the id-derived tags;
 *   - buildSidebarSections: a stamped-test session with a live-looking id goes
 *     to Testing; a stamped-live session with a test-prefix id goes to Live;
 *     an unstamped test-prefix id still goes to Testing (legacy fallback).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveTenant, tenantedTags } from "../../src/event-source/registry.js";
import { buildSidebarSections } from "../../src/session-batches.js";
import type { SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";

function ev(extra: Partial<ManduEvent>): ManduEvent {
  return {
    id: "e",
    sessionId: "s",
    turn: 0,
    ts: "2026-09-05T00:00:00.000Z",
    seq: 1,
    callId: null,
    parentId: null,
    kind: "tllm_call",
    view: "AgentView",
    boundary: "model_context",
    emitter: "anthropic-proxy",
    input: null,
    output: null,
    invariant: { violatedInvariant: false },
    ...extra,
  } as ManduEvent;
}

test("deriveTenant: summary hint wins; else the first stamped event; garbage is ignored", () => {
  assert.equal(deriveTenant([], "test"), "test");
  assert.equal(deriveTenant([ev({ tenant: "live" })], "test"), "test", "the arbiter's summary is authoritative");
  assert.equal(deriveTenant([ev({}), ev({ tenant: "live" })]), "live");
  assert.equal(deriveTenant([ev({})]), undefined);
  assert.equal(deriveTenant([ev({})], "staging"), undefined, "an unknown hint is not a tenant");
});

test("tenantedTags: test always carries the tag, live never does, unstamped keeps the id-derived tags", () => {
  assert.deepEqual(tenantedTags("1757000000-4242", "test"), ["test"]);
  assert.deepEqual(tenantedTags("claude-e2e-greeting-1757000000000", "test"), ["test", "claude-e2e"]);
  assert.equal(tenantedTags("claude-e2e-greeting-1757000000000", "live"), undefined, "a live stamp overrides a test-looking id");
  assert.equal(tenantedTags("1757000000-4242", "live"), undefined);
  assert.deepEqual(tenantedTags("replay-e2e-ipi-1757000000000", undefined), ["test", "replay-e2e"]);
  assert.equal(tenantedTags("1757000000-4242", undefined), undefined);
});

function ref(id: string, over: Partial<SessionRef> = {}): SessionRef {
  return {
    id,
    label: null,
    eventCount: 1,
    firstTs: "2026-09-05T00:00:00.000Z",
    lastTs: "2026-09-05T00:00:01.000Z",
    violated: false,
    ...over,
  };
}

test("buildSidebarSections: the stamp decides the section; the id prefix is only the unstamped fallback", () => {
  const sessions: SessionRef[] = [
    // A launcher-driven live TEST (golden-path / kernel-tier / dev rig): plain
    // id, stamped test → Testing, not Live.
    ref("1757000000-4242", { tenant: "test", tags: ["test"] }),
    // A human's real run whose id happens to look like a suite prefix → Live.
    ref("claude-e2e-lookalike-1757000000000", { tenant: "live" }),
    // Unstamped legacy test session → Testing by prefix, as before.
    ref("replay-e2e-ipi-1757000000000", { tags: ["test", "replay-e2e"] }),
    // Unstamped plain session → Live, as before.
    ref("1757000001-4243"),
  ];
  const out = buildSidebarSections(sessions, [], Date.parse("2026-09-05T00:00:02.000Z"), "UTC");
  const liveIds = out.live.flatMap((b) => b.sessions.map((s) => s.id));
  const testIds = out.testing.flatMap((b) => b.sessions.map((s) => s.id));
  assert.deepEqual(liveIds.sort(), ["1757000001-4243", "claude-e2e-lookalike-1757000000000"]);
  assert.deepEqual(testIds.sort(), ["1757000000-4242", "replay-e2e-ipi-1757000000000"]);
});

test("tenantedTags: a live-stamped harness FRAGMENT (no conversation, no launch) files with the tests", () => {
  // Found 2026-09-28: twelve `claude-e2e-*` logs from 2026-09-05 in Live, each
  // only a U-LLM inspection + net events a test run sent to the live arbiter.
  const id = "claude-e2e-agentdojo-slack-message-1788582078778";
  const sideTraffic = [ev({ kind: "ullm_call", emitter: "inspect-mcp" }), ev({ kind: "net_action", emitter: "net-supervisor" })];
  assert.deepEqual(tenantedTags(id, "live", sideTraffic), ["test", "claude-e2e"]);
  // A conversation or a launch means someone ran it: the live stamp stands.
  assert.equal(tenantedTags(id, "live", [...sideTraffic, ev({ kind: "tllm_call" })]), undefined);
  assert.equal(tenantedTags(id, "live", [ev({ kind: "launch_posture", emitter: "launcher" })]), undefined);
  // A plain id is never a fragment, whatever it holds.
  assert.equal(tenantedTags("1757000000-4242", "live", sideTraffic), undefined);
  // Without events (a summary-only stub) the stamp decides, as before.
  assert.equal(tenantedTags(id, "live"), undefined);
});

test("buildSidebarSections: watch-runner ids are drills even when their run record is gone", () => {
  const sessions: SessionRef[] = [
    ref("watch-20260918T075114-p1", { tenant: "live" }),
    ref("watch-20260918T214500-conf-c7", { tenant: "live", batchId: "watch-20260918T214500-conf" }),
    ref("watch-dbg-1", { tenant: "live" }),
    ref("1757000001-4243", { tenant: "live" }),
  ];
  const out = buildSidebarSections(sessions, [], Date.parse("2026-09-05T00:00:02.000Z"), "UTC", []);
  assert.deepEqual(out.live.flatMap((b) => b.sessions.map((s) => s.id)), ["1757000001-4243"]);
  assert.deepEqual(
    out.drills.flatMap((b) => b.sessions.map((s) => s.id)).sort(),
    ["watch-20260918T075114-p1", "watch-20260918T214500-conf-c7", "watch-dbg-1"],
  );
});

test("buildSidebarSections: logs that are not sessions sit in one 'System logs' group, last in Live", () => {
  const sessions: SessionRef[] = [
    ref("arbiter-admin", { lastTs: "2026-09-05T00:00:09.000Z" }),
    ref("net-guard"),
    ref("eg_mu81mj93_fivr", { tenant: "live" }),
    ref("1757000001-4243", { tenant: "live" }),
  ];
  const out = buildSidebarSections(sessions, [], Date.parse("2026-09-05T00:00:10.000Z"), "UTC");
  assert.equal(out.live.length, 2);
  assert.deepEqual(out.live[0]!.sessions.map((s) => s.id), ["1757000001-4243"]);
  const sys = out.live[1]!;
  assert.equal(sys.id, "system-logs");
  assert.equal(sys.title, "System logs");
  assert.equal(sys.ungrouped, false);
  assert.deepEqual(sys.sessions.map((s) => s.id), ["arbiter-admin", "net-guard", "eg_mu81mj93_fivr"]);
  assert.ok(sys.status, "the group carries a status rollup like every batch");
});

test("the local-model drill (test-tenant private arbiter + launcher) files under Testing, never Live", () => {
  // Its sessions carry a launch AND a conversation, so no fragment rule is in
  // play: the stamp alone decides, and the drill stamps `test` (2026-09-28;
  // before, its `lm-local-*` ids and a `live` launcher stamp sat in Live).
  const id = "local-model-e2e-local-model-1790555000000";
  const drill = [ev({ kind: "launch_posture", emitter: "launcher", tenant: "test" }), ev({ tenant: "test" })];
  assert.equal(deriveTenant(drill), "test");
  assert.deepEqual(tenantedTags(id, "test", drill), ["test", "local-model-e2e"]);
  const sessions: SessionRef[] = [
    ref(id, { tenant: "test", tags: tenantedTags(id, "test", drill) }),
    ref("1757000001-4243", { tenant: "live" }),
  ];
  const out = buildSidebarSections(sessions, [], Date.parse("2026-09-05T00:00:02.000Z"), "UTC");
  assert.deepEqual(out.live.flatMap((b) => b.sessions.map((s) => s.id)), ["1757000001-4243"]);
  assert.deepEqual(out.testing.flatMap((b) => b.sessions.map((s) => s.id)), [id]);
});
