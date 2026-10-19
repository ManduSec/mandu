/**
 * sessions-payload.test — the /api/sessions body (server/api-routes.ts
 * sessionsPayload, dashboard.md §4.30): the list goes out once per role. The
 * flat `sessions` map carries no replay annotation, the old `batches` copy is
 * gone, and a recorded row in `sections` keeps only what the sidebar row
 * draws (dev/js/app.js replayRow): no run id, key or run block, which the
 * batch and the session id already carry. A row's chip counts (§4.33) ride
 * the section rows only. `canStart` (what the server can start, §4.8) goes
 * out as given.
 *
 * Mandu-new test (NO reference origin). Pure: no server.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { sessionsPayload, wireReplay } from "../../../src/server/api-routes.js";
import { buildSidebarSections } from "../../../src/session-batches.js";
import type { SessionRef } from "../../../src/event-source.js";

const replay: NonNullable<SessionRef["replay"]> = {
  runId: "gl-501-7", key: "conf-read-exfil-claude-120x40", drill: "conf-read-exfil", title: "Read a secret", agent: "claude",
  size: "120x40", mode: "interactive", verdict: "PASS",
  tally: { security: { pass: 2, total: 2 }, utility: { pass: 1, total: 1 }, fidelity: { pass: 0, total: 0 } },
  script: { version: "a1b2c3d4", origin: "hand" }, engine: 1, recorded: true, plainRecorded: false,
  run: { commit: "4f1c2e9a0b1c", ref: "master", source: "ci", startedAt: "2026-10-01T09:00:00Z" },
};
const recorded: SessionRef = {
  id: "gl-501-7/conf-read-exfil-claude-120x40", label: "Read a secret", eventCount: 2,
  firstTs: "2026-10-01T09:00:06.000Z", lastTs: "2026-10-01T09:00:40.000Z", violated: false, batchId: "gl-501-7", agent: "claude", replay,
};
/** A server with all its runners (the controls on). */
const ON = { agent: true, suite: true, drill: true };
const live: SessionRef = { id: "1750000000-42", label: "hello", eventCount: 3, firstTs: "2026-10-01T08:00:00.000Z", lastTs: "2026-10-01T08:01:00.000Z", violated: false };

test("sessionsPayload: no `batches`; the flat map without replay; a replay row trimmed to what it draws", () => {
  const sessions = [recorded, live];
  const sections = buildSidebarSections(sessions, [], Date.parse("2026-10-02T00:00:00Z"), "UTC", [], { watchStoreRead: false });
  const body = sessionsPayload(sessions, sections, true, { agent: false, suite: true, drill: false });
  assert.deepEqual(Object.keys(body).sort(), ["canDelete", "canStart", "sections", "sessions"], "the old `batches` copy is gone");
  assert.equal(body.canDelete, true);
  assert.deepEqual(body.canStart, { agent: false, suite: true, drill: false }, "what the server can start, as given");
  assert.deepEqual(body.sessions.map((s) => s.id), [recorded.id, live.id], "every session, in order");
  assert.equal("replay" in body.sessions[0]!, false, "the flat map carries no replay annotation");
  assert.equal(body.sessions[0]!.batchId, "gl-501-7", "…but every other field");
  assert.deepEqual(body.sessions[1], live);

  const row = body.sections.replay[0]!.sessions[0]!;
  assert.equal(row.id, recorded.id);
  assert.equal(row.status, "pass", "the section's own annotations stay");
  const { runId: _r, key: _k, run: _u, ...drawn } = replay;
  assert.deepEqual(row.replay, drawn, "the row keeps exactly the fields replayRow draws");
  assert.deepEqual(body.sections.replay[0]!.replayRun, { commit: "4f1c2e9a0b1c", ref: "master", source: "ci", startedAt: "2026-10-01T09:00:00Z" },
    "the run block rides the batch once, not every row");
  assert.equal(body.sections.live[0]!.sessions[0]!.id, live.id, "a live row is untouched");
  assert.deepEqual(body.sections.live[0]!.sessions[0], sections.live[0]!.sessions[0]);
  // the input is not mutated
  assert.ok(sessions[0]!.replay?.run, "the source's refs keep their annotation");
});

test("the wire body is smaller than the old one by more than its duplicate", () => {
  const sessions: SessionRef[] = Array.from({ length: 300 }, (_, i) => ({
    ...recorded, id: `gl-501-7/k${i}`, replay: { ...replay, key: `k${i}` },
  }));
  const sections = buildSidebarSections(sessions, [], Date.now(), "UTC", [], { watchStoreRead: false });
  const now = JSON.stringify(sessionsPayload(sessions, sections, false, ON)).length;
  const old = JSON.stringify({ sessions, batches: sections.replay, sections, canDelete: false }).length;
  assert.ok(now < old / 2, `${now} bytes now vs ${old} before`);
});

test("wireReplay drops only runId, key and run", () => {
  const w = wireReplay({ ...replay, lane: "real-config", recordLost: true });
  assert.equal(w.lane, "real-config");
  assert.equal(w.recordLost, true);
  assert.equal("runId" in w || "key" in w || "run" in w, false);
});

test("a row's chip counts ride its section row only, not the flat label map", () => {
  const counted: SessionRef = { ...live, counts: { masked: 2, blocked: 1 } };
  const rec: SessionRef = { ...recorded, counts: { asks: 3 } };
  const sessions = [rec, counted];
  const sections = buildSidebarSections(sessions, [], Date.parse("2026-10-02T00:00:00Z"), "UTC", [], { watchStoreRead: false });
  const body = sessionsPayload(sessions, sections, false, ON);
  assert.ok(body.sessions.every((s) => !("counts" in s)), "the flat map carries no counts");
  assert.equal(body.sessions[1]!.label, "hello", "…but the rest of the row");
  assert.deepEqual(body.sections.live[0]!.sessions[0]!.counts, { masked: 2, blocked: 1 });
  assert.deepEqual(body.sections.replay[0]!.sessions[0]!.counts, { asks: 3 });
  assert.deepEqual(sessions[1]!.counts, { masked: 2, blocked: 1 }, "the source's refs are not mutated");
});
