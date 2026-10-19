/**
 * session-paths-api.test — /api/events ships the recorded run paths
 * (`sessionPaths`) for EVERY session, not only test sessions.
 *
 * The client's session-wide short↔full path display (app.js escFold) folds the
 * session's recorded deep roots wherever the trace renders them; test sessions
 * already get the roots inside `testSetup`, so this pins the LIVE-session path:
 * a plain (non `claude-e2e-*`) session with dual-view events must carry
 * `sessionPaths` = { cwd, agentViewRoot, humanViewRoot } (session-paths.ts,
 * event-sourced — null per field when the events don't record it), and a
 * session that recorded no paths must carry NO `sessionPaths` key at all.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer } from "../../src/server.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";

const HUMAN = "/home/user/proj/notes.md";
const AGENT = "/home/user/proj/.mandu/view-state/workspaces/w1/agentview/notes.md";

/** One live-looking session with a dual-view path_rewrite (typed path field),
 *  plus one pathless session (a Track-A-only run). */
function fakeSource(): EventSource {
  const base = {
    sessionId: "live-session-1", turn: 0, callId: null, parentId: null,
    view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, invariant: { violatedInvariant: false },
  };
  const events: ManduEvent[] = [
    {
      ...base, kind: "path_rewrite", id: "e1", seq: 1, ts: "2026-07-16T00:00:00.001Z",
      rewrite: { direction: "forward", tool: "Read", field: "file_path", human: HUMAN, agent: AGENT },
    } as unknown as ManduEvent,
  ];
  const bare: ManduEvent[] = [
    { ...base, sessionId: "bare-session-1", kind: "tllm_call", id: "b1", seq: 1, ts: "2026-07-16T00:00:00.001Z" } as unknown as ManduEvent,
  ];
  return {
    async listSessions(): Promise<SessionRef[]> {
      return [
        { id: "live-session-1", label: "live", eventCount: 1, firstTs: null, lastTs: null, violated: false },
        { id: "bare-session-1", label: "bare", eventCount: 1, firstTs: null, lastTs: null, violated: false },
      ];
    },
    async readEvents(session: string): Promise<ManduEvent[]> {
      return session === "live-session-1" ? events : session === "bare-session-1" ? bare : [];
    },
    subscribe(): () => void { return () => {}; },
    close(): void {},
  };
}

let server: DashboardServer;
let baseUrl: string;

before(async () => {
  server = new DashboardServer({ source: fakeSource(), log: () => {} });
  const port = await server.listen(0);
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await server.close();
});

test("a NON-test session with dual-view events carries sessionPaths (no testSetup)", async () => {
  const res = await fetch(`${baseUrl}/api/events?session=live-session-1`);
  assert.equal(res.status, 200);
  const body = (await res.json()) as Record<string, unknown>;
  assert.equal(body.testSetup, undefined, "a live session has no test-setup panel");
  assert.deepEqual(body.sessionPaths, {
    cwd: null, // no agent env block in these events — honest null, never a guess
    agentViewRoot: "/home/user/proj/.mandu/view-state/workspaces/w1/agentview",
    humanViewRoot: "/home/user/proj",
  });
});

test("a session that recorded no paths ships NO sessionPaths key", async () => {
  const res = await fetch(`${baseUrl}/api/events?session=bare-session-1`);
  assert.equal(res.status, 200);
  const body = (await res.json()) as Record<string, unknown>;
  assert.ok(!("sessionPaths" in body), "nothing recorded → the key is absent, not a null-stuffed object");
});
