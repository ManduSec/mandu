/**
 * agent-page-launch-time — dashboard.md §4.25ag end to end: the REAL
 * DashboardServer over a FileEventSource holding a session whose launcher
 * recorded its step timings (a `launch_posture` and a `session_exit`
 * event, as launcher/src/services/observe.ts writes them): GET
 * /api/home/agent carries "Mandu took … to start this session" with the
 * slowest steps first, and the clean-up line; signed out it is the same
 * (the times are no value the AI did not see). A session whose launch
 * recorded none gets no line.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";

const dir = mkdtempSync(join(tmpdir(), "mandu-launch-time-"));
let server: DashboardServer;
let base: string;

function ev(session: string, kind: string, ts: string, extra: Record<string, unknown>): string {
  return JSON.stringify({
    id: `ev_${session}_${kind}`, sessionId: session, turn: 0, ts, seq: 0, callId: null, parentId: null, kind,
    view: kind === "tllm_call" ? "AgentView" : "HumanView", boundary: kind === "tllm_call" ? "model_context" : "shell",
    emitter: kind === "tllm_call" ? "anthropic-proxy" : "launcher", invariant: { violatedInvariant: false },
    input: { symbolized: "hello", original: null, differs: false, symbols: [] },
    output: { symbolized: "hi", original: null, differs: false, symbols: [] },
    ...extra,
  });
}

before(async () => {
  writeFileSync(join(dir, "sess-timed.ndjson"), [
    ev("sess-timed", "launch_posture", "2026-10-21T01:00:00.000Z", {
      target: "claude", argv0: "claude", live: [], dropped: [], notes: [],
      timings: { v: 1, totalMs: 1712, steps: [{ step: "node", ms: 255 }, { step: "services", ms: 368 }, { step: "secrets", ms: 420 }, { step: "secrets.history", ms: 378 }] },
    }),
    ev("sess-timed", "tllm_call", "2026-10-21T01:00:02.000Z", {}),
    ev("sess-timed", "session_exit", "2026-10-21T01:00:09.000Z", {
      code: 0, durationMs: 9000, output: null,
      timings: { v: 1, totalMs: 9300, steps: [{ step: "agent", ms: 7000 }, { step: "teardown.services", ms: 120 }, { step: "teardown.placeholder", ms: 30 }] },
    }),
  ].join("\n") + "\n");
  writeFileSync(join(dir, "sess-plain.ndjson"), [
    ev("sess-plain", "launch_posture", "2026-10-21T01:00:00.000Z", { target: "claude", argv0: "claude", live: [], dropped: [], notes: [] }),
    ev("sess-plain", "tllm_call", "2026-10-21T01:00:02.000Z", {}),
  ].join("\n") + "\n");
  server = new DashboardServer({ ...ADMIN_OPTS, source: new FileEventSource(dir), log: () => {}, extensions: [] });
  base = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function page(session: string, admin: boolean): Promise<any> {
  const r = await fetch(`${base}/api/home/agent?session=${session}`, admin ? { headers: CSRF_ADMIN } : {});
  assert.equal(r.status, 200);
  return r.json();
}

test("the served page's projection says how long Mandu took to start and to clean up, slowest steps first", async () => {
  const vm = await page("sess-timed", true);
  assert.equal(vm.found, true);
  assert.equal(vm.launchTime.sentence, "Mandu took 1.7 s to start this session: checking git history for secrets 0.38 s, starting the session's helpers 0.37 s, starting Mandu 0.26 s.");
  assert.equal(vm.launchTime.cleanup, "After the AI stopped, Mandu took 0.15 s to clean up.");
  const out = await page("sess-timed", false);
  assert.equal(out.valuesShown, false);
  assert.deepEqual(out.launchTime, vm.launchTime, "signed out: the same line");
});

test("a launch that recorded no timings: no line", async () => {
  assert.equal((await page("sess-plain", true)).launchTime, null);
});
