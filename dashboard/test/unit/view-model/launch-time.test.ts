/**
 * launch-time — the session page's "Mandu took 1.7 s to start this session"
 * line (dashboard.md §4.25ag, view-model/launch-time.ts): from the
 * launcher's step timings on its `launch_posture` and `session_exit`
 * events, the slowest steps first in plain words, the secret setup told by
 * its parts, the clean-up after the AI stopped; nothing from a launch that
 * recorded none or a malformed record; no inspector word; on the agent
 * page's projection, signed in or out.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ManduEvent } from "../../../src/event-model.js";
import { launchTimeOf, MIN_SHOWN_MS, seconds, SLOWEST, STEP_WORDS } from "../../../src/view-model/launch-time.js";
import { buildAgentPage } from "../../../src/view-model/agent-page.js";
import { redactEvents } from "../../../src/view-model/redact.js";

const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|symbol|twin|placeholder|teardown|posture|discovery)\b|\$MDU:/i;

function ev(kind: string, ts: string, timings: unknown): ManduEvent {
  return {
    id: `ev_${kind}_${ts}`, sessionId: "s1", turn: 0, ts, seq: 0, callId: null, parentId: null, kind, view: "HumanView",
    boundary: "shell", emitter: "launcher", invariant: { violatedInvariant: false },
    input: { symbolized: "x", original: null, differs: false, symbols: [] }, output: null, timings,
  } as unknown as ManduEvent;
}

const START = {
  v: 1, totalMs: 1712,
  steps: [
    { step: "node", ms: 255 }, { step: "plan", ms: 25 }, { step: "arbiter", ms: 33 }, { step: "services", ms: 368 },
    { step: "secrets", ms: 520 }, { step: "secrets.discovery", ms: 40 }, { step: "secrets.history", ms: 378 },
    { step: "secrets.twin-index", ms: 9 }, { step: "compose", ms: 41 }, { step: "banner", ms: 2 },
  ],
};
const END = { v: 1, totalMs: 9000, steps: [{ step: "agent", ms: 7000 }, { step: "teardown.index", ms: 2 }, { step: "teardown.services", ms: 150 }, { step: "teardown.placeholder", ms: 48 }] };

test("the start: its total and its slowest steps first, in plain words; the secret setup by its parts", () => {
  const lt = launchTimeOf([ev("launch_posture", "2026-10-21T01:00:00.000Z", START)])!;
  assert.equal(lt.total, "1.7 s");
  assert.equal(lt.totalMs, 1712);
  assert.deepEqual(lt.slowest.map((s) => [s.words, s.time]), [
    ["checking git history for secrets", "0.38 s"],
    ["starting the session's helpers", "0.37 s"],
    ["starting Mandu", "0.26 s"],
  ], "the history step named alone; what is left of the secret setup (93 ms) is not among the slowest");
  assert.equal(lt.slowest.length, SLOWEST);
  assert.equal(lt.sentence, "Mandu took 1.7 s to start this session: checking git history for secrets 0.38 s, starting the session's helpers 0.37 s, starting Mandu 0.26 s.");
  assert.equal(lt.cleanup, null, "no session_exit yet: no clean-up line");
});

test("the clean-up after the AI stopped, from session_exit; the AI's own run is not Mandu's time", () => {
  const lt = launchTimeOf([ev("launch_posture", "2026-10-21T01:00:00.000Z", START), ev("session_exit", "2026-10-21T01:00:09.000Z", END)])!;
  assert.equal(lt.cleanup, "After the AI stopped, Mandu took 0.20 s to clean up.");
});

test("short steps are not named; a quick start is one plain sentence", () => {
  const quick = { v: 1, totalMs: 120, steps: [{ step: "plan", ms: 30 }, { step: "services", ms: MIN_SHOWN_MS - 1 }] };
  assert.equal(launchTimeOf([ev("launch_posture", "2026-10-21T01:00:00.000Z", quick)])!.sentence, "Mandu took 0.12 s to start this session.");
  const future = { v: 1, totalMs: 900, steps: [{ step: "warp-drive", ms: 800 }, { step: "services", ms: 90 }] };
  assert.deepEqual(launchTimeOf([ev("launch_posture", "2026-10-21T01:00:00.000Z", future)])!.slowest.map((s) => s.words), ["starting the session's helpers"], "a step it has no words for is not named");
});

test("nothing from a launch that recorded no timings, a malformed record, or an event not the launcher's", () => {
  assert.equal(launchTimeOf([]), null);
  assert.equal(launchTimeOf([ev("launch_posture", "t", undefined)]), null);
  assert.equal(launchTimeOf([ev("launch_posture", "t", { v: 2, totalMs: 1, steps: [] })]), null);
  assert.equal(launchTimeOf([ev("launch_posture", "t", { v: 1, totalMs: "1", steps: [] })]), null);
  assert.equal(launchTimeOf([ev("launch_posture", "t", { v: 1, totalMs: 1, steps: [{ step: "x", ms: "2" }] })]), null);
  const other = { ...ev("launch_posture", "t", START), emitter: "anthropic-proxy" } as ManduEvent;
  assert.equal(launchTimeOf([other]), null);
});

test("the latest launch's record wins (a resumed session launched again)", () => {
  const again = { v: 1, totalMs: 900, steps: [{ step: "services", ms: 400 }] };
  const lt = launchTimeOf([ev("launch_posture", "2026-10-21T01:00:00.000Z", START), ev("launch_posture", "2026-10-21T02:00:00.000Z", again)])!;
  assert.equal(lt.total, "0.90 s");
});

test("seconds: two decimals under a second, one under ten, whole from ten", () => {
  assert.equal(seconds(378), "0.38 s");
  assert.equal(seconds(1712), "1.7 s");
  assert.equal(seconds(12400), "12 s");
  assert.equal(seconds(-5), "0.00 s");
});

test("plain words only: no inspector term in any step's words or the sentences", () => {
  for (const [k, w] of Object.entries(STEP_WORDS)) assert.doesNotMatch(w, FORBIDDEN, k);
  const lt = launchTimeOf([ev("launch_posture", "2026-10-21T01:00:00.000Z", START), ev("session_exit", "2026-10-21T01:00:09.000Z", END)])!;
  assert.doesNotMatch(lt.sentence, FORBIDDEN);
  assert.doesNotMatch(lt.cleanup!, FORBIDDEN);
});

test("the agent page carries it, signed in and signed out (the times are no value the AI did not see)", () => {
  const events = [ev("launch_posture", "2026-10-21T01:00:00.000Z", START), ev("session_exit", "2026-10-21T01:00:09.000Z", END)];
  const page = buildAgentPage({ session: null, id: "s1", vm: null, cwd: null, waiting: [], events });
  assert.equal(page.launchTime?.sentence, launchTimeOf(events)!.sentence);
  const out = buildAgentPage({ session: null, id: "s1", vm: null, cwd: null, waiting: [], events: redactEvents(events), valuesShown: false });
  assert.equal(out.launchTime?.cleanup, "After the AI stopped, Mandu took 0.20 s to clean up.");
  assert.equal(buildAgentPage({ session: null, id: "s1", vm: null, cwd: null, waiting: [] }).launchTime, null);
});
