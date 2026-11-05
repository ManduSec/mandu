/**
 * home-js-limit-reset — dashboard.md §4.21 *On the product page* and
 * §4.25u *Every moment reads absolute and relative*: when the AI plan's
 * usage limit stopped an agent, its warning says when the limit lifts in
 * the reader's own clock ("It resets Oct 29, 06:00."), the full date on
 * hover, never in UTC. The parts are the view model's own
 * (`agentNoticeParts`); the page draws their `time` part with momentNode,
 * on a Home row's warning mark and on the session page's written-out line
 * and mark.
 *
 * Over the real dashboard and a recorded session:
 * test/component/limit-reset-time.test.ts.
 * Axes: none (display only).
 */
process.env.TZ = "Asia/Seoul"; // UTC+9, no daylight saving time

import { test } from "node:test";
import assert from "node:assert/strict";

import { AGENT, home, load, tick } from "./home-js-fixtures.js";
import { agentNotice, agentNoticeParts } from "../../../src/view-model/home.js";
import { deriveHealth } from "../../../src/session-health.js";
import type { ManduEvent } from "../../../src/event-model.js";

const RESETS = "2026-10-28T21:00:00.000Z";
/** The words clockWords writes for RESETS in Seoul: the next morning, the
 *  year only when it is not this year. */
const LOCAL = `Oct 29${new Date().getFullYear() === 2026 ? "" : ", 2026"}, 06:00`;
const FULL = "Thursday, Oct 29, 2026, 06:00";

function ev(kind: string, extra: Record<string, unknown> = {}): ManduEvent {
  return {
    id: `ev_${kind}`, sessionId: "s1", turn: 0, ts: "2026-10-28T12:00:00.000Z", seq: 0, callId: null, parentId: null, kind,
    view: "HumanView", boundary: "shell", emitter: "launcher", invariant: { violatedInvariant: false },
    input: { symbolized: "", original: null, differs: false, symbols: [] }, output: null, ...extra,
  } as unknown as ManduEvent;
}
const health = deriveHealth([
  ev("launch_posture", { target: "claude", live: ["fs"], dropped: [] }),
  ev("tllm_call", { upstreamLimit: { status: 429, unifiedStatus: "rejected", claim: "seven_day", resetsAt: RESETS, hard: true } }),
  ev("session_exit", { code: 0 }),
])!;
const notice = agentNotice(health, false, "s1")!;
const noticeParts = agentNoticeParts(health, false, "s1")!;

/** The one moment in `node`: its datetime, its words, its hover. */
function moment(node: any): { datetime: string; text: string; title: string } {
  const times = [...node.querySelectorAll("time")] as any[];
  assert.equal(times.length, 1, node.innerHTML);
  return { datetime: times[0].getAttribute("datetime"), text: times[0].textContent, title: times[0].getAttribute("title") };
}

test("the parts are the view model's: the plain line in UTC, the moment as a time part", () => {
  assert.match(notice, /It resets 2026-10-28 at 21:00 UTC\.$/);
  assert.deepEqual(noticeParts.filter((p) => p.kind === "time"), [{ kind: "time", text: RESETS }]);
});

test("a Home row's warning mark says when the limit lifts in the reader's clock, the full date on hover, no UTC", async () => {
  const vm = home();
  Object.assign((vm.agents as any[])[0], { notice, noticeParts });
  const { doc, err } = load({ homeVm: vm });
  assert.equal(err, null);
  await tick();
  const btn = doc.querySelector("#home-agents .row.agent .name .notice-btn");
  assert.ok(btn, "a warning mark by the name");
  btn.click();
  const pop = doc.getElementById(btn.getAttribute("aria-controls"));
  assert.deepEqual(moment(pop), { datetime: RESETS, text: LOCAL, title: FULL });
  assert.ok(pop.textContent.endsWith(`This limit is your AI provider's, not Mandu's. It resets ${LOCAL}.`), pop.textContent);
  assert.doesNotMatch(pop.textContent, /UTC|2026-10-28/);
});

test("the session page's warning line and its mark say it the same way", async () => {
  const { doc, err } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, notice, noticeParts, noticeShown: true } } });
  assert.equal(err, null);
  await tick();
  const line = doc.getElementById("agent-notice");
  assert.equal(line.hidden, false);
  assert.deepEqual(moment(line), { datetime: RESETS, text: LOCAL, title: FULL });
  assert.ok(line.textContent.endsWith(`It resets ${LOCAL}.`), line.textContent);
  assert.doesNotMatch(line.textContent, /UTC|2026-10-28/);
  const mark = doc.querySelector("#agent-name .notice-btn");
  assert.ok(mark);
  mark.click();
  const pop = doc.getElementById(mark.getAttribute("aria-controls"));
  assert.deepEqual(moment(pop), { datetime: RESETS, text: LOCAL, title: FULL });
  assert.doesNotMatch(pop.textContent, /UTC/);
});

test("a server that sends only the plain line (no parts): the page shows it as written", async () => {
  const { doc } = load({ url: "http://127.0.0.1:4500/mandu/agents/s1", routes: { "GET home/agent?session=s1": { ...AGENT, notice, noticeParts: null, noticeShown: true } } });
  await tick();
  const line = doc.getElementById("agent-notice");
  assert.equal(line.querySelector("time"), null);
  assert.ok(line.textContent.endsWith("It resets 2026-10-28 at 21:00 UTC."), line.textContent);
});
