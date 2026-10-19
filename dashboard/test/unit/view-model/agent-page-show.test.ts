/**
 * agent-page-show.test — dashboard.md §4.25ad: the agent page is where a
 * user checks what the model saw, so it shows what it used to leave to the
 * detailed trace, and its words point there only in a build that serves it.
 *
 *   - `show` lifts each cap the page asked to lift (every turn, every step of
 *     a turn named, every secret), each to its ALL cap, and says so
 *     (`allTurns`, `allSteps`, `allSecrets`); the tiles count as Home does,
 *     whatever the page shows;
 *   - the step an ask was raised at is found past TURN_STEP_CAP, its turn
 *     shown whole;
 *   - `dev: false`: no part names the detailed trace (a step that reached the
 *     AI unmasked; Your secrets' lines and `show.secrets` are pinned in
 *     secret-story.test.ts), and the sentence that is left says what
 *     happened; `dev` absent or true: the words are as before;
 *   - Home's failed-session sentence and the service line, the same;
 *   - `agentShowOf`: the query the page sends, bounded.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  actionOutcome, osSentence, buildAgentPage, buildStory, capTurn, TURN_CAP, TURN_STEP_CAP, TURN_ALL_CAP, type StoryStep,
} from "../../../src/view-model/agent-page.js";
import { toSessionViewModel, type SessionViewModel } from "../../../src/view-model.js";
import type { DualOsStep, DualStep, DualToolStep } from "../../../src/view-model/dual-lanes.js";
import type { PairedTurn } from "../../../src/view-model/paired-rows.js";
import type { SessionRef } from "../../../src/event-source/contract.js";
import { buildHomeViewModel } from "../../../src/view-model/home.js";
import { buildServiceSummary, HELPER_NOTE, HELPER_NOTE_PRODUCT } from "../../../src/view-model/service-summary.js";
import { agentShowOf, SHOW_STEPS_MAX } from "../../../src/server/home-routes.js";
import { FINDING_POINTER } from "../../../src/view-model/secret-story.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import { snapshot } from "../policy-snapshot-fixture.js";

const SESSION: SessionRef = {
  id: "s1", label: "Read them all", eventCount: 4,
  firstTs: "2026-09-25T10:00:00.000Z", lastTs: "2026-09-25T10:00:09.000Z", violated: false, agent: "codex", status: "running",
};

function tool(over: Partial<DualToolStep>): DualToolStep {
  return {
    step: "tool", id: "t1", ts: "2026-09-25T10:00:01.000Z", turn: 1, violated: false,
    callId: "c1", tool: "Read", trust: "TRUSTED", crossing: false, readsTwin: false, quarantine: false,
    input: null, resultAgent: null, resultHuman: null, origin: null, reason: null, secretNote: null,
    usage: null, downSyms: [], upSyms: [], symbolizedBy: null, desymbolizedBy: null, quarantinedBy: null,
    newSymbols: [], pathRewrites: [], gates: [], repeats: 1,
    ...over,
  };
}
function os(over: Partial<DualOsStep>): DualOsStep {
  return {
    step: "os", id: "os1", ts: "2026-09-25T10:00:02.000Z", turn: 1, violated: false, kind: "net_action",
    title: "net_action · blocked evil.example", note: null, quarantine: false, repeats: 1, ruleRef: null,
    action: "blocked", usage: null, target: "evil.example", ...over,
  };
}
function vmOf(steps: DualStep[], turns: PairedTurn[]): SessionViewModel {
  const base = toSessionViewModel("s1", []);
  return {
    ...base,
    dualLanes: { ...base.dualLanes, steps },
    paired: { integrity: "on", mode: null, maskedCount: 0, turns } as SessionViewModel["paired"],
  };
}
const toolRow = (s: DualToolStep) => ({ row: "tool" as const, stepId: s.id, masked: false, original: null, pathMapped: false, checked: true, inspect: null, flaggedValue: null });

/** `n` turns of one question each. */
function turnsVm(n: number): SessionViewModel {
  const steps: DualStep[] = Array.from({ length: n }, (_, i) => ({ step: "input", id: `i${i}`, ts: "2026-09-25T10:00:00.000Z", turn: i, violated: false, text: `prompt ${i}` }));
  return vmOf(steps, steps.map((s) => ({ id: "turn:" + s.id, inputId: s.id, rows: [], background: [] })));
}

/** Two turns of `n` reads each; every read of turn B blocked (a deny). */
function stepsVm(n: number): SessionViewModel {
  const steps: DualStep[] = [];
  const turns: PairedTurn[] = [];
  for (const t of ["a", "b"]) {
    const input: DualStep = { step: "input", id: `in-${t}`, ts: "2026-09-25T10:00:00.000Z", turn: 1, violated: false, text: `turn ${t}` };
    const reads = Array.from({ length: n }, (_, i) => tool({ id: `tool:${t}${i}`, callId: `${t}${i}`, ...(t === "b" ? { usage: "deny" as const } : {}) }));
    steps.push(input, ...reads);
    turns.push({ id: `turn:in-${t}`, inputId: `in-${t}`, background: [], rows: reads.map(toolRow) });
  }
  return vmOf(steps, turns);
}

test("show.turns: every turn up to TURN_ALL_CAP, and the page says it asked (allTurns)", () => {
  const capped = buildAgentPage({ session: SESSION, id: "s1", vm: turnsVm(TURN_CAP + 7), cwd: null, waiting: [] });
  assert.equal(capped.earlier, 7);
  assert.equal("allTurns" in capped, false);
  const all = buildAgentPage({ session: SESSION, id: "s1", vm: turnsVm(TURN_CAP + 7), cwd: null, waiting: [], show: { turns: true } });
  assert.equal(all.earlier, 0);
  assert.equal(all.story.length, TURN_CAP + 7);
  assert.equal(all.story[0]!.prompt, "prompt 0");
  assert.equal(all.allTurns, true);
  // Past the ALL cap, the oldest are still counted, never drawn.
  const huge = buildAgentPage({ session: SESSION, id: "s1", vm: turnsVm(TURN_ALL_CAP + 3), cwd: null, waiting: [], show: { turns: true } });
  assert.equal(huge.story.length, TURN_ALL_CAP);
  assert.equal(huge.earlier, 3);
  assert.equal(huge.story[huge.story.length - 1]!.prompt, `prompt ${TURN_ALL_CAP + 2}`);
});

test("show.steps: the turns named show every step (allSteps); the others keep TURN_STEP_CAP; the tiles do not move", () => {
  const n = TURN_STEP_CAP + 5;
  const capped = buildAgentPage({ session: SESSION, id: "s1", vm: stepsVm(n), cwd: null, waiting: [] });
  for (const t of capped.story) {
    assert.equal(t.steps.length, TURN_STEP_CAP);
    assert.equal(t.moreSteps, 5);
    assert.equal("allSteps" in t, false);
  }
  assert.equal(capped.story[1]!.moreFrom, `tool:b${TURN_STEP_CAP}`);
  const page = buildAgentPage({ session: SESSION, id: "s1", vm: stepsVm(n), cwd: null, waiting: [], show: { steps: new Set(["turn:in-b", "turn:nope"]) } });
  const [a, b] = page.story;
  assert.equal(a!.steps.length, TURN_STEP_CAP, "a turn not named keeps its cap");
  assert.equal(a!.moreSteps, 5);
  assert.equal(b!.steps.length, n);
  assert.equal(b!.moreSteps, 0);
  assert.equal("moreFrom" in b!, false);
  assert.equal(b!.allSteps, true);
  // The tiles count each turn's first TURN_STEP_CAP steps, as Home does,
  // whatever the page asked to see.
  assert.equal(page.blocked, TURN_STEP_CAP);
  assert.equal(capped.blocked, TURN_STEP_CAP);
  // A turn no longer than the cap is not marked: nothing was lifted.
  const short = buildAgentPage({ session: SESSION, id: "s1", vm: stepsVm(3), cwd: null, waiting: [], show: { steps: new Set(["turn:in-a"]) } });
  assert.equal("allSteps" in short.story[0]!, false);
});

test("capTurn: cuts a turn's steps, counts the rest on top of any already left out, and names the first of them", () => {
  const steps = Array.from({ length: 5 }, (_, i) => ({ kind: "aside" as const, id: `x${i}`, ts: "" }));
  const turn = { id: "t", ts: null, prompt: null, promptParts: null, shell: null, summary: null, summaryParts: null, tone: "plain" as const, steps, moreSteps: 2, reply: null, routine: null, promptNote: null };
  const cut = capTurn(turn, 3);
  assert.deepEqual(cut.steps.map((s) => s.id), ["x0", "x1", "x2"]);
  assert.equal(cut.moreSteps, 4);
  assert.equal(cut.moreFrom, "x3");
  assert.equal(capTurn(turn, 5), turn, "nothing to cut: the same turn");
});

test("an ask raised at a step past TURN_STEP_CAP is found, and its turn is shown whole", () => {
  const n = TURN_STEP_CAP + 5;
  const stepId = `tool:a${TURN_STEP_CAP + 2}`;
  const page = buildAgentPage({ session: SESSION, id: "s1", vm: stepsVm(n), cwd: null, waiting: [], focus: { ask: "egr-1", stepId, match: "exact" } });
  assert.deepEqual(page.focus, { ask: "egr-1", turnId: "turn:in-a", stepId, match: "exact" });
  assert.ok(page.story[0]!.steps.some((s) => s.id === stepId));
  assert.equal(page.story[0]!.allSteps, true);
  assert.equal(page.story[1]!.moreSteps, 5, "the other turn keeps its cap");
});

// ── Without the developer view (§4.25ad) ─────────────────────────────────────

const traced = (x: unknown): boolean => /"trace":/.test(JSON.stringify(x)) || /detailed trace|developer view/i.test(JSON.stringify(x));

test("dev false: a step that reached the AI unmasked says so and points at the page's own finding (§4.25ae), naming no trace; dev absent: as before", () => {
  const call = actionOutcome(tool({ violated: true }), false);
  assert.deepEqual(call, { outcome: "unmasked", note: `This reached the AI without a mask. ${FINDING_POINTER}` });
  assert.ok(traced(actionOutcome(tool({ violated: true }))));
  const leak = osSentence(os({ violated: true }), undefined, false);
  assert.equal(leak.outcome, "unmasked");
  assert.equal(leak.note, FINDING_POINTER, "its note points at the finding");
  assert.equal("noteParts" in leak, false);
  assert.ok(traced(osSentence(os({ violated: true }))));

  // Through buildStory and buildAgentPage: no part anywhere names the trace.
  const steps: DualStep[] = [
    { step: "input", id: "in1", ts: "2026-09-25T10:00:00.000Z", turn: 1, violated: false, text: "Post it" },
    tool({ id: "tool:v", violated: true }),
    os({ id: "os1", violated: true }),
  ];
  const turns: PairedTurn[] = [{ id: "turn:in1", inputId: "in1", background: [], rows: [toolRow(steps[1] as DualToolStep), { row: "action", stepId: "os1" }] }];
  const bare = buildAgentPage({ session: SESSION, id: "s1", vm: vmOf(steps, turns), cwd: null, waiting: [], dev: false });
  const [v, o] = bare.story[0]!.steps as Extract<StoryStep, { kind: "action" }>[];
  assert.equal(v!.note, `This reached the AI without a mask. ${FINDING_POINTER}`);
  assert.equal(o!.note, FINDING_POINTER);
  assert.equal(traced(bare), false);
  assert.equal(traced(buildStory(vmOf(steps, turns), undefined, undefined, "", undefined, { dev: false })), false);
  assert.ok(traced(buildAgentPage({ session: SESSION, id: "s1", vm: vmOf(steps, turns), cwd: null, waiting: [] })));
});

// ── Home and the service line (§4.25ad) ──────────────────────────────────────

function failedHome(ids: string[], dev?: boolean) {
  const now = Date.parse("2026-09-25T12:00:00.000Z");
  const sessions: SessionRef[] = ids.map((id) => ({ ...SESSION, id, lastTs: "2026-09-25T11:00:00.000Z", violated: true, status: "pass" as const }));
  const facts = new Map(ids.map((id) => [id, {
    stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, holds: false, violations: 1, blocked: 0, sent: 0, cwd: null,
  }]));
  return buildHomeViewModel({
    sessions, facts: facts as never, panel: toPolicyPanelViewModel(snapshot()), configuredMode: "secrets", nowMs: now, windowHours: 24, historyTotal: ids.length,
    ...(dev === undefined ? {} : { dev }),
  });
}

test("Home, protection failed: with the developer view, its trace; without, the agent page of the one session, or each agent's row", () => {
  const one = failedHome(["s9"]);
  assert.equal(one.verdict, "failed");
  assert.deepEqual(one.sentenceParts.find((p) => p.kind === "link"), { kind: "link", text: "Open the detailed trace", to: "trace", session: "s9" });
  const bareOne = failedHome(["s9"], false);
  assert.deepEqual(bareOne.sentenceParts, [
    { kind: "text", text: "One item reached the AI unmasked in the last 24 hours. " },
    { kind: "link", text: "Open that agent's page", to: "agent", session: "s9" },
    { kind: "text", text: " to see which." },
  ]);
  const bareTwo = failedHome(["s8", "s9"], false);
  assert.equal(bareTwo.sentenceParts.some((p) => p.kind === "link"), false);
  assert.equal(bareTwo.sentenceParts.map((p) => p.text).join(""), "2 items reached the AI unmasked in the last 24 hours. Each agent where it happened says \"protection failed\" below, and its page shows which.");
  assert.equal(traced(bareTwo.sentenceParts), false);
});

test("the service line: without the developer view, no sentence points there", () => {
  const svc = (id: string, state: "running" | "crashed") => ({ id, state, pid: 1, since: 1, restarts: 0, lastExit: null, adopted: false }) as never;
  const crashed = [svc("arbiter", "running"), svc("net-proxy", "crashed")];
  assert.equal(buildServiceSummary(crashed).helperNote, HELPER_NOTE);
  assert.equal(buildServiceSummary(crashed, { dev: false }).helperNote, HELPER_NOTE_PRODUCT);
  assert.doesNotMatch(HELPER_NOTE_PRODUCT, /developer view/);
  assert.match(buildServiceSummary([]).sentence, /developer view/);
  assert.equal(buildServiceSummary([], { dev: false }).sentence, "This dashboard does not run the protection service.");
});

test("agentShowOf: turns=all, secrets=all and each steps=<turn id>, at most SHOW_STEPS_MAX; anything else is the caps", () => {
  assert.deepEqual(agentShowOf(new URLSearchParams("session=s1")), {});
  assert.deepEqual(agentShowOf(new URLSearchParams("turns=1&secrets=yes&steps=")), {}, "only `all` lifts a cap; an empty id is none");
  const show = agentShowOf(new URLSearchParams("turns=all&secrets=all&steps=turn%3Aa&steps=turn%3Ab"));
  assert.equal(show.turns, true);
  assert.equal(show.secrets, true);
  assert.deepEqual([...show.steps!], ["turn:a", "turn:b"]);
  const many = new URLSearchParams(Array.from({ length: SHOW_STEPS_MAX + 9 }, (_, i) => `steps=t${i}`).join("&"));
  assert.equal(agentShowOf(many).steps!.size, SHOW_STEPS_MAX);
});
