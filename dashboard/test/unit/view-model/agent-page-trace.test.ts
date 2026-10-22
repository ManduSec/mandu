/**
 * agent-page-trace.test — dashboard.md §4.25ae: the product page is a whole
 * trace. What the detailed trace showed and the agent page did not:
 *
 *   - the leak check's finding (`finding`): each place a recorded event
 *     flagged, when, the step on the page that shows it (its time opens it),
 *     the secrets a flagged result held by name, a flagged request to the AI
 *     said as such; never the text the check found (the event's
 *     `invariant.detail` quotes it), and the signed-out projection drops
 *     that quote while keeping the flag;
 *   - its *What to do now* (`finding.todo`): change each secret the lines
 *     name, once, in their order, at most TODO_NAMES_CAP and the rest
 *     counted; a line that names none says the same for whatever it was;
 *     always, report the fault, linked to ISSUES_URL; never a value;
 *   - each background step, listed when the page asks for its turn
 *     (`show.background`, `?background=<turn id>`), oldest first, a folded
 *     repeat counted, up to BACKGROUND_ALL_CAP;
 *   - the whole original past HIDDEN_CAP, only for the admin route that asks
 *     (`show.original`), never for a secret;
 *   - History's rows (`historyPage`, `buildHistoryViewModel`): newest first,
 *     paged by the last id drawn, the system logs left out, each row Home's.
 *
 * Axes: none (pure projections; the mode is read from the recorded events).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  backgroundItems, buildAgentPage, BACKGROUND_ALL_CAP, FINDING_CAP, findingTodo, HIDDEN_CAP, leakFinding, ORIGINAL_ALL_CAP, TODO_NAMES_CAP, type StoryStep,
} from "../../../src/view-model/agent-page.js";
import { ISSUES_URL } from "../../../src/agent-versions.js";
import { toSessionViewModel, type SessionViewModel } from "../../../src/view-model.js";
import type { DualOsStep, DualStep, DualToolStep } from "../../../src/view-model/dual-lanes.js";
import type { PairedTurn } from "../../../src/view-model/paired-rows.js";
import type { SessionRef } from "../../../src/event-source/contract.js";
import { buildHistoryViewModel, historyPage, HISTORY_PAGE_MAX, type HomeSessionFacts } from "../../../src/view-model/home.js";
import { redactEvent, redactEvents } from "../../../src/view-model/redact.js";
import { agentShowOf } from "../../../src/server/home-routes.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { walkthroughEvents, SESSION } from "./walkthrough-fixture.js";

const words = (parts: readonly { text: string }[]): string => parts.map((p) => p.text).join("");
const CANARY = "sk_live_CANARY_7d1e";

// ── The leak check's finding ─────────────────────────────────────────────────

/** The walkthrough with its `.env` read flagged, and a request to the AI
 *  flagged too, whose detail quotes a value (as the proxies write it). */
function flaggedEvents(): ManduEvent[] {
  const events = walkthroughEvents({ flagged: true });
  const call = events.filter((e) => e.kind === "tllm_call")[2]!;
  call.invariant = { violatedInvariant: true, detail: `un-symbolized untrusted span survived in forwarded prompt: PASTE_KEY=${CANARY}` };
  return events;
}

test("the finding lists each flagged place, oldest first: the step's words, when (opening the step), the secret it held by name; a flagged request is said as such; never the text the check found", () => {
  const vm = toSessionViewModel(SESSION, flaggedEvents());
  const page = buildAgentPage({ session: null, id: SESSION, vm, cwd: null, waiting: [] });
  const f = page.finding!;
  assert.ok(f, "a flagged session has a finding");
  assert.equal(f.count, 2);
  assert.equal(f.items.length, 2);
  assert.equal(f.more, 0);
  const [read, request] = f.items;
  assert.match(words(read!.parts), /^At .+, the result of this step reached the AI without a mask: Read \S*\.env\. It held your secret PASTE_KEY\.$/);
  assert.equal(read!.step, "tool:c2", "the step the page shows");
  assert.deepEqual(read!.parts.find((p) => p.kind === "time"), { kind: "time", text: read!.ts, step: "tool:c2" });
  assert.match(words(request!.parts), /^At .+, a request to the AI carried an item as it was, though Mandu had masked it\.$/);
  assert.equal("step" in request!, false, "a request is no step on the page");
  assert.ok(Date.parse(read!.ts!) < Date.parse(request!.ts!), "oldest first");
  // Never the quoted text, never a token.
  assert.doesNotMatch(JSON.stringify(f), new RegExp(CANARY));
  assert.doesNotMatch(JSON.stringify(f), /\$MDU:/);
  // A step the page does not show keeps its time, without a link.
  const none = leakFinding(vm, page.story, new Set());
  assert.equal(none!.items[0]!.step, undefined);
  assert.equal(none!.items[0]!.parts.find((p) => p.kind === "time")!.step, undefined);
});

test("a session the check never flagged has no finding; past FINDING_CAP the rest is counted", () => {
  const clean = toSessionViewModel(SESSION, walkthroughEvents());
  assert.equal(buildAgentPage({ session: null, id: SESSION, vm: clean, cwd: null, waiting: [] }).finding, null);
  const events = walkthroughEvents();
  const base = events[events.length - 1]!;
  for (let i = 0; i < FINDING_CAP + 3; i++) {
    events.push({ ...base, id: `leak-${i}`, seq: 1000 + i, kind: "tllm_call", ts: new Date(Date.parse(base.ts) + (i + 1) * 1000).toISOString(), invariant: { violatedInvariant: true } } as ManduEvent);
  }
  const vm = toSessionViewModel(SESSION, events);
  const f = leakFinding(vm, [], new Set())!;
  assert.equal(f.items.length, FINDING_CAP);
  assert.equal(f.more, 3);
});

const REPORT = "This is a fault in Mandu, not in your rules. Report a problem, with this session's time. Never paste the key itself.";
const UNNAMED = /^If what reached the AI held a key or a password, change it /;

test("What to do now: change each secret the lines name, once and in order; a line naming none says the same for whatever it was; always report it, linked to the issue tracker; never a value", () => {
  const vm = toSessionViewModel(SESSION, flaggedEvents());
  const f = buildAgentPage({ session: null, id: SESSION, vm, cwd: null, waiting: [] }).finding!;
  // The .env read names PASTE_KEY; the flagged request names none.
  assert.deepEqual(f.todo.map(words), [
    "Change PASTE_KEY where it was issued, and turn the old one off: the AI's provider received it as it was.",
    "If what reached the AI held a key or a password, change it the same way. Open the step to see what it was.",
    REPORT,
  ]);
  assert.deepEqual(f.todo[0]!.filter((p) => p.kind === "code").map((p) => p.text), ["PASTE_KEY"]);
  const report = f.todo[f.todo.length - 1]!.find((p) => p.href);
  assert.deepEqual(report, { kind: "text", text: "Report a problem", href: ISSUES_URL });
  assert.equal(f.todo.flat().filter((p) => p.href).length, 1, "the one link");
  assert.doesNotMatch(JSON.stringify(f.todo), new RegExp(CANARY));
  assert.doesNotMatch(JSON.stringify(f.todo), /\$MDU:/);

  // Only the read flagged: one name, no line for an unnamed place.
  const events = walkthroughEvents({ flagged: true });
  const only = buildAgentPage({ session: null, id: SESSION, vm: toSessionViewModel(SESSION, events), cwd: null, waiting: [] }).finding!;
  assert.deepEqual(only.todo.map(words), [
    "Change PASTE_KEY where it was issued, and turn the old one off: the AI's provider received it as it was.",
    REPORT,
  ]);

  // Only a request flagged: no name, the line spelled out in full.
  const plain = walkthroughEvents();
  plain.find((e) => e.kind === "tllm_call")!.invariant = { violatedInvariant: true };
  const none = buildAgentPage({ session: null, id: SESSION, vm: toSessionViewModel(SESSION, plain), cwd: null, waiting: [] }).finding!;
  assert.deepEqual(none.todo.map(words), [
    "If what reached the AI held a key or a password, change it where it was issued, and turn the old one off. Open the step to see what it was.",
    REPORT,
  ]);
  assert.match(words(none.todo[0]!), UNNAMED);
});

test("What to do now names at most TODO_NAMES_CAP secrets, each once, then counts the rest", () => {
  const names = ["A_KEY", "B_KEY", "C_KEY", "D_KEY", "E_KEY", "F_KEY", "G_KEY"];
  const todo = findingTodo(names, false);
  assert.equal(TODO_NAMES_CAP, 5);
  assert.deepEqual(todo.slice(0, TODO_NAMES_CAP).map((l) => l.find((p) => p.kind === "code")!.text), names.slice(0, 5));
  assert.equal(words(todo[TODO_NAMES_CAP]!), "And 2 more: change each the same way.");
  assert.equal(words(todo[TODO_NAMES_CAP + 1]!), REPORT);
  assert.equal(todo.length, TODO_NAMES_CAP + 2);
  // Exactly five: no count line.
  assert.equal(findingTodo(names.slice(0, 5), false).length, 6);
  // None and nothing unnamed: the report alone.
  assert.deepEqual(findingTodo([], false).map(words), [REPORT]);
});

test("signed out, the projection keeps the leak check's flag and drops its quote; the page built from it finds the same places", () => {
  const events = flaggedEvents();
  const call = events.find((e) => e.invariant.detail)!;
  const r = redactEvent(call);
  assert.deepEqual(r.invariant, { violatedInvariant: true });
  assert.equal(call.invariant.detail !== undefined, true, "the input is not mutated");
  const redacted = redactEvents(events);
  assert.doesNotMatch(JSON.stringify(redacted), new RegExp(CANARY));
  const page = buildAgentPage({ session: null, id: SESSION, vm: toSessionViewModel(SESSION, redacted), cwd: null, waiting: [], valuesShown: false });
  assert.equal(page.finding!.items.length, 2);
  assert.match(words(page.finding!.todo[0]!), /^Change PASTE_KEY where it was issued/, "the names the lines show signed out");
  assert.doesNotMatch(JSON.stringify(page), new RegExp(CANARY));
});

// ── Background steps ─────────────────────────────────────────────────────────

const SREF: SessionRef = {
  id: "s1", label: "Read them all", eventCount: 4,
  firstTs: "2026-09-25T10:00:00.000Z", lastTs: "2026-09-25T10:00:09.000Z", violated: false, agent: "codex", status: "running",
};

function os(over: Partial<DualOsStep>): DualOsStep {
  return {
    step: "os", id: "os1", ts: "2026-09-25T10:00:02.000Z", turn: 1, violated: false, kind: "net_action",
    title: "net_action · forwarded api.anthropic.com", note: null, quarantine: false, repeats: 1, ruleRef: null,
    action: "forwarded", usage: null, target: "api.anthropic.com:443", ...over,
  };
}
function vmOf(steps: DualStep[], turns: PairedTurn[]): SessionViewModel {
  const base = toSessionViewModel("s1", []);
  return { ...base, dualLanes: { ...base.dualLanes, steps }, paired: { integrity: "on", mode: null, maskedCount: 0, turns } as SessionViewModel["paired"] };
}

test("asked for a turn's background (`show.background`), the page lists each step, oldest first, in plain words; a repeat says how many times; other turns and an unasked page carry none", () => {
  const input: DualStep = { step: "input", id: "in1", ts: "2026-09-25T10:00:00.000Z", turn: 1, violated: false, text: "Go" };
  const steps: DualStep[] = [
    input,
    os({ id: "os:b", ts: "2026-09-25T10:00:03.000Z", kind: "exec_action", title: "exec_action · allow git status --porcelain", action: null, usage: "allow", target: null }),
    os({ id: "os:a", ts: "2026-09-25T10:00:02.000Z", repeats: 4 }),
    os({ id: "os:c", ts: "2026-09-25T10:00:04.000Z", kind: "path_rewrite", title: "path_rewrite", action: null, target: null }),
  ];
  const turns: PairedTurn[] = [{
    id: "turn:in1", inputId: "in1", rows: [],
    background: [
      { category: "connections", count: 4, labels: ["api.anthropic.com"], stepIds: ["os:a"] },
      { category: "command-checks", count: 1, labels: [], stepIds: ["os:b"] },
      { category: "paths", count: 1, labels: [], stepIds: ["os:c"] },
    ],
  }];
  const vm = vmOf(steps, turns);
  const plain = buildAgentPage({ session: SREF, id: "s1", vm, cwd: null, waiting: [] });
  assert.equal(plain.story[0]!.routine!.count, 6);
  assert.equal("items" in plain.story[0]!.routine!, false, "not asked: the count alone");
  const asked = buildAgentPage({ session: SREF, id: "s1", vm, cwd: null, waiting: [], show: { background: new Set(["turn:in1"]) } });
  const r = asked.story[0]!.routine!;
  assert.deepEqual(r.items!.map((i) => words(i.parts)), [
    "Connected to api.anthropic.com (4 times)",
    "Mandu checked a command: git status --porcelain",
    "Translated a file path between your folder and the AI's masked copy of it",
  ]);
  assert.deepEqual(r.items!.map((i) => i.ts), ["2026-09-25T10:00:02.000Z", "2026-09-25T10:00:03.000Z", "2026-09-25T10:00:04.000Z"]);
  assert.equal(r.moreItems, 0);
  assert.equal(r.items![0]!.parts[1]!.kind, "code", "a host is code");
});

test("a turn's background past BACKGROUND_ALL_CAP lists the first ones and counts the rest; a masked item in a command stays a chip", () => {
  const many = Array.from({ length: BACKGROUND_ALL_CAP + 2 }, (_, i) => os({ id: `os:${i}`, ts: new Date(Date.parse("2026-09-25T10:00:00.000Z") + i * 10).toISOString() }));
  const byId = new Map<string, DualStep>(many.map((s) => [s.id, s]));
  const out = backgroundItems([{ category: "connections", count: many.length, labels: ["api.anthropic.com"], stepIds: many.map((s) => s.id) }], byId);
  assert.equal(out.items.length, BACKGROUND_ALL_CAP);
  assert.equal(out.moreItems, 2);
  const cmd = os({ id: "os:x", kind: "exec_action", title: "exec_action · allow cat $MDU:nomodel_Env[ab12].TOKEN", action: null, usage: "allow", target: null });
  const one = backgroundItems([{ category: "command-checks", count: 1, labels: [], stepIds: ["os:x"] }], new Map([["os:x", cmd]]));
  assert.doesNotMatch(JSON.stringify(one), /\$MDU:/);
  assert.ok(one.items[0]!.parts.some((p) => p.kind === "masked" && p.text === "secret"));
});

test("agentShowOf reads `background=<turn id>`, at most SHOW_STEPS_MAX, and never `original`", () => {
  const show = agentShowOf(new URLSearchParams("background=turn%3Aa&background=&background=turn%3Ab&original=tool%3Ac1"));
  assert.deepEqual([...show.background!], ["turn:a", "turn:b"]);
  assert.equal("original" in show, false, "the page's own query never asks for a whole original");
});

// ── The whole original ───────────────────────────────────────────────────────

function tool(over: Partial<DualToolStep>): DualToolStep {
  return {
    step: "tool", id: "tool:c1", ts: "2026-09-25T10:00:01.000Z", turn: 1, violated: false,
    callId: "c1", tool: "WebFetch", trust: "UNTRUSTED", crossing: false, readsTwin: false, quarantine: false,
    input: '{"url":"https://example.com"}', resultAgent: null, resultHuman: null, origin: null, reason: null, secretNote: null,
    usage: null, downSyms: [], upSyms: [], symbolizedBy: null, desymbolizedBy: null, quarantinedBy: null,
    newSymbols: [], pathRewrites: [], gates: [], repeats: 1,
    ...over,
  };
}

test("past HIDDEN_CAP the page's original is cut; `show.original` carries that step's whole original up to ORIGINAL_ALL_CAP; a secret's has none", () => {
  const TOK = "$MDU:WebFetch[abcd]";
  const long = "x".repeat(HIDDEN_CAP + 500) + "END";
  const input: DualStep = { step: "input", id: "in1", ts: "2026-09-25T10:00:00.000Z", turn: 1, violated: false, text: "Fetch" };
  const fetched = tool({ resultAgent: TOK, resultHuman: long, upSyms: [{ name: TOK, value: long } as DualToolStep["upSyms"][number]], newSymbols: [TOK] });
  const row = { row: "tool" as const, stepId: "tool:c1", masked: true, original: long, pathMapped: false, checked: true, inspect: null, flaggedValue: null };
  const base = toSessionViewModel("s1", []);
  const vm: SessionViewModel = {
    ...vmOf([input, fetched], [{ id: "turn:in1", inputId: "in1", rows: [row], background: [] }]),
    symbols: [{ name: TOK, value: long } as SessionViewModel["symbols"][number], ...base.symbols],
  };
  const page = buildAgentPage({ session: SREF, id: "s1", vm, cwd: null, waiting: [] });
  const step = page.story[0]!.steps[0] as Extract<StoryStep, { kind: "action" }>;
  assert.equal(step.split!.hidden!.truncated, true);
  assert.equal(step.split!.hidden!.text!.length, HIDDEN_CAP);
  assert.equal("original" in page, false, "the page's own read carries no whole original");
  const whole = buildAgentPage({ session: SREF, id: "s1", vm, cwd: null, waiting: [], show: { original: "tool:c1" } });
  assert.equal(whole.original!.text, long);
  assert.equal(whole.original!.truncated, false);
  assert.ok(ORIGINAL_ALL_CAP > long.length);
  assert.equal(buildAgentPage({ session: SREF, id: "s1", vm, cwd: null, waiting: [], show: { original: "tool:nope" } }).original, null);
  // A secret's original is never carried.
  const SEC = "$MDU:nomodel_Env[ab12].TOKEN";
  const secretVm = vmOf([input, tool({ resultAgent: SEC, upSyms: [{ name: SEC, value: CANARY } as DualToolStep["upSyms"][number]] })], [{ id: "turn:in1", inputId: "in1", rows: [{ ...row, original: CANARY }], background: [] }]);
  const sec = buildAgentPage({ session: SREF, id: "s1", vm: secretVm, cwd: null, waiting: [], show: { original: "tool:c1" } });
  assert.equal(sec.original, null);
  assert.doesNotMatch(JSON.stringify(sec), new RegExp(CANARY));
});

// ── History ──────────────────────────────────────────────────────────────────

const ref = (id: string, over: Partial<SessionRef> = {}): SessionRef => ({
  id, label: `task ${id}`, labelFrom: "prompt", eventCount: 3, firstTs: "2026-09-01T10:00:00.000Z", lastTs: "2026-09-01T10:05:00.000Z", violated: false, agent: "claude", status: "idle", ...over,
} as SessionRef);

test("History pages the agent sessions newest first by the last id drawn; the system logs are left out; an unknown cursor starts over; the limit is bounded", () => {
  const list = [ref("a"), ref("arbiter-admin"), ref("b"), ref("c"), ref("d"), ref("e")];
  const first = historyPage(list, null, 2);
  assert.deepEqual(first.page.map((s) => s.id), ["a", "b"]);
  assert.equal(first.next, "b");
  const second = historyPage(list, first.next, 2);
  assert.deepEqual(second.page.map((s) => s.id), ["c", "d"]);
  const last = historyPage(list, second.next, 2);
  assert.deepEqual(last.page.map((s) => s.id), ["e"]);
  assert.equal(last.next, null);
  assert.deepEqual(historyPage(list, "gone", 2).page.map((s) => s.id), ["a", "b"]);
  assert.equal(historyPage(Array.from({ length: 300 }, (_, i) => ref(`s${i}`)), null, 10_000).page.length, HISTORY_PAGE_MAX);
  assert.equal(historyPage(list, null, 0).page.length, 1);
  assert.equal(historyPage(list, null, Number.NaN).page.length, 5);
});

test("a History row is Home's row: counts from the session's facts, its verdict, its prompt label; without facts, the listing's verdict", () => {
  const facts = new Map<string, HomeSessionFacts>([["a", {
    stats: { flows: 2, secret: 1, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 },
    secrets: { masked: 1, early: 0 }, untrusted: 0, blocked: 2, sent: 1, holds: false, violations: 1, cwd: "/home/u/ws", exited: true,
  }]]);
  const vm = buildHistoryViewModel({ total: 7, page: [ref("a"), ref("b", { violated: true, labelFrom: "posture" })], next: "b", facts });
  assert.equal(vm.total, 7);
  assert.equal(vm.next, "b");
  const [a, b] = vm.rows;
  assert.deepEqual({ id: a!.id, agent: a!.agent, title: a!.title, cwd: a!.cwd, holds: a!.holds, blocked: a!.blocked, sent: a!.sent, secrets: a!.secrets, state: a!.state },
    { id: "a", agent: "Claude Code", title: "task a", cwd: "/home/u/ws", holds: false, blocked: 2, sent: 1, secrets: { masked: 1, early: 0 }, state: "idle" });
  assert.equal(b!.holds, false, "the listing's flag, without facts");
  assert.equal(b!.title, null, "a fallback label is no prompt");
});
