/**
 * human-plane — the human plane's exposure as the inspector's chip and the
 * product page's notice (arbiter-human-plane.md §10.1.1, dashboard.md
 * §4.25x). Unknown is never walled; the product copy keeps the product's
 * vocabulary (the §4.18 sweep); a session name or pid is copied, never a
 * spread of the arbiter's answer. Axes: secrets (display only; nothing here
 * reads an axis).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { homeExposure, toHumanPlaneVM } from "../../../src/view-model/human-plane.js";
import { buildHomeViewModel } from "../../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";

/** The same inspector-term sweep home-view-model.test.ts applies. */
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;

const EXPOSED = { exposed: true, since: 1_700_000_000_000, launches: [{ pid: 4242, mode: "off", posture: "off", session: "claude-20261003-x1", begunAt: 1_699_999_999_000 }] };

test("toHumanPlaneVM: unknown without an answer, walled, exposed with each launch named; never a spread", () => {
  for (const none of [null, undefined, { exposed: "no" } as never]) {
    const vm = toHumanPlaneVM(none);
    assert.equal(vm.state, "unknown");
    assert.match(JSON.stringify(vm.detail), /Unknown is not walled/);
  }
  const walled = toHumanPlaneVM({ exposed: false, since: null, launches: [] });
  assert.equal(walled.state, "walled");
  assert.deepEqual(walled.launches, []);
  const x = toHumanPlaneVM({ ...EXPOSED, launches: [{ ...EXPOSED.launches[0]!, extra: "x" } as never] });
  assert.equal(x.state, "exposed");
  assert.equal(x.since, EXPOSED.since);
  assert.deepEqual(x.launches, [{ pid: 4242, mode: "off", posture: "off", session: "claude-20261003-x1", begunAt: 1_699_999_999_000 }]);
  const drawer = JSON.stringify(x.detail);
  assert.match(drawer, /pid 4242, session claude-20261003-x1: mode off, posture off, no wall/);
  assert.match(drawer, /placeholder/);
  assert.match(drawer, /Fix: stop the launch below/);
  // a store that could not answer (pid 0) or launches without `exposed`: still exposed
  assert.equal(toHumanPlaneVM({ exposed: false, since: null, launches: [{ pid: 0, mode: "unknown", posture: "unknown" }] }).state, "exposed");
  assert.match(JSON.stringify(toHumanPlaneVM({ exposed: true, since: null, launches: [] }).detail), /could not read its launch records/);
});

test("homeExposure: a notice only while exposed, naming the process and session, with the fix, in product words", () => {
  assert.equal(homeExposure(undefined), null);
  assert.equal(homeExposure(toHumanPlaneVM(null)), null, "unknown says nothing on the product page");
  assert.equal(homeExposure(toHumanPlaneVM({ exposed: false, since: null, launches: [] })), null);
  const n = homeExposure(toHumanPlaneVM(EXPOSED))!;
  assert.equal(n.headline, "Another agent can reach Mandu's own controls.");
  assert.match(n.sentence, /placeholders instead of secret files/);
  assert.match(n.sentence, /changes to protected files are blocked/);
  assert.match(n.sentence, /command output is masked/);
  assert.match(n.sentence, /Your secrets stay protected/);
  assert.match(n.fix, /^Stop that agent, or start it again with the file guard on \(without --mode off or --no-net-guard\)\./);
  // No Home row for the session: its id, as code (§4.25x).
  assert.deepEqual(n.causes, [{
    pid: 4242, session: "claude-20261003-x1", words: "process 4242, session claude-20261003-x1, protection off, no file guard",
    parts: [{ kind: "text", text: "process 4242, session " }, { kind: "code", text: "claude-20261003-x1" }, { kind: "text", text: ", protection off, no file guard" }],
  }]);
  assert.equal(n.since, EXPOSED.since);
  const two = homeExposure(toHumanPlaneVM({ ...EXPOSED, launches: [...EXPOSED.launches, { pid: 0, mode: "unknown", posture: "unknown" }] }))!;
  assert.match(two.sentence, /^2 agents were started/);
  assert.equal(two.causes[1]!.words, "an agent Mandu could not name");
  for (const s of [n, two]) {
    for (const text of [s.headline, s.sentence, s.fix, ...s.causes.map((c) => c.words)]) assert.doesNotMatch(text, FORBIDDEN, text);
  }
});

test("homeExposure: a cause whose session Home draws a row for is named as that row names it, a link to its page; any other keeps its id, as code (§4.25x)", () => {
  const status = {
    ...EXPOSED,
    launches: [
      EXPOSED.launches[0]!,
      { pid: 4343, mode: "secrets", posture: "off", session: "codex-20261003-y2" },
      { pid: 4444, mode: "secrets", posture: "off", session: "claude-elsewhere" },
      { pid: 4545, mode: "off", posture: "off" },
      { pid: 0, mode: "unknown", posture: "unknown", session: "claude-20261003-x1" },
    ],
  };
  const agents = [
    { id: "claude-20261003-x1", agent: "Claude Code" },
    { id: "codex-20261003-y2", agent: "Codex CLI" },
    { id: "unrelated", agent: "Goose" },
  ];
  const n = homeExposure(toHumanPlaneVM(status), agents)!;
  assert.deepEqual(n.causes.map((c) => c.parts), [
    [{ kind: "link", text: "Claude Code", to: "agent", session: "claude-20261003-x1" }, { kind: "text", text: ", process 4242, protection off, no file guard" }],
    [{ kind: "link", text: "Codex CLI", to: "agent", session: "codex-20261003-y2" }, { kind: "text", text: ", process 4343, secrets protection, no file guard" }],
    // a session Home has no row for: its id, as code; never another row's agent
    [{ kind: "text", text: "process 4444, session " }, { kind: "code", text: "claude-elsewhere" }, { kind: "text", text: ", secrets protection, no file guard" }],
    [{ kind: "text", text: "process 4545, protection off, no file guard" }],
    // an unreadable launch record names nothing, whatever session it carries
    [{ kind: "text", text: "an agent Mandu could not name" }],
  ]);
  assert.deepEqual(n.causes.map((c) => c.words), [
    "Claude Code, process 4242, protection off, no file guard",
    "Codex CLI, process 4343, secrets protection, no file guard",
    "process 4444, session claude-elsewhere, secrets protection, no file guard",
    "process 4545, protection off, no file guard",
    "an agent Mandu could not name",
  ]);
  for (const c of n.causes) {
    assert.equal(c.parts.map((p) => p.text).join(""), c.words, "the parts are the words");
    assert.doesNotMatch(c.words, FORBIDDEN, c.words);
  }
  assert.deepEqual(n.causes.map((c) => [c.pid, c.session]), [[4242, "claude-20261003-x1"], [4343, "codex-20261003-y2"], [4444, "claude-elsewhere"], [4545, null], [0, "claude-20261003-x1"]]);
  // The rest of the notice does not depend on the rows.
  const bare = homeExposure(toHumanPlaneVM(status))!;
  for (const k of ["headline", "sentence", "fix", "since"] as const) assert.deepEqual(n[k], bare[k]);
});

test("homeExposure: the fix comes as parts too, the launch flags as code, the same words as `fix` (dashboard.md §4.25x)", () => {
  const one = homeExposure(toHumanPlaneVM(EXPOSED))!;
  const two = homeExposure(toHumanPlaneVM({ ...EXPOSED, launches: [...EXPOSED.launches, { pid: 4343, mode: "secrets", posture: "off" }] }))!;
  for (const n of [one, two]) {
    assert.equal(n.fixParts.map((p) => p.text).join(""), n.fix, "the parts are the fix");
    assert.deepEqual(n.fixParts.filter((p) => p.kind === "code").map((p) => p.text), ["--mode off", "--no-net-guard"]);
    for (const p of n.fixParts.filter((x) => x.kind === "text")) assert.doesNotMatch(p.text, /--/, `a flag outside code: ${p.text}`);
  }
  assert.equal(one.fix, "Stop that agent, or start it again with the file guard on (without --mode off or --no-net-guard). Your other agents work normally again as soon as it ends.");
  assert.equal(two.fix, "Stop those agents, or start them again with the file guard on (without --mode off or --no-net-guard). Your other agents work normally again as soon as they end.");
});

test("buildHomeViewModel carries the notice from the panel's humanPlane; none when the panel is unavailable", () => {
  const base = {
    sessions: [], facts: new Map(), configuredMode: "secrets" as const, nowMs: Date.now(), windowHours: 24, historyTotal: 1,
  };
  const snap = { specId: "x", origins: [], tools: [], posture: { integrity: false, confidentiality: true }, verdicts: [] } as never;
  const panel = { ...toPolicyPanelViewModel(snap), humanPlane: toHumanPlaneVM(EXPOSED) };
  const vm = buildHomeViewModel({ ...base, panel });
  assert.ok(vm.exposure, "the notice");
  assert.equal(vm.exposure!.causes[0]!.pid, 4242);
  assert.equal(vm.verdict, "secrets-only", "the verdict itself is unchanged: secrets stay guarded (fail closed)");
  assert.equal(buildHomeViewModel({ ...base, panel: { ...panel, humanPlane: toHumanPlaneVM({ exposed: false, since: null, launches: [] }) } }).exposure, null);
  assert.equal(buildHomeViewModel({ ...base, panel: { ...toPolicyPanelViewModel(null), humanPlane: toHumanPlaneVM(EXPOSED) } }).exposure, null);
});

test("buildHomeViewModel: the notice names the cause's agent as its Home row does, with a link to its page (§4.25x)", () => {
  const now = Date.parse("2026-10-10T12:00:00Z");
  const session = {
    id: "claude-20261003-x1", label: "Summarize notes.md", eventCount: 3, agent: "claude", status: "running" as const, violated: false,
    firstTs: new Date(now - 30 * 60_000).toISOString(), lastTs: new Date(now - 60_000).toISOString(),
  };
  const facts = new Map([[session.id, { stats: { flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 }, blocked: 0, sent: 0, holds: true, violations: 0, cwd: "/home/u/proj" }]]);
  const snap = { specId: "x", origins: [], tools: [], posture: { integrity: false, confidentiality: true }, verdicts: [] } as never;
  const panel = { ...toPolicyPanelViewModel(snap), humanPlane: toHumanPlaneVM(EXPOSED) };
  const vm = buildHomeViewModel({ sessions: [session], facts, panel, configuredMode: "secrets", nowMs: now, windowHours: 24, historyTotal: 1 } as never);
  const row = vm.agents.find((a) => a.id === session.id)!;
  assert.equal(row.agent, "Claude Code");
  const cause = vm.exposure!.causes[0]!;
  assert.deepEqual(cause.parts[0], { kind: "link", text: row.agent, to: "agent", session: row.id }, "the row's own name, a link to its page");
  assert.equal(cause.words, "Claude Code, process 4242, protection off, no file guard");
  // Outside Home's window: no row, so the session id as code, as before.
  const old = buildHomeViewModel({ sessions: [session], facts, panel, configuredMode: "secrets", nowMs: now + 48 * 3_600_000, windowHours: 24, historyTotal: 1 } as never);
  assert.equal(old.exposure!.causes[0]!.words, "process 4242, session claude-20261003-x1, protection off, no file guard");
});
