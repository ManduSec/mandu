/**
 * agent-versions.test — the dashboard's half of release checklist e4
 * (supported-agents.md): the session-health chip degrades for an agent outside
 * the tested versions, from the proxy's `client_info` (Claude Code) or the
 * launcher's probe on `launch_posture` (every agent), and the product page's
 * agent row carries ONE plain sentence saying so, in the product vocabulary.
 * The table itself is pinned to the launcher's by
 * tests/stack/agent-versions-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAgentVersion, generationOf, ISSUES_URL, parseAgentVersion, previewLineOf, rangeLabel, supportStatusOf, TESTED_AGENT_GENERATIONS, TESTED_AGENT_VERSIONS } from "../../src/agent-versions.js";
import { deriveHealth } from "../../src/session-health.js";
import { agentName, agentNotice, agentPreview, askedBy, buildHomeViewModel } from "../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../src/view-model/policy-panel.js";
import type { ManduEvent } from "../../src/event-model.js";
import type { PolicySnapshot } from "../../src/policy-model.js";

let n = 0;
function ev(kind: string, extra: Record<string, unknown> = {}): ManduEvent {
  n++;
  return {
    id: `e${n}`, sessionId: "s", turn: n, ts: new Date(1700000000000 + n * 1000).toISOString(), seq: n,
    callId: null, parentId: null, kind: kind as ManduEvent["kind"], view: "HumanView", boundary: "shell",
    emitter: "launcher", input: null, output: null, invariant: { violatedInvariant: false },
    ...extra,
  } as ManduEvent;
}
const posture = (target: string, extra: Record<string, unknown> = {}) => ev("launch_posture", { target, live: ["fs"], dropped: [], ...extra });
const MAX = TESTED_AGENT_VERSIONS.claude.max;

test("the dashboard's check: same verdicts as the launcher's rules", () => {
  assert.equal(checkAgentVersion("claude", MAX).verdict, "tested");
  assert.equal(checkAgentVersion("claude", "9.0.0").verdict, "newer");
  assert.equal(checkAgentVersion("codex", "0.1.0").verdict, "older");
  assert.equal(checkAgentVersion("codex", "not a version").verdict, "unknown");
  assert.equal(parseAgentVersion("2026.7.1-2")?.raw, "2026.7.1");
});

test("OpenCode 2 is judged against its own tested range: 2.0.23 is healthy, 2.0.27 degrades naming 2.x's range, 1.x keeps 1.x's", () => {
  assert.equal(checkAgentVersion("opencode", "opencode v2.0.23").verdict, "tested");
  assert.equal(checkAgentVersion("opencode", "opencode v2.0.26").verdict, "tested");
  assert.equal(checkAgentVersion("opencode", "1.18.13").verdict, "tested");
  assert.equal(checkAgentVersion("opencode", "1.18.35").verdict, "tested");
  assert.equal(checkAgentVersion("opencode", "1.18.36").max, "1.18.35");
  const probed = (version: string) => deriveHealth([posture("opencode", { agentVersion: { agent: "opencode", version, verdict: "newer" } })])!;
  const v2 = probed("2.0.23");
  assert.equal(v2.agentVersion?.verdict, "tested", "re-derived from this table: 2.0.23 is no longer newer than 1.18.13");
  assert.equal(v2.verdict, "ok");
  const newer = probed("2.0.27");
  assert.equal(newer.verdict, "degraded");
  assert.match(newer.reasons.join("\n"), /OpenCode 2\.0\.27 is newer than the tested range \(2\.0\.23 to 2\.0\.26\)/);
});

test("Goose is graded from the launcher's probe: 1.53.0 and 1.54.0 are healthy, 1.55.0 degrades naming the range", () => {
  const probed = (version: string) => deriveHealth([posture("goose", { agentVersion: { agent: "goose", version, verdict: "tested" } })])!;
  for (const v of ["1.53.0", "1.54.0"]) {
    const ok = probed(v);
    assert.equal(ok.agentVersion?.verdict, "tested", v);
    assert.equal(ok.verdict, "ok", v);
  }
  const newer = probed("1.55.0");
  assert.equal(newer.agentVersion?.verdict, "newer", "re-derived from this table, not the event's verdict");
  assert.equal(newer.verdict, "degraded");
  assert.match(newer.reasons.join("\n"), /Goose 1\.55\.0 is newer than the tested range \(1\.53\.0 to 1\.54\.0\)/);
});

test("health: a claude newer than tested (from client_info) degrades with a reason; an in-range one does not", () => {
  const newer = deriveHealth([posture("claude"), ev("client_info", { clientVersion: "9.0.0" })])!;
  assert.equal(newer.verdict, "degraded");
  assert.equal(newer.agentVersion?.verdict, "newer");
  assert.match(newer.reasons.join("\n"), /Claude Code 9\.0\.0 is newer than the tested range \(2\.1\.273 to /);
  const ok = deriveHealth([posture("claude"), ev("client_info", { clientVersion: MAX })])!;
  assert.equal(ok.verdict, "ok");
  assert.equal(ok.agentVersion?.verdict, "tested");
});

test("health: the proxy's version wins over the launcher's probe for claude; codex reads the probe", () => {
  const both = deriveHealth([
    posture("claude", { agentVersion: { agent: "claude", version: "1.0.0", verdict: "older", min: "x", max: "y" } }),
    ev("client_info", { clientVersion: MAX }),
  ])!;
  assert.equal(both.agentVersion?.verdict, "tested", "what the agent said on the wire is authoritative");
  const codex = deriveHealth([posture("codex", { agentVersion: { agent: "codex", version: "0.200.0", verdict: "newer", min: "x", max: "y" } })])!;
  assert.equal(codex.agentVersion?.verdict, "newer");
  assert.equal(codex.verdict, "degraded");
  // The verdict is re-derived from THIS dashboard's table, not trusted off the event.
  const reclassified = deriveHealth([posture("codex", { agentVersion: { agent: "codex", version: "0.154.0", verdict: "newer" } })])!;
  assert.equal(reclassified.agentVersion?.verdict, "tested");
});

test("health: a version the launcher could not read is a note, not a degrade; a non-agent target has no check", () => {
  const unknown = deriveHealth([posture("claude", { agentVersion: { agent: "claude", version: null, verdict: "unknown" } })])!;
  assert.equal(unknown.verdict, "ok");
  assert.match(unknown.reasons.join("\n"), /could not read the Claude Code version/);
  const shell = deriveHealth([posture("shell"), ev("client_info", { clientVersion: "9.0.0" })])!;
  assert.equal(shell.agentVersion, null);
  const old = deriveHealth([ev("launch_posture", { live: [], dropped: [] }), ev("client_info", { clientVersion: "9.0.0" })])!;
  assert.equal(old.agentVersion, null, "a posture without a target (an older launcher) is not graded");
});

// ── The product page's notice ────────────────────────────────────────────────

const health = (events: ManduEvent[]) => deriveHealth(events)!;
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|inbound spec|fail[- ]closed)\b|\$MDU:/i;

test("notice: newer / older / unknown tools, worded for the running protection level", () => {
  const newer = agentNotice(health([posture("claude"), ev("client_info", { clientVersion: "9.0.0" })]), true)!;
  assert.match(newer, /^Claude Code 9\.0\.0 is newer than the versions Mandu was tested with \(2\.1\.273 to .+\)\. Tools it has that Mandu does not know yet have their output masked in full/);
  const newerSecrets = agentNotice(health([posture("claude"), ev("client_info", { clientVersion: "9.0.0" })]), false)!;
  assert.doesNotMatch(newerSecrets, /masked/, "at the secrets level untrusted output is not masked: never claim it is");
  const older = agentNotice(health([posture("codex", { agentVersion: { agent: "codex", version: "0.1.0" } })]), true)!;
  assert.match(older, /^Codex 0\.1\.0 is older than the versions Mandu was tested with \(0\.136\.0 to 0\.162\.0\)\. Upgrade it/);
  const tools = agentNotice(health([posture("claude"), ev("client_info", { clientVersion: MAX }), ev("tool_surface", { names: ["A", "B"], unknown: ["NewTool"] })]), true)!;
  assert.equal(tools, "Mandu does not know one of this agent's tools yet (NewTool), so their output is masked in full and the agent may work less well.");
  const many = agentNotice(health([posture("claude"), ev("tool_surface", { names: [], unknown: ["A", "B", "C", "D", "E"] })]), true)!;
  assert.match(many, /5 of this agent's tools yet \(A, B, C and 2 more\)/);
  assert.equal(agentNotice(health([posture("claude"), ev("tool_surface", { names: [], unknown: ["A"] })]), false), null);
  assert.equal(agentNotice(health([posture("claude"), ev("client_info", { clientVersion: MAX })]), true), null);
  assert.equal(agentNotice(undefined, true), null);
  for (const s of [newer, newerSecrets, older, tools, many]) assert.doesNotMatch(s, FORBIDDEN, s);
});

test("home projection: the agent row carries the notice from the session's health", () => {
  const NOW = Date.parse("2026-09-27T12:00:00Z");
  const snap = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: true, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts: [],
  } as unknown as PolicySnapshot;
  const vm = buildHomeViewModel({
    sessions: [{
      id: "s1", label: "Fix it", eventCount: 3, firstTs: new Date(NOW - 60_000).toISOString(), lastTs: new Date(NOW - 1000).toISOString(),
      violated: false, agent: "claude", status: "running",
      health: health([posture("claude"), ev("client_info", { clientVersion: "9.0.0" })]),
    }],
    facts: new Map(),
    panel: toPolicyPanelViewModel(snap),
    configuredMode: "full",
    nowMs: NOW,
    windowHours: 24,
    historyTotal: 1,
  });
  assert.match(vm.agents[0]!.notice!, /Claude Code 9\.0\.0 is newer than the versions Mandu was tested with/);
});

// ── Support status: supported or preview (supported-agents.md §2.0) ─────────

test("support status: a version is judged on its own line; Goose, OpenCode 1 and OpenCode 2 are a preview, every other line is supported", () => {
  assert.equal(rangeLabel(TESTED_AGENT_VERSIONS.goose), "Goose");
  assert.equal(rangeLabel(TESTED_AGENT_GENERATIONS.opencode![0]!), "OpenCode 2");
  assert.equal(supportStatusOf("goose", "1.53.0"), "preview");
  assert.equal(supportStatusOf("goose", null), "preview", "an unreadable version is judged on the agent's first line");
  assert.equal(supportStatusOf("opencode", "opencode v2.0.23"), "preview");
  assert.equal(supportStatusOf("opencode", "2.0.99"), "preview", "a newer 2.x is still OpenCode 2's line");
  assert.equal(supportStatusOf("opencode", "1.18.13"), "preview", "OpenCode 1 is a preview since 2026-10-09");
  assert.equal(supportStatusOf("opencode", null), "preview", "an unreadable version is judged on OpenCode 1's line");
  for (const agent of ["claude", "codex", "openclaw"] as const) assert.equal(supportStatusOf(agent, TESTED_AGENT_VERSIONS[agent].max), "supported");
  assert.equal(previewLineOf("goose", " 1.54.0"), "Goose");
  assert.equal(previewLineOf("opencode", "2.0.23"), "OpenCode 2");
  assert.equal(previewLineOf("opencode", "1.18.13"), "OpenCode", "OpenCode 1's line, under the name its row keeps");
  assert.equal(previewLineOf("opencode", "1.19.0"), "OpenCode", "a newer 1.x is still OpenCode 1's line");
  assert.equal(previewLineOf("claude", "9.0.0"), null);
});

test("health: a preview agent carries its line's label and a note, never a downgrade; a supported one carries neither", () => {
  const goose = deriveHealth([posture("goose", { agentVersion: { agent: "goose", version: "1.53.0" } })])!;
  assert.equal(goose.preview, "Goose");
  assert.equal(goose.verdict, "ok", "the status is about testing, not about what Mandu enforces");
  assert.deepEqual(goose.reasons, ["Goose support is a preview: tested less than Claude Code and Codex"]);
  const opencode2 = deriveHealth([posture("opencode", { agentVersion: { agent: "opencode", version: "2.0.23" } })])!;
  assert.equal(opencode2.preview, "OpenCode 2");
  const opencode1 = deriveHealth([posture("opencode", { agentVersion: { agent: "opencode", version: "1.18.13" } })])!;
  assert.equal(opencode1.preview, "OpenCode");
  assert.equal(opencode1.verdict, "ok");
  assert.deepEqual(opencode1.reasons, ["OpenCode support is a preview: tested less than Claude Code and Codex"]);
  const newer = deriveHealth([posture("goose", { agentVersion: { agent: "goose", version: "1.55.0" } })])!;
  assert.equal(newer.verdict, "degraded", "a newer version still degrades");
  assert.equal(newer.preview, "Goose");
  assert.match(newer.reasons.join("\n"), /Goose 1\.55\.0 is newer than the tested range[^\n]*\nGoose support is a preview/);
  const unread = deriveHealth([posture("goose", { agentVersion: { agent: "goose", version: null } })])!;
  assert.equal(unread.preview, "Goose", "an unreadable Goose version is still Goose");
  for (const supported of [
    deriveHealth([posture("claude"), ev("client_info", { clientVersion: MAX })])!,
    deriveHealth([posture("codex", { agentVersion: { agent: "codex", version: "0.162.0" } })])!,
  ]) {
    assert.equal("preview" in supported, false, `${supported.agentVersion?.name}: no preview`);
    assert.doesNotMatch(supported.reasons.join("\n"), /preview/);
  }
  assert.equal("preview" in deriveHealth([posture("goose")])!, false, "no version check (an older launcher): nothing is claimed");
});

test("the preview tag: what a preview means and where to report a problem, in plain words; none for a supported agent", () => {
  const goose = agentPreview(health([posture("goose", { agentVersion: { agent: "goose", version: "1.53.0" } })]))!;
  assert.deepEqual(goose, {
    label: "Goose",
    sentence: "Goose support is a preview: Mandu was tested less with it than with Claude Code and Codex.",
    issues: ISSUES_URL,
  });
  const opencode2 = agentPreview(health([posture("opencode", { agentVersion: { agent: "opencode", version: "2.0.23" } })]))!;
  assert.equal(opencode2.sentence, "OpenCode 2 support is a preview: Mandu was tested less with it than with Claude Code and Codex.");
  const opencode1 = agentPreview(health([posture("opencode", { agentVersion: { agent: "opencode", version: "1.18.13" } })]))!;
  assert.equal(opencode1.sentence, "OpenCode support is a preview: Mandu was tested less with it than with Claude Code and Codex.");
  assert.equal(agentPreview(health([posture("claude"), ev("client_info", { clientVersion: MAX })])), null);
  assert.equal(agentPreview(undefined), null);
  for (const p of [goose, opencode2, opencode1]) assert.doesNotMatch(p.sentence, FORBIDDEN, p.sentence);
  // The version notice keeps its own sentence; the tag never folds into it.
  assert.equal(agentNotice(health([posture("goose", { agentVersion: { agent: "goose", version: "1.53.0" } })]), false), null);
});

test("home projection: a preview agent's row carries its tag beside any notice; a supported agent's carries none", () => {
  const NOW = Date.parse("2026-09-27T12:00:00Z");
  const snap = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts: [],
  } as unknown as PolicySnapshot;
  const row = (id: string, agent: "goose" | "claude", events: ManduEvent[]) => ({
    id, label: "Fix it", eventCount: 3, firstTs: new Date(NOW - 60_000).toISOString(), lastTs: new Date(NOW - 1000).toISOString(),
    violated: false, agent, status: "running" as const, health: health(events),
  });
  const vm = buildHomeViewModel({
    sessions: [
      row("g1", "goose", [posture("goose", { agentVersion: { agent: "goose", version: "1.55.0" } })]),
      row("c1", "claude", [posture("claude"), ev("client_info", { clientVersion: MAX })]),
    ],
    facts: new Map(),
    panel: toPolicyPanelViewModel(snap),
    configuredMode: "secrets",
    nowMs: NOW,
    windowHours: 24,
    historyTotal: 2,
  });
  const goose = vm.agents.find((a) => a.id === "g1")!;
  assert.equal(goose.preview?.label, "Goose");
  assert.match(goose.notice!, /^Goose 1\.55\.0 is newer than the versions Mandu was tested with/, "the version notice stays its own");
  assert.equal(vm.agents.find((a) => a.id === "c1")!.preview, null);
});

// ── The agent's name says its generation (2026-10-09) ───────────────────────

test("generation: a version on a later tested line gives that line's major; the first line, an unreadable version or another agent none", () => {
  assert.equal(generationOf("opencode", "2.0.23"), 2);
  assert.equal(generationOf("opencode", "opencode v2.1.0"), 2, "a newer 2.x is still OpenCode 2's line");
  assert.equal(generationOf("opencode", "1.18.13"), null);
  assert.equal(generationOf("opencode", null), null);
  assert.equal(generationOf("opencode", "3.0.0"), null, "no line of its own: judged on the first, so no generation");
  for (const agent of ["claude", "codex", "openclaw", "goose"] as const) assert.equal(generationOf(agent, "2.0.23"), null, agent);
  // Every generation the table holds is named by its own label.
  for (const [agent, lines] of Object.entries(TESTED_AGENT_GENERATIONS)) {
    for (const line of lines!) assert.equal(generationOf(agent as "opencode", line.min), line.major);
  }
});

test("name: an OpenCode 2.x session is \"OpenCode 2\", the label its preview tag uses; OpenCode 1, no check, an unreadable version or a check for another agent keep the kind's name", () => {
  const of = (agent: string, version: string | null) => health([posture(agent, { agentVersion: { agent, version } })]);
  const two = of("opencode", "2.0.23");
  assert.equal(agentName("opencode", two), "OpenCode 2");
  assert.equal(agentName("opencode", two), agentPreview(two)!.label, "the name and the tag agree");
  assert.equal(agentName("opencode", of("opencode", "2.0.30")), "OpenCode 2", "newer than tested: still OpenCode 2");
  assert.equal(agentName("opencode", of("opencode", "1.18.13")), "OpenCode");
  assert.equal(agentName("opencode", of("opencode", null)), "OpenCode");
  assert.equal(agentName("opencode", health([posture("opencode")])), "OpenCode", "no version check (an older launcher)");
  assert.equal(agentName("opencode"), "OpenCode");
  assert.equal(agentName("opencode", of("goose", "2.0.23")), "OpenCode", "a check made for another agent names nothing");
  assert.equal(agentName("goose", of("goose", "1.53.0")), "Goose");
  assert.equal(agentName("codex", of("codex", "0.160.0")), "Codex CLI");
  assert.equal(agentName("claude", health([posture("claude"), ev("client_info", { clientVersion: MAX })])), "Claude Code");
  assert.equal(agentName(undefined, two), "The agent");
});

test("home projection: an OpenCode 2 session is \"OpenCode 2\" on its row and in the asks it raised, waiting and answered; an OpenCode 1 session stays \"OpenCode\"", () => {
  const NOW = Date.parse("2026-09-27T12:00:00Z");
  const verdict = (id: string, sessions: string[], status: "pending" | "denied") => ({
    id, symbol: "$MDU:nomodel_Env[ab12]", destination: "paste.example", status, reason: "r", count: 1,
    firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, sessions, ...(status === "pending" ? {} : { resolvedAt: NOW - 30_000 }),
  });
  const snap = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] },
    verdicts: [verdict("egr-1", ["oc2"], "pending"), verdict("egr-2", ["oc1", "oc2"], "denied"), verdict("egr-3", ["hidden"], "pending")],
  } as unknown as PolicySnapshot;
  const row = (id: string, version: string) => ({
    id, label: "Fix it", eventCount: 3, firstTs: new Date(NOW - 60_000).toISOString(), lastTs: new Date(NOW - 1000).toISOString(),
    violated: false, agent: "opencode" as const, status: "running" as const,
    health: health([posture("opencode", { agentVersion: { agent: "opencode", version } })]),
  });
  const sessions = [row("oc2", "2.0.23"), row("oc1", "1.18.13")];
  // A test session's ask names its agent's generation too (agentOf covers every session).
  const hidden = { ...row("hidden", "2.0.23"), id: "hidden" };
  const vm = buildHomeViewModel({
    sessions,
    agentOf: new Map([...sessions, hidden].map((s) => [s.id, s])),
    facts: new Map(),
    panel: toPolicyPanelViewModel(snap),
    configuredMode: "secrets",
    nowMs: NOW,
    windowHours: 24,
    historyTotal: 2,
  });
  const text = (parts: Array<{ text: string }>) => parts.map((p) => p.text).join("");
  assert.equal(vm.agents.find((a) => a.id === "oc2")!.agent, "OpenCode 2");
  assert.equal(vm.agents.find((a) => a.id === "oc2")!.preview?.label, "OpenCode 2", "the row's name and its tag agree");
  assert.equal(vm.agents.find((a) => a.id === "oc1")!.agent, "OpenCode");
  assert.equal(vm.agents.find((a) => a.id === "oc1")!.preview?.label, "OpenCode", "OpenCode 1 is a preview too, its tag under the row's name");
  const waiting = vm.waiting.find((a) => a.id === "egr-1")!;
  assert.match(text(waiting.sentence), /^OpenCode 2 wants to send /);
  assert.deepEqual(waiting.agents, ["OpenCode 2"]);
  assert.match(text(vm.waiting.find((a) => a.id === "egr-3")!.sentence), /^OpenCode 2 wants to send /, "a hidden session's ask");
  assert.match(text(vm.answered.find((a) => a.id === "egr-2")!.sentence), /^OpenCode 2 wants to send /, "the asker is the session that raised it last");
  assert.equal(askedBy({ sessions: ["oc2", "oc1"] }, new Map(sessions.map((s) => [s.id, s]))), "OpenCode");
});
