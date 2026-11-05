/**
 * home-failed-names.test — Home's hero when protection failed in two or
 * more sessions, in the build without the developer view (dashboard.md
 * §4.25, *Protection failed in several sessions*): it names where it
 * happened, each place a link to that session's page, newest first; past
 * three it counts the rest; two alike are told apart by when they ended;
 * a window not wholly counted says "at least". One failed session and the
 * developer view's trace link are as before. No part carries a value or a
 * token.
 *
 * The same naming, in the calm verdicts' sentence, for the running agents
 * that run with less protection than usual (§4.25, *A running agent with
 * less protection than usual*): named after the running phrase, an ended
 * one never; at `waiting` after its own sentence (#292); the headline and
 * the failed and off sentences unchanged; no part carries the launch line.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import type { ManduEvent } from "../../../src/event-model.js";
import type { SessionRef } from "../../../src/event-source/contract.js";
import { deriveHealth } from "../../../src/session-health.js";
import { buildHomeViewModel, failedSessionParts, FAILED_NAMED, lessProtectionParts, type HomeAgent, type HomeHeroPart, type HomeSessionFacts } from "../../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import { snapshot } from "../policy-snapshot-fixture.js";

const NOW = Date.parse("2026-10-25T15:00:00.000Z");
const SECRET = "sk-live-0123456789abcdefFAILEDNAMES";
const TOKEN = "$MDU:secret:1a2b3c4d";

interface Spec { id: string; agent: SessionRef["agent"]; cwd: string | null; endedMinutesAgo: number; running?: boolean; failed?: boolean }

/** The sessions and their facts, a failed one holding one unmasked item;
 *  each label holds a token and the secret's value, which no hero part may
 *  repeat. */
function input(specs: Spec[], over: { dev?: boolean; unreadable?: string[] } = {}) {
  const sessions: SessionRef[] = specs.map((s) => {
    const last = new Date(NOW - s.endedMinutesAgo * 60_000).toISOString();
    return {
      id: s.id, label: `Deploy with ${TOKEN} and ${SECRET}`, eventCount: 3, firstTs: new Date(NOW - (s.endedMinutesAgo + 30) * 60_000).toISOString(), lastTs: last,
      violated: s.failed !== false, agent: s.agent, status: s.running ? "running" : "pass",
    };
  });
  const facts = new Map<string, HomeSessionFacts>(specs.filter((s) => !over.unreadable?.includes(s.id)).map((s) => [s.id, {
    stats: { flows: 1, secret: 1, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 },
    holds: s.failed === false, violations: s.failed === false ? 0 : 1, blocked: 0, sent: 0, cwd: s.cwd,
  } as HomeSessionFacts]));
  return buildHomeViewModel({
    sessions, facts, panel: toPolicyPanelViewModel(snapshot()), configuredMode: "secrets", nowMs: NOW, windowHours: 24, historyTotal: specs.length,
    home: "/home/u", dev: over.dev ?? false,
  });
}

const links = (parts: readonly HomeHeroPart[]) => parts.flatMap((p) => (p.kind === "link" && p.to === "agent" ? [p] : []));
const words = (parts: readonly HomeHeroPart[]) => parts.map((p) => p.text).join("");

test("two failed sessions: two agent links, newest first, each its agent and ~/ folder, joined by 'and'", () => {
  const vm = input([
    { id: "old", agent: "codex", cwd: "/home/u/api", endedMinutesAgo: 120 },
    { id: "new", agent: "claude", cwd: "/home/u/shop", endedMinutesAgo: 10 },
  ]);
  assert.equal(vm.verdict, "failed");
  assert.equal(vm.headline, "Protection failed.");
  assert.equal(vm.sentence, "2 items reached the AI unmasked in the last 24 hours, in Claude Code in ~/shop and Codex CLI in ~/api. Open each to see which.");
  const [a, b] = links(vm.sentenceParts);
  assert.equal(a!.session, "new");
  assert.equal(b!.session, "old");
  assert.deepEqual(a!.parts, [{ kind: "text", text: "Claude Code in " }, { kind: "code", text: "~/shop" }], "the folder is a name, drawn as code");
  assert.equal(a!.text, "Claude Code in ~/shop");
});

test("three are all named, 'A, B and C'; four name the newest three and count the rest, marked in the lists below", () => {
  const three = input([
    { id: "c", agent: "codex", cwd: "/home/u/c", endedMinutesAgo: 30 },
    { id: "a", agent: "codex", cwd: "/home/u/a", endedMinutesAgo: 10 },
    { id: "b", agent: "codex", cwd: "/home/u/b", endedMinutesAgo: 20 },
  ]);
  assert.equal(three.sentence, "3 items reached the AI unmasked in the last 24 hours, in Codex CLI in ~/a, Codex CLI in ~/b and Codex CLI in ~/c. Open each to see which.");
  const four = input([
    { id: "d", agent: "codex", cwd: "/home/u/d", endedMinutesAgo: 40 },
    { id: "c", agent: "codex", cwd: "/home/u/c", endedMinutesAgo: 30 },
    { id: "a", agent: "codex", cwd: "/home/u/a", endedMinutesAgo: 10 },
    { id: "b", agent: "codex", cwd: "/home/u/b", endedMinutesAgo: 20 },
  ]);
  assert.equal(FAILED_NAMED, 3);
  assert.deepEqual(links(four.sentenceParts).map((l) => l.session), ["a", "b", "c"]);
  assert.equal(four.sentence, "4 items reached the AI unmasked in the last 24 hours, in Codex CLI in ~/a, Codex CLI in ~/b, Codex CLI in ~/c and 1 more, each marked \"protection failed\" in the lists below. Open each to see which.");
});

test("two sessions of one agent in one folder are told apart by when they ended (a time part); one still running, by when it started", () => {
  const vm = input([
    { id: "x", agent: "claude", cwd: "/home/u/shop", endedMinutesAgo: 58 },
    { id: "y", agent: "claude", cwd: "/home/u/shop", endedMinutesAgo: 0, running: true },
    { id: "z", agent: "codex", cwd: "/home/u/api", endedMinutesAgo: 70 },
  ]);
  const [y, x, z] = links(vm.sentenceParts);
  assert.equal(y!.session, "y");
  assert.deepEqual(y!.parts!.slice(2), [{ kind: "text", text: ", started " }, { kind: "time", text: "2026-10-25T14:30:00.000Z" }]);
  assert.deepEqual(x!.parts!.slice(2), [{ kind: "text", text: ", ended " }, { kind: "time", text: "2026-10-25T14:02:00.000Z" }]);
  assert.equal(x!.text, "Claude Code in ~/shop, ended 14:02 UTC", "the plain words say the moment in UTC; the page draws it in the reader's clock");
  assert.equal(z!.text, "Codex CLI in ~/api", "a place named once needs no moment");
});

test("a session with no folder is named by its agent alone; a folder outside home stays whole", () => {
  const vm = input([
    { id: "n", agent: "claude", cwd: null, endedMinutesAgo: 5 },
    { id: "o", agent: "codex", cwd: "/srv/build", endedMinutesAgo: 9 },
  ]);
  const [n, o] = links(vm.sentenceParts);
  assert.equal(n!.text, "Claude Code");
  assert.deepEqual(n!.parts, [{ kind: "text", text: "Claude Code" }]);
  assert.equal(o!.text, "Codex CLI in /srv/build");
});

test("a window not wholly counted says 'at least': a session left out may have failed too", () => {
  const vm = input([
    { id: "a", agent: "codex", cwd: "/home/u/a", endedMinutesAgo: 10 },
    { id: "b", agent: "codex", cwd: "/home/u/b", endedMinutesAgo: 20 },
    { id: "u", agent: "codex", cwd: "/home/u/u", endedMinutesAgo: 30, failed: false },
  ], { unreadable: ["u"] });
  assert.ok(vm.window.counted < vm.window.sessions);
  assert.equal(vm.sentence, "2 items reached the AI unmasked in the last 24 hours, at least in Codex CLI in ~/a and Codex CLI in ~/b. Open each to see which.");
});

test("one failed session keeps 'Open that agent's page'; the developer view keeps its trace link; a clean session is never named", () => {
  const one = input([
    { id: "f", agent: "codex", cwd: "/home/u/a", endedMinutesAgo: 10 },
    { id: "ok", agent: "codex", cwd: "/home/u/b", endedMinutesAgo: 5, failed: false },
  ]);
  assert.deepEqual(one.sentenceParts, [
    { kind: "text", text: "One item reached the AI unmasked in the last 24 hours. " },
    { kind: "link", text: "Open that agent's page", to: "agent", session: "f" },
    { kind: "text", text: " to see which." },
  ]);
  const specs: Spec[] = [
    { id: "a", agent: "codex", cwd: "/home/u/a", endedMinutesAgo: 10 },
    { id: "b", agent: "codex", cwd: "/home/u/b", endedMinutesAgo: 20 },
    { id: "ok", agent: "claude", cwd: "/home/u/clean", endedMinutesAgo: 1, failed: false },
  ];
  const dev = input(specs, { dev: true });
  assert.deepEqual(dev.sentenceParts.filter((p) => p.kind === "link"), [{ kind: "link", text: "Open the detailed trace", to: "trace", session: null }]);
  assert.deepEqual(links(input(specs).sentenceParts).map((l) => l.session), ["a", "b"]);
});

test("the oracle: no part's text, words or moment carries a token or the secret's value", () => {
  const vm = input([
    { id: "a", agent: "claude", cwd: "/home/u/shop", endedMinutesAgo: 10 },
    { id: "b", agent: "claude", cwd: "/home/u/shop", endedMinutesAgo: 20 },
    { id: "c", agent: "codex", cwd: null, endedMinutesAgo: 30 },
    { id: "d", agent: "codex", cwd: "/home/u/d", endedMinutesAgo: 40 },
  ]);
  const all = JSON.stringify([vm.sentence, vm.sentenceParts]);
  assert.equal(all.includes(SECRET), false);
  assert.doesNotMatch(all, /\$MDU:/);
  assert.equal(words(vm.sentenceParts), vm.sentence);
  // The helper alone, over rows whose title holds both: it reads agent and folder only.
  const rows = vm.agents.map((a): HomeAgent => ({ ...a, title: `${TOKEN} ${SECRET}` }));
  const parts = failedSessionParts(rows, ["a", "b"], 24, 2, "/home/u", false);
  assert.equal(JSON.stringify(parts).includes(SECRET), false);
  assert.doesNotMatch(JSON.stringify(parts), /\$MDU:/);
});

// ── A running agent with less protection than usual (§4.25) ─────────────────

/** The launch line a dropped network proxy prints; no hero part may carry it. */
const NET_PROXY_DOWN = "mandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it (opt out explicitly with --no-net-proxy to silence this)";

/** A session's health as the launcher's record makes it: `less`, the
 *  network proxy did not start (`droppedProtections` 1); else a full launch. */
function healthOf(less: boolean) {
  const ev = (kind: string, extra: Record<string, unknown>) => ({
    id: `${kind}-1`, sessionId: "s", turn: 1, ts: "2026-10-25T14:00:00.000Z", seq: 1, callId: null, parentId: null,
    kind, view: "HumanView", boundary: "shell", emitter: "launcher", input: null, output: null, invariant: { violatedInvariant: false }, ...extra,
  }) as unknown as ManduEvent;
  return deriveHealth([
    ev("launch_posture", { target: "claude", live: ["fs"], dropped: less ? [NET_PROXY_DOWN] : [] }),
    ev("tllm_call", { callShape: { toolCount: 12 }, output: { symbolized: "Done.", original: null, differs: false, symbols: [] } }),
  ])!;
}

interface LessSpec { id: string; agent: SessionRef["agent"]; cwd: string | null; lastMinutesAgo: number; running?: boolean; less?: boolean }

/** Home over these sessions at a level: `secrets` (secrets-only), `full`
 *  with nothing masked (quiet) or one item masked (protected), `off`; a
 *  question waiting (`waiting`) or an unmasked item in the first session
 *  (`failed`) on top. Each label holds a token and the secret's value. */
function lessHome(specs: LessSpec[], over: { level?: "secrets" | "full" | "off"; masked?: boolean; waiting?: boolean; askedBy?: string; failed?: boolean } = {}) {
  const level = over.level ?? "secrets";
  const sessions: SessionRef[] = specs.map((s) => ({
    id: s.id, label: `Deploy with ${TOKEN} and ${SECRET}`, eventCount: 3,
    firstTs: new Date(NOW - (s.lastMinutesAgo + 30) * 60_000).toISOString(), lastTs: new Date(NOW - s.lastMinutesAgo * 60_000).toISOString(),
    violated: false, agent: s.agent, status: s.running === false ? "pass" : "running", health: healthOf(s.less === true),
  }));
  const facts = new Map<string, HomeSessionFacts>(specs.map((s, i) => [s.id, {
    stats: { flows: over.masked ? 1 : 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0 },
    holds: !(over.failed && i === 0), violations: over.failed && i === 0 ? 1 : 0, blocked: 0, sent: 0, cwd: s.cwd,
  } as HomeSessionFacts]));
  const base = snapshot();
  const panel = toPolicyPanelViewModel({
    ...base,
    posture: { integrity: level === "full", confidentiality: level !== "off" },
    // `askedBy`: the waiting question names its asking session.
    verdicts: over.waiting ? (base.verdicts ?? []).map((v) => (v.status === "pending" && over.askedBy ? { ...v, sessions: [over.askedBy] } : v)) : [],
  });
  return buildHomeViewModel({
    sessions, facts, panel, configuredMode: level === "full" ? "full" : level, nowMs: NOW, windowHours: 24, historyTotal: specs.length,
    home: "/home/u", dev: false,
  });
}

const SECRETS_REST = "Keys and secret files leave this computer only where a rule or your OK allows. Untrusted content is not masked in this mode.";

test("secrets-only: a running agent with less protection than usual is named, a link to its page, between the running phrase and the level's words", () => {
  const vm = lessHome([
    { id: "drop", agent: "claude", cwd: "/home/u/shop", lastMinutesAgo: 2, less: true },
    { id: "ok", agent: "codex", cwd: "/home/u/api", lastMinutesAgo: 1 },
  ]);
  assert.equal(vm.verdict, "secrets-only");
  assert.equal(vm.headline, "Your secrets are guarded.", "the headline stays as the level makes it");
  assert.deepEqual(vm.sentenceParts, [
    { kind: "text", text: "2 agents are running under Mandu. " },
    { kind: "link", text: "Claude Code in ~/shop", to: "agent", session: "drop", parts: [{ kind: "text", text: "Claude Code in " }, { kind: "code", text: "~/shop" }] },
    { kind: "text", text: " runs with less protection than usual: not all of Mandu's protections started for it." },
    { kind: "text", text: ` ${SECRETS_REST}` },
  ]);
  assert.equal(vm.sentence, `2 agents are running under Mandu. Claude Code in ~/shop runs with less protection than usual: not all of Mandu's protections started for it. ${SECRETS_REST}`);
  // None: the sentence as before, one text part.
  const none = lessHome([{ id: "ok", agent: "codex", cwd: "/home/u/api", lastMinutesAgo: 1 }]);
  assert.deepEqual(none.sentenceParts, [{ kind: "text", text: `One agent is running under Mandu. ${SECRETS_REST}` }]);
});

test("two are joined by 'and' and 'run'; four name the newest three and count the rest, marked in Running now below", () => {
  const two = lessHome([
    { id: "a", agent: "claude", cwd: "/home/u/a", lastMinutesAgo: 5, less: true },
    { id: "b", agent: "codex", cwd: null, lastMinutesAgo: 1, less: true },
  ]);
  assert.deepEqual(links(two.sentenceParts).map((l) => l.session), ["b", "a"], "newest first");
  assert.equal(two.sentence, `2 agents are running under Mandu. Codex CLI and Claude Code in ~/a run with less protection than usual: not all of Mandu's protections started for each. ${SECRETS_REST}`);
  const four = lessHome([
    { id: "d", agent: "codex", cwd: "/home/u/d", lastMinutesAgo: 40, less: true },
    { id: "c", agent: "codex", cwd: "/home/u/c", lastMinutesAgo: 30, less: true },
    { id: "a", agent: "codex", cwd: "/home/u/a", lastMinutesAgo: 10, less: true },
    { id: "b", agent: "codex", cwd: "/home/u/b", lastMinutesAgo: 20, less: true },
  ]);
  assert.deepEqual(links(four.sentenceParts).map((l) => l.session), ["a", "b", "c"]);
  assert.equal(four.sentence, `4 agents are running under Mandu. Codex CLI in ~/a, Codex CLI in ~/b, Codex CLI in ~/c and 1 more, each marked in Running now below, run with less protection than usual: not all of Mandu's protections started for each. ${SECRETS_REST}`);
  // Two alike are told apart as failed sessions are: by when each started.
  const alike = lessHome([
    { id: "x", agent: "claude", cwd: "/home/u/shop", lastMinutesAgo: 1, less: true },
    { id: "y", agent: "claude", cwd: "/home/u/shop", lastMinutesAgo: 3, less: true },
  ]);
  const [x] = links(alike.sentenceParts);
  assert.deepEqual(x!.parts!.slice(2), [{ kind: "text", text: ", started " }, { kind: "time", text: "2026-10-25T14:29:00.000Z" }]);
});

test("an ended session is never named in the hero: its row says it", () => {
  const vm = lessHome([
    { id: "gone", agent: "claude", cwd: "/home/u/old", lastMinutesAgo: 30, running: false, less: true },
    { id: "ok", agent: "codex", cwd: "/home/u/api", lastMinutesAgo: 1 },
  ]);
  assert.equal(vm.agents.find((a) => a.id === "gone")!.lessProtection, true, "its row is marked (#199)");
  assert.deepEqual(vm.sentenceParts, [{ kind: "text", text: `One agent is running under Mandu. ${SECRETS_REST}` }]);
  const onlyEnded = lessHome([{ id: "gone", agent: "claude", cwd: "/home/u/old", lastMinutesAgo: 30, running: false, less: true }]);
  assert.equal(onlyEnded.sentence, `No agent is running right now. ${SECRETS_REST}`);
  assert.deepEqual(lessProtectionParts(onlyEnded.agents, "/home/u"), []);
});

test("quiet and protected name it too; failed and off keep their sentences", () => {
  const specs: LessSpec[] = [{ id: "drop", agent: "claude", cwd: "/home/u/shop", lastMinutesAgo: 2, less: true }];
  const quiet = lessHome(specs, { level: "full" });
  assert.equal(quiet.verdict, "quiet");
  assert.equal(quiet.headline, "You are protected.");
  assert.equal(quiet.sentence, "One agent is running under Mandu. Claude Code in ~/shop runs with less protection than usual: not all of Mandu's protections started for it. No untrusted content has reached the AI in the last 24 hours.");
  assert.deepEqual(links(quiet.sentenceParts).map((l) => l.session), ["drop"]);
  const prot = lessHome(specs, { level: "full", masked: true });
  assert.equal(prot.verdict, "protected");
  assert.equal(prot.headline, "You are protected.");
  assert.match(prot.sentence, /^One agent is running under Mandu\. Claude Code in ~\/shop runs with less protection than usual: not all of Mandu's protections started for it\. In the last 24 hours, the one untrusted item/);
  assert.deepEqual(links(prot.sentenceParts).map((l) => l.session), ["drop"]);
  for (const [name, vm, verdict] of [
    ["failed", lessHome([...specs, { id: "f2", agent: "codex", cwd: "/home/u/f", lastMinutesAgo: 3 }], { failed: true }), "failed"],
    ["off", lessHome(specs, { level: "off" }), "off"],
  ] as const) {
    assert.equal(vm.verdict, verdict, name);
    assert.doesNotMatch(vm.sentence, /less protection than usual/, name);
    assert.equal(vm.agents.find((a) => a.id === "drop")!.lessProtection, true, `${name}: its row still says it`);
  }
});

const WAITING = "Protection is holding while you decide: what it asks for happens only if you allow it. Untrusted content is not masked in this mode.";
const DROP_LINK = { kind: "link", text: "Claude Code in ~/shop", to: "agent", session: "drop", parts: [{ kind: "text", text: "Claude Code in " }, { kind: "code", text: "~/shop" }] } as const;
const LESS_ONE = " runs with less protection than usual: not all of Mandu's protections started for it.";

test("waiting names it too, after its own sentence; the headline stays (#292)", () => {
  const specs: LessSpec[] = [
    { id: "drop", agent: "claude", cwd: "/home/u/shop", lastMinutesAgo: 2, less: true },
    { id: "ok", agent: "codex", cwd: "/home/u/api", lastMinutesAgo: 1 },
  ];
  const vm = lessHome(specs, { waiting: true });
  assert.equal(vm.verdict, "waiting");
  assert.equal(vm.headline, "One question is waiting for you.", "the headline stays as the verdict makes it");
  assert.equal(vm.waiting.length, 1, "the count stays");
  assert.deepEqual(vm.sentenceParts, [{ kind: "text", text: `${WAITING} ` }, DROP_LINK, { kind: "text", text: LESS_ONE }]);
  assert.equal(vm.sentence, `${WAITING} Claude Code in ~/shop${LESS_ONE}`);
  assert.equal(words(vm.sentenceParts), vm.sentence);
  // Every question from ended sessions: their own news first, then the running agent.
  const ended = lessHome([...specs, { id: "gone", agent: "codex", cwd: "/home/u/old", lastMinutesAgo: 30, running: false }], { waiting: true, askedBy: "gone" });
  assert.equal(ended.headline, "One question from a session that has ended is waiting for you.");
  assert.deepEqual(ended.sentenceParts, [
    { kind: "text", text: "No agent is waiting on it now. Your answer decides what happens the next time an agent asks the same. Untrusted content is not masked in this mode. " },
    DROP_LINK, { kind: "text", text: LESS_ONE },
  ]);
  // Only an ended less-protected session, or none: one text part, as before.
  const onlyEnded = lessHome([{ id: "gone", agent: "claude", cwd: "/home/u/old", lastMinutesAgo: 30, running: false, less: true }], { waiting: true });
  assert.equal(onlyEnded.agents.find((a) => a.id === "gone")!.lessProtection, true, "its row still says it");
  assert.deepEqual(onlyEnded.sentenceParts, [{ kind: "text", text: WAITING }]);
  const none = lessHome([{ id: "ok", agent: "codex", cwd: "/home/u/api", lastMinutesAgo: 1 }], { waiting: true });
  assert.deepEqual(none.sentenceParts, [{ kind: "text", text: WAITING }]);
});

test("the oracle: the less-protection words carry no launch line, token or value", () => {
  const specs: LessSpec[] = [
    { id: "a", agent: "claude", cwd: "/home/u/shop", lastMinutesAgo: 1, less: true },
    { id: "b", agent: "claude", cwd: "/home/u/shop", lastMinutesAgo: 2, less: true },
    { id: "c", agent: "codex", cwd: null, lastMinutesAgo: 3, less: true },
    { id: "d", agent: "codex", cwd: "/home/u/d", lastMinutesAgo: 4, less: true },
  ];
  const vm = lessHome(specs);
  // The waiting form too (#292).
  for (const form of [vm, lessHome(specs, { waiting: true })]) {
    assert.equal(links(form.sentenceParts).length, 3, form.verdict);
    const all = JSON.stringify([form.sentence, form.sentenceParts]);
    assert.equal(all.includes(SECRET), false, form.verdict);
    assert.doesNotMatch(all, /\$MDU:|net-proxy|8790|WITHOUT|--no-|failed to start/, form.verdict);
    assert.equal(words(form.sentenceParts), form.sentence, form.verdict);
  }
  // The helper alone, over rows whose title holds both: it reads agent and folder only.
  const rows = vm.agents.map((a): HomeAgent => ({ ...a, title: `${TOKEN} ${SECRET} ${NET_PROXY_DOWN}` }));
  const parts = JSON.stringify(lessProtectionParts(rows, "/home/u"));
  assert.equal(parts.includes(SECRET), false);
  assert.doesNotMatch(parts, /\$MDU:|net-proxy/);
});
