/**
 * home-view-model.test — the PRODUCT home projection (dashboard.md §4.25).
 *
 * Contracts, in order of importance:
 *   1. The verdict ladder: unknown (no arbiter) > failed (a violation) > off >
 *      waiting > secrets-only > quiet > protected. A red state is never hidden
 *      behind a green one.
 *   2. Every ask is a plain sentence built from the queue row's family; the
 *      raw key (`$MDU:…`, `open:cat`, `exec-program:`) never reaches the page
 *      except as the destination/program it names.
 *   3. Counts cover the window only, and only LIVE sessions the route passed.
 *   4. The eight-word vocabulary: no inspector term leaks into product copy —
 *      the same sweep the simple register had, applied to the projection AND
 *      to the product's static page + script.
 *   5. The first-run card: present only while no live session exists, and in
 *      `secrets` mode it says untrusted content is NOT masked.
 *   6. The Rules page's built-in protections follow the running mode: the
 *      masking sentence only where masking is on (§4.25z).
 *   7. Settings › About Mandu: the release and three https help links
 *      (§4.25 *About Mandu*).
 *
 * docs-lane-exempt: docs/usage.md is only a path in About Mandu's expected
 * URLs; this file reads no doc.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { ANSWERED_PAGE, ANSWERED_PAGE_MAX, aboutUpdate, agentNotice, agentNoticeParts, answeredPage, buildHomeViewModel, homeAbout, isAgentSession, askedBy, buildFirstRun, builtInProtections, describeAsk, agentName, oneLine, promptLabel, POLICY_FILE_WORDS, secretsPostureNote, type HomeInput } from "../../../src/view-model/home.js";
import { deriveHealth, SECRETS_FIX, SECRETS_PARTIAL_NOTE, SECRETS_SENTENCE, type SessionHealth } from "../../../src/session-health.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { manduPath } from "../../../src/generated/mandu-paths.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import type { SessionRef } from "../../../src/event-source/contract.js";
import type { SessionFlowStats } from "../../../src/view-model/lineage.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import { buildStory, pageSecrets, storyCounts, untrustedMasked } from "../../../src/view-model/agent-page.js";
import { firstSessionEvents, FIRST_SESSION } from "./first-session-fixture.js";
import { DOCS_BASE_URL } from "../../../src/release-version.js";
import { ISSUES_URL } from "../../../src/agent-versions.js";
import type { UpdateCache } from "../../../src/update-notice.js";

const PUB = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "public");

const NOW = Date.parse("2026-09-25T12:00:00Z");
const BARE: PolicySnapshot = { specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__" };

function snapshot(over: { integrity?: boolean; confidentiality?: boolean; verdicts?: VerdictEntry[] } = {}): PolicySnapshot {
  return {
    ...BARE,
    posture: { integrity: over.integrity ?? true, confidentiality: over.confidentiality ?? true },
    usage: { rules: [], sensitivePaths: [] },
    verdicts: over.verdicts ?? [],
  } as PolicySnapshot;
}
function verdict(over: Partial<VerdictEntry>): VerdictEntry {
  return {
    id: "egr-1", symbol: "$MDU:Read[aaaa].content", destination: "evil.example",
    status: "pending", reason: "r", count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000,
    sessions: ["s-claude"],
    ...over,
  } as VerdictEntry;
}
function session(over: Partial<SessionRef> & { id: string }): SessionRef {
  return {
    label: "Summarize notes.md", eventCount: 12,
    firstTs: new Date(NOW - 30 * 60_000).toISOString(), lastTs: new Date(NOW - 60_000).toISOString(),
    violated: false, agent: "claude", status: "running",
    ...over,
  };
}
const stats = (over: Partial<SessionFlowStats> = {}): SessionFlowStats => ({
  flows: 0, secret: 0, complete: 0, egressAllowed: 0, egressBlocked: 0, egressPending: 0, ...over,
});
function input(over: Partial<HomeInput> = {}): HomeInput {
  return {
    sessions: [session({ id: "s-claude" })],
    facts: new Map([["s-claude", { stats: stats({ flows: 3 }), blocked: 0, sent: 0, holds: true, violations: 0, cwd: "/home/u/project" }]]),
    panel: toPolicyPanelViewModel(snapshot()),
    configuredMode: "full",
    nowMs: NOW,
    windowHours: 24,
    historyTotal: 7,
    ...over,
  };
}

// ── 1. The verdict ladder ─────────────────────────────────────────────────────

test("no arbiter → unknown: nothing is claimed, the inbox is unknown too", () => {
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(null) }));
  assert.equal(vm.verdict, "unknown");
  assert.equal(vm.protection.level, "unknown");
  assert.equal(vm.protection.connected, false);
  assert.equal(vm.waitingKnown, false);
  assert.deepEqual(vm.waiting, []);
  assert.match(vm.headline, /Not connected/);
  // Its next step is a link to Settings (§4.25, *The hero links where it points*).
  assert.equal(vm.sentence, "The protection service is not reachable, so nothing can be checked. Start an agent with Mandu, or open Settings.");
  assert.deepEqual(vm.sentenceParts.filter((p) => p.kind === "link"), [{ kind: "link", text: "open Settings", to: "settings" }]);
});

test("nothing of Mandu's runs (§4.25, *Protection is off when nothing runs*): protection is off, said plainly with the command that starts it; never Not connected, never protected", () => {
  // The scan-only person: no arbiter, no session, Mandu never ran.
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(null), sessions: [], facts: new Map(), historyTotal: 0, configuredMode: "secrets", notRunning: { everRan: false } }));
  assert.equal(vm.verdict, "off");
  assert.equal(vm.headline, "Protection is off: no agent runs with Mandu.");
  assert.equal(vm.sentence, "Your agents send what they read to the AI as it is, secrets included. To protect one, start it with mandu claude (or mandu codex).");
  assert.deepEqual(vm.sentenceParts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu claude", "mandu codex"], "the commands drawn as code");
  assert.deepEqual(vm.protection, { level: "unknown", configured: "secrets", connected: false, notRunning: true }, "the level stays unknown: nothing answered");
  assert.equal(vm.waitingKnown, false);
  assert.deepEqual(vm.agents, []);
  // Never ran: the setup card says Mandu starts with the first agent.
  assert.match(vm.firstRun?.protects ?? "", /^Mandu starts with your first agent, in the Secrets mode\./);
  for (const words of [vm.headline, vm.sentence]) {
    assert.doesNotMatch(words, FORBIDDEN);
    assert.doesNotMatch(words, /Not connected|protected\.|are guarded/);
  }
  // Mandu ran here before (a session on record) and was stopped: the same
  // hero, and no setup card.
  const stopped = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(null), sessions: [], facts: new Map(), historyTotal: 0, notRunning: { everRan: true } }));
  assert.equal(stopped.headline, "Protection is off: no agent runs with Mandu.");
  assert.equal(stopped.firstRun, null);
  // An arbiter that answers decides, whatever the route passed: a stale
  // "not running" never hides what runs.
  const up = buildHomeViewModel(input({ notRunning: { everRan: true } }));
  assert.notEqual(up.verdict, "off");
  assert.equal(up.protection.notRunning, undefined);
  // Not known to be not running (the route found something of Mandu's, or
  // asked nothing): the fault it is, "Not connected.".
  for (const notRunning of [null, undefined]) {
    const fault = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(null), ...(notRunning === null ? { notRunning } : {}) }));
    assert.equal(fault.verdict, "unknown");
    assert.equal(fault.headline, "Not connected.");
    assert.equal(fault.protection.notRunning, undefined);
  }
});

test("a violation in the window wins over everything, including pending asks", () => {
  const vm = buildHomeViewModel(input({
    facts: new Map([["s-claude", { stats: stats({ flows: 3 }), blocked: 0, sent: 0, holds: false, violations: 2, cwd: null }]]),
    panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({})] })),
  }));
  assert.equal(vm.verdict, "failed");
  assert.match(vm.headline, /Protection failed/);
  assert.match(vm.sentence, /2 items reached the AI unmasked/);
  assert.equal(vm.waiting.length, 1, "the ask is still listed");
  assert.equal(vm.agents[0]!.holds, false);
  // "Open the detailed trace" opens the one failed session's trace.
  assert.equal(vm.sentence, "2 items reached the AI unmasked in the last 24 hours. Open the detailed trace to see which.");
  assert.deepEqual(vm.sentenceParts, [
    { kind: "text", text: "2 items reached the AI unmasked in the last 24 hours. " },
    { kind: "link", text: "Open the detailed trace", to: "trace", session: "s-claude" },
    { kind: "text", text: " to see which." },
  ]);
});

test("failed in two sessions: the trace link opens the trace's session list, not one of them", () => {
  const failed = (n: number) => ({ stats: stats({ flows: 1 }), blocked: 0, sent: 0, holds: false, violations: n, cwd: null });
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s-claude" }), session({ id: "s-codex", agent: "codex" }), session({ id: "s-fine" })],
    facts: new Map([["s-claude", failed(1)], ["s-codex", failed(2)], ["s-fine", { ...failed(0), holds: true }]]),
  }));
  assert.equal(vm.verdict, "failed");
  assert.equal(vm.sentence, "3 items reached the AI unmasked in the last 24 hours. Open the detailed trace to see which.");
  assert.deepEqual(vm.sentenceParts.filter((p) => p.kind === "link"), [{ kind: "link", text: "Open the detailed trace", to: "trace", session: null }]);
});

test("both axes off → off, before any pending ask", () => {
  const vm = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: false, verdicts: [verdict({})] })),
  }));
  assert.equal(vm.verdict, "off");
  assert.equal(vm.protection.level, "off");
  // The switch is in Settings (since 2026-10-05), and the words link there.
  // Until 2026-10-08 they said "Turn it back on under Rules.": Rules has no
  // switch (§4.25, *The hero links where it points*).
  assert.equal(vm.sentence, "The AI can read untrusted content as-is, and your secrets are not guarded. Turn it back on in Settings.");
  assert.deepEqual(vm.sentenceParts, [
    { kind: "text", text: "The AI can read untrusted content as-is, and your secrets are not guarded. " },
    { kind: "link", text: "Turn it back on in Settings", to: "settings" },
    { kind: "text", text: "." },
  ]);
  assert.doesNotMatch(vm.sentence, /Rules/);
});

test("pending asks → waiting, with the count in the headline", () => {
  const vm = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({}), verdict({ id: "egr-2", destination: "b.example" })] })),
  }));
  assert.equal(vm.verdict, "waiting");
  assert.equal(vm.headline, "2 questions are waiting for you.");
  assert.equal(vm.sentence, "Protection is holding while you decide: what each one asks for happens only if you allow it.");
  assert.equal(vm.window.waiting, 2);
  assert.equal(vm.agents[0]!.state, "waiting");
  assert.equal(vm.agents[0]!.waiting, 2);
});

// The waiting sentence claims only what holds for every ask (2026-10-07). It
// said "Nothing leaves your machine until you answer.", but a rule sends a
// secret to its own host meanwhile (a "may be sent to" host, an Always-allow,
// a locked row), most asks are not sends (a program's read, a write, a
// command), and at Secrets it replaced the level's "not masked" sentence.
test("waiting: what is asked happens only if you allow it; never 'nothing leaves'; Secrets keeps its disclosure", () => {
  const one = (o: { integrity: boolean; confidentiality: boolean }) => buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ ...o, verdicts: [verdict({})] })),
  }));
  const secrets = one({ integrity: false, confidentiality: true });
  assert.equal(secrets.verdict, "waiting");
  assert.equal(secrets.protection.level, "secrets");
  assert.equal(secrets.headline, "One question is waiting for you.");
  assert.equal(secrets.sentence,
    "Protection is holding while you decide: what it asks for happens only if you allow it. Untrusted content is not masked in this mode.");
  // The frozen masking levels mask untrusted content: no disclosure, one claim.
  for (const [o, level] of [[{ integrity: true, confidentiality: true }, "full"], [{ integrity: true, confidentiality: false }, "injection"]] as const) {
    const vm = one(o);
    assert.equal(vm.protection.level, level);
    assert.equal(vm.sentence, "Protection is holding while you decide: what it asks for happens only if you allow it.", level);
  }
  // Each family of ask, at each level: no blanket claim about what leaves.
  const families: Partial<VerdictEntry>[] = [
    {}, // a send
    { id: "egr-p", symbol: "prompt:card number#1", destination: "model" }, // a held message
    { id: "egr-r", symbol: "open:/usr/bin/cat#ab12", destination: "/home/u/project/.env" }, // a program's read
    { id: "egr-w", symbol: "write:/usr/bin/bash#cd34", destination: "/home/u/.bashrc" }, // a file that runs later
  ];
  for (const o of [{ integrity: false, confidentiality: true }, { integrity: true, confidentiality: true }]) {
    const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ ...o, verdicts: families.map((f) => verdict(f)) })) }));
    assert.equal(vm.verdict, "waiting");
    assert.equal(vm.headline, "4 questions are waiting for you.");
    assert.doesNotMatch(vm.sentence, /[Nn]othing leaves|leaves? your machine|until you answer|cannot leave|without your OK/);
    assert.match(vm.sentence, /what each one asks for happens only if you allow it\./);
  }
});

// The hero counts what the Approvals badge counts: questions AND rule changes
// waiting (2026-10-18). Until then a rule change alone left the hero green,
// "Your secrets are guarded.", over "Approvals waiting (1)".
test("rule changes waiting count in the hero, as the badge counts them: alone, with questions, plural (Secrets and the frozen Full, stated)", () => {
  const SECRETS = { integrity: false, confidentiality: true };
  const FULL = { integrity: true, confidentiality: true };
  const vm = (o: { integrity: boolean; confidentiality: boolean }, asks: number, changes: number | undefined) => buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ ...o, verdicts: Array.from({ length: asks }, (_, i) => verdict({ id: `egr-${i}`, destination: `h${i}.example` })) })),
    ...(changes !== undefined ? { proposalsWaiting: changes } : {}),
  }));
  const DISCLOSE = " Untrusted content is not masked in this mode.";
  const ASKS1 = "Protection is holding while you decide: what it asks for happens only if you allow it.";
  const ASKS2 = "Protection is holding while you decide: what each one asks for happens only if you allow it.";
  const RULES = "Your rules stay as they are until you answer.";
  const cases: Array<[number, number, string, string]> = [
    [1, 0, "One question is waiting for you.", ASKS1],
    [2, 0, "2 questions are waiting for you.", ASKS2],
    [0, 1, "A rule change is waiting for you.", RULES],
    [0, 2, "2 rule changes are waiting for you.", RULES],
    [1, 1, "One question and one rule change are waiting for you.", ASKS1],
    [2, 1, "2 questions and 1 rule change are waiting for you.", ASKS2],
    [1, 3, "1 question and 3 rule changes are waiting for you.", ASKS1],
    [2, 2, "2 questions and 2 rule changes are waiting for you.", ASKS2],
  ];
  for (const [o, level, tail] of [[SECRETS, "secrets", DISCLOSE], [FULL, "full", ""]] as const) {
    for (const [asks, changes, headline, sentence] of cases) {
      const h = vm(o, asks, changes);
      const at = `${level}, ${asks} questions, ${changes} rule changes`;
      assert.equal(h.protection.level, level, at);
      assert.equal(h.verdict, "waiting", at);
      assert.equal(h.headline, headline, at);
      assert.equal(h.sentence, sentence + tail, at);
      assert.equal(h.ruleChangesWaiting, changes, at);
      assert.equal(h.window.waiting, asks, `${at}: the window's count stays the questions'`);
      assert.doesNotMatch(h.sentence, /[Nn]othing leaves|leaves? your machine|cannot leave/, at);
    }
    // No rule change, or none read: today's hero.
    for (const changes of [0, undefined]) {
      const none = vm(o, 0, changes);
      assert.equal(none.verdict, level === "secrets" ? "secrets-only" : "protected", `${level}: nothing waiting`);
      assert.equal(none.ruleChangesWaiting, 0);
      assert.equal(vm(o, 1, changes).headline, "One question is waiting for you.");
    }
  }
  // A count that is not one is none.
  for (const bad of [Number.NaN, -1]) assert.equal(vm(SECRETS, 0, bad).verdict, "secrets-only", String(bad));
});

test("rule changes waiting never hide a failure, protection off or no connection: the ladder's order holds", () => {
  const failed = buildHomeViewModel(input({
    facts: new Map([["s-claude", { stats: stats({ flows: 3 }), blocked: 0, sent: 0, holds: false, violations: 1, cwd: null }]]),
    proposalsWaiting: 2,
  }));
  assert.equal(failed.verdict, "failed");
  assert.equal(failed.headline, "Protection failed.");
  assert.equal(failed.ruleChangesWaiting, 2, "the page's waiting fact counts them under a failure");
  const off = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: false })), proposalsWaiting: 1 }));
  assert.equal(off.verdict, "off");
  const unknown = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(null), proposalsWaiting: 1 }));
  assert.equal(unknown.verdict, "unknown");
});

test("secrets level → secrets-only: says untrusted content is NOT masked", () => {
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })) }));
  assert.equal(vm.verdict, "secrets-only");
  assert.equal(vm.protection.level, "secrets");
  assert.match(vm.sentence, /Untrusted content is not masked in this mode/);
  // A binding sends a secret's real value to its host, and the session's page
  // shows that send: the sentence never says a secret cannot leave.
  assert.match(vm.sentence, /Keys and secret files leave this computer only where a rule or your OK allows\./);
  assert.doesNotMatch(vm.sentence, /cannot leave/);
});

test("masking on, nothing masked yet → quiet; something masked → protected", () => {
  const quiet = buildHomeViewModel(input({ facts: new Map([["s-claude", { stats: stats(), blocked: 0, sent: 0, holds: true, violations: 0, cwd: null }]]) }));
  assert.equal(quiet.verdict, "quiet");
  assert.match(quiet.sentence, /No untrusted content has reached the AI/);
  const prot = buildHomeViewModel(input());
  assert.equal(prot.verdict, "protected");
  assert.equal(prot.headline, "You are protected.");
  assert.match(prot.sentence, /all 3 untrusted items agents read were masked/);
  assert.match(prot.sentence, /One agent is running under Mandu/);
});

test("the level is read from the RUNNING posture; the configured mode is reported beside it", () => {
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: true, confidentiality: false })), configuredMode: "full" }));
  assert.equal(vm.protection.level, "injection");
  assert.equal(vm.protection.configured, "full");
});

// ── 2. Asks as plain sentences ────────────────────────────────────────────────

function textOf(parts: { text: string }[]): string {
  return parts.map((p) => p.text).join("");
}

test("a network ask names the agent, the item's kind and the destination, never the key", () => {
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({})] })) }));
  const ask = vm.waiting[0]!;
  assert.equal(ask.family, "send");
  assert.equal(textOf(ask.sentence), "Claude Code wants to send text from a file to evil.example");
  assert.deepEqual(ask.sentence[1], { kind: "code", text: "evil.example" });
  assert.doesNotMatch(JSON.stringify(ask), /\$MDU/);
  assert.deepEqual(ask.agents, ["Claude Code"]);
  assert.equal(ask.askedAt, NOW - 60_000);
});

test("an ask raised by an unknown session says 'The agent'", () => {
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({ sessions: ["gone"] })] })) }));
  assert.match(textOf(vm.waiting[0]!.sentence), /^The agent wants to send/);
});

test("describeAsk covers every family with a sentence, a why, what the AI has now and an if-allowed, the AI their subject", () => {
  const base = { id: "x", family: "network", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const cases: { where: string; subject: string; target: string; expect: RegExp; family: string; reason?: string }[] = [
    { where: "network", subject: "$MDU:WebFetch[1234].body", target: "api.example", expect: /send text from a web page to api\.example/, family: "send" },
    { where: "network", subject: "$MDU:nomodel_Bash[1234]", target: "api.example", expect: /send a secret to/, family: "send" },
    { where: "network", subject: "$MDU:anymodel_Read[1234]", target: "api.example", expect: /send a secret to/, family: "send" },
    { where: "network", subject: "$MDU:localmodel_Read[1234]", target: "api.example", expect: /send a secret to/, family: "send" },
    { where: "network", subject: "$MDU:security_scan[1234]", target: "api.example", expect: /send masked text to/, family: "send" },
    { where: "file", subject: "open:cat", target: "/home/u/ws/.env", expect: /^Codex CLI's program cat wants to read a secret file: \.env$/, family: "read" },
    // Plan 13 D8: the row names the binary by path (the hash is not shown), so a copy in the workspace reads as one
    { where: "file", subject: `open:/home/u/ws/psql#${"a".repeat(64)}`, target: "/home/u/.pgpass", expect: /^Codex CLI's program \/home\/u\/ws\/psql wants to read a secret file: \.pgpass$/, family: "read" },
    { where: "file", subject: "fs:Read:r", target: "/home/u/ws/secret.txt", expect: /open a protected file: secret\.txt/, family: "read" },
    // The sensitive-path gate's reason says which kind of file it is (fs-sync.md §1.4.1)
    { where: "file", subject: "fs:Read:read", target: "/home/u/.ssh/id_rsa", reason: "sensitive path (~/.ssh): read by 'Read' requires approval", expect: /^Codex CLI wants to open a secret file: id_rsa$/, family: "read" },
    { where: "file", subject: "fs:Write:write", target: "/etc/hosts", reason: "fail-closed: out-of-workspace write of '/etc/hosts' by 'Write' requires approval", expect: /^Codex CLI wants to change a file outside its work folder: hosts$/, family: "read" },
    // supported-agents.md §2: a tool that sends a local file off the computer (Claude Code's DesignSync)
    { where: "file", subject: "fs:DesignSync:upload", target: "/home/u/ws/.env", reason: "'/home/u/ws/.env' is a secret file (no-model) and no rule lets it go to claude.ai", expect: /^Codex CLI wants to send a file off this computer: \.env$/, family: "send" },
    { where: "file", subject: "write:bash", target: "/home/u/.bashrc", expect: /^Codex CLI's program bash wants to change a file that runs later: \.bashrc$/, family: "other" },
    // The D8 follow-up (write-protection.md §2.1): the change names the binary by path, never the hash
    { where: "file", subject: `write:/tmp/x/vim#${"a".repeat(64)}`, target: "/home/u/.ssh/authorized_keys", expect: /^Codex CLI's program \/tmp\/x\/vim wants to change a file that runs later: authorized_keys$/, family: "other" },
    // An unhashed file whose name ends like a hash keeps its name (the arbiter escaped it with one more '#')
    { where: "file", subject: `write:/w/tool#${"b".repeat(64)}#`, target: "/home/u/.bashrc", expect: new RegExp(`^Codex CLI's program /w/tool#${"b".repeat(64)} wants to change`), family: "other" },
    { where: "exec", subject: "exec-program:evil.example", target: "(stdin)", expect: /run code straight from a download from evil\.example/, family: "run" },
    { where: "exec", subject: "exec-program:evil.example", target: "/tmp/x.sh", expect: /downloaded from evil\.example: x\.sh/, family: "run" },
    { where: "exec", subject: "$MDU:Read[1234]", target: "bash -c …", expect: /run a command that uses masked text/, family: "run" },
    // exec-routing.md §5: an escalation names what the command needs
    { where: "exec", subject: "exec-escalate:network", target: "npm install", expect: /^Codex CLI wants to run a command with network access: npm install$/, family: "run" },
    { where: "exec", subject: "exec-escalate:original-fs", target: "make", expect: /^Codex CLI wants to run a command on your real files: make$/, family: "run" },
    { where: "model context", subject: "$MDU:Read[1234]", target: "", expect: /show the AI text from a file as it is/, family: "show" },
    { where: "?", subject: "weird", target: "", expect: /wants to use masked text/, family: "other" },
    // Plan 15 §7 (phase 3): a held message names its category, never the found text (the row has none)
    { where: "prompt", subject: `prompt:acme.codename#${"a".repeat(32)}`, target: `model:s1#turn:${"b".repeat(32)}`, expect: /^Codex CLI wants to send your message to the AI\. It holds acme\.codename\.$/, family: "prompt" },
  ];
  for (const c of cases) {
    const d = describeAsk({ ...base, where: c.where, subject: c.subject, target: c.target, reason: c.reason ?? "", family: "unknown" } as never, "Codex CLI");
    const at = c.where + " " + c.subject;
    assert.equal(d.family, c.family, at);
    assert.match(textOf(d.sentence), c.expect, at);
    assert.ok(d.why.length > 10 && d.aiNow.length > 10 && d.ifAllowed.length > 10, at);
    // One subject across the card (dashboard.md §4.25u): the AI, never a
    // switch to "The program …" or "The file …" mid-card.
    assert.match(d.aiNow, /^The AI('s)?\b/, at);
    assert.match(d.ifAllowed, /^(The AI('s)?|When the AI)\b/, at);
    assert.doesNotMatch(d.why + d.aiNow + d.ifAllowed, /placeholder|locked file/i, at);
  }
});

test("describeAsk: a program allowed to read a secret file reads it itself; the AI still gets only masked output, never the file", () => {
  const base = { id: "x", family: "filesystem", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const d = describeAsk({ ...base, where: "file", subject: `open:/usr/bin/psql#${"c".repeat(64)}`, target: "/home/u/proj/.env" } as never, "Claude Code");
  assert.equal(d.why, ".env is a secret file, and Mandu keeps secret files from the AI. If you want /usr/bin/psql to read it, click Allow once or Always allow.");
  assert.equal(d.aiNow, "The AI has not seen the real file, and its program /usr/bin/psql has not read it.");
  assert.equal(d.ifAllowed, "The AI's program /usr/bin/psql reads the real file. What it prints still reaches the AI masked.");
  // A false security statement would be "the AI reads it": no line says so.
  for (const line of [d.why, d.aiNow, d.ifAllowed]) assert.doesNotMatch(line, /\bAI (reads|can read|sees|gets) the (real )?file/, line);
  // A send keeps the AI the subject: the request is the AI's, the real value goes to the place.
  const send = describeAsk({ ...base, family: "network", where: "network", subject: "$MDU:nomodel_Env[ab12]", target: "paste.example" } as never, "Claude Code");
  assert.equal(send.ifAllowed, "The AI's next request goes to paste.example with the real secret filled in. Mandu refused this one, so nothing was sent. After you answer, tell the agent to try again.");
  assert.equal(send.aiNow, "The AI has only the masked version. It has never read the real one.");
});

// dashboard.md §4.34 "A send names its secret" (2026-10-07): every send card
// read "wants to send a secret to …", so two keys bound for one host were
// one card twice, and an Always allow did not say what it allowed.
test("describeAsk: a send names its secret (its key or variable, else its file); `~` only with the page's home", () => {
  const base = { id: "x", family: "network", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const ask = (subject: string, origin: string | undefined, home?: string) =>
    describeAsk({ ...base, where: "network", subject, target: "api.stripe.com", ...(origin === undefined ? {} : { origin }) } as never, "Claude Code", home);
  // A key of a registered file (the registry's field row): its name, and the file in the why.
  const key = ask("$MDU:nomodel_Read[9bbd].STRIPE_KEY", "/home/u/mandu-try/.env", "/home/u");
  assert.deepEqual(key.sentence, [
    { kind: "text", text: "Claude Code wants to send your secret " }, { kind: "code", text: "STRIPE_KEY" },
    { kind: "text", text: " to " }, { kind: "code", text: "api.stripe.com" },
  ]);
  assert.equal(key.why, "STRIPE_KEY comes from ~/mandu-try/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
  assert.equal(key.ifAllowed, "The AI's next request goes to api.stripe.com with the real secret filled in. Mandu refused this one, so nothing was sent. After you answer, tell the agent to try again.");
  // The inspector passes no home: the path as recorded.
  assert.match(ask("$MDU:nomodel_Read[9bbd].STRIPE_KEY", "/home/u/mandu-try/.env").why, /^STRIPE_KEY comes from \/home\/u\/mandu-try\/\.env\. /);
  // Another account's home is not `~` (the page's home only).
  assert.match(ask("$MDU:nomodel_Read[9bbd].STRIPE_KEY", "/home/eve/.env", "/home/u").why, /^STRIPE_KEY comes from \/home\/eve\/\.env\. /);
  // The decoded value of a key reads as the key; a dotted key stays whole.
  assert.equal(textOf(ask("$MDU:nomodel_Read[9bbd].NPM_TOKEN.encoded", "/home/u/.npmrc", "/home/u").sentence), "Claude Code wants to send your secret NPM_TOKEN to api.stripe.com");
  assert.equal(textOf(ask("$MDU:localmodel_Read[9bbd].default.aws_secret_access_key", "/home/u/.aws/credentials", "/home/u").sentence),
    "Claude Code wants to send your secret default.aws_secret_access_key to api.stripe.com");
  // An environment variable: its name, from the origin.
  const env = ask("$MDU:nomodel_Env[e5b9].GITHUB_TOKEN", "env:GITHUB_TOKEN", "/home/u");
  assert.equal(textOf(env.sentence), "Claude Code wants to send your secret GITHUB_TOKEN to api.stripe.com");
  assert.equal(env.why, "GITHUB_TOKEN is an environment variable. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
  // A whole secret file: the file.
  const whole = ask("$MDU:anymodel_Read[1131]", "/home/u/mandu-try/deploy/staging.conf", "/home/u");
  assert.deepEqual(whole.sentence, [
    { kind: "text", text: "Claude Code wants to send a secret from " }, { kind: "code", text: "~/mandu-try/deploy/staging.conf" },
    { kind: "text", text: " to " }, { kind: "code", text: "api.stripe.com" },
  ]);
  assert.equal(whole.why, "Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
  // A field that is not a key's name reads as the file: fs-sync's path field,
  // its encoded form, a human edit's piece, a place in a result, an extraction's number.
  for (const field of ["notes.md", "__mdu_field_0061", "notes.md.__mdu_split[0]", "content", "text", "extract_3"]) {
    assert.equal(textOf(ask(`$MDU:nomodel_Read[77aa].${field}`, "/home/u/ws/notes.md", "/home/u").sentence),
      "Claude Code wants to send a secret from ~/ws/notes.md to api.stripe.com", field);
  }
  // Nothing known (no origin, or one that is not a file or a variable): as before.
  for (const origin of [undefined, "https://example.com/x", "cat .env"]) {
    const d = ask("$MDU:nomodel_Read[9bbd].STRIPE_KEY", origin, "/home/u");
    assert.equal(textOf(d.sentence), "Claude Code wants to send a secret to api.stripe.com", String(origin));
    assert.equal(d.why, "Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.", String(origin));
  }
  // Untrusted text is never called a secret, whatever its origin.
  assert.equal(textOf(ask("$MDU:Read[aaaa].content", "/home/u/ws/notes.md", "/home/u").sentence), "Claude Code wants to send text from a file to api.stripe.com");
  // Never the token: no card part carries `$MDU`.
  for (const d of [key, env, whole]) assert.doesNotMatch(JSON.stringify(d), /\$MDU/);
});

test("the home names a waiting and an answered send's secret with its own `~`; its asks carry no origin", () => {
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: [
    verdict({ id: "egr-1", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "api.stripe.com", source: { tool: "Read", origin: "/home/u/proj/.env" } }),
    verdict({ id: "egr-2", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "paste.example", status: "denied", resolvedAt: NOW - 30_000, source: { tool: "Read", origin: "/home/u/proj/.env" } }),
  ] }));
  const vm = buildHomeViewModel(input({ panel, home: "/home/u" }));
  assert.equal(textOf(vm.waiting[0]!.sentence), "Claude Code wants to send your secret STRIPE_KEY to api.stripe.com");
  assert.match(vm.waiting[0]!.why, /^STRIPE_KEY comes from ~\/proj\/\.env\. /);
  assert.equal(textOf(vm.answered[0]!.sentence), "Claude Code wants to send your secret STRIPE_KEY to paste.example");
  assert.ok(!("origin" in vm.waiting[0]!), "the product's ask carries its words, not the row's origin");
  assert.doesNotMatch(JSON.stringify(vm), /\$MDU/);
  // No home given: the path as the arbiter recorded it.
  assert.match(buildHomeViewModel(input({ panel })).waiting[0]!.why, /^STRIPE_KEY comes from \/home\/u\/proj\/\.env\. /);
});

// dashboard.md §4.34 "Read before it was marked" (2026-10-07): a send of a
// secret the AI read as it was before its label said "Mandu masked it, so the
// AI never read it" and "It has never read the real one" (the tour's
// staging.conf, read at 10:41 and labelled at 10:42).
test("describeAsk: an item the AI read before it was masked is never called never read, in a send, a command or a show", () => {
  const base = { id: "x", family: "network", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const TS = "2026-10-05T01:41:29.686Z";
  const ask = (where: string, subject: string, readFirst?: string, origin?: string) =>
    describeAsk({ ...base, where, subject, target: "api.stripe.com", ...(origin === undefined ? {} : { origin }), ...(readFirst === undefined ? {} : { readFirst }) } as never, "Claude Code", "/home/u");
  const READ_FIRST_NOW = "The AI read the real value before it was marked a secret. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself.";
  // A key of a registered file: the name and the file stay; the claim changes.
  const key = ask("network", "$MDU:nomodel_Read[9bbd].STRIPE_KEY", TS, "/home/u/proj/.env");
  assert.equal(textOf(key.sentence), "Claude Code wants to send your secret STRIPE_KEY to api.stripe.com");
  assert.equal(key.why, "STRIPE_KEY comes from ~/proj/.env. Mandu masks it now, but the AI read its real value before it was marked a secret. Sending it would show the real secret to api.stripe.com.");
  assert.equal(key.aiNow, READ_FIRST_NOW);
  assert.equal(key.ifAllowed, "The AI's next request goes to api.stripe.com with the real secret filled in. Mandu refused this one, so nothing was sent. After you answer, tell the agent to try again.");
  // A whole secret file (the tour's staging.conf).
  const whole = ask("network", "$MDU:nomodel_Read[1131]", TS, "/home/u/mandu-try/deploy/staging.conf");
  assert.equal(textOf(whole.sentence), "Claude Code wants to send a secret from ~/mandu-try/deploy/staging.conf to api.stripe.com");
  assert.equal(whole.why, "Mandu masks it now, but the AI read its real value before it was marked a secret. Sending it would show the real secret to api.stripe.com.");
  // Text that is not a secret: "before Mandu masked it", never "marked a secret".
  const text = ask("network", "$MDU:Read[aaaa].content", TS);
  assert.equal(text.why, "Mandu masks it now, but the AI read its real text before Mandu masked it. Sending it would show the real text to api.stripe.com.");
  assert.equal(text.aiNow, "The AI read the real text before Mandu masked it. Since then it gets the masked version, but Mandu does not mask what the AI wrote itself.");
  // A command that uses it, and a request to show it to the AI as-is.
  const cmd = ask("exec", "$MDU:nomodel_Read[1131]", TS);
  assert.equal(cmd.aiNow, READ_FIRST_NOW);
  assert.equal(cmd.why, "The command uses masked text, and Mandu does not put the real text into a command without your OK.");
  const show = ask("model context", "$MDU:nomodel_Read[1131]", TS);
  assert.equal(show.why, "Mandu masks this now, but the AI read it as it was before it was marked a secret.");
  assert.equal(show.aiNow, READ_FIRST_NOW);
  for (const d of [key, whole, text, cmd, show]) assert.doesNotMatch(`${d.why} ${d.aiNow}`, /never|only the masked/, d.why);
  // Nothing known (no time, or an empty one): the words as before.
  for (const rf of [undefined, ""]) {
    const d = ask("network", "$MDU:nomodel_Read[9bbd].STRIPE_KEY", rf, "/home/u/proj/.env");
    assert.equal(d.why, "STRIPE_KEY comes from ~/proj/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.", String(rf));
    assert.equal(d.aiNow, "The AI has only the masked version. It has never read the real one.", String(rf));
    assert.equal(ask("exec", "$MDU:nomodel_Read[1131]", rf).aiNow, "The AI has only the masked text. It has never read the real one.");
    assert.equal(ask("model context", "$MDU:nomodel_Read[1131]", rf).why, "Mandu masked this before the AI read it.");
  }
});

// §4.34 "Read before it was marked", a program's read (2026-10-07): an
// `open:` or `trust:` card said "The AI has not seen the real file" also for a
// file the AI read as it was before its label.
test("describeAsk: a program's request to read a file the AI read before it was marked never says the AI has not seen the file", () => {
  const base = { id: "x", family: "filesystem", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const TS = "2026-10-05T01:41:29.686Z";
  const h = "c".repeat(64);
  const ask = (subject: string, readFirst?: string) =>
    describeAsk({ ...base, where: "file", subject, target: "/home/u/mandu-try/deploy/staging.conf", ...(readFirst === undefined ? {} : { readFirst }) } as never, "Claude Code", "/home/u");
  const open = ask(`open:/usr/bin/cat#${h}`, TS);
  assert.equal(textOf(open.sentence), "Claude Code's program /usr/bin/cat wants to read a secret file: staging.conf");
  assert.equal(open.aiNow, "The AI read the file as it was before it was marked a secret, and its program /usr/bin/cat has not read it. Since then the AI gets the masked version, but Mandu does not mask what the AI wrote itself.");
  // Why it stopped and what Allow does stay true, so they stay.
  assert.equal(open.why, "staging.conf is a secret file, and Mandu keeps secret files from the AI. If you want /usr/bin/cat to read it, click Allow once or Always allow.");
  assert.equal(open.ifAllowed, "The AI's program /usr/bin/cat reads the real file. What it prints still reaches the AI masked.");
  // The warning question about a program Mandu does not know.
  const trust = ask(`trust:/usr/local/bin/deploy#${h}`, TS);
  assert.equal(trust.aiNow, "The AI read the file as it was before it was marked a secret, and its program /usr/local/bin/deploy has not read it. Since then the AI gets the masked version, but Mandu does not mask what the AI wrote itself.");
  assert.match(trust.why, /^Mandu does not know whether \/usr\/local\/bin\/deploy keeps what it reads out of what it prints\./);
  for (const d of [open, trust]) {
    assert.doesNotMatch(d.aiNow, /has not seen|never|only the masked/, d.aiNow);
    assert.ok(!JSON.stringify(d).includes(h), "no hash on the card");
  }
  // Nothing known (no time, or an empty one): the words as before.
  for (const rf of [undefined, ""]) {
    assert.equal(ask(`open:/usr/bin/cat#${h}`, rf).aiNow, "The AI has not seen the real file, and its program /usr/bin/cat has not read it.", String(rf));
    assert.equal(ask(`trust:/usr/local/bin/deploy#${h}`, rf).aiNow, "The AI has not seen the real file, and its program /usr/local/bin/deploy has not read it.", String(rf));
  }
  // A change to a file that runs later is not a read: no time changes it.
  const write = describeAsk({ ...base, where: "file", subject: `write:/usr/bin/bash#${h}`, target: "/home/u/.bashrc", readFirst: TS } as never, "Claude Code", "/home/u");
  assert.equal(write.aiNow, "The AI's program /usr/bin/bash has not changed the file.");
});

test("the home's waiting card says the AI read it first when its row says so; the product's ask carries words, not the time", () => {
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: [
    verdict({ id: "egr-1", symbol: "$MDU:nomodel_Read[1131]", destination: "paste.example", source: { tool: "Read", origin: "/home/u/mandu-try/deploy/staging.conf" } }),
    verdict({ id: "egr-2", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "api.stripe.com", lastSeen: NOW - 90_000, source: { tool: "Read", origin: "/home/u/proj/.env" } }),
  ] }), new Map([["egr-1", "2026-10-05T01:41:29.686Z"]]));
  const vm = buildHomeViewModel(input({ panel, home: "/home/u" }));
  const card = (id: string) => vm.waiting.find((a) => a.id === id)!;
  assert.equal(card("egr-1").why, "Mandu masks it now, but the AI read its real value before it was marked a secret. Sending it would show the real secret to paste.example.");
  assert.match(card("egr-1").aiNow, /^The AI read the real value before it was marked a secret\./);
  // The other row keeps its claim.
  assert.match(card("egr-2").why, /Mandu masked it, so the AI never read it\./);
  assert.ok(!("readFirst" in card("egr-1")), "the product's ask carries its words, not the row's time");
});

test("plan 13 D8 (12): the warning question about a program Mandu does not know says plainly that it may pass on what it reads; the AI still never reads the file", () => {
  const base = { id: "x", family: "filesystem", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const h = "c".repeat(64);
  const d = describeAsk({ ...base, where: "file", subject: `trust:/usr/local/bin/deploy#${h}`, target: "/home/u/proj/.env" } as never, "Claude Code");
  assert.equal(d.family, "read");
  assert.deepEqual(d.sentence.map((p) => p.text).join(""), "Claude Code's program /usr/local/bin/deploy wants to read a secret file: .env");
  assert.equal(d.why, "Mandu does not know whether /usr/local/bin/deploy keeps what it reads out of what it prints. If you allow it, the AI's other programs may be able to read the file through it. Allow it only if you know /usr/local/bin/deploy does not show or pass on what it reads.");
  assert.match(d.ifAllowed, /^The AI's program \/usr\/local\/bin\/deploy reads the real file\. What it prints still reaches the AI masked/);
  for (const line of [d.why, d.aiNow, d.ifAllowed]) {
    assert.doesNotMatch(line, /\bAI (reads|can read|sees|gets) the (real )?file/, line);
    assert.ok(!line.includes(h), "the hash never shows");
    assert.doesNotMatch(line, /vetted|trust:|prints: nothing/, "product words, not the law's");
  }
});

test("plan 13 §8 decision (c): the card names the script an interpreter runs, or that it runs code no pin names (this change only); the hash never shows", async () => {
  const { programOfSubject } = await import("../../../src/view-model/home.js");
  const base = { id: "x", family: "filesystem", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const h = "c".repeat(64);
  const open = describeAsk({ ...base, where: "file", subject: `open:/usr/bin/python3.12#${h}#script:%2Fopt%2Ftools%2Freport.py#${h}`, target: "/home/u/.pgpass" } as never, "Claude Code");
  assert.equal(textOf(open.sentence), "Claude Code's program /usr/bin/python3.12 running /opt/tools/report.py wants to read a secret file: .pgpass");
  assert.match(open.ifAllowed, /^The AI's program \/usr\/bin\/python3\.12 running \/opt\/tools\/report\.py reads the real file/);
  const run = describeAsk({ ...base, where: "file", subject: `write:/usr/bin/bash#${h}#run:123-456`, target: "/home/u/.bashrc" } as never, "Claude Code");
  assert.equal(textOf(run.sentence), "Claude Code's program /usr/bin/bash running its own code wants to change a file that runs later: .bashrc");
  assert.match(run.why, /your answer covers this change only/);
  for (const d of [open, run]) assert.ok(!JSON.stringify(d).includes(h), "no hash on the card");
  assert.deepEqual(programOfSubject(`/usr/bin/psql#${h}`), { binary: "/usr/bin/psql" });
  assert.deepEqual(programOfSubject(`/opt/x %231#${h}#script:%2Fopt%2Fx%20%231%2Fs.js#${h}`), { binary: "/opt/x %231", script: "/opt/x #1/s.js" });
});

test("§4.34 `~` is the dashboard's home: the product's card names a program and its script under it `~/…`; another account's home and the inspector's words keep the path", () => {
  const h = "c".repeat(64);
  const node = `/home/u/.nvm/versions/node/v22.11.0/bin/node#${h}#script:%2Fhome%2Fu%2Fproj%2Fx.js#${h}`;
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: [
    verdict({ id: "egr-1", symbol: `open:${node}`, destination: "/home/u/proj/.env", reason: "held for the human" }),
    verdict({ id: "egr-2", symbol: `trust:/home/u/bin/pg#${h}`, destination: "/home/u/.pgpass", reason: "held for the human", lastSeen: NOW - 70_000 }),
    verdict({ id: "egr-3", symbol: `write:/home/alice/bin/tool#${h}`, destination: "/home/u/.bashrc", reason: "held for the human", lastSeen: NOW - 80_000 }),
    verdict({ id: "egr-4", symbol: `open:/home/user/bin/cat#${h}`, destination: "/home/u/.env", reason: "held for the human", lastSeen: NOW - 90_000 }),
  ] }));
  const vm = buildHomeViewModel(input({ panel, home: "/home/u" }));
  const card = (id: string) => vm.waiting.find((a) => a.id === id)!;
  assert.equal(textOf(card("egr-1").sentence), "Claude Code's program ~/.nvm/versions/node/v22.11.0/bin/node running ~/proj/x.js wants to read a secret file: .env");
  assert.equal(card("egr-1").ifAllowed, "The AI's program ~/.nvm/versions/node/v22.11.0/bin/node running ~/proj/x.js stopped waiting and could not read the file. If you allow it, it reads the real file the next time the AI runs it. After you answer, tell the agent to try again. What it prints still reaches the AI masked.", "asked a minute ago: the guard stopped holding it");
  assert.match(card("egr-1").aiNow, /its program ~\/\.nvm\/versions\/node\/v22\.11\.0\/bin\/node running ~\/proj\/x\.js has not read it/);
  assert.equal(textOf(card("egr-2").sentence), "Claude Code's program ~/bin/pg wants to read a secret file: .pgpass");
  assert.match(card("egr-2").why, /whether ~\/bin\/pg keeps what it reads/);
  assert.equal(textOf(card("egr-3").sentence), "Claude Code's program /home/alice/bin/tool wants to change a file that runs later: .bashrc", "another account's home folder is never `~`");
  assert.equal(textOf(card("egr-4").sentence), "Claude Code's program /home/user/bin/cat wants to read a secret file: .env", "a folder that only starts like the home is another folder");
  for (const a of vm.waiting) assert.ok(!JSON.stringify(a).includes(h), "no hash on the card");
  // The inspector's card (the panel's own words, no home) keeps full paths.
  const inspector = panel.queue.find((q) => q.id === "egr-1")!;
  assert.equal(textOf(inspector.words!.sentence), "The agent's program /home/u/.nvm/versions/node/v22.11.0/bin/node running /home/u/proj/x.js wants to read a secret file: .env");
  // A macOS home folder is `~` too.
  assert.equal(textOf(describeAsk({ where: "file", subject: `open:/Users/u/bin/pg#${h}`, target: "/Users/u/.pgpass", reason: "" } as never, "Claude Code", "/Users/u").sentence), "Claude Code's program ~/bin/pg wants to read a secret file: .pgpass");
});

test("answered rows: blocked / always allowed / once (unused vs spent), newest decision first, capped", () => {
  const vs = [
    verdict({ id: "a", status: "denied", resolvedAt: NOW - 5_000 }),
    verdict({ id: "b", status: "approved", resolvedAt: NOW - 1_000 }),
    verdict({ id: "c", status: "approved", scope: "once", resolvedAt: NOW - 3_000 }),
    verdict({ id: "d", status: "approved", scope: "once", consumedAt: NOW - 2_000, resolvedAt: NOW - 4_000 }),
    verdict({ id: "e" }),
  ];
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ verdicts: vs })) }));
  assert.deepEqual(vm.answered.map((a) => a.id), ["b", "c", "d", "a"]);
  assert.deepEqual(vm.answered.map((a) => a.outcome), ["allowed", "allowed-once", "allowed-once-used", "blocked"]);
  assert.equal(vm.waiting.length, 1);
});

test("answeredPage (§4.25 *Past the newest 20*): newest decision first, a page after `after`, ties in the queue's order, `total` and `next`; Home's first page is its first", () => {
  // 63 answers, two with no decision time (by when they were last asked),
  // and a tie at the boundary of the first page (rows t0 and t1).
  const vs: VerdictEntry[] = [];
  for (let i = 0; i < 61; i++) vs.push(verdict({ id: `r${String(i).padStart(2, "0")}`, status: i % 2 ? "approved" : "denied", resolvedAt: NOW - (i + 1) * 1_000 }));
  vs.splice(30, 0, verdict({ id: "t0", status: "denied", resolvedAt: NOW - 20_000 }), verdict({ id: "t1", status: "denied", resolvedAt: NOW - 20_000 }));
  vs.push(verdict({ id: "w", lastSeen: NOW }));
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: vs }));
  const order = panel.queue.map((q) => q.id);
  const inp = input({ panel });
  // The agents as Home names them (askedBy reads the sessions on record).
  const byId = new Map(inp.sessions.map((x) => [x.id, x]));
  const all = answeredPage(panel.queue, byId, undefined, null, ANSWERED_PAGE_MAX);
  assert.equal(all.total, 63, "every answer, the waiting one left out");
  assert.equal(all.rows.length, 63);
  assert.equal(all.next, null, "nothing after the last");
  const times = all.rows.map((a) => a.decidedAt!);
  assert.deepEqual(times, [...times].sort((a, b) => b - a), "newest decision first");
  // The tie keeps the queue's order wherever a page is cut.
  const tie = all.rows.findIndex((a) => a.id === "t0");
  assert.equal(all.rows[tie + 1]!.id, "t1");
  const first = answeredPage(panel.queue, byId, undefined, null, ANSWERED_PAGE);
  assert.equal(first.rows.length, 20);
  assert.equal(first.next, first.rows[19]!.id, "the cursor is the last row's id");
  assert.equal(first.total, 63);
  // Page after page from the cursor: the whole list, once each, in order.
  const paged = [...first.rows];
  let next: string | null = first.next;
  while (next) {
    const p = answeredPage(panel.queue, byId, undefined, next, ANSWERED_PAGE);
    paged.push(...p.rows);
    next = p.next;
  }
  assert.deepEqual(paged.map((a) => a.id), all.rows.map((a) => a.id), "no row twice, none skipped");
  // A cursor at the tie's first row goes on with the second.
  assert.equal(answeredPage(panel.queue, byId, undefined, "t0", 1).rows[0]!.id, "t1");
  // A cursor no longer answered: from the top, as History's.
  assert.deepEqual(answeredPage(panel.queue, byId, undefined, "gone", 2).rows.map((a) => a.id), all.rows.slice(0, 2).map((a) => a.id));
  // A limit out of range is brought into it.
  assert.equal(answeredPage(panel.queue, byId, undefined, null, 0).rows.length, 1);
  assert.equal(answeredPage(panel.queue, byId, undefined, null, Number.NaN).rows.length, ANSWERED_PAGE);
  assert.equal(answeredPage(panel.queue, byId, undefined, null, 10_000).rows.length, 63);
  // Home's list is exactly the first page, and says how many there are.
  const vm = buildHomeViewModel(inp);
  assert.deepEqual(vm.answered, first.rows);
  assert.equal(vm.answeredTotal, 63);
  // The queue as read is left in its order.
  assert.deepEqual(panel.queue.map((q) => q.id), order);
});

test("Home counts no answer while the queue is not known", () => {
  const vm = buildHomeViewModel(input({ panel: { ...toPolicyPanelViewModel(snapshot({ verdicts: [verdict({ id: "a", status: "denied", resolvedAt: NOW })] })), verdictsKnown: false } }));
  assert.deepEqual(vm.answered, []);
  assert.equal(vm.answeredTotal, 0);
});

test("an answered row keeps the sessions that raised it, most recent last, for its link to where it was asked (§4.25h)", () => {
  // Until 2026-10-08 the row dropped them, so Approvals' Answered earlier
  // could not link the moment its waiting card linked.
  const vs = [
    verdict({ id: "a", status: "approved", scope: "once", resolvedAt: NOW - 1_000, sessions: ["s-claude", "s-codex"] }),
    verdict({ id: "b", status: "denied", resolvedAt: NOW - 2_000, sessions: [] }),
  ];
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ verdicts: vs })) }));
  assert.deepEqual(vm.answered.map((a) => [a.id, a.sessions]), [["a", ["s-claude", "s-codex"]], ["b", []]]);
  // The waiting card's list, the same shape.
  const pending = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({ sessions: ["s-claude", "s-codex"] })] })) }));
  assert.deepEqual(pending.waiting[0]!.sessions, vm.answered[0]!.sessions);
});

// ── 3. Windows, agents, counts ────────────────────────────────────────────────

test("counts cover only sessions inside the window; older sessions still count toward history", () => {
  const old = session({ id: "s-old", lastTs: new Date(NOW - 30 * 3_600_000).toISOString(), status: undefined });
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s-claude" }), old],
    facts: new Map([
      ["s-claude", { stats: stats({ flows: 3, egressBlocked: 1, egressAllowed: 2, secret: 1 }), secrets: { masked: 1, early: 0 }, untrusted: 2, blocked: 2, sent: 3, holds: true, violations: 0, cwd: null }],
      ["s-old", { stats: stats({ flows: 50 }), secrets: { masked: 20, early: 4 }, untrusted: 30, blocked: 9, sent: 9, holds: true, violations: 0, cwd: null }],
    ]),
    historyTotal: 2,
  }));
  assert.deepEqual(vm.window, { hours: 24, sessions: 1, counted: 1, masked: 3, secretsMasked: 1, secretsEarly: 0, untrusted: 2, blocked: 2, sent: 3, waiting: 0,
    only: { secretsMasked: "s-claude", secretsEarly: null, blocked: "s-claude", sent: "s-claude" } });
  assert.equal(vm.agents.length, 1);
  assert.equal(vm.history.total, 2);
});

test("the window says how many of its sessions the counts add up: those with facts, never one outside it (§4.25, a busy day)", () => {
  const fact = (blocked: number) => ({ stats: stats({ flows: 1 }), secrets: { masked: 1, early: 0 }, blocked, sent: 0, holds: true, violations: 0, cwd: null });
  // Four in the window, one modeled past the route's cap left out, one older
  // than the window with facts of its own.
  const sessions = [
    session({ id: "s1" }), session({ id: "s2" }), session({ id: "s3" }), session({ id: "s4", status: undefined }),
    session({ id: "s-old", lastTs: new Date(NOW - 30 * 3_600_000).toISOString(), status: undefined }),
  ];
  const vm = buildHomeViewModel(input({
    sessions,
    facts: new Map([["s1", fact(1)], ["s2", fact(2)], ["s3", fact(3)], ["s-old", fact(50)]]),
    historyTotal: 5,
  }));
  assert.equal(vm.window.sessions, 4, "every live session active in the window");
  assert.equal(vm.window.counted, 3, "the ones whose facts the counts add up; s-old is outside the window");
  assert.equal(vm.window.blocked, 6, "a floor: s4 adds nothing");
  assert.equal(vm.window.secretsMasked, 3);
  // Every session counted: the two match, as before.
  const all = buildHomeViewModel(input({ sessions: sessions.slice(0, 3), facts: new Map([["s1", fact(1)], ["s2", fact(2)], ["s3", fact(3)]]) }));
  assert.deepEqual([all.window.sessions, all.window.counted], [3, 3]);
  // None readable: nothing is counted, and nothing is claimed failed (the
  // row keeps the listing's verdict, as below).
  const none = buildHomeViewModel(input({ sessions: sessions.slice(0, 2), facts: new Map() }));
  assert.deepEqual([none.window.sessions, none.window.counted], [2, 0]);
});

test("the window names the one session holding each count, so the hero links to it; null for none, for two, and when only partly counted (§4.25 *The counts link where they point*)", () => {
  const fact = (o: { masked?: number; early?: number; blocked?: number; sent?: number }) => ({ stats: stats({ flows: 1 }), secrets: { masked: o.masked ?? 0, early: o.early ?? 0 }, untrusted: 0, blocked: o.blocked ?? 0, sent: o.sent ?? 0, holds: true, violations: 0, cwd: null });
  // One session holds the block and the early read; two hold masked secrets; none sent.
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s1" }), session({ id: "s2" }), session({ id: "s3" })],
    facts: new Map([["s1", fact({ masked: 1, blocked: 2, early: 1 })], ["s2", fact({ masked: 3 })], ["s3", fact({})]]),
  }));
  assert.deepEqual(vm.window.only, { secretsMasked: null, secretsEarly: "s1", blocked: "s1", sent: null });
  assert.equal(vm.window.blocked, 2, "the counts are as before");
  // A second session's block: no one session holds it any more.
  const two = buildHomeViewModel(input({
    sessions: [session({ id: "s1" }), session({ id: "s2" })],
    facts: new Map([["s1", fact({ blocked: 1 })], ["s2", fact({ blocked: 1, sent: 1 })]]),
  }));
  assert.deepEqual(two.window.only, { secretsMasked: null, secretsEarly: null, blocked: null, sent: "s2" });
  // Partly counted (s2 could not be read): a session left out may hold it too.
  const partly = buildHomeViewModel(input({
    sessions: [session({ id: "s1" }), session({ id: "s2" })],
    facts: new Map([["s1", fact({ blocked: 1, masked: 1 })]]),
  }));
  assert.deepEqual([partly.window.counted, partly.window.sessions], [1, 2]);
  assert.deepEqual(partly.window.only, { secretsMasked: null, secretsEarly: null, blocked: null, sent: null });
  // A session outside the window never holds one.
  const old = buildHomeViewModel(input({
    sessions: [session({ id: "s1" }), session({ id: "s-old", lastTs: new Date(NOW - 30 * 3_600_000).toISOString(), status: undefined })],
    facts: new Map([["s1", fact({ blocked: 1 })], ["s-old", fact({ blocked: 4 })]]),
  }));
  assert.equal(old.window.only.blocked, "s1");
});

test("a row counts its secrets as its page's tiles do, and the window adds them up; never the lineage's masked tokens (§4.25)", () => {
  // The tour: three masked tokens, two secrets, one of them read before it
  // was marked. A frozen-level session masks two untrusted items too.
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s-claude" }), session({ id: "s-codex", agent: "codex" }), session({ id: "s-unread" })],
    facts: new Map([
      ["s-claude", { stats: stats({ flows: 3, secret: 3 }), secrets: { masked: 1, early: 1 }, untrusted: 0, blocked: 1, sent: 1, holds: true, violations: 0, cwd: null }],
      ["s-codex", { stats: stats({ flows: 4, secret: 1 }), secrets: { masked: 1, early: 0 }, untrusted: 2, blocked: 0, sent: 0, holds: true, violations: 0, cwd: null }],
    ]),
  }));
  const row = (id: string) => vm.agents.find((a) => a.id === id)!;
  assert.deepEqual([row("s-claude").secrets, row("s-claude").untrusted], [{ masked: 1, early: 1 }, 0]);
  assert.deepEqual([row("s-codex").secrets, row("s-codex").untrusted], [{ masked: 1, early: 0 }, 2]);
  // Facts that could not be read claim nothing.
  assert.deepEqual([row("s-unread").secrets, row("s-unread").untrusted], [{ masked: 0, early: 0 }, 0]);
  assert.equal(vm.window.secretsMasked, 2);
  assert.equal(vm.window.secretsEarly, 1);
  assert.equal(vm.window.untrusted, 2);
  assert.equal("secret" in vm.window, false, "the lineage's secret-flow count is not a Home count");
  // Facts from before these fields (absent) claim nothing either.
  const bare = buildHomeViewModel(input({ facts: new Map([["s-claude", { stats: stats({ flows: 3, secret: 3 }), blocked: 0, sent: 0, holds: true, violations: 0, cwd: null }]]) }));
  assert.deepEqual([bare.agents[0]!.secrets, bare.agents[0]!.untrusted, bare.window.secretsMasked, bare.window.secretsEarly, bare.window.untrusted], [{ masked: 0, early: 0 }, 0, 0, 0, 0]);
});

test("a row's blocked count is its page's (the story's blocked steps), never the lineage's items-blocked count (§4.25)", () => {
  // The lineage says one item's worst outcome was a block (an exec gate
  // counts there too); the page's story blocked a command and a file.
  const vm = buildHomeViewModel(input({
    facts: new Map([["s-claude", { stats: stats({ flows: 1, secret: 1, egressBlocked: 1 }), blocked: 2, sent: 0, holds: true, violations: 0, cwd: null }]]),
  }));
  assert.equal(vm.agents[0]!.blocked, 2);
  assert.equal(vm.window.blocked, 2);
  assert.equal(vm.window.sent, 0);
  // A session whose facts could not be read claims no block.
  const unread = buildHomeViewModel(input({ facts: new Map() }));
  assert.equal(unread.agents[0]!.blocked, 0);
  assert.equal(unread.window.blocked, 0);
});

test("a row carries its sends with a real value filled in, its page's tile, and the window adds them up (§4.25)", () => {
  // The tour: one request left with STRIPE_KEY filled in; a second session
  // sent two. A row that hid them read as if Mandu only masked and blocked.
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s-claude" }), session({ id: "s-codex", agent: "codex" }), session({ id: "s-unread" })],
    facts: new Map([
      ["s-claude", { stats: stats({ flows: 3, secret: 3 }), secrets: { masked: 1, early: 1 }, blocked: 1, sent: 1, holds: true, violations: 0, cwd: null }],
      ["s-codex", { stats: stats({ flows: 2, secret: 2 }), secrets: { masked: 2, early: 0 }, blocked: 0, sent: 2, holds: true, violations: 0, cwd: null }],
    ]),
  }));
  const row = (id: string) => vm.agents.find((a) => a.id === id)!;
  assert.equal(row("s-claude").sent, 1);
  assert.equal(row("s-codex").sent, 2);
  // A session whose facts could not be read claims no send.
  assert.equal(row("s-unread").sent, 0);
  assert.equal(vm.window.sent, 3, "the hero's sum is the rows' sum");
});

test("an agent row carries the plain name, a one-line title, the cwd and its own stats", () => {
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s-codex", agent: "codex", label: "  fix   the\nfailing test  " + "x".repeat(100), status: undefined })],
    facts: new Map([["s-codex", { stats: stats({ flows: 4 }), blocked: 0, sent: 0, holds: true, violations: 0, cwd: "/home/u/ws" }]]),
  }));
  const a = vm.agents[0]!;
  assert.equal(a.agent, "Codex CLI");
  assert.equal(a.state, "idle");
  assert.equal(a.cwd, "/home/u/ws");
  assert.equal(a.title!.length, 80);
  assert.match(a.title!, /…$/);
  // A fallback label (the launcher's posture line) is not a title a person reads.
  const posture = buildHomeViewModel(input({
    sessions: [session({ id: "s-claude", label: "claude launch: 7 rung(s) live [exec-wrap]", labelFrom: "posture", status: undefined })],
  }));
  assert.equal(posture.agents[0]!.title, null);
  assert.equal(promptLabel({ label: "fix it", labelFrom: "prompt" }), "fix it");
  assert.equal(promptLabel({ label: "fix it" }), "fix it", "a ref without a source keeps its label");
  assert.equal(promptLabel({ label: "U-LLM inspection of $MDU:x", labelFrom: "inspection" }), null);
  assert.equal(a.stats.flows, 4);
  assert.equal(vm.verdict, "protected");
  assert.match(vm.sentence, /No agent is running right now/);
});

test("a session without facts (unreadable) still lists, with empty stats and the listing's verdict", () => {
  const vm = buildHomeViewModel(input({ facts: new Map(), sessions: [session({ id: "s-claude", violated: true })] }));
  assert.equal(vm.agents[0]!.stats.flows, 0);
  assert.equal(vm.agents[0]!.holds, false);
  assert.equal(vm.verdict, "quiet", "no computed violation → not claimed as failed (the row shows it)");
});

test("helpers: agentName + oneLine", () => {
  assert.equal(agentName("openclaw"), "OpenClaw");
  assert.equal(agentName(undefined), "The agent");
  assert.equal(oneLine("  a  b "), "a b");
  assert.equal(oneLine(""), null);
});

// ── 4. Vocabulary ─────────────────────────────────────────────────────────────

/** Inspector terms that must not appear in end-user copy (the §4.18 sweep,
 *  inherited). `symbol` is allowed only inside identifiers the page never
 *  shows (checked separately below). */
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter)\b|\$MDU:/i;

test("the projection's copy uses the product vocabulary only", () => {
  const panels = [
    toPolicyPanelViewModel(null),
    toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: false })),
    toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })),
    toPolicyPanelViewModel(snapshot({ verdicts: [verdict({}), verdict({ id: "k", status: "denied", resolvedAt: 1 })] })),
  ];
  for (const panel of panels) {
    for (const facts of [new Map(), input().facts, new Map([["s-claude", { stats: stats({ flows: 1 }), blocked: 0, sent: 0, holds: false, violations: 1, cwd: null }]])]) {
      const vm = buildHomeViewModel(input({ panel, facts }));
      const copy = [vm.headline, vm.sentence, ...vm.waiting.flatMap((a) => [textOf(a.sentence), a.why, a.aiNow, a.ifAllowed]), ...vm.answered.map((a) => textOf(a.sentence))].join("\n");
      assert.doesNotMatch(copy, FORBIDDEN, copy);
    }
  }
});

test("in every verdict the hero's sentence is its parts joined, and a link part names a place, never an address", () => {
  const panels = [
    toPolicyPanelViewModel(null),
    toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: false })),
    toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })),
    toPolicyPanelViewModel(snapshot()),
    toPolicyPanelViewModel(snapshot({ verdicts: [verdict({})] })),
  ];
  const seen = new Set<string>();
  for (const panel of panels) {
    for (const facts of [new Map(), input().facts, new Map([["s-claude", { stats: stats({ flows: 1 }), blocked: 0, sent: 0, holds: false, violations: 1, cwd: null }]])]) {
      const vm = buildHomeViewModel(input({ panel, facts }));
      seen.add(vm.verdict);
      assert.ok(vm.sentenceParts.length > 0, vm.verdict);
      assert.equal(vm.sentence, vm.sentenceParts.map((p) => p.text).join(""), vm.verdict);
      const links = vm.sentenceParts.filter((p) => p.kind === "link");
      assert.ok(links.length <= 1, `${vm.verdict}: one place at most`);
      for (const l of links) {
        assert.ok(l.to === "settings" || l.to === "trace", `${vm.verdict}: a known place (${l.to})`);
        assert.doesNotMatch(JSON.stringify(l), /https?:|\/\//, "the page builds the address");
      }
      // Only the three verdicts that send the person somewhere link.
      assert.equal(links.length, ["unknown", "failed", "off"].includes(vm.verdict) ? 1 : 0, vm.verdict);
    }
  }
  assert.deepEqual([...seen].sort(), ["failed", "off", "protected", "quiet", "secrets-only", "unknown", "waiting"], "every verdict was checked");
});

test("plan 15 §12 (2026-10-04): a held message under a locked ask row offers no session answer and says why, in the product's words", () => {
  const subject = `prompt:acme.codename#${"a".repeat(32)}`;
  const target = `model:s-claude#turn:${"b".repeat(32)}`;
  const panel = toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true, verdicts: [
    verdict({ id: "egr-7", symbol: subject, destination: target, onceOnly: true }),
    verdict({ id: "egr-8", symbol: subject, destination: `model:s-claude#turn:${"c".repeat(32)}` }),
  ] }));
  const row = (id: string) => panel.queue.find((r) => r.id === id)!;
  assert.deepEqual(row("egr-7").actions.map((a) => a.promptScope), ["once", "once", "once"], "no session answer under the lock");
  assert.equal(row("egr-7").onceOnly, true);
  assert.match(row("egr-7").words.onlyThisMessage ?? "", /^Your administrator set this to ask every time, so your answer covers this message only\./);
  assert.deepEqual(row("egr-8").actions.map((a) => a.promptScope), ["once", "session", "once", "once"], "an unlocked ask keeps the session answer");
  assert.equal(row("egr-8").words.onlyThisMessage, undefined);
  const vm = buildHomeViewModel(input({ panel }));
  const ask = vm.waiting.find((a) => a.id === "egr-7")!;
  assert.equal(ask.onlyThisMessage, row("egr-7").words.onlyThisMessage);
  assert.equal(vm.waiting.find((a) => a.id === "egr-8")!.onlyThisMessage, undefined);
  assert.doesNotMatch(ask.onlyThisMessage!, FORBIDDEN);
  // An answered row is never marked: the lock speaks only to a waiting hold.
  const done = toPolicyPanelViewModel(snapshot({ verdicts: [verdict({ id: "egr-9", symbol: subject, destination: target, status: "approved", resolvedAt: 1, onceOnly: true })] }));
  assert.equal(done.queue[0]!.onceOnly, undefined);
});

test("the product page and script carry no inspector vocabulary in their copy", () => {
  const html = readFileSync(join(PUB, "index.html"), "utf8");
  // Strip comments (they explain the design in inspector terms on purpose).
  const visible = html.replace(/<!--[\s\S]*?-->/g, "");
  assert.doesNotMatch(visible, FORBIDDEN);
  const js = readFileSync(join(PUB, "js", "home.js"), "utf8");
  // Only string literals are user-visible; identifiers and comments are not.
  const strings = [...js.matchAll(/'((?:[^'\\]|\\.)*)'/g)].map((m) => m[1]!).join("\n");
  // The route paths are the one legitimate use of "egress" (the URL the
  // inspector shares); everything else must be plain.
  const copy = strings.replace(/egress\/approvals\//g, "");
  assert.doesNotMatch(copy, FORBIDDEN, copy);
});

/** Words the product retired (dashboard.md §4.25u): the page is Approvals,
 *  a secret file is not a "locked file", and a masked value is "masked". */
const RETIRED = new RegExp([
  /\bInbox\b/.source, // the page's old name (the "inbox" page key and ids are routing, lower-case)
  /\b[Tt]he inbox\b/.source,
  /\b[Ll]ocked[ -]files?\b/.source,
  /\b[Pp]laceholders?\b(?!\s*:)/.source, // not an <input>'s placeholder attribute
].join("|"));

test("no product string names the Inbox, a locked file or a placeholder", () => {
  const html = readFileSync(join(PUB, "index.html"), "utf8").replace(/<!--[\s\S]*?-->/g, "");
  // Visible text and the attributes a person reads; ids and data-page keys
  // ("inbox") are routing, not copy.
  const visible = html.replace(/<[^>]*>/g, (tag) => [...tag.matchAll(/\b(?:aria-label|title|placeholder)="([^"]*)"/g)].map((m) => m[1]).join(" "));
  assert.doesNotMatch(visible, RETIRED, visible.match(RETIRED)?.[0]);
  const js = readFileSync(join(PUB, "js", "home.js"), "utf8");
  const strings = [...js.matchAll(/'((?:[^'\\]|\\.)*)'/g)].map((m) => m[1]!).filter((s) => !/^[a-z-]+$/.test(s)).join("\n");
  assert.doesNotMatch(strings, RETIRED, strings.match(RETIRED)?.[0]);
  const panels = [toPolicyPanelViewModel(snapshot({ verdicts: [verdict({}), verdict({ id: "k", status: "denied", resolvedAt: 1 })] })), toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true }))];
  for (const panel of panels) {
    const vm = buildHomeViewModel(input({ panel }));
    const copy = [vm.headline, vm.sentence, ...vm.waiting.flatMap((a) => [textOf(a.sentence), a.why, a.aiNow, a.ifAllowed])].join("\n");
    assert.doesNotMatch(copy, RETIRED, copy);
  }
  for (const level of ["secrets", "full", "injection", "off"] as const) assert.doesNotMatch(buildFirstRun(level, level).protects, RETIRED);
});

test("the product page marks itself and loads only its own assets", () => {
  const html = readFileSync(join(PUB, "index.html"), "utf8");
  assert.match(html, /<meta name="mandu-app" content="home">/);
  assert.match(html, /href="app\.css"/);
  assert.match(html, /src="js\/home\.js"/);
  assert.doesNotMatch(html, /dashboard\.css|js\/app\.js/, "the inspector's assets are not the product's");
});

test("an ask raised from a hidden (drill/test) session still names its agent via agentOf", () => {
  const vm = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({ sessions: ["watch-drill-1"] })] })),
    agentOf: new Map([["watch-drill-1", { agent: "codex" }], ["s-claude", { agent: "claude" }]]),
  }));
  assert.match(textOf(vm.waiting[0]!.sentence), /^Codex CLI wants to send/);
  assert.equal(vm.agents.length, 1, "the drill session itself stays off the agent list");
});

test("an ask shared by two sessions names the agent that raised it LAST, waiting and answered (2026-10-05)", () => {
  // One row per (item, destination): a Codex session sent the secret a Claude
  // Code session had sent to the same host; the arbiter appended it last.
  const agentOf = new Map<string, Pick<SessionRef, "agent">>([["s-claude", { agent: "claude" }], ["s-codex", { agent: "codex" }]]);
  const waiting = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({ sessions: ["s-claude", "s-codex"] })] })),
    agentOf,
  }));
  assert.match(textOf(waiting.waiting[0]!.sentence), /^Codex CLI wants to send/);
  assert.deepEqual(waiting.waiting[0]!.agents, ["Claude Code", "Codex CLI"], "who ever raised it stays listed");
  const answered = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ verdicts: [verdict({ sessions: ["s-claude", "s-codex"], status: "approved", resolvedAt: NOW - 1000, scope: "once" } as Partial<VerdictEntry>)] })),
    agentOf,
  }));
  assert.match(textOf(answered.answered[0]!.sentence), /^Codex CLI wants to send/);
  assert.equal(askedBy({ sessions: ["s-codex", "s-claude"] }, agentOf), "Claude Code");
  assert.equal(askedBy({ sessions: [] }, agentOf), "The agent");
});

test("system logs are not agents: the admin log and the network fallbacks are never a row or a count (2026-10-05)", () => {
  // A fresh install, one `mandu claude`: the arbiter's admin audit log and
  // the net-guard's sessionless fallback were listed as two more running
  // agents ("3 agents are running under Mandu").
  const fact = (blocked: number) => ({ stats: stats({ flows: 1, secret: 1 }), blocked, sent: 0, holds: true, violations: 0, cwd: null });
  const vm = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })),
    sessions: [
      session({ id: "s-claude" }),
      session({ id: "net-guard", agent: undefined, label: "Network guard events with no session" }),
      session({ id: "arbiter-admin", agent: undefined, label: "Admin log: approval verdicts and settings changes" }),
      session({ id: "eg_m1abc_x9", agent: undefined }),
    ],
    facts: new Map([["s-claude", fact(0)], ["net-guard", fact(4)], ["arbiter-admin", fact(0)]]),
    historyTotal: 1,
  }));
  assert.deepEqual(vm.agents.map((a) => a.id), ["s-claude"]);
  assert.equal(vm.window.sessions, 1);
  assert.equal(vm.window.masked, 1, "the admin log's echo of an approved item is not a masked item");
  assert.equal(vm.window.blocked, 0, "a system log's events are not an agent's count");
  assert.equal(vm.verdict, "secrets-only");
  assert.match(vm.sentence, /^One agent is running under Mandu\./);
  assert.ok(!vm.agents.some((a) => a.agent === "The agent"));
  assert.equal(isAgentSession({ id: "s-claude" }), true);
  for (const id of ["arbiter-admin", "net-guard", "eg_m1abc_x9"]) assert.equal(isAgentSession({ id }), false, id);
});

test("an agent whose exit was recorded is not running, however recent its last event (2026-10-05)", () => {
  const fact = (exited: boolean) => ({ stats: stats(), blocked: 0, sent: 0, holds: true, violations: 0, cwd: null, exited });
  const vm = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })),
    sessions: [session({ id: "s-new" }), session({ id: "s-old-exited" })],
    facts: new Map([["s-new", fact(false)], ["s-old-exited", fact(true)]]),
  }));
  assert.deepEqual(vm.agents.map((a) => [a.id, a.state]), [["s-new", "running"], ["s-old-exited", "idle"]]);
  assert.match(vm.sentence, /^One agent is running under Mandu\./);
});

test("a session that only read .env: one secret masked before the AI saw it, and no send counted (2026-10-05)", () => {
  // The recorded first session: the reply filter showed STRIPE_KEY on the
  // person's own terminal; nothing left the machine and nothing was blocked.
  const events = firstSessionEvents();
  const vm0 = toSessionViewModel(FIRST_SESSION, events);
  const { blocked, sent } = storyCounts(buildStory(vm0));
  assert.deepEqual({ blocked, sent }, { blocked: 0, sent: 0 });
  // Counted as the route counts it (home-routes.ts HomeFacts).
  const secrets = pageSecrets(vm0, events).counts;
  const untrusted = untrustedMasked(vm0.lineage.stats, vm0.paired.mode);
  const vm = buildHomeViewModel(input({
    panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })),
    sessions: [session({ id: FIRST_SESSION, label: "What is in .env?" })],
    facts: new Map([[FIRST_SESSION, { stats: vm0.lineage.stats, secrets, untrusted, blocked, sent, holds: true, violations: 0, cwd: null }]]),
    historyTotal: 1,
  }));
  assert.deepEqual(vm.window, { hours: 24, sessions: 1, counted: 1, masked: 1, secretsMasked: 1, secretsEarly: 0, untrusted: 0, blocked: 0, sent: 0, waiting: 0,
    only: { secretsMasked: FIRST_SESSION, secretsEarly: null, blocked: null, sent: null } });
});

// ── 5. The first-run card (§4.25, "First-run card") ───────────────────────────

const firstRunCopy = (fr: NonNullable<ReturnType<typeof buildFirstRun>>) =>
  [fr.headline, fr.protects, ...fr.steps.flatMap((s) => [s.title, s.text, ...s.commands.flatMap((c) => [c.command, c.does]), s.link?.text ?? ""])].join("\n");

test("first run: the card is there only while no live session has ever been recorded", () => {
  const fresh = buildHomeViewModel(input({ sessions: [], facts: new Map(), historyTotal: 0, panel: toPolicyPanelViewModel(snapshot({ integrity: false })) }));
  assert.ok(fresh.firstRun, "never a session → the setup card");
  assert.deepEqual(fresh.firstRun!.steps.map((s) => s.id), ["start", "secrets", "check"]);
  assert.equal(buildHomeViewModel(input()).firstRun, null, "one session on record → no card");
  // An old session outside the window still counts: the card is for a first run, not a quiet day.
  const old = buildHomeViewModel(input({
    sessions: [session({ id: "s-old", lastTs: new Date(NOW - 30 * 86_400_000).toISOString() })], historyTotal: 1,
  }));
  assert.equal(old.agents.length, 0);
  assert.equal(old.firstRun, null);
});

test("first run in secrets mode: secrets are kept from the AI, and it SAYS untrusted content is not masked", () => {
  const vm = buildHomeViewModel(input({
    sessions: [], facts: new Map(), historyTotal: 0, configuredMode: "secrets",
    panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })),
  }));
  const fr = vm.firstRun!;
  assert.equal(fr.mode, "secrets");
  assert.equal(fr.saved, false, "the running level, read from the service");
  assert.match(fr.protects, /^Mandu is running in the Secrets mode\./);
  assert.match(fr.protects, /keeps your secrets away from the AI/);
  assert.match(fr.protects, /files you mark as secret/);
  assert.match(fr.protects, /Untrusted content, such as a web page or a file from outside, is not masked in this mode/);
});

test("first run with the service not running: the saved mode, said to apply when Mandu starts", () => {
  const vm = buildHomeViewModel(input({ sessions: [], facts: new Map(), historyTotal: 0, configuredMode: "secrets", panel: toPolicyPanelViewModel(null) }));
  assert.equal(vm.verdict, "unknown");
  assert.equal(vm.firstRun!.mode, "secrets");
  assert.equal(vm.firstRun!.saved, true);
  assert.match(vm.firstRun!.protects, /^Mandu starts with your first agent, in the Secrets mode\./);
  assert.match(vm.firstRun!.protects, /is not masked in this mode/);
});

test("first run: every mode says what it does and does not do", () => {
  const off = buildFirstRun("off", "secrets");
  assert.match(off.protects, /not guarded and untrusted content is not masked/);
  assert.match(off.protects, /Turn it on in Settings › Protection\./);
  const full = buildFirstRun("full", "secrets");
  assert.match(full.protects, /keeps your secrets away/);
  assert.match(full.protects, /masks untrusted content/);
  assert.doesNotMatch(full.protects, /not masked/);
  const inj = buildFirstRun("injection", "secrets");
  assert.match(inj.protects, /masks untrusted content/);
  assert.match(inj.protects, /secrets are not guarded/);
});

test("first run: how to start each agent, how to mark a secret, where mandu doctor is", () => {
  const fr = buildFirstRun("secrets", "secrets");
  const byId = new Map(fr.steps.map((s) => [s.id, s]));
  assert.deepEqual(
    byId.get("start")!.commands,
    [
      { command: "mandu claude", does: "Claude Code" },
      { command: "mandu codex", does: "Codex CLI" },
      { command: "mandu openclaw", does: "OpenClaw" },
      { command: "mandu opencode", does: "OpenCode" },
      { command: "mandu goose", does: "Goose" },
    ],
    "every agent the product names, as its launch command",
  );
  const secrets = byId.get("secrets")!;
  assert.match(secrets.text, /choose "No AI" for it under Rules/, "the Rules menu's own words for the level");
  assert.match(secrets.text, /Files and folders/);
  assert.match(secrets.text, /paths: in ~\/\.mandu\/policy\.yaml/);
  assert.equal(POLICY_FILE_WORDS, manduPath("policy", {}, "~"), "the path table's policy entry, home spelled ~");
  assert.deepEqual(secrets.link, { page: "rules", text: "Open Files and folders" });
  assert.deepEqual(secrets.commands.map((c) => c.command), ["mandu doctor --secrets", "mandu why ~/.pgpass"]);
  assert.deepEqual(byId.get("check")!.commands.map((c) => c.command), ["mandu doctor"]);
});

test("first run: each step's sentence comes as parts too, its commands, files and policy keys as code, the same words as its text", () => {
  // Found 2026-10-08 (nightly run 0030): the card wrote "Put mandu in
  // front …", "under paths: in ~/.mandu/policy.yaml" and "Run mandu doctor
  // …" as plain text, right above its own `mandu doctor` chips, while every
  // other sentence the page writes draws a command as code (§4.25 "Empty
  // states"). The plain text is unchanged, so nothing that reads it moves.
  for (const level of ["secrets", "off", "injection", "full", "unknown"] as const) {
    const fr = buildFirstRun(level, "secrets");
    for (const s of fr.steps) {
      assert.equal(s.parts.map((p) => p.text).join(""), s.text, `${level} ${s.id}: the parts are the text`);
      assert.ok(s.parts.every((p) => (p.kind === "text" || p.kind === "code") && p.text !== ""), `${level} ${s.id}: no empty or unknown part`);
      assert.ok(!s.text.includes("`"), `${level} ${s.id}: no backtick reaches the words`);
      for (const p of s.parts.filter((x) => x.kind === "text")) {
        assert.doesNotMatch(p.text, /\bmandu [a-z]|~\/|\bpaths:|_TOKEN\b|_API_KEY\b/, `${level} ${s.id}: a command or file outside code: ${p.text}`);
      }
    }
    const code = (id: string) => fr.steps.find((s) => s.id === id)!.parts.filter((p) => p.kind === "code").map((p) => p.text);
    assert.deepEqual(code("start"), ["mandu"]);
    assert.deepEqual(code("secrets"), ["~/.aws/credentials", ".env", "*_TOKEN", "*_API_KEY", "paths:", POLICY_FILE_WORDS]);
    assert.deepEqual(code("check"), ["mandu doctor"]);
  }
  const fr = buildFirstRun("secrets", "secrets");
  const byId = new Map(fr.steps.map((s) => [s.id, s]));
  assert.equal(byId.get("start")!.text, "Put mandu in front of the command that starts your agent. The first run starts everything Mandu needs, and the agent shows up here.");
  assert.equal(byId.get("check")!.text, "Run mandu doctor in a terminal at any time. It says in plain words what Mandu needs, whether it is running, and what it enforces here.");
  assert.match(byId.get("secrets")!.text, /^Mandu finds the usual credential files \(such as ~\/\.aws\/credentials, \.env files and ssh keys\) and variables named like \*_TOKEN or \*_API_KEY by itself\./);
});

test("first run: the card's copy uses the product vocabulary only, in every mode", () => {
  for (const level of ["secrets", "off", "injection", "full", "unknown"] as const) {
    const copy = firstRunCopy(buildFirstRun(level, "secrets"));
    assert.doesNotMatch(copy, FORBIDDEN, copy);
    assert.doesNotMatch(copy, /\bsymbol/i, copy);
  }
});

// ── 6. The Rules page's built-in protections follow the mode (§4.25z) ───────

const MASKS_UNTRUSTED = /Untrusted content is masked before the AI reads it/;

test("built-in protections: Secrets mode never claims masking and says untrusted content reaches the AI as written", () => {
  const b = builtInProtections("secrets");
  assert.ok(!b.items.some((s) => MASKS_UNTRUSTED.test(s)), b.items.join(" | "));
  assert.ok(!b.items.some((s) => /^Masked text/.test(s)), "no claim about masked untrusted text either");
  assert.ok(b.items.some((s) => /Untrusted content is not masked in this mode: the AI reads it as-is\./.test(s)));
  assert.ok(b.items.includes("Keys and secret files leave this computer only where a rule or your OK allows."));
  assert.match(b.note, /Secrets mode/);
  // the home carries it, from the posture: integrity off + confidentiality on
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })) }));
  assert.equal(vm.protection.level, "secrets");
  assert.deepEqual(vm.builtIn, b);
});

test("built-in protections: with masking on (Full, Injection) the masking sentence is kept; Off and unknown claim nothing", () => {
  for (const level of ["full", "injection"] as const) {
    assert.ok(builtInProtections(level).items.some((s) => MASKS_UNTRUSTED.test(s)), level);
  }
  const KEPT = /^Keys and secret files leave this computer only where a rule or your OK allows\.$/;
  assert.ok(builtInProtections("full").items.some((s) => KEPT.test(s)));
  assert.ok(!builtInProtections("injection").items.some((s) => KEPT.test(s)), "injection does not guard secrets");
  for (const level of ["off", "unknown"] as const) {
    const b = builtInProtections(level);
    assert.ok(!b.items.some((s) => /is masked before|only where a rule or your OK|without your OK/.test(s)), `${level}: ${b.items.join(" | ")}`);
  }
  const full = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: true, confidentiality: true })) }));
  assert.deepEqual(full.builtIn, builtInProtections("full"));
  assert.deepEqual(buildHomeViewModel(input({ panel: toPolicyPanelViewModel(null) })).builtIn, builtInProtections("unknown"));
});

test("built-ins and the first-run card: a secret is never promised an OK that a rule skips (dashboard.md §4.25d)", () => {
  // A rule (a file's "may be sent to" host, an Always-allow, an
  // administrator's locked row) sends a secret's real value with no question
  // asked, so no sentence says "not sent anywhere without your OK" or
  // "cannot leave … unless you allow it". Home's verdict sentence words it.
  const PROMISE = /without your OK|cannot leave|can't leave|unless you allow it/;
  for (const level of ["secrets", "full"] as const) {
    const b = builtInProtections(level);
    assert.ok(b.items.includes("Keys and secret files leave this computer only where a rule or your OK allows."), level);
    assert.ok(!b.items.some((s) => PROMISE.test(s)), `${level}: ${b.items.join(" | ")}`);
    const fr = buildFirstRun(level, "secrets");
    assert.match(fr.protects, /leave this computer only where a rule or your OK allows/, level);
    assert.doesNotMatch(fr.protects, PROMISE, level);
  }
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })) }));
  assert.match(vm.sentence, /leave this computer only where a rule or your OK allows/, "the built-ins say what Home says");
  // The frozen levels' masking verdict (copy only): Full words its sends as
  // Secrets does; injection guards no secret, so it claims none.
  const full = buildHomeViewModel(input());
  assert.equal(full.verdict, "protected");
  assert.match(full.sentence, /before the AI saw it, and keys and secret files left this computer only where a rule or your OK allowed\.$/);
  const injection = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: true, confidentiality: false })) }));
  assert.equal(injection.verdict, "protected");
  assert.match(injection.sentence, /were masked before the AI saw it\.$/);
  for (const v of [full, injection]) assert.doesNotMatch(v.sentence, PROMISE);
});

test("built-in protections: the copy uses the product vocabulary only, in every mode", () => {
  for (const level of ["secrets", "off", "injection", "full", "unknown"] as const) {
    const b = builtInProtections(level);
    const copy = [b.note, ...b.items].join("\n");
    assert.doesNotMatch(copy, FORBIDDEN, copy);
    assert.doesNotMatch(copy, RETIRED, copy);
    assert.doesNotMatch(copy, /\bsymbol/i, copy);
  }
});

test("built-in protections: the issuer item is there in Secrets and Full, absent in Off, Injection and unknown (§4.25z)", () => {
  const read = { read: true as const, raw: { issuers_off: ["stripe"] } };
  for (const level of ["secrets", "full"] as const) {
    const it = builtInProtections(level, read).issuers;
    assert.ok(it, level);
    assert.equal(it.state, "partly");
    assert.match(it.text, /Off for: Stripe\.$/);
    assert.equal(builtInProtections(level).issuers?.state, "unknown", `${level}: not read is never on`);
    const copy = [it.text, it.change!.text, ...it.companies.map((c) => c.name)].join("\n");
    assert.doesNotMatch(copy, FORBIDDEN, copy);
    assert.doesNotMatch(copy, RETIRED, copy);
    // The sentence beside it stays.
    assert.ok(builtInProtections(level, read).items.includes("Keys and secret files leave this computer only where a rule or your OK allows."));
  }
  for (const level of ["off", "injection", "unknown"] as const) assert.equal(builtInProtections(level, read).issuers, null, level);
  // the home carries what the route read
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: true })), issuerBindings: { read: true, raw: false } }));
  assert.equal(vm.builtIn.issuers?.state, "off");
  assert.deepEqual(vm.builtIn, builtInProtections("secrets", { read: true, raw: false }));
  const offVm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ integrity: false, confidentiality: false })), issuerBindings: { read: true, raw: undefined } }));
  assert.equal(offVm.builtIn.issuers, null);
});

// ── Where the front-ends are found (source checkout vs installed bundle) ──────

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { isCheckoutBuildDir, resolveStaticDir } from "../../../src/server.js";
import { tmpDir } from "../tmp-dir.js";

test("resolveStaticDir: source layout (../public) first, then the bundle layout (./dashboard/public)", () => {
  const root = tmpDir("mdu-static-");
  try {
    // bundle layout: <dist>/dashboard.mjs with <dist>/dashboard/{public,dev}
    const dist = join(root, "dist");
    for (const n of ["public", "dev"]) {
      mkdirSync(join(dist, "dashboard", n), { recursive: true });
      writeFileSync(join(dist, "dashboard", n, "index.html"), "<head></head>");
    }
    assert.equal(resolveStaticDir(dist, "public"), join(dist, "dashboard", "public"));
    assert.equal(resolveStaticDir(dist, "dev"), join(dist, "dashboard", "dev"));
    // source layout wins when both exist: <pkg>/src with <pkg>/public
    mkdirSync(join(root, "public"), { recursive: true });
    writeFileSync(join(root, "public", "index.html"), "<head></head>");
    assert.equal(resolveStaticDir(dist, "public"), join(root, "public"));
    // neither: the source path (its missing index.html is reported by the route)
    assert.equal(resolveStaticDir(join(root, "nowhere", "x"), "dev"), join(root, "nowhere", "dev"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("resolveStaticDir: a checkout's build (launcher/dist beside launcher/src/run.ts) serves the checkout's own front-ends, not its build's copies", () => {
  const repo = tmpDir("mdu-static-checkout-");
  try {
    const dist = join(repo, "launcher", "dist");
    mkdirSync(join(repo, "launcher", "src"), { recursive: true });
    writeFileSync(join(repo, "launcher", "src", "run.ts"), "export {};\n");
    for (const base of [join(dist, "dashboard"), join(repo, "dashboard")]) {
      for (const n of ["public", "dev"]) {
        mkdirSync(join(base, n), { recursive: true });
        writeFileSync(join(base, n, "index.html"), "<head></head>");
      }
    }
    assert.equal(resolveStaticDir(dist, "public"), join(repo, "dashboard", "public"), "the checkout's source, not the copy");
    assert.equal(resolveStaticDir(dist, "dev"), join(repo, "dashboard", "dev"));
    assert.equal(isCheckoutBuildDir(dist), true);
    rmSync(join(repo, "launcher", "src"), { recursive: true, force: true });
    assert.equal(isCheckoutBuildDir(dist), false, "no src/run.ts: an installed dist");
    assert.equal(resolveStaticDir(dist, "public"), join(dist, "dashboard", "public"), "installed: the copies beside the bundle");
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

// ── §4.34 "After you answer" (2026-10-11) ────────────────────────────────────

test("§4.34 After you answer: a refused attempt says only a new try goes, and that the person tells the agent", () => {
  const base = { id: "x", family: "network", status: "pending", outcome: "pending", reason: "", count: 1, firstSeen: 0, lastSeen: 0, resolvedAt: null, sessions: [], scope: "always", consumedAt: null, actions: [], ruleRefId: null, detail: [], originHost: null, mintable: null } as const;
  const ask = (where: string, subject: string, target: string, reason = "") => describeAsk({ ...base, where, subject, target, reason } as never, "Claude Code");
  // A send: the gate refused it (403), so nothing was sent.
  assert.equal(ask("network", "$MDU:nomodel_Read[1234]", "paste.example").ifAllowed,
    "The AI's next request goes to paste.example with the real secret filled in. Mandu refused this one, so nothing was sent. After you answer, tell the agent to try again.");
  for (const [where, subject, target] of [
    ["file", "fs:Read:read", "/home/u/.ssh/id_rsa"], ["file", "fs:DesignSync:upload", "/home/u/.env"],
    ["exec", "exec-program:evil.example", "/tmp/x.sh"], ["exec", "exec-escalate:network", "npm install"],
    ["exec", "$MDU:Read[1234]", "bash -c …"], ["model context", "$MDU:nomodel_Read[1234]", "model_context:in-context-read"],
  ] as const) {
    assert.match(ask(where, subject, target).ifAllowed, /After you answer, tell the agent to try again\.$/, `${where} ${subject}`);
  }
  // A held message's answer outlives its request: the next one carries the message again.
  const held = ask("prompt", `prompt:card.number#${"a".repeat(32)}`, `model:s1#turn:${"b".repeat(32)}`);
  assert.equal(held.aiNow, "The AI has not seen the message as you wrote it. Its request waits for your answer for a short while, then goes with that part masked.");
  assert.match(held.ifAllowed, /An answer given after the request went applies from the AI's next request, which carries your message again\.$/);
});

test("§4.34 After you answer: a held open or change says whether the program still waits, from the row's last ask; the inspector claims neither", () => {
  const h = "a".repeat(64);
  const rows = [
    verdict({ id: "open-now", symbol: `open:/usr/bin/psql#${h}`, destination: "/home/u/.pgpass", lastSeen: NOW - 1_000, count: 40 }),
    verdict({ id: "open-gone", symbol: `open:/usr/bin/psql#${h}`, destination: "/home/u/.pgpass2", lastSeen: NOW - 90_000, count: 121 }),
    verdict({ id: "write-gone", symbol: `write:/usr/bin/vim#${h}`, destination: "/home/u/.bashrc", lastSeen: NOW - 90_000 }),
    verdict({ id: "run-gone", symbol: `write:/usr/bin/bash#${h}#run:12-34`, destination: "/home/u/.profile", lastSeen: NOW - 90_000 }),
    verdict({ id: "send", symbol: "$MDU:nomodel_Read[1234]", destination: "paste.example", lastSeen: NOW - 1_000 }),
  ];
  const vm = buildHomeViewModel(input({ panel: toPolicyPanelViewModel(snapshot({ verdicts: rows })) }));
  const card = (id: string) => vm.waiting.find((a) => a.id === id)!;
  assert.equal(card("open-now").held, true);
  assert.equal(card("open-now").ifAllowed, "The AI's program /usr/bin/psql is waiting for your answer now, and goes on at once: it reads the real file. What it prints still reaches the AI masked.");
  assert.equal(card("open-gone").held, false);
  assert.equal(card("open-gone").ifAllowed, "The AI's program /usr/bin/psql stopped waiting and could not read the file. If you allow it, it reads the real file the next time the AI runs it. After you answer, tell the agent to try again. What it prints still reaches the AI masked.");
  assert.match(card("write-gone").why, /Mandu held the change for a while, then refused it\.$/);
  assert.match(card("write-gone").ifAllowed, /^The AI's program \/usr\/bin\/vim stopped waiting and could not change the file\. If you allow it, it changes the file the next time the AI runs it\./);
  // One run's answer covers that process only: once it stopped waiting, no answer helps it.
  assert.equal(card("run-gone").ifAllowed, "The AI's program /usr/bin/bash running its own code stopped waiting and its change was refused. Your answer covers that run only, so a new try asks again.");
  // Not a held kind: no `held`, so the page keeps its count.
  assert.ok(!("held" in card("send")));
  // The inspector's words (no clock): neither claim.
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: rows }));
  const row = panel.queue.find((r) => r.id === "open-gone")!;
  assert.equal(row.words.ifAllowed, "The AI's program /usr/bin/psql reads the real file. What it prints still reaches the AI masked.");
  assert.equal(textOf(row.words.sentence), "The agent's program /usr/bin/psql wants to read a secret file: .pgpass2");
});

test("§4.34 After you answer: a question from an agent that has ended is marked, and that agent is not under Running now", () => {
  const rows = [
    verdict({ id: "from-ended", sessions: ["s-ended"] }),
    verdict({ id: "from-live", symbol: "$MDU:Read[bbbb].content", sessions: ["s-claude"] }),
    verdict({ id: "from-unknown", symbol: "$MDU:Read[cccc].content", sessions: ["s-not-listed"] }),
  ];
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s-claude" }), session({ id: "s-ended", lastTs: new Date(NOW - 2 * 3_600_000).toISOString() })],
    facts: new Map([
      ["s-claude", { stats: stats(), blocked: 0, sent: 0, holds: true, violations: 0, cwd: null }],
      ["s-ended", { stats: stats(), blocked: 0, sent: 0, holds: true, violations: 0, cwd: null, exited: true }],
    ]),
    panel: toPolicyPanelViewModel(snapshot({ verdicts: rows })),
  }));
  const card = (id: string) => vm.waiting.find((a) => a.id === id)!;
  assert.equal(card("from-ended").askerEnded, true);
  assert.ok(!("askerEnded" in card("from-live")), "a running agent's question");
  assert.ok(!("askerEnded" in card("from-unknown")), "a session not on record: nothing claimed");
  const agent = (id: string) => vm.agents.find((a) => a.id === id)!;
  assert.equal(agent("s-ended").state, "idle", "an ended agent with a question is not running");
  assert.equal(agent("s-ended").waiting, 1, "its row still counts the question");
  assert.equal(agent("s-claude").state, "waiting");
});

// Until 2026-10-22 the hero said "Protection is holding while you decide"
// over a card that said nothing waits on its question now: a question left
// unanswered when its session ended (questions never expire) held Home amber
// with an agent "held up" every day after.
test("§4.25 A question from a session that has ended: the hero says so when every asker ended, counts them when some did, and is as before with none or with a rule change waiting (Secrets and the frozen Full, stated)", () => {
  const SECRETS = { integrity: false, confidentiality: true };
  const FULL = { integrity: true, confidentiality: true };
  const fact = (exited: boolean) => ({ stats: stats(), blocked: 0, sent: 0, holds: true, violations: 0, cwd: null, ...(exited ? { exited: true as const } : {}) });
  // `ended`, `live`, `unlisted`: how many questions each kind of session raised.
  const vm = (o: { integrity: boolean; confidentiality: boolean }, n: { ended?: number; live?: number; unlisted?: number }, changes = 0) => {
    const rows: Partial<VerdictEntry>[] = [];
    for (const [kind, sid] of [["ended", "s-ended"], ["live", "s-claude"], ["unlisted", "s-not-listed"]] as const) {
      for (let i = 0; i < (n[kind] ?? 0); i++) rows.push({ id: `${kind}-${i}`, destination: `${kind}${i}.example`, sessions: [sid] });
    }
    return buildHomeViewModel(input({
      sessions: [session({ id: "s-claude" }), session({ id: "s-ended", lastTs: new Date(NOW - 2 * 3_600_000).toISOString() })],
      facts: new Map([["s-claude", fact(false)], ["s-ended", fact(true)]]),
      panel: toPolicyPanelViewModel(snapshot({ ...o, verdicts: rows.map((r) => verdict(r)) })),
      ...(changes ? { proposalsWaiting: changes } : {}),
    }));
  };
  const HOLD1 = "Protection is holding while you decide: what it asks for happens only if you allow it.";
  const HOLD2 = "Protection is holding while you decide: what each one asks for happens only if you allow it.";
  for (const [o, level, tail] of [[SECRETS, "secrets", " Untrusted content is not masked in this mode."], [FULL, "full", ""]] as const) {
    const cases: Array<[{ ended?: number; live?: number; unlisted?: number }, number, string, string]> = [
      // Every asker ended: what is true, in the card's words.
      [{ ended: 1 }, 0, "One question from a session that has ended is waiting for you.",
        "No agent is waiting on it now. Your answer decides what happens the next time an agent asks the same."],
      [{ ended: 3 }, 0, "3 questions from sessions that have ended are waiting for you.",
        "No agent is waiting on them now. Your answers decide what happens the next time an agent asks the same."],
      // Some ended: today's headline, and how many of them ended.
      [{ ended: 1, live: 1 }, 0, "2 questions are waiting for you.", `${HOLD2} (1 of them is from a session that has ended.)`],
      [{ ended: 2, live: 1 }, 0, "3 questions are waiting for you.", `${HOLD2} (2 of them are from sessions that have ended.)`],
      // None ended: today's words, byte for byte.
      [{ live: 1 }, 0, "One question is waiting for you.", HOLD1],
      [{ live: 2 }, 0, "2 questions are waiting for you.", HOLD2],
      // A session not on record is not ended, as its card claims nothing.
      [{ unlisted: 1 }, 0, "One question is waiting for you.", HOLD1],
      [{ ended: 1, unlisted: 1 }, 0, "2 questions are waiting for you.", `${HOLD2} (1 of them is from a session that has ended.)`],
      // A rule change waiting holds the rules: today's combined words.
      [{ ended: 1 }, 1, "One question and one rule change are waiting for you.", HOLD1],
      [{ ended: 2 }, 1, "2 questions and 1 rule change are waiting for you.", HOLD2],
      [{ ended: 1, live: 1 }, 2, "2 questions and 2 rule changes are waiting for you.", HOLD2],
    ];
    for (const [n, changes, headline, sentence] of cases) {
      const h = vm(o, n, changes);
      const at = `${level}, ${JSON.stringify(n)}, ${changes} rule changes`;
      const asks = (n.ended ?? 0) + (n.live ?? 0) + (n.unlisted ?? 0);
      assert.equal(h.protection.level, level, at);
      assert.equal(h.verdict, "waiting", `${at}: the verdict, its clock and its badge stay`);
      assert.equal(h.headline, headline, at);
      assert.equal(h.sentence, sentence + tail, `${at}: the mode's disclosure still follows`);
      assert.deepEqual(h.sentenceParts, [{ kind: "text", text: sentence + tail }], at);
      assert.equal(h.window.waiting, asks, `${at}: every question still counts`);
      assert.equal(h.waiting.filter((a) => a.askerEnded).length, n.ended ?? 0, at);
      assert.doesNotMatch(`${h.headline}\n${h.sentence}`, FORBIDDEN, at);
      assert.doesNotMatch(h.sentence, /[Nn]othing leaves|leaves? your machine|cannot leave/, at);
    }
  }
  // Nothing waiting at all: the level's own hero, unchanged.
  assert.equal(vm(SECRETS, {}).verdict, "secrets-only");
});

test("§4.25u A question says which session asked: the folder of the session that asked last, its agent, and how many sessions asked; nothing without a known folder", () => {
  const fact = (cwd: string | null) => ({ stats: stats(), blocked: 0, sent: 0, holds: true, violations: 0, cwd });
  const rows = [
    verdict({ id: "shop", sessions: ["s-shop"] }),
    verdict({ id: "both", symbol: "$MDU:Read[bbbb].content", sessions: ["s-shop", "s-blog"] }),
    verdict({ id: "no-cwd", symbol: "$MDU:Read[cccc].content", sessions: ["s-nocwd"] }),
    verdict({ id: "no-facts", symbol: "$MDU:Read[dddd].content", sessions: ["s-outside"] }),
    verdict({ id: "none", symbol: "$MDU:Read[eeee].content", sessions: [] }),
  ];
  const vm = buildHomeViewModel(input({
    sessions: [session({ id: "s-shop" }), session({ id: "s-blog", agent: "codex" }), session({ id: "s-nocwd" }), session({ id: "s-outside" })],
    agentOf: new Map([["s-shop", { agent: "claude" }], ["s-blog", { agent: "codex" }], ["s-nocwd", { agent: "claude" }], ["s-outside", { agent: "claude" }]]),
    facts: new Map([["s-shop", fact("/home/u/projects/shop")], ["s-blog", fact("/home/u/projects/blog")], ["s-nocwd", fact(null)]]),
    panel: toPolicyPanelViewModel(snapshot({ verdicts: rows })),
  }));
  const card = (id: string) => vm.waiting.find((a) => a.id === id)!;
  assert.equal(card("shop").askerCwd, "/home/u/projects/shop");
  assert.equal(card("shop").askerAgent, "Claude Code", "the agent the sentence names");
  assert.equal(card("shop").askerSessions, 1);
  assert.equal(card("both").askerCwd, "/home/u/projects/blog", "the session that asked last");
  assert.equal(card("both").askerAgent, agentName("codex"));
  assert.equal(card("both").askerSessions, 2, "two sessions asked");
  for (const id of ["no-cwd", "no-facts", "none"]) {
    for (const k of ["askerCwd", "askerAgent", "askerSessions"]) assert.ok(!(k in card(id)), `${id}: no ${k}, the card is as before`);
  }
});

test("§4.34 After you answer: a masked value asked to be shown to the AI as it is reads as a show, named as a send names it, never a send to model_context", () => {
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: [
    verdict({ id: "show", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "model_context:in-context-read", source: { tool: "Read", origin: "/home/u/proj/.env" } } as Partial<VerdictEntry>),
  ] }));
  const row = panel.queue[0]!;
  assert.equal(row.where, "model context");
  assert.equal(row.words.family, "show");
  const vm = buildHomeViewModel(input({ panel, home: "/home/u" }));
  assert.equal(textOf(vm.waiting[0]!.sentence), "Claude Code wants to show the AI your secret STRIPE_KEY as it is");
  assert.doesNotMatch(JSON.stringify(vm.waiting[0]), /model_context/);
});

test("§4.34 A held message's answer: it reads as what went to the AI, a message's answer has no reversal, a session's flips as itself", () => {
  const ref = "a".repeat(32);
  const turn = `model:s1#turn:${"b".repeat(32)}`;
  const rows = [
    verdict({ id: "masked", symbol: `prompt:acme.codename#${ref}`, destination: turn, status: "denied", scope: "once", resolvedAt: NOW - 5_000 } as Partial<VerdictEntry>),
    verdict({ id: "sent", symbol: `prompt:acme.codename#${ref}`, destination: `model:s1#turn:${"c".repeat(32)}`, status: "approved", scope: "once", resolvedAt: NOW - 4_000 } as Partial<VerdictEntry>),
    verdict({ id: "sent-turn-session", symbol: `prompt:acme.codename#${ref}`, destination: `model:s1#turn:${"d".repeat(32)}`, status: "approved", scope: "always", resolvedAt: NOW - 3_000 } as Partial<VerdictEntry>),
    verdict({ id: "session", symbol: `prompt:acme.codename#${ref}`, destination: "model:s1", status: "approved", scope: "always", resolvedAt: NOW - 2_000 } as Partial<VerdictEntry>),
    verdict({ id: "session-masked", symbol: `prompt:acme.ticket#${ref}`, destination: "model:s1", status: "denied", scope: "always", resolvedAt: NOW - 1_000 } as Partial<VerdictEntry>),
    verdict({ id: "send", symbol: "$MDU:nomodel_Read[1234]", destination: "paste.example", status: "denied", scope: "always", resolvedAt: NOW - 500 } as Partial<VerdictEntry>),
  ];
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: rows }));
  const vm = buildHomeViewModel(input({ panel }));
  const row = (id: string) => vm.answered.find((a) => a.id === id)!;
  assert.equal(row("masked").outcome, "masked", "Send masked (or Cancel) is never Blocked");
  assert.equal(row("sent").outcome, "sent");
  assert.equal(row("sent-turn-session").outcome, "sent-session");
  assert.equal(row("session").outcome, "sent-session");
  assert.equal(row("session-masked").outcome, "masked-session");
  assert.equal(row("send").outcome, "blocked", "a send's Block is unchanged");
  for (const id of ["masked", "sent", "sent-turn-session"]) assert.deepEqual(row(id).actions, [], `${id}: an answer about one message has no reversal`);
  assert.deepEqual(row("session").actions, [{ approve: false, label: "Send masked instead" }]);
  assert.deepEqual(row("session-masked").actions, [{ approve: true, label: "Send as written instead" }]);
  assert.deepEqual(row("send").actions, [{ approve: true, label: "Allow instead" }]);
});

test("§4.34 Answers that no longer apply: the arbiter's mark reads as why, with no reversal; Rules and the inspector get the same words", () => {
  const rows = [
    verdict({ id: "name", symbol: "write:tee", destination: "/home/u/.bashrc", status: "approved", scope: "always", resolvedAt: NOW - 5_000, noLongerApplies: "name-only" } as Partial<VerdictEntry>),
    verdict({ id: "printer", symbol: `open:/usr/bin/cat#${"a".repeat(64)}`, destination: "/home/u/.env", status: "approved", scope: "always", resolvedAt: NOW - 4_000, noLongerApplies: "printer" } as Partial<VerdictEntry>),
    verdict({ id: "live", symbol: `open:/usr/bin/ssh-add#${"a".repeat(64)}`, destination: "/home/u/.ssh/id_ed25519", status: "denied", scope: "always", resolvedAt: NOW - 3_000 } as Partial<VerdictEntry>),
    // A pending row is never marked (the arbiter retires a moot question).
    verdict({ id: "pending", symbol: "write:tee", destination: "/home/u/.profile", noLongerApplies: "name-only" } as Partial<VerdictEntry>),
  ];
  const panel = toPolicyPanelViewModel(snapshot({ verdicts: rows }));
  const q = (id: string) => panel.queue.find((r) => r.id === id)!;
  assert.equal(q("name").noLongerApplies, "name-only");
  assert.equal(q("name").staleNote, "This answer no longer applies: it names the program by its name only, as Mandu asked before October 2, 2026. Mandu now asks about the program's file, so it asks again.");
  assert.deepEqual(q("name").actions, [], "changing it would change nothing");
  assert.match(q("printer").staleNote ?? "", /prints what it reads, so it never gets the real file/);
  assert.ok(!("staleNote" in q("live")) && q("live").actions.length === 1, "a live answer keeps its reversal");
  assert.ok(!("noLongerApplies" in q("pending")), "a waiting row is not marked");
  const vm = buildHomeViewModel(input({ panel }));
  const row = (id: string) => vm.answered.find((a) => a.id === id)!;
  assert.equal(row("name").staleNote, q("name").staleNote);
  assert.deepEqual(row("name").actions, []);
  assert.ok(!("staleNote" in row("live")));
});

// ── Settings › About Mandu (§4.25 *About Mandu*) ─────────────────────────────

test("about: the home carries the release it was given and the three help links, each https", () => {
  const vm = buildHomeViewModel(input({ version: "0.2.0-beta.7" }));
  assert.deepEqual(vm.about, {
    version: "0.2.0-beta.7",
    guideUrl: DOCS_BASE_URL + "docs/usage.md",
    troubleshootingUrl: DOCS_BASE_URL + "docs/usage.md#troubleshooting",
    issuesUrl: ISSUES_URL,
    // The route read no update cache (a test seam): nothing said of updates.
    update: null,
  });
  for (const k of ["guideUrl", "troubleshootingUrl", "issuesUrl"] as const) assert.match(vm.about[k], /^https:\/\//, k);
  // The same on every rung of the ladder: not connected too, since the
  // release and the links do not depend on the service.
  assert.deepEqual(buildHomeViewModel(input({ version: "0.2.0-beta.7", panel: toPolicyPanelViewModel(null) })).about, vm.about);
});

test("about: no version, a blank one or \"unknown\" reads \"unknown\", never empty; the links stay", () => {
  for (const version of [undefined, "", "   ", "unknown"]) {
    const about = buildHomeViewModel(input(version === undefined ? {} : { version })).about;
    assert.equal(about.version, "unknown", JSON.stringify(version));
    assert.match(about.issuesUrl, /^https:\/\//);
  }
  assert.equal(homeAbout(" 1.0.0 ").version, "1.0.0", "trimmed");
});

// ── About Mandu: a newer release (dashboard.md §4.25 *A newer release*) ────────

/** An update-check cache as the launcher writes it, fetched an hour before NOW. */
const cache = (releases: UpdateCache["releases"], over: Partial<UpdateCache> = {}): UpdateCache => ({
  v: 1, checkedAt: NOW - 3_600_000, ok: true, releases, releasesAt: NOW - 3_600_000, ...over,
});

test("about update: newer, newer with security fixes, newest, and no answer, each its own form", () => {
  const releases = [{ version: "0.2.0-beta.8", security: true }, { version: "0.2.0-beta.9", security: false }, { version: "0.2.0-beta.6", security: true }];
  // Newer, plain: the newest, its npm line pinned to it, and when the list came.
  assert.deepEqual(aboutUpdate("0.2.0-beta.7", cache(releases.map((r) => ({ ...r, security: false }))), "npm", NOW), {
    state: "newer", at: NOW - 3_600_000, newest: "0.2.0-beta.9", security: false, install: "npm install -g @mandusec/mandu@0.2.0-beta.9",
  });
  // With security fixes: a release in between carries the marker; the
  // installer's channel gives the release's install.sh line.
  assert.deepEqual(aboutUpdate("0.2.0-beta.7", cache(releases), "release", NOW), {
    state: "newer", at: NOW - 3_600_000, newest: "0.2.0-beta.9", security: true,
    install: "curl -fsSL https://github.com/ManduSec/mandu/releases/download/v0.2.0-beta.9/install.sh | sh",
  });
  // A security release older than the running one says nothing.
  assert.deepEqual(aboutUpdate("0.2.0-beta.9", cache(releases), "npm", NOW), { state: "current", at: NOW - 3_600_000 });
  // No cache, or one no check ever filled: no answer, and the page says when Mandu checks.
  assert.deepEqual(aboutUpdate("0.2.0-beta.7", null, "npm", NOW), { state: "unknown" });
  assert.deepEqual(aboutUpdate("0.2.0-beta.7", cache([], { ok: false, releasesAt: null }), "npm", NOW), { state: "unknown" });
  // A version that is not semver: nothing to compare.
  assert.equal(aboutUpdate("unknown", cache(releases), "npm", NOW), null);
});

test("about update: a list fetched in the future gives no time; a failed later check keeps the list and its own time", () => {
  assert.deepEqual(aboutUpdate("1.0.0", cache([{ version: "1.0.1", security: false }], { releasesAt: NOW + 86_400_000 }), "npm", NOW),
    { state: "newer", at: null, newest: "1.0.1", security: false, install: "npm install -g @mandusec/mandu@1.0.1" });
  const kept = cache([{ version: "1.0.0", security: false }], { ok: false, checkedAt: NOW - 1000, releasesAt: NOW - 5 * 86_400_000 });
  assert.deepEqual(aboutUpdate("1.0.0", kept, "npm", NOW), { state: "current", at: NOW - 5 * 86_400_000 });
});

test("about update: the install line holds only the semver version, trimmed, never other text from the file", () => {
  const up = aboutUpdate("1.0.0", cache([{ version: " 1.0.1\n", security: true }]), "npm", NOW);
  assert.deepEqual(up, { state: "newer", at: NOW - 3_600_000, newest: "1.0.1", security: true, install: "npm install -g @mandusec/mandu@1.0.1" });
});

test("about update: the home carries the answer when the route read the cache, and none when it did not", () => {
  const read = buildHomeViewModel(input({ version: "0.2.0-beta.7", update: { cache: cache([{ version: "0.2.0-beta.8", security: true }]), channel: "npm" } }));
  assert.deepEqual(read.about.update, { state: "newer", at: NOW - 3_600_000, newest: "0.2.0-beta.8", security: true, install: "npm install -g @mandusec/mandu@0.2.0-beta.8" });
  assert.deepEqual(buildHomeViewModel(input({ version: "0.2.0-beta.7", update: { cache: null, channel: "npm" } })).about.update, { state: "unknown" });
  assert.equal(buildHomeViewModel(input({ version: "unknown", update: { cache: null, channel: "npm" } })).about.update, null);
  assert.equal(buildHomeViewModel(input({ version: "0.2.0-beta.7" })).about.update, null);
});

// ── The secret posture card (dashboard.md §4.23 *Product page*) ───────────────

/** A launcher session's health with the given secret posture (`null`: the
 *  launch recorded none), as session-health.ts lifts it. */
function launched(posture: "confined" | "read-blocked" | "gated" | null, gap?: string): SessionHealth {
  return {
    verdict: posture === "gated" ? "degraded" : "ok", live: [], dropped: [], relay: null, clientVersion: null, unknownTools: [],
    agentVersion: null, turns: 1, toolFailures: 0, exitCode: null, reasons: [],
    ...(posture ? { secrets: { posture, sentence: SECRETS_SENTENCE[posture], ...(gap ? { gap } : {}), ...(gap && SECRETS_FIX[gap] ? { fix: SECRETS_FIX[gap] } : {}) } } : {}),
  };
}
const at = (minutesAgo: number): string => new Date(NOW - minutesAgo * 60_000).toISOString();

test("secret posture: the newest launch decides; a gated one with gap apparmor-userns carries its sentence and `mandu setup` as code", () => {
  const vm = buildHomeViewModel(input({
    sessions: [
      session({ id: "s-new", status: undefined, firstTs: at(20), lastTs: at(10), health: launched("gated", "apparmor-userns") }),
      session({ id: "s-old", status: undefined, firstTs: at(120), lastTs: at(100), health: launched("confined") }),
    ],
    facts: new Map(),
  }));
  assert.deepEqual(vm.secretsPosture, {
    gap: "apparmor-userns",
    session: "s-new",
    headline: "Programs your agent runs can still read your credential files.",
    sentence: SECRETS_SENTENCE.gated,
    note: null,
    fix: "mandu setup",
    fixParts: [
      { kind: "text", text: "Run " },
      { kind: "code", text: "mandu setup" },
      { kind: "text", text: " in a terminal once, then start your agent again." },
    ],
  });
  // The confined launch is the newer one: no card, the gated one is history.
  const after = buildHomeViewModel(input({
    sessions: [
      session({ id: "s-old", status: undefined, firstTs: at(120), lastTs: at(100), health: launched("gated", "apparmor-userns") }),
      session({ id: "s-new", status: undefined, firstTs: at(20), lastTs: at(10), health: launched("confined") }),
    ],
    facts: new Map(),
  }));
  assert.equal(after.secretsPosture, null, "once a new agent starts confined, the card goes");
  // The headline stays as the level makes it.
  assert.equal(vm.headline, buildHomeViewModel(input({ sessions: [session({ id: "s-new", status: undefined, firstTs: at(20), lastTs: at(10) })], facts: new Map() })).headline);
});

test("secret posture: a running launch wins over a newer ended one; a running agent with a recorded exit has ended", () => {
  const sessions = [
    session({ id: "s-ended", status: undefined, firstTs: at(5), lastTs: at(2), health: launched("confined") }),
    session({ id: "s-running", status: "running", firstTs: at(60), lastTs: at(1), health: launched("gated", "no-bwrap") }),
  ];
  const vm = buildHomeViewModel(input({ sessions, facts: new Map() }));
  assert.equal(vm.secretsPosture?.session, "s-running");
  assert.equal(vm.secretsPosture?.fix, "sudo apt install bubblewrap");
  const exited = buildHomeViewModel(input({ sessions, facts: new Map([["s-running", { stats: stats(), blocked: 0, sent: 0, holds: true, violations: 0, cwd: null, exited: true }]]) }));
  assert.equal(exited.secretsPosture, null, "its exit makes the newer confined launch the one that decides");
  // A session no launcher recorded (no health) never decides.
  const plain = buildHomeViewModel(input({ sessions: [session({ id: "s-proxy", status: "running", firstTs: at(1) }), ...sessions.slice(1)], facts: new Map() }));
  assert.equal(plain.secretsPosture?.session, "s-running");
});

test("secret posture: confined, read-blocked and no posture on record give no card; nor a launch outside the window", () => {
  for (const h of [launched("confined"), launched("read-blocked"), launched(null), undefined]) {
    const vm = buildHomeViewModel(input({ sessions: [session({ id: "s-claude", ...(h ? { health: h } : {}) })] }));
    assert.equal(vm.secretsPosture, null, JSON.stringify(h?.secrets ?? null));
  }
  const old = buildHomeViewModel(input({ sessions: [session({ id: "s-old", status: undefined, firstTs: at(48 * 60), lastTs: at(47 * 60), health: launched("gated", "apparmor-userns") })], facts: new Map() }));
  assert.equal(old.secretsPosture, null, "only Home's window");
});

test("secret posture: a bind-only gap carries its partial note and no command; a gap with no fix, neither", () => {
  for (const gap of ["no-guard", "guard-off"] as const) {
    const p = secretsPostureNote(launched("gated", gap).secrets, "home")!;
    assert.equal(p.note, SECRETS_PARTIAL_NOTE[gap]);
    assert.equal(p.fix, null);
    assert.equal(p.fixParts, null);
  }
  const off = secretsPostureNote(launched("gated", "userns-off").secrets, "home")!;
  assert.deepEqual([off.note, off.fix, off.fixParts], [null, null, null]);
  const bare = secretsPostureNote(launched("gated").secrets, "home")!;
  assert.equal(bare.gap, null);
  // The session page speaks of the agent it shows.
  assert.equal(secretsPostureNote(launched("gated", "apparmor-userns").secrets, "session")!.headline, "Programs this agent ran could read your credential files.");
  assert.equal(secretsPostureNote(launched("confined").secrets, "session"), null);
});

test("secret posture: the card's words use the product vocabulary, never borrow the confined claim, and its fix is its parts joined", () => {
  for (const gap of ["apparmor-userns", "no-bwrap", "bwrap-nesting", "userns-off", "no-guard", "guard-off", "arbiter"]) {
    for (const of of ["home", "session"] as const) {
      const p = secretsPostureNote(launched("gated", gap).secrets, of)!;
      const copy = [p.headline, p.sentence, p.note ?? "", ...(p.fixParts ?? []).map((x) => x.text)].join("\n");
      assert.doesNotMatch(copy, FORBIDDEN, copy);
      assert.doesNotMatch(copy, /placeholder copy of each credential file, never the real one|cannot open your credential files/, "never the confined or read-blocked claim");
      if (p.fixParts) assert.equal(p.fixParts.filter((x) => x.kind === "code").map((x) => x.text).join(""), p.fix);
    }
  }
});

// ── The session's own troubles on the product page (dashboard.md §4.21) ─────

let hn = 0;
function hev(kind: string, extra: Record<string, unknown> = {}): ManduEvent {
  hn++;
  return {
    id: `h${hn}`, sessionId: "s-claude", turn: hn, ts: new Date(1700000000000 + hn * 1000).toISOString(), seq: hn,
    callId: null, parentId: null, kind: kind as ManduEvent["kind"], view: "HumanView", boundary: "shell",
    emitter: "launcher", input: null, output: null, invariant: { violatedInvariant: false },
    ...extra,
  } as ManduEvent;
}
const claudeLaunch = () => hev("launch_posture", { target: "claude", live: ["fs"], dropped: [] });
const aTurn = () => hev("tllm_call", { callShape: { toolCount: 12 }, output: { symbolized: "Done.", original: null, differs: false, symbols: [] } });
const aSideCall = () => hev("tllm_call", { callShape: { toolCount: 0 }, output: { symbolized: "title", original: null, differs: false, symbols: [] } });
/** One Bash call through the exec gate whose result says `text`. */
const command = (id: string, text: string) => [
  hev("tool_use", { callId: id, input: { symbolized: `Bash({"command":"run ${id}"})`, original: null, differs: false, symbols: [] } }),
  hev("exec_action", { callId: id }),
  hev("tool_result", { tool: "Bash", callId: id, output: { symbolized: text, original: text, differs: false, symbols: [] } }),
];
const NOT_FOUND = "Exit code 127\n/bin/bash: line 1: python3: command not found";
const noticeOf = (events: ManduEvent[], masking = false) => agentNotice(deriveHealth(events)!, masking, "s-claude");
const RELAY = "Your terminal showed masked values instead of your real ones: Mandu's reply filter was not working in this session. The AI's side was not affected. Start the agent again; if it happens again, run mandu doctor.";
const LOG = "Run mandu log s-claude for this launch's notices.";

test("a session that could not do its job, or some of whose commands could not run, says so in the product's words, from its health (dashboard.md §4.21 On the product page)", () => {
  // The reply filter in passthrough, or its LAST record says its lookups fail.
  assert.equal(noticeOf([claudeLaunch(), hev("relay_mode", { mode: "passthrough" }), aTurn()]), RELAY);
  assert.equal(noticeOf([claudeLaunch(), hev("relay_mode", { mode: "pty" }), hev("relay_mode", { mode: "pty", resolveFailure: "arbiter: ECONNREFUSED" }), aTurn()]), RELAY);
  // A failure it recovered from says nothing: the last record is plain.
  assert.equal(noticeOf([claudeLaunch(), hev("relay_mode", { mode: "pty", resolveFailure: "timeout" }), hev("relay_mode", { mode: "pty" }), aTurn()]), null);
  // Every command failed: how many, and the launch log of this session.
  assert.equal(noticeOf([claudeLaunch(), ...command("c1", NOT_FOUND), ...command("c2", "Exit code 126\nbwrap: Can't mount proc"), aTurn()]),
    `None of the 2 commands the agent ran could start: a sandbox or a missing program stopped them. ${LOG}`);
  assert.equal(noticeOf([claudeLaunch(), ...command("c1", NOT_FOUND), aTurn()]),
    `The one command the agent ran could not start: a sandbox or a missing program stopped it. ${LOG}`);
  // Some failed.
  assert.equal(noticeOf([claudeLaunch(), ...command("c1", NOT_FOUND), ...command("c2", "README.md"), ...command("c3", NOT_FOUND), aTurn()]),
    "2 of the commands the agent ran could not start.");
  // Model calls but no turn; an exit before any model call, with its code.
  assert.equal(noticeOf([claudeLaunch(), aSideCall(), hev("session_exit", { code: 0 })]), "The agent stopped before it finished a single turn.");
  assert.equal(noticeOf([claudeLaunch(), hev("session_exit", { code: 3 })]),
    "The agent stopped before it finished a single turn: it exited with code 3 before its first request to the AI model.");
  // A quit at the prompt (exit 0, no call) and a healthy session: nothing.
  assert.equal(noticeOf([claudeLaunch(), hev("session_exit", { code: 0 })]), null);
  assert.equal(noticeOf([claudeLaunch(), hev("relay_mode", { mode: "pty" }), aTurn(), ...command("c1", "ok"), hev("session_exit", { code: 0 })]), null);
  assert.equal(deriveHealth([claudeLaunch(), aTurn()])!.verdict, "ok");
  // No launch_posture: no health, no notice.
  assert.equal(deriveHealth([aTurn()]), null);
  assert.equal(agentNotice(undefined, false), null);
});

test("several troubles: the most serious first, the version last; the parts carry each command as code and read as the line", () => {
  const events = [
    claudeLaunch(), hev("relay_mode", { mode: "passthrough" }), hev("client_info", { clientVersion: "9.0.0" }),
    ...command("c1", NOT_FOUND), aSideCall(), hev("session_exit", { code: 1 }),
  ];
  const health = deriveHealth(events)!;
  assert.equal(health.verdict, "broken");
  assert.deepEqual(health.broken, ["relay", "no-turn", "commands"], "deriveHealth's own order");
  const notice = agentNotice(health, false, "s-claude")!;
  const order = [RELAY, "The one command the agent ran could not start", "The agent stopped before it finished a single turn.", "Claude Code 9.0.0 is newer than the versions Mandu was tested with"];
  const at = order.map((x) => notice.indexOf(x));
  assert.ok(at.every((i) => i >= 0), notice);
  assert.deepEqual([...at].sort((a, b) => a - b), at, `the most serious first: ${notice}`);
  const parts = agentNoticeParts(health, false, "s-claude")!;
  assert.equal(parts.map((p) => p.text).join(""), notice);
  assert.deepEqual(parts.filter((p) => p.kind === "code").map((p) => p.text), ["mandu doctor", "mandu log s-claude"]);
  // Some failed (degraded) comes after a broken cause.
  const mixed = agentNotice(deriveHealth([claudeLaunch(), hev("relay_mode", { mode: "passthrough" }), ...command("c1", NOT_FOUND), ...command("c2", "ok"), aTurn()])!, false)!;
  assert.ok(mixed.indexOf(RELAY) === 0 && mixed.endsWith("1 of the commands the agent ran could not start."), mixed);
  // Without a session id the log command is the plain one.
  assert.match(agentNotice(deriveHealth([claudeLaunch(), ...command("c1", NOT_FOUND), aTurn()])!, false)!, /Run mandu log for this launch's notices\.$/);
  // Its Home row carries both forms.
  const vm = buildHomeViewModel(input({ sessions: [session({ id: "s-claude", health })] }));
  const row = vm.agents.find((a) => a.id === "s-claude")!;
  const masking = row.notice !== notice; // worded for the level the input runs
  assert.equal(row.notice, agentNotice(health, masking, "s-claude"));
  assert.deepEqual(row.noticeParts, agentNoticeParts(health, masking, "s-claude"));
  assert.ok(row.notice!.startsWith(RELAY), row.notice!);
});

test("the trouble notices use the product's words: no developer term, no retired word, no token, and never a leak", () => {
  const cases: ManduEvent[][] = [
    [claudeLaunch(), hev("relay_mode", { mode: "passthrough" }), aTurn()],
    [claudeLaunch(), hev("relay_mode", { mode: "pipe", resolveFailure: "arbiter: refused" }), aTurn()],
    [claudeLaunch(), ...command("c1", NOT_FOUND), ...command("c2", NOT_FOUND), aTurn()],
    [claudeLaunch(), ...command("c1", NOT_FOUND), ...command("c2", "ok"), aTurn()],
    [claudeLaunch(), aSideCall(), hev("session_exit", { code: 0 })],
    [claudeLaunch(), hev("session_exit", { code: 2 })],
  ];
  for (const events of cases) {
    for (const masking of [false, true]) {
      const notice = noticeOf(events, masking);
      assert.ok(notice, JSON.stringify(events.map((e) => e.kind)));
      assert.doesNotMatch(notice, /PASSTHROUGH|passthrough|\brungs?\b|\bsymbols?\b|reply-filter|exit 12[67]|resolveFailure|arbiter|ECONN|refused/i, notice);
      assert.doesNotMatch(notice, FORBIDDEN, notice);
      assert.doesNotMatch(notice, RETIRED, notice);
      assert.doesNotMatch(notice, /leak|exposed|protection failed|not protected/i, "a failure of display and use, never a leak");
    }
  }
});

test("built-in protections, protection off: Turn it on in Settings is a link part to Settings › Protection; joined, the same words", () => {
  const off = builtInProtections("off");
  assert.equal(off.itemsParts!.length, off.items.length);
  off.items.forEach((text, i) => assert.equal(off.itemsParts![i]!.map((x) => x.text).join(""), text));
  assert.deepEqual(off.itemsParts![0]!.filter((x) => x.kind === "link"), [{ kind: "link", text: "Turn it on in Settings", to: "protection" }]);
  for (const level of ["secrets", "full", "injection", "unknown"] as const) assert.equal(builtInProtections(level).itemsParts, undefined, level);
});
