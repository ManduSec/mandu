/**
 * ask-after-allow.test — dashboard.md §4.25 *An answer says what it did*.
 * After an answer that worked, the list its card was in shows one line
 * where the card was ("Allowed once: send your secret `STRIPE_KEY` to
 * `api.stripe.com`. Tell Claude Code to try again."). The page reads what
 * is left to do from the ask's own field, `afterAllow`, never out of
 * `ifAllowed`, and what was asked from `whatParts`.
 *
 *   A1  each family's `afterAllow`: "Tell <agent> to try again." where
 *       `ifAllowed` says TELL_AGENT (a send, a program's send, an
 *       upload, the agent's tool on a file, the three runs, a show, a held
 *       program that stopped waiting), "The program goes on now." for one
 *       still waiting, none for the others (a held message, a session's
 *       asks, a run's change that stopped waiting, a program not known to
 *       wait, the catch-all);
 *   A2  the invariant behind A1, over every row of A1: the reminder iff
 *       `ifAllowed` holds TELL_AGENT;
 *   A3  the agent is named as the sentence names it; an unknown one is
 *       "the agent" mid-sentence;
 *   A4  `whatParts` is the sentence from its verb on, its names still
 *       code, its parts its own; a sentence whose subject is more than the
 *       agent stays whole;
 *   A5  Home's ask carries both (home.ts spreads describeAsk).
 *
 * Pure: describeAsk and buildHomeViewModel over queue rows, no I/O. Axes: none
 * (display words only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { describeAsk, TELL_AGENT, type AskWords, type HomeTextPart } from "../../../src/view-model/ask-words.js";
import { buildHomeViewModel } from "../../../src/view-model/home.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot } from "../../../src/policy-model.js";

const HOME = "/home/u";
const KEY = "$MDU:nomodel_Read[3c4d].STRIPE_KEY";
const HEX = "a".repeat(64);
const TRY = "Tell Claude Code to try again.";
const GOES = "The program goes on now.";
const text = (parts: HomeTextPart[]): string => parts.map((p) => p.text).join("");

type Row = Parameters<typeof describeAsk>[0];
const ask = (row: Partial<Row>, who = "Claude Code"): AskWords =>
  describeAsk({ where: "network", subject: KEY, target: "api.stripe.com", reason: "", ...row }, who, HOME);

const cat = `/usr/bin/cat#${HEX}`;
const env = `${HOME}/ws/app/.env`;
const reads = [{ symbol: KEY, origin: env }];
/** Every family, with what is left after an Allow (A1). */
const FAMILIES: Array<[string, Partial<Row>, string | undefined]> = [
  ["a send of a named secret", { origin: env }, TRY],
  ["a send of a secret file's values", { origin: env, subject: "$MDU:nomodel_Read[3c4d].content", fileValues: 3 }, TRY],
  ["a send of masked text", { subject: "$MDU:anymodel_Read[1a2b].content" }, TRY],
  ["a program's send of the files it holds", { subject: `holder-send:${JSON.stringify({ session: "s-1", files: [env] })}`, target: "hooks.slack.com", holderSources: [{ path: env, level: "no-model", bindings: [], blocks: true, always: true }] }, TRY],
  ["a held message", { where: "prompt", subject: "prompt:card-number#1", target: "model:s-1#turn:3" }, undefined],
  ["a program's read, still waiting", { where: "file", subject: `open:${cat}`, target: env, held: true }, GOES],
  ["a program's read, stopped waiting", { where: "file", subject: `open:${cat}`, target: env, held: false }, TRY],
  ["a program's read, not known", { where: "file", subject: `open:${cat}`, target: env }, undefined],
  ["a program not vetted, still waiting", { where: "file", subject: `trust:${cat}`, target: env, held: true }, GOES],
  ["a program not vetted, stopped waiting", { where: "file", subject: `trust:${cat}`, target: env, held: false }, TRY],
  ["a change to a file that runs later, still waiting", { where: "file", subject: `write:/usr/bin/sh#${HEX}`, target: `${HOME}/.bashrc`, held: true }, GOES],
  ["a change to a file that runs later, stopped waiting", { where: "file", subject: `write:/usr/bin/sh#${HEX}`, target: `${HOME}/.bashrc`, held: false }, TRY],
  ["a run's change that stopped waiting", { where: "file", subject: "write:/usr/bin/sh#run:42", target: `${HOME}/.bashrc`, held: false }, undefined],
  ["a run's change, still waiting", { where: "file", subject: "write:/usr/bin/sh#run:42", target: `${HOME}/.bashrc`, held: true }, GOES],
  ["an upload", { where: "file", subject: "fs:DesignSync:upload", target: env }, TRY],
  ["the agent's tool on a secret file", { where: "file", subject: "fs:Read:read", target: `${HOME}/.aws/credentials`, reason: "sensitive path ~/.aws" }, TRY],
  ["code from a download", { where: "exec", subject: "exec-program:get.example", target: "(stdin)" }, TRY],
  ["a command with the network", { where: "exec", subject: "exec-escalate:network", target: "npm install" }, TRY],
  ["a command on the real files", { where: "exec", subject: "exec-escalate:files", target: "make" }, TRY],
  ["a command with masked text", { where: "exec", subject: KEY, target: "echo $MDU" }, TRY],
  ["a show", { where: "model context", subject: KEY, target: "", origin: env }, TRY],
  ["a session's request", { subject: "session-net:s-1", target: "evil.example", sessionReads: reads }, undefined],
  ["a held command's connection", { subject: "session-net:s-1", target: "evil.example", sessionReads: reads, sessionHeld: true, sessionBindings: ["api.stripe.com"] }, undefined],
  ["a session's command", { where: "exec", subject: "session-exec:s-1", target: "make deploy", sessionReads: reads, sessionConfined: true, sessionBindings: [] }, undefined],
  ["anything else", { where: "elsewhere", subject: "something", target: "x" }, undefined],
];

test("A1: each family says what is left after an Allow, or nothing", () => {
  for (const [name, row, after] of FAMILIES) {
    const w = ask(row);
    assert.equal(w.afterAllow, after, name);
    if (after === undefined) assert.ok(!("afterAllow" in w), `${name}: no field at all`);
  }
});

test("A2: the reminder comes exactly where the card's If you click Allow says 'tell the agent to try again'", () => {
  for (const [name, row] of FAMILIES) {
    const w = ask(row);
    assert.equal(w.afterAllow === TRY, w.ifAllowed.includes(TELL_AGENT), name);
    if (w.afterAllow === GOES) assert.match(w.ifAllowed, /goes on at once/, name);
  }
});

test("A3: the agent is named as the sentence names it; an unknown one is 'the agent'", () => {
  assert.equal(ask({ origin: env }, "Codex CLI").afterAllow, "Tell Codex CLI to try again.");
  assert.equal(ask({ origin: env }, "The agent").afterAllow, "Tell the agent to try again.");
  assert.equal(ask({ where: "file", subject: `open:${cat}`, target: env, held: true }, "The agent").afterAllow, GOES);
});

test("A4: what was asked, from its verb on, its names still code; a sentence about a program stays whole", () => {
  const send = ask({ origin: env });
  assert.deepEqual(send.whatParts, [{ kind: "text", text: "send your secret " }, { kind: "code", text: "STRIPE_KEY" }, { kind: "text", text: " to " }, { kind: "code", text: "api.stripe.com" }]);
  assert.ok(send.whatParts.every((p) => !send.sentence.includes(p)), "its parts are its own");
  assert.equal(text(ask({ where: "exec", subject: "exec-escalate:network", target: "npm install" }).whatParts), "run a command with network access: npm install");
  assert.equal(text(ask({ where: "model context", subject: KEY, target: "", origin: env }).whatParts), "show the AI your secret STRIPE_KEY as it is");
  assert.equal(text(ask({ origin: env }, "The agent").whatParts), "send your secret STRIPE_KEY to api.stripe.com");
  // The subject is a program, or a command the agent ran: the whole sentence.
  const program = ask({ where: "file", subject: `open:${cat}`, target: env, held: true });
  assert.deepEqual(program.whatParts, program.sentence);
  assert.equal(text(program.whatParts), "Claude Code's program /usr/bin/cat wants to read a secret file: .env");
  const held = ask({ subject: "session-net:s-1", target: "evil.example", sessionReads: reads, sessionHeld: true, sessionBindings: [] });
  assert.equal(text(held.whatParts), text(held.sentence));
  for (const [name, row] of FAMILIES) assert.ok(ask(row).whatParts.length > 0, `${name}: never empty`);
});

test("A5: Home's waiting ask carries both", () => {
  const NOW = Date.parse("2026-10-22T12:00:00Z");
  const snapshot = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] },
    verdicts: [{
      id: "egr-1", symbol: KEY, destination: "api.stripe.com", status: "pending", reason: "r", count: 1,
      firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, sessions: ["s-claude"], source: { origin: env },
    }],
  } as unknown as PolicySnapshot;
  const vm = buildHomeViewModel({
    sessions: [{ id: "s-claude", label: "Pay", eventCount: 3, firstTs: new Date(NOW - 600_000).toISOString(), lastTs: new Date(NOW - 60_000).toISOString(), violated: false, agent: "claude", status: "running" }],
    facts: new Map(), panel: toPolicyPanelViewModel(snapshot), configuredMode: "secrets", nowMs: NOW, windowHours: 24, historyTotal: 1, home: HOME,
  });
  const w = vm.waiting[0]!;
  assert.equal(w.afterAllow, TRY);
  assert.equal(text(w.whatParts), "send your secret STRIPE_KEY to api.stripe.com");
  assert.ok(!JSON.stringify(w.whatParts).includes("$MDU"), "names, never a placeholder");
});
