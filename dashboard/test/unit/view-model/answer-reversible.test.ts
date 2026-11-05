/**
 * answer-reversible.test — dashboard.md §4.25 *An answer says what it did*
 * (2026-10-28). The line an answer leaves ended with *Change your answer*
 * after every answer, also where the answered row on Approvals has no
 * button to change it (a held message, Send without it, a HIGH session's
 * ask). The rule of that row's buttons is now one helper,
 * `policy-panel.ts answerHasReversal`, and the waiting ask carries it as
 * `HomeAsk.reversible`, so the page's link and the row cannot disagree:
 *
 *   R1  the helper is true exactly where the answered row's `actions` are
 *       not empty, for every family: a held message's row (`#turn:`, once
 *       and for the session), the session's own row, Send without it, a
 *       HIGH session's ask (`session-net:` / `session-exec:`), a send, a
 *       read, and an answer that no longer applies; the actions themselves
 *       are as before (a refactor);
 *   R2  a waiting ask's `reversible` is the helper over its row: false for
 *       a held message and a HIGH session's ask, true for a send (with
 *       Send without it offered: the page adds that answer's own rule) and
 *       a read.
 *
 * Axes: none (view model only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { answerHasReversal, toPolicyPanelViewModel, type QueueRowVM } from "../../../src/view-model/policy-panel.js";
import { buildHomeViewModel } from "../../../src/view-model/home.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";

const NOW = Date.parse("2026-10-28T00:00:00Z");
const SEND = "$MDU:nomodel_Read[ab12cd34].STRIPE_KEY";
const PROMPT = `prompt:acme.codename#${"a".repeat(32)}`;
const TURN = `model:s-claude#turn:${"b".repeat(32)}`;

function verdict(over: Partial<VerdictEntry>): VerdictEntry {
  return {
    id: "egr-1", symbol: SEND, destination: "api.stripe.com", source: { tool: "Read", origin: "/home/u/shop/.env" },
    status: "approved", reason: "r", count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, resolvedAt: NOW - 60_000,
    sessions: ["s-claude"],
    ...over,
  } as VerdictEntry;
}
function queue(verdicts: VerdictEntry[]): QueueRowVM[] {
  const snapshot = {
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts,
  } as unknown as PolicySnapshot;
  return toPolicyPanelViewModel(snapshot).queue;
}
const helper = (r: QueueRowVM): boolean => answerHasReversal(r);

test("R1: the helper is true exactly where the answered row offers a change, and the actions are as before", () => {
  const cases: Array<[string, Partial<VerdictEntry>, string[]]> = [
    ["a held message, Send as written", { symbol: PROMPT, destination: TURN, status: "approved", scope: "once" }, []],
    ["a held message, Send masked", { symbol: PROMPT, destination: TURN, status: "denied", scope: "once" }, []],
    ["a held message answered for the session (its own row)", { symbol: PROMPT, destination: TURN, status: "approved", scope: "always" }, []],
    ["the session's row of a held message, sent", { symbol: PROMPT, destination: "model:s-claude", status: "approved", scope: "always" }, ["Send masked instead"]],
    ["the session's row of a held message, masked", { symbol: PROMPT, destination: "model:s-claude", status: "denied", scope: "always" }, ["Send as written instead"]],
    ["Send without it", { status: "denied", scope: "once", strip: true }, []],
    ["a HIGH session's network ask", { symbol: "session-net:s-claude", destination: "example.com", status: "approved", scope: "once" }, []],
    ["a HIGH session's command", { symbol: "session-exec:s-claude", destination: "curl example.com", status: "denied" }, []],
    ["a send, allowed", { status: "approved", scope: "always" }, ["Block instead"]],
    ["a send, allowed once", { status: "approved", scope: "once" }, ["Block instead"]],
    ["a send, blocked", { status: "denied" }, ["Allow instead"]],
    ["a read, allowed", { symbol: `open:/usr/bin/cat#${"c".repeat(64)}`, destination: "/home/u/.env", status: "approved", scope: "always" }, ["Block instead"]],
    ["an answer that no longer applies", { symbol: "write:tee", destination: "/home/u/.bashrc", status: "approved", scope: "always", noLongerApplies: "name-only" }, []],
  ];
  const rows = queue(cases.map(([, over], i) => verdict({ ...over, id: `egr-${i}` })));
  cases.forEach(([what, , labels], i) => {
    const r = rows.find((x) => x.id === `egr-${i}`)!;
    assert.deepEqual(r.actions.map((a) => a.label), labels, `${what}: its actions`);
    assert.equal(helper(r), labels.length > 0, `${what}: the helper agrees`);
  });
});

test("R2: a waiting ask is reversible exactly when its answered row would offer a change", () => {
  const waiting = [
    verdict({ id: "prompt", symbol: PROMPT, destination: TURN, status: "pending", resolvedAt: undefined }),
    verdict({ id: "net", symbol: "session-net:s-claude", destination: "example.com", status: "pending", resolvedAt: undefined }),
    verdict({ id: "exec", symbol: "session-exec:s-claude", destination: "curl example.com", status: "pending", resolvedAt: undefined }),
    verdict({ id: "send", status: "pending", resolvedAt: undefined, stripOffered: true }),
    verdict({ id: "read", symbol: `open:/usr/bin/cat#${"c".repeat(64)}`, destination: "/home/u/.env", status: "pending", resolvedAt: undefined }),
  ];
  const panel = toPolicyPanelViewModel({
    specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
    posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] }, verdicts: waiting,
  } as unknown as PolicySnapshot);
  const vm = buildHomeViewModel({ sessions: [], facts: new Map(), panel, configuredMode: "secrets", nowMs: NOW, windowHours: 24, historyTotal: 0, home: "/home/u" });
  const by = new Map(vm.waiting.map((a) => [a.id, a.reversible]));
  assert.deepEqual(Object.fromEntries(by), { prompt: false, net: false, exec: false, send: true, read: true });
  // Answered as the page answers them (no Send without it), each agrees.
  for (const v of waiting) {
    const answered = queue([{ ...v, status: v.id === "prompt" ? "denied" : "approved", resolvedAt: NOW, stripOffered: undefined } as VerdictEntry])[0]!;
    assert.equal(answered.actions.length > 0, by.get(v.id), `${v.id}: the answered row agrees`);
  }
  assert.ok(vm.waiting.find((a) => a.id === "send")!.actions.some((a) => a.strip), "Send without it is offered; the page reads its own rule from the verb");
});
