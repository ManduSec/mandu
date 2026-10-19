/**
 * holder-send-asks.test — a program's send of the secret files it holds
 * (confidentiality plan 13 §5.4, §9 R2; dashboard.md §4.34 "A send names
 * every file"): the arbiter's `holder-send:` row with its read-time
 * `holderSources` becomes a card that names every file, where each may go
 * and which are in the way, with Allow once, Allow this session (only when
 * the row names its session) and Block, and one *Always* per file in the
 * way. Pins: the family, the sentence and cells, the per-file words and
 * buttons, the "still in the way" line after one Always, the answered row's
 * plain words, the product vocabulary.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { toPolicyPanelViewModel, verdictFamily } from "../../../src/view-model/policy-panel.js";
import type { HolderSourceWire, PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import { describeAsk, holderLeftWords, holderSendOf, holderSourceWords } from "../../../src/view-model/ask-words.js";
import { buildHomeViewModel, type HomeInput } from "../../../src/view-model/home.js";

const BARE: PolicySnapshot = { specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__" };
const EXT = { posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] } };
const ENV = "/home/u/ws/app/.env";
const CSV = "/home/u/data/customers.csv";
const H = "hooks.slack.com";
const subject = (session: string | null, files: string[]) => `holder-send:${JSON.stringify({ session, files: [...files].sort() })}`;
const SOURCES: HolderSourceWire[] = [
  { path: ENV, level: "no-model", bindings: ["api.stripe.com", "*.amazonaws.com"], blocks: true, always: true },
  { path: CSV, level: "no-model", bindings: [], blocks: true, always: true },
];

function row(over: Partial<VerdictEntry> = {}): VerdictEntry {
  return {
    id: "egr-7", symbol: subject("s-1", [ENV, CSV]), destination: H, status: "pending",
    reason: "python3 holds …; hooks.slack.com is not a place all of it may go (plan 13 §5.4)", count: 1, firstSeen: 10, lastSeen: 20,
    sessions: ["s-1"], holderSources: SOURCES,
    ...over,
  };
}
const text = (parts: { text: string }[]): string => parts.map((p) => p.text).join("");
const panel = (rows: VerdictEntry[]) => toPolicyPanelViewModel({ ...BARE, ...EXT, verdicts: rows } as PolicySnapshot);

test("the key names the session and the files; the family is a send", () => {
  assert.deepEqual(holderSendOf(subject("s-1", [ENV, CSV])), { session: "s-1", files: [CSV, ENV] });
  assert.deepEqual(holderSendOf(subject(null, [ENV])), { session: null, files: [ENV] });
  assert.equal(holderSendOf("session-net:s-1"), null);
  assert.equal(holderSendOf("holder-send:{"), null);
  assert.equal(verdictFamily(subject("s-1", [ENV])), "network");
});

test("the card names every file and the place; the files in the way say why; the answers are once, this session, block", () => {
  const q = panel([row()]).queue[0]!;
  assert.deepEqual(q.actions, [
    { approve: true, scope: "once", label: "Allow once" },
    { approve: true, label: "Allow this session" },
    { approve: false, label: "Block" },
  ], "no generic Always allow: the Always is one per file, a rule change");
  assert.equal(q.mintable, null);
  assert.equal(q.holderSources?.length, 2, "the files ride on the row");
  const w = q.words as { family: string; sentence: { kind: string; text: string }[]; why: string; aiNow: string; ifAllowed: string };
  assert.equal(w.family, "send");
  assert.equal(text(w.sentence), `The agent's program wants to send data from ${CSV} and ${ENV} to ${H}`);
  assert.ok(w.sentence.some((p) => p.kind === "code" && p.text === H));
  assert.equal(w.why, `A program that read these files may send only where every one of them may go, and ${ENV}, ${CSV} may not go to ${H}.`);
  assert.equal(w.aiNow, `The AI's program has not sent anything: Mandu refused its connection to ${H}.`);
  assert.match(w.ifAllowed, /^Allow once lets the program's next connection to hooks\.slack\.com go, with what it read\. Allow this session lets it go for the rest of this session\. Always adds hooks\.slack\.com to where one file may be sent; once every file may go there, the program sends without asking\. After you answer, tell the agent to try again\.$/);
  for (const s of [text(w.sentence), w.why, w.aiNow, w.ifAllowed]) {
    assert.doesNotMatch(s, /\$MDU|symbol|egress|invariant|binding|placeholder/i, "the product's words only");
  }
});

test("a row with no session offers no Allow this session (the arbiter keeps an Always as once)", () => {
  const q = panel([row({ symbol: subject(null, [ENV, CSV]) })]).queue[0]!;
  assert.deepEqual(q.actions.map((a) => a.label), ["Allow once", "Block"]);
  assert.doesNotMatch(String(q.words.ifAllowed), /this session/);
});

test("one line per file: where it may go, whether it is in the way, its Always or why it has none", () => {
  const words = holderSourceWords([
    ...SOURCES,
    { path: "/home/u/keys/id_ed25519", level: "no-model", bindings: [], blocks: true, always: false, noAlways: "folder-rule" },
    { path: "/home/u/ws/app/.env", via: "/home/u/out/copy.txt", level: "no-model", bindings: [H], blocks: false, always: false },
  ], H, "/home/u");
  assert.deepEqual(words[0], {
    path: ENV, name: "~/ws/app/.env", nameParts: [{ kind: "code", text: "~/ws/app/.env" }],
    mayGo: "may go to: api.stripe.com, *.amazonaws.com",
    mayGoParts: [{ kind: "text", text: "may go to: " }, { kind: "code", text: "api.stripe.com" }, { kind: "text", text: ", " }, { kind: "code", text: "*.amazonaws.com" }],
    blocks: true, always: `Always: add ${H} to .env`,
  });
  assert.deepEqual(words[1], {
    path: CSV, name: "~/data/customers.csv", nameParts: [{ kind: "code", text: "~/data/customers.csv" }],
    mayGo: "may go nowhere", mayGoParts: [{ kind: "text", text: "may go nowhere" }],
    blocks: true, always: `Always: add ${H} to customers.csv`,
  });
  assert.equal(words[2]!.always, undefined, "a folder rule takes no Always from here");
  assert.match(words[2]!.noAlways!, /covers a whole folder.*Change it under Rules\./);
  assert.deepEqual([words[3]!.via, words[3]!.blocks, words[3]!.always], ["~/out/copy.txt", false, undefined], "a copy is named by its source; a file not in the way has no button");
  for (const w of words) assert.doesNotMatch(JSON.stringify(w), /placeholder|binding|symbol/i);
});

test("after one Always: the bound file is no longer in the way, and the card says which are left", () => {
  const after: HolderSourceWire[] = [{ ...SOURCES[0]!, bindings: [...SOURCES[0]!.bindings, H], blocks: false, always: false }, SOURCES[1]!];
  assert.equal(holderLeftWords(SOURCES, H, "/home/u"), "", "nothing answered yet: no line");
  assert.equal(holderLeftWords(after, H, "/home/u"), `The send goes once every file may go to ${H}. Still in the way: ~/data/customers.csv.`);
  const q = panel([row({ holderSources: after })]).queue[0]!;
  assert.equal(q.words.why, `A program that read these files may send only where every one of them may go, and ${CSV} may not go to ${H}.`, "only the file left is named");
  const input: HomeInput = {
    sessions: [], facts: new Map(), panel: panel([row({ holderSources: after })]), configuredMode: "secrets", nowMs: 1_000, windowHours: 24, historyTotal: 0, home: "/home/u",
  };
  const ask = buildHomeViewModel(input).waiting[0]!;
  assert.equal(text(ask.sentence), `The agent's program wants to send data from ~/data/customers.csv and ~/ws/app/.env to ${H}`);
  assert.deepEqual(ask.sources!.map((s) => [s.name, s.blocks, s.always ?? null]), [["~/ws/app/.env", false, null], ["~/data/customers.csv", true, `Always: add ${H} to customers.csv`]]);
  assert.equal(ask.sourcesLeft, `The send goes once every file may go to ${H}. Still in the way: ~/data/customers.csv.`);
});

test("an answered row reads as the session's answer for those files; no files are attached to it", () => {
  const q = panel([row({ status: "approved", resolvedAt: 30, scope: "always", holderSources: undefined })]).queue[0]!;
  assert.equal(q.holderSources, undefined);
  assert.deepEqual(q.plain, {
    subject: H,
    reach: `a program in one session sending data from ${CSV}, ${ENV}`,
    // Each file a code (§4.25u, *Rules names what a send covers*).
    reachParts: [{ kind: "text", text: "a program in one session sending data from " }, { kind: "code", text: CSV }, { kind: "text", text: ", " }, { kind: "code", text: ENV }],
    effect: q.plain.effect,
  });
  assert.equal(text(describeAsk({ where: "network", subject: row().symbol, target: H, reason: "" }, "Claude Code").sentence), `Claude Code's program wants to send data from ${CSV} and ${ENV} to ${H}`);
});
