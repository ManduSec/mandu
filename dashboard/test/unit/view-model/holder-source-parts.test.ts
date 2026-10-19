/**
 * holder-source-parts.test — dashboard.md §4.25u *Approvals names things
 * whole*. Until 2026-10-16 a program's send listed its files under *What
 * the program holds* from strings only: the file one code (a folder rule's
 * "files in " inside it), the hosts it may go to and the line naming the
 * files left plain text, while the same card's headline and cells name each
 * file and host as code. Now each file also comes as parts, `nameParts` and
 * `mayGoParts`, and the line as `sourcesLeftParts`.
 *
 *   S1  each file's parts are exactly its strings (the strings stay as they
 *       were), with no empty part and no two text parts in a row;
 *   S2  the names are the code parts: the file, each host; a folder rule's
 *       "files in " and "may go to: " / "may go nowhere" are words;
 *   S3  the line naming the files left: the place and each file as code,
 *       exactly `holderLeftWords`; no line, no parts;
 *   S4  Home's view model sends them on the card, `sourcesLeftParts` only
 *       with `sourcesLeft`;
 *   S5  no part is shared between files or with the card's sentence.
 *
 * Pure: the view model over queue rows, no I/O.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { HolderSourceWire, PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";
import { holderLeftParts, holderLeftWords, holderSourceWords, type HomeTextPart } from "../../../src/view-model/ask-words.js";
import { buildHomeViewModel, type HomeInput } from "../../../src/view-model/home.js";

const HOME = "/home/u";
const ENV = "/home/u/ws/app/.env";
const CSV = "/home/u/data/customers.csv";
const KEYS = "/home/u/keys";
const H = "hooks.slack.com";
const SOURCES: HolderSourceWire[] = [
  { path: ENV, level: "no-model", bindings: ["api.stripe.com", "*.amazonaws.com", "db.internal:5432"], blocks: true, always: true },
  { path: CSV, level: "no-model", bindings: [], blocks: true, always: true },
  { path: KEYS, level: "no-model", bindings: [H], blocks: false, always: false, rule: true },
  { path: "/srv/shared/token", via: "/home/u/out/copy.txt", level: "no-model", bindings: ["", "deploy.example.com"], blocks: false, always: false },
];
const text = (parts: HomeTextPart[]): string => parts.map((p) => p.text).join("");
const codes = (parts: HomeTextPart[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);
function wellFormed(parts: HomeTextPart[], what: string): void {
  for (const p of parts) assert.notEqual(p.text, "", `${what}: no empty part`);
  parts.forEach((p, i) => { if (i > 0) assert.ok(!(p.kind === "text" && parts[i - 1]!.kind === "text"), `${what}: no two text parts in a row`); });
}

test("S1: each file's parts are exactly its strings, well formed", () => {
  const words = holderSourceWords(SOURCES, H, HOME);
  assert.equal(words.length, SOURCES.length);
  for (const w of words) {
    assert.equal(text(w.nameParts), w.name, `${w.name}: nameParts read as name`);
    assert.equal(text(w.mayGoParts), w.mayGo, `${w.name}: mayGoParts read as mayGo`);
    wellFormed(w.nameParts, w.name);
    wellFormed(w.mayGoParts, w.mayGo);
  }
  // The strings are as they were.
  assert.deepEqual(words.map((w) => [w.name, w.mayGo]), [
    ["~/ws/app/.env", "may go to: api.stripe.com, *.amazonaws.com, db.internal:5432"],
    ["~/data/customers.csv", "may go nowhere"],
    ["files in ~/keys", `may go to: ${H}`],
    ["/srv/shared/token", "may go to: deploy.example.com"],
  ]);
});

test("S2: the file and each host are the code parts; a folder rule's 'files in' and the rest are words", () => {
  const [env, csv, keys, token] = holderSourceWords(SOURCES, H, HOME);
  assert.deepEqual(env!.nameParts, [{ kind: "code", text: "~/ws/app/.env" }]);
  assert.deepEqual(codes(env!.mayGoParts), ["api.stripe.com", "*.amazonaws.com", "db.internal:5432"]);
  assert.deepEqual(env!.mayGoParts[0], { kind: "text", text: "may go to: " });
  assert.deepEqual(csv!.mayGoParts, [{ kind: "text", text: "may go nowhere" }], "no host: words, never code");
  assert.deepEqual(keys!.nameParts, [{ kind: "text", text: "files in " }, { kind: "code", text: "~/keys" }], "a folder rule: its folder is the name");
  assert.deepEqual(codes(keys!.mayGoParts), [H]);
  assert.deepEqual(token!.nameParts, [{ kind: "code", text: "/srv/shared/token" }], "outside the home: in full");
  assert.deepEqual(codes(token!.mayGoParts), ["deploy.example.com"], "an empty binding is no host");
  assert.equal(token!.via, "~/out/copy.txt", "the copy stays a name the page draws as code");
});

test("S3: the line naming the files left names the place and each file as code, exactly as its words", () => {
  assert.deepEqual(holderLeftParts(SOURCES.slice(0, 2), H, HOME), [], "nothing answered yet: no line, no parts");
  assert.equal(holderLeftWords(SOURCES.slice(0, 2), H, HOME), "");
  assert.deepEqual(holderLeftParts(SOURCES.slice(2), H, HOME), [], "nothing in the way: no line");
  const after = SOURCES;
  const parts = holderLeftParts(after, H, HOME);
  assert.equal(text(parts), holderLeftWords(after, H, HOME));
  assert.equal(text(parts), `The send goes once every file may go to ${H}. Still in the way: ~/ws/app/.env, ~/data/customers.csv.`);
  assert.deepEqual(codes(parts), [H, "~/ws/app/.env", "~/data/customers.csv"]);
  wellFormed(parts, "left");
});

const BARE: PolicySnapshot = { specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__" };
const EXT = { posture: { integrity: false, confidentiality: true }, usage: { rules: [], sensitivePaths: [] } };
const subject = (files: string[]) => `holder-send:${JSON.stringify({ session: "s-1", files: [...files].sort() })}`;
function row(sources: HolderSourceWire[]): VerdictEntry {
  return {
    id: "egr-7", symbol: subject(sources.map((s) => s.path)), destination: H, status: "pending",
    reason: "a program holds files", count: 1, firstSeen: 10, lastSeen: 20, sessions: ["s-1"], holderSources: sources,
  };
}
const homeOf = (sources: HolderSourceWire[]) => {
  const input: HomeInput = {
    sessions: [], facts: new Map(), panel: toPolicyPanelViewModel({ ...BARE, ...EXT, verdicts: [row(sources)] } as PolicySnapshot),
    configuredMode: "secrets", nowMs: 1_000, windowHours: 24, historyTotal: 0, home: HOME,
  };
  return buildHomeViewModel(input).waiting[0]!;
};

test("S4: Home's card sends the parts; the line's parts only with the line", () => {
  const ask = homeOf(SOURCES);
  assert.deepEqual(ask.sources!.map((s) => text(s.nameParts)), ask.sources!.map((s) => s.name));
  assert.deepEqual(ask.sources!.map((s) => codes(s.mayGoParts)), [["api.stripe.com", "*.amazonaws.com", "db.internal:5432"], [], [H], ["deploy.example.com"]]);
  assert.equal(text(ask.sourcesLeftParts!), ask.sourcesLeft);
  assert.deepEqual(codes(ask.sourcesLeftParts!), [H, "~/ws/app/.env", "~/data/customers.csv"]);
  const first = homeOf(SOURCES.slice(0, 2));
  assert.equal(first.sourcesLeft, undefined);
  assert.equal("sourcesLeftParts" in first, false, "no line: no parts");
});

test("S5: no part is shared between the files, the line and the sentence", () => {
  const ask = homeOf(SOURCES);
  const seen = new Set<HomeTextPart>();
  const lists = [ask.sentence, ask.sourcesLeftParts!, ...ask.sources!.flatMap((s) => [s.nameParts, s.mayGoParts])];
  for (const list of lists) for (const p of list) {
    assert.equal(seen.has(p), false, `a part is in two places: ${JSON.stringify(p)}`);
    seen.add(p);
  }
});
