/**
 * product-words — the product's copy keeps its words (dashboard.md §4.25u):
 * "masked" for what the AI gets in a secret's place, never "placeholder",
 * and "this computer", never "this machine".
 *
 * Contracts:
 *   - every string and template literal of the product page's script
 *     (home.js) and of the session page's sentence builders
 *     (secret-story.ts, agent-page.ts, block-why.ts) holds no retired word.
 *     The literals are read with the TypeScript compiler (js-literals.ts),
 *     so an apostrophe in a comment or a regex cannot shift what counts as
 *     a string (the quote-pairing sweep this replaces could be fooled that
 *     way);
 *   - so does every literal of Home's, Rules' and Approvals' other sentence
 *     builders: the exposure card (human-plane.ts), the posture card and
 *     the chip's reasons (session-health.ts), Where your data lives
 *     (data-locations.ts), a file's readers (reader-runs-code.ts) and a rule
 *     change's sentences (policy-proposals.ts) (2026-10-27), and Home's
 *     lost-route card (attachment-route.ts) (2026-11-04);
 *   - the posture sentences come from the launcher's confinement-posture.ts
 *     (one text with its terminal line, whose other lines keep their own
 *     words), so its tables the dashboard shows are checked, not the file:
 *     every posture's sentence, every partial-layer note and every gap's
 *     own sentence (an OpenClaw attachment's, which the Plugins page, the
 *     session page and History show; 2026-11-04);
 *   - a built exposure card, a gated posture card and a Rules line for a
 *     reader that gets the masked copy say "masked" and no retired word;
 *   - routing keys and rule ids (lower-case words joined by `-` or `:`,
 *     "egress:shell-expanded-placeholder") are not copy and are skipped;
 *   - a session page built from recorded sessions (the walkthrough fixture
 *     with every option, and the tour record) says no retired word on any
 *     card line, step, note, why or summary, so a sentence assembled from
 *     parts is covered too; and every rule the "why it was blocked" note
 *     words says none.
 *
 * Axes: none (pure reads of source text and projections over recorded events).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAgentPage } from "../../../src/view-model/agent-page.js";
import { blockWhy, WHY_RULE_IDS } from "../../../src/view-model/block-why.js";
import { believedEvents, type ManduEvent } from "../../../src/event-model.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import { walkthroughEvents, SESSION } from "./walkthrough-fixture.js";
import { RETIRED, THIS_MACHINE } from "./retired-words.js";
import { literals } from "./js-literals.js";
import { homeExposure, toHumanPlaneVM } from "../../../src/view-model/human-plane.js";
import { secretsPostureNote } from "../../../src/view-model/home.js";
import { GAP_SENTENCE, POSTURES } from "../../../src/confinement-posture.js";
import { SECRETS_PARTIAL_NOTE, SECRETS_SENTENCE } from "../../../src/session-health.js";
import { codeRunningReadersWarning, READS_PLACEHOLDER } from "../../../src/view-model/reader-runs-code.js";
import { changeWarnings, editWords } from "../../../src/view-model/policy-proposals.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** A routing key, an attribute name or a rule id: not copy. */
const KEY = /^[a-z][a-z-]*(:[a-z][a-z-]*)?$/;

/** The retired words `text` holds, if any. */
const retired = (text: string) => text.match(RETIRED)?.[0] ?? text.match(THIS_MACHINE)?.[0] ?? null;

const SOURCES = [
  "public/js/home.js",
  "src/view-model/secret-story.ts",
  "src/view-model/agent-page.ts",
  "src/view-model/block-why.ts",
  "src/view-model/human-plane.ts",
  "src/session-health.ts",
  "src/data-locations.ts",
  "src/view-model/reader-runs-code.ts",
  "src/view-model/policy-proposals.ts",
  "src/view-model/attachment-route.ts",
];

test("the literals are read by the compiler, not by pairing quotes: an apostrophe in a comment or a regex shifts nothing", () => {
  const sample = "// the AI's own words\nconst re = /'/;\nconst a = 'one';\nconst b = `two ${a} three`;\nconst c = \"four\";\n";
  assert.deepEqual(literals("sample.js", sample), [
    { text: "one", line: 3 }, { text: "two ", line: 4 }, { text: " three", line: 4 }, { text: "four", line: 5 },
  ]);
});

for (const rel of SOURCES) {
  test(`${rel}: no string says "placeholder", "this machine", the Inbox or a locked file`, () => {
    const all = literals(join(ROOT, rel));
    assert.ok(all.length > 20, `read the file's literals: ${all.length}`);
    const hits = all.filter((l) => !KEY.test(l.text) && retired(l.text) !== null).map((l) => `${rel}:${l.line}: ${l.text}`);
    assert.deepEqual(hits, []);
  });
}

/** Every string value in `v`, with where it sits. */
function strings(v: unknown, where: string, out: { where: string; text: string }[] = []): { where: string; text: string }[] {
  if (typeof v === "string") out.push({ where, text: v });
  else if (Array.isArray(v)) v.forEach((x, i) => strings(x, `${where}[${i}]`, out));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) strings(x, `${where}.${k}`, out);
  return out;
}

function pageOf(id: string, events: ManduEvent[]) {
  const believed = believedEvents(events);
  return buildAgentPage({ session: null, id, vm: toSessionViewModel(id, events), cwd: null, waiting: [], events: believed, believedVm: toSessionViewModel(id, believed) });
}

const TOUR_ID = "1791164083-1418381";
const TOUR = readFileSync(join(ROOT, "test", "fixtures", `tour-${TOUR_ID}.ndjson`), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as ManduEvent);

/** Where a page holds words that are not Mandu's. */
const OWN_WORDS = /\.(reply|prompt|result|output|input)\b/;

const PAGES: [string, () => ReturnType<typeof pageOf>][] = [
  ["the walkthrough, every option", () => pageOf(SESSION, walkthroughEvents({ refusals: true, readRefusals: true, replyReveal: true, execGates: true, background: true }))],
  ["the walkthrough, no sends", () => pageOf(SESSION, walkthroughEvents({ noNetwork: true, replyReveal: true }))],
  ["the tour record (a block, a send let out, a file read before its label)", () => pageOf(TOUR_ID, TOUR)],
];

for (const [name, build] of PAGES) {
  test(`a session page built from ${name} says "masked" and "this computer" on every card and step`, () => {
    const page = build();
    assert.ok(page.secrets.secrets.length > 0, "the page has its Your secrets cards");
    assert.ok(page.story.some((t) => t.steps.length > 0), "and its steps");
    // Each card line and each step, as the page joins its parts.
    const sentences = [
      ...page.secrets.secrets.flatMap((s) => s.lines.map((l) => l.parts.map((p) => p.text).join(""))),
      ...page.story.flatMap((t) => [t.summary ?? "", ...t.steps.flatMap((s) => (s.kind === "action" ? [s.sentence.map((p) => p.text).join(""), s.note ?? "", (s.why ?? []).map((p) => p.text).join("")] : []))]),
    ].filter(Boolean);
    assert.ok(sentences.some((s) => /masked/.test(s)), sentences.join("\n"));
    assert.deepEqual(sentences.filter((s) => retired(s) !== null), []);
    // …and every other string on it, wherever it sits, but the person's and
    // the AI's own words (a question, a reply, what a tool returned):
    // Mandu shows those as written.
    assert.deepEqual(strings(page, "page").filter((s) => !OWN_WORDS.test(s.where) && !KEY.test(s.text) && retired(s.text) !== null), []);
  });
}

test("every rule the \"why it was blocked\" note words says no retired word", () => {
  assert.ok(WHY_RULE_IDS.length > 20);
  for (const id of WHY_RULE_IDS) {
    for (const ctx of [{ outcome: "blocked" as const, host: "evil.example", carried: 2 }, { outcome: "waiting" as const }]) {
      const why = (blockWhy({ source: "builtin", id }, ctx) ?? []).map((p) => p.text).join("");
      assert.equal(retired(why), null, `${id}: ${why}`);
    }
  }
});

test("the posture card's sentences and partial-layer notes (the launcher's words, shown on Home and the session page) say no retired word", () => {
  for (const p of POSTURES) assert.equal(retired(SECRETS_SENTENCE[p]), null, `${p}: ${SECRETS_SENTENCE[p]}`);
  const notes = Object.entries(SECRETS_PARTIAL_NOTE);
  assert.ok(notes.length >= 2, "the no-guard and guard-off notes");
  for (const [gap, note] of notes) assert.equal(retired(note ?? ""), null, `${gap}: ${note}`);
  assert.match(SECRETS_SENTENCE.confined, /get a masked copy of each credential file, never the real one/);
  assert.match(SECRETS_SENTENCE.gated, /^The AI sees your secrets masked /);
});

test("every gap's own sentence (an OpenClaw attachment's, shown on the Plugins page, the session page and History) says no retired word", () => {
  const gaps = Object.entries(GAP_SENTENCE);
  assert.ok(gaps.length >= 2, "the plugin's and the lost route's");
  for (const [gap, sentence] of gaps) assert.equal(retired(sentence), null, `${gap}: ${sentence}`);
  assert.match(GAP_SENTENCE["openclaw-plugin"]!, /^The AI sees your secrets masked, because every model call goes through Mandu\./);
  assert.match(GAP_SENTENCE["model-route-lost"]!, /the AI can read your secrets as they are, not masked\./);
});

test("a built exposure card, gated posture card, Rules readers line and rule change say \"masked\" and \"this computer\"", () => {
  const exposure = homeExposure(toHumanPlaneVM({ exposed: true, since: 1, launches: [{ pid: 4242, mode: "off", posture: "off", session: "claude-x1", begunAt: 0 }] }))!;
  const posture = secretsPostureNote({ posture: "gated", gap: "no-guard", sentence: SECRETS_SENTENCE.gated }, "home")!;
  const warning = codeRunningReadersWarning(["deploy"])!;
  const prompt = editWords({ op: "set-prompt-action", category: "api-keys", action: "mask" }, "/home/u").map((p) => p.text).join("");
  const far = changeWarnings([{ op: "add-model", name: "lab", url: "http://203.0.113.9:8000", local: true }])[0]!.map((p) => p.text).join("");
  const copy: [string, string, RegExp][] = [
    ["exposure", [exposure.headline, exposure.sentence, exposure.fix].join(" "), /get masked copies of secret files/],
    ["posture", [posture.headline, posture.sentence, posture.note ?? ""].join(" "), /The AI sees your secrets masked/],
    ["readers", `deploy${READS_PLACEHOLDER} ${warning}`, /deploy \(reads the masked copy\) .*so it reads the masked copy\./],
    ["prompt filter", prompt, /^In your prompts, api-keys is masked, as a short code the AI can still use$/],
    ["far model", far, /is not on this computer or a private network address/],
  ];
  for (const [what, text, says] of copy) {
    assert.match(text, says, `${what}: ${text}`);
    assert.equal(retired(text), null, `${what}: ${text}`);
  }
});
