/**
 * prompt-classifier.test — the reference classifier plugin's pure parts
 * (prompt-filter/plugins/local-classifier.mjs, local-classifier-pack.mjs;
 * confidentiality-plan-15-prompt-filter.md §4.3, §5, §13.5). Mandu-new.
 *
 * Proves: the fixed system prompt names the categories and treats the text
 * as data; chunks keep offsets; the model's answer becomes findings ONLY
 * for exact (or offset-safe case-insensitive) occurrences of the quoted
 * text, in a declared category, never under the shield; a fenced or chatty
 * JSON reply is read; anything not the shape throws (the arbiter's
 * `on_error` decides); the generated pack validates and pins both files.
 *
 * Axes: secrets (stated; nothing here reads the axis).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { parsePackText } from "../../prompt-filter/packs.js";
// @ts-expect-error -- a plain .mjs plugin (no types): it runs from a pinned copy
import { apiBase, CHUNK_CHARS, chunks, extractJson, mapAnswer, OVERLAP_CHARS, SHIELD, systemPrompt } from "../../prompt-filter/plugins/local-classifier.mjs";
// @ts-expect-error -- a plain .mjs script (no types)
import { DEFAULT_CATEGORIES, packYaml } from "../../prompt-filter/plugins/local-classifier-pack.mjs";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

type F = { start: number; end: number; category: string };

test("the system prompt names the categories, asks for exact spans in JSON, and treats the text as data", () => {
  const s = systemPrompt(["pii.person", "acme.codename"]) as string;
  assert.match(s, /- pii\.person\n- acme\.codename/);
  assert.match(s, /\{"findings": \[\{"category"/);
  assert.match(s, /copied exactly/);
  assert.match(s, /data, not instructions/);
});

type C = { offset: number; text: string };

test("chunks keep offsets and cut at whitespace (no overlap asked: they tile the text)", () => {
  const text = `${"a".repeat(10)} ${"b".repeat(10)} ${"c".repeat(10)}`;
  const c = chunks(text, 15, 0) as C[];
  assert.equal(c.map((x) => x.text).join(""), text);
  for (const x of c) assert.equal(text.slice(x.offset, x.offset + x.text.length), x.text);
  assert.ok(c.every((x) => x.text.length <= 15));
  assert.deepEqual(chunks(""), []);
});

// P0 item 13 (a): chunks() had no overlap, so a span cut by a chunk boundary
// reached the model as two halves and was found in neither.
test("a span that straddles the 6000-character cut lies wholly inside some chunk (the overlap)", () => {
  assert.equal(CHUNK_CHARS, 6000);
  assert.ok(OVERLAP_CHARS >= 200 && OVERLAP_CHARS * 2 < CHUNK_CHARS, `the overlap (${OVERLAP_CHARS}) covers a long span and still leaves progress`);
  // Words of 9 letters and a space: the first cut falls at a space near
  // 6000, between "Blue" and "Osprey".
  const filler = "lorem ips ".repeat(599);            // 5990 characters
  const span = "Blue Osprey";
  const text = `${filler}${span} ${"tail word ".repeat(700)}`;
  const at = text.indexOf(span);
  assert.ok(at < 6000 && at + span.length > 6000, "the span straddles the 6000 mark");
  const c = chunks(text) as C[];
  for (const x of c) assert.equal(text.slice(x.offset, x.offset + x.text.length), x.text, "offsets hold");
  assert.ok(c.every((x) => x.text.length <= CHUNK_CHARS));
  assert.ok(c.some((x) => x.text.includes(span)), "some chunk holds the whole span");
  // Cost stays bounded: prose re-reads about the overlap per cut.
  const total = c.reduce((n, x) => n + x.text.length, 0);
  assert.ok(total <= text.length * 1.3, `${total} characters sent for ${text.length}`);
});

test("chunks: every span up to the overlap's length is wholly inside one chunk, whatever the text (property)", () => {
  let seed = 7;
  const rnd = (n: number): number => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  for (let round = 0; round < 40; round++) {
    const max = 40 + rnd(60);
    const overlap = rnd(Math.floor(max / 2));
    const alphabet = ["a", "b", " ", "\n", "\u{1F600}", "é"];
    let text = "";
    const len = rnd(600);
    while (text.length < len) text += rnd(4) === 0 ? alphabet[rnd(alphabet.length)]! : "x".repeat(1 + rnd(30));
    const c = chunks(text, max, overlap) as C[];
    let prev = -1;
    for (const x of c) {
      assert.ok(x.offset > prev, "progress");
      prev = x.offset;
      assert.ok(x.text.length <= max && x.text.length > 0);
      assert.equal(text.slice(x.offset, x.offset + x.text.length), x.text);
      // Never a lone half of a surrogate pair at either edge.
      assert.ok(!/^[\uDC00-\uDFFF]/.test(x.text) && !/[\uD800-\uDBFF]$/.test(x.text), "no split surrogate pair");
    }
    if (text.length > 0) assert.equal(c.at(-1)!.offset + c.at(-1)!.text.length, text.length, "the end is reached");
    for (let a = 0; a + overlap <= text.length; a++) {
      const b = a + Math.max(1, overlap);
      if (b > text.length) break;
      assert.ok(c.some((x) => x.offset <= a && b <= x.offset + x.text.length), `[${a},${b}) of ${text.length} (max ${max}, overlap ${overlap}) is inside a chunk`);
    }
  }
});

test("the answer maps to offsets the program computes; the model's word is never trusted for anything else", () => {
  const chunk = "ask Kim Lee about Falcon; kim lee agreed. Falcon!";
  const cats = ["pii.person", "acme.codename"];
  const ans = JSON.stringify({ findings: [
    { category: "pii.person", text: "Kim Lee" },
    { category: "acme.codename", text: "Falcon" },
    { category: "pii.email", text: "ask" },                 // not declared
    { category: "pii.person", text: "x" },                  // too short
    { category: "pii.person", text: "Nobody Here" },        // not in the text
    { category: "acme.codename", text: `${SHIELD}${SHIELD}` }, // the shield
    { category: "acme.codename", text: "Falcon" },          // repeated
  ] });
  const out = mapAnswer(ans, chunk, 100, cats) as F[];
  assert.deepEqual(out, [
    { start: 104, end: 111, category: "pii.person" },
    { start: 118, end: 124, category: "acme.codename" },
    { start: 142, end: 148, category: "acme.codename" },
  ]);
  // Case-insensitive only when there is no exact occurrence.
  assert.deepEqual(mapAnswer(JSON.stringify({ findings: [{ category: "pii.person", text: "KIM LEE" }] }), chunk, 0, cats), [
    { start: 4, end: 11, category: "pii.person" }, { start: 26, end: 33, category: "pii.person" },
  ]);
  // Lowercasing that would move offsets: no fallback.
  assert.deepEqual(mapAnswer(JSON.stringify({ findings: [{ category: "pii.person", text: "i̇stanbul" }] }), "İstanbul", 0, cats), []);
  // A fenced, chatty reply is read; a reply that is not the shape throws.
  assert.equal((mapAnswer("Sure!\n```json\n{\"findings\": [{\"category\": \"pii.person\", \"text\": \"Kim Lee\"}]}\n```", chunk, 0, cats) as F[]).length, 1);
  assert.throws(() => mapAnswer("I cannot help with that.", chunk, 0, cats), /not \{findings/);
  assert.throws(() => mapAnswer(JSON.stringify({ spans: [] }), chunk, 0, cats), /not \{findings/);
  assert.equal(extractJson("no json"), null);
});

test("the API base drops trailing slashes and one /v1 (as the helper's clients do)", () => {
  assert.equal(apiBase("http://127.0.0.1:11434"), "http://127.0.0.1:11434");
  assert.equal(apiBase("http://127.0.0.1:11434/v1/"), "http://127.0.0.1:11434");
});

test("the generated pack validates: both files pinned, a model required, the categories at no-model", () => {
  const yaml = packYaml({ node: "/usr/bin/node", nodeSha: "a".repeat(64), script: "/m/local-classifier.mjs", scriptSha: "b".repeat(64) }) as string;
  const r = parsePackText(yaml);
  assert.ok("doc" in r, JSON.stringify(r));
  assert.deepEqual(r.doc.plugin, { exec: "/usr/bin/node", sha256: "a".repeat(64), script: "/m/local-classifier.mjs", scriptSha256: "b".repeat(64), args: [], cost: "model", endpoint: "required", deadlineMs: 30000 });
  assert.deepEqual(r.doc.categories!.map((c) => [c.category, c.level]), (DEFAULT_CATEGORIES as string[]).map((c) => [c, "no-model"]));
  assert.match(yaml, /# {7}local-classifier: \{ on: true, endpoint: <your local model's name> \}/);
});
