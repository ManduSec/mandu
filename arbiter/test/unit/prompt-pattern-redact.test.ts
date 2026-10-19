/**
 * prompt-pattern-redact.test — the data socket's policy reads with every
 * prompt exception's pattern taken out (policy/prompt-pattern-redact.ts;
 * confidentiality-plan-15-prompt-filter.md §13.7 item 4). Pure.
 *
 * Proves: the policy file's text loses only the `match:` values of its
 * `prompt_filters:` block (block, flow, quoted, plain) and the patterns a
 * comment repeats, byte for byte elsewhere (a `match:` outside the block
 * stays); a text the scan cannot edit provably is rebuilt from the redacted
 * parse; the document, the admin layer's view, the messages, an exception
 * edit and its delta line carry the placeholder and `patternHidden`; a
 * document with no exception is answered unchanged; the validator refuses
 * the placeholder as a pattern and the flag as a key, so nothing built from
 * a data-socket read can be written back over a stored pattern.
 *
 * Axes: none is pinned (no arbiter; pure functions).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import yaml from "js-yaml";

import {
  PROMPT_PATTERN_PLACEHOLDER as PH,
  redactChange,
  redactDelta,
  redactEdit,
  redactPolicyDocument,
  redactPolicyDocumentResult,
  redactPolicyText,
  redactProposal,
} from "../../policy/prompt-pattern-redact.js";
import { checkPromptFilters } from "../../prompt-filter/policy.js";

const WORDS = "*@my-own-private-words.example";
const CODE = "falcon ridge";

const TEXT = [
  "version: 1",
  "# my rules",
  "lists:",
  "  docs: [https://a.example/]",
  "prompt_filters:",
  "  actions:",
  "    pii.email: mask",
  "  exceptions:",
  `    - { category: pii.email, match: '${WORDS}' }   # mail to ${WORDS} is fine`,
  "    - category: acme.codename",
  `      match: ${CODE}`,
  "    - category: acme.ticket",
  '      match: "ACME-2*"',
  "user_rules:",
  "  - { id: r-0001, kind: release, to: { host: '*' }, mode: block, match: keep-me }",
  "",
].join("\n");

const parse = (t: string): unknown => yaml.load(t);

test("the file's text: only the exceptions' match values (and comments repeating them) change, byte for byte elsewhere", () => {
  const parsed = parse(TEXT);
  const r = redactPolicyText(TEXT, parsed, [WORDS, CODE, "ACME-2*"]);
  assert.equal(r.rebuilt, false);
  for (const p of [WORDS, CODE, "ACME-2*"]) assert.ok(!r.text.includes(p), `${p} is gone: ${r.text}`);
  const before = TEXT.split("\n");
  const after = r.text.split("\n");
  assert.equal(after.length, before.length);
  for (const i of [0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 13, 14]) assert.equal(after[i], before[i], `line ${i} is untouched`);
  assert.equal(after[8], `    - { category: pii.email, match: '${PH}' }   # mail to ${PH} is fine`);
  assert.equal(after[10], `      match: '${PH}'`);
  assert.equal(after[12], `      match: '${PH}'`);
  assert.ok(r.text.includes("match: keep-me"), "a match: outside prompt_filters stays");
  const back = parse(r.text) as { prompt_filters: { exceptions: Array<{ match: string }> } };
  assert.deepEqual(back.prompt_filters.exceptions.map((e) => e.match), [PH, PH, PH]);
});

test("a text the scan cannot prove is rebuilt from the redacted parse; no exception means no change", () => {
  // JSON-style keys: the scan finds no `match:` to edit, so the parse proves it missed one.
  const aliased = `version: 1\nprompt_filters:\n  exceptions:\n    - {"category": "pii.email", "match": "${WORDS}"}\n`;
  const r = redactPolicyText(aliased, parse(aliased), [WORDS]);
  assert.equal(r.rebuilt, true);
  assert.ok(!r.text.includes("my-own-private-words"), r.text);
  assert.deepEqual((parse(r.text) as { prompt_filters: { exceptions: Array<{ match: string }> } }).prompt_filters.exceptions[0]!.match, PH);
  const plain = "version: 1\nlists:\n  docs: [https://a.example/]\n";
  assert.deepEqual(redactPolicyText(plain, parse(plain), []), { text: plain, rebuilt: false });
});

test("the policyDocument answer: document, parse, admin layer and messages carry the placeholder and the flag", () => {
  const parsed = parse(TEXT);
  const result = {
    status: { path: "/p", found: true, valid: true, problems: [`exceptions[0].match: '${WORDS}' is odd`], loadedAt: 1, refusedAt: null },
    inForce: parsed,
    onDisk: { text: TEXT, parsed, problems: [], warnings: [] },
    admin: { files: ["/etc/mandu/policy.d/10-org.yaml"], locked: false, models: [], perimeter: null, perimeterFile: null, conflicts: [`not in force: ${CODE}`], refused: [], promptFilters: [{ file: "/etc/mandu/policy.d/10-org.yaml", config: { exceptions: [{ category: "acme.x", match: "admin-words" }] } }] },
  };
  const out = redactPolicyDocumentResult(result, ["admin-words"]);
  const json = JSON.stringify(out);
  for (const p of [WORDS, CODE, "ACME-2*", "admin-words"]) assert.ok(!json.includes(p), `${p} is nowhere in the data answer`);
  assert.equal(out.patternsHidden, true);
  const inForce = out.inForce as { prompt_filters: { exceptions: Array<Record<string, unknown>> }; user_rules: unknown; lists: unknown };
  assert.deepEqual(inForce.prompt_filters.exceptions[0], { category: "pii.email", match: PH, patternHidden: true });
  assert.deepEqual(inForce.user_rules, (parsed as { user_rules: unknown }).user_rules, "the rest is as it was");
  assert.deepEqual(Object.keys(inForce), Object.keys(parsed as object), "the keys keep their order");
  assert.ok(JSON.stringify(result).includes(WORDS), "the input is not changed");
  assert.deepEqual(redactPolicyDocument(null), null);
  const noExc = { version: 1, lists: {} };
  assert.equal(redactPolicyDocument(noExc), noExc);
});

test("an exception edit and its delta line: the placeholder and the flag; any other edit or line as it was", () => {
  assert.deepEqual(redactEdit({ op: "add-prompt-exception", category: "pii.email", match: WORDS }), { op: "add-prompt-exception", category: "pii.email", match: PH, patternHidden: true });
  assert.deepEqual(redactEdit({ op: "remove-prompt-exception", category: "pii.email", match: WORDS }), { op: "remove-prompt-exception", category: "pii.email", match: PH, patternHidden: true });
  const lock = { op: "lock-path", path: "/x.pem", level: "no-model" };
  assert.equal(redactEdit(lock), lock);
  const relax = { facet: "prompt-filters", direction: "relax" as const, subject: "prompt exception pii.email", detail: `findings of pii.email matching ${WORDS} are let through` };
  assert.deepEqual(redactDelta(relax), { ...relax, detail: `findings of pii.email matching ${PH} are let through`, patternHidden: true });
  const tighten = { ...relax, direction: "tighten" as const, detail: `findings of pii.email matching ${WORDS} are no longer let through` };
  assert.equal(redactDelta(tighten).detail, `findings of pii.email matching ${PH} are no longer let through`);
  const other = { facet: "paths", direction: "relax" as const, subject: "/x", detail: "less" };
  assert.equal(redactDelta(other), other);
  const p = redactProposal({ id: "pp-1", edits: [{ op: "add-prompt-exception", category: "pii.email", match: WORDS }], relaxes: [relax], tightens: [] });
  assert.ok(!JSON.stringify(p).includes("private-words"));
  const c = redactChange({ id: "pc-1", edits: [], delta: [tighten] });
  assert.ok(!JSON.stringify(c).includes("private-words"));
});

test("WRITES: the validator refuses the placeholder as a pattern and patternHidden as a key", () => {
  const problems = (pf: unknown): string[] => { const out: string[] = []; checkPromptFilters(pf, "prompt_filters", out); return out; };
  assert.deepEqual(problems({ exceptions: [{ category: "pii.email", match: WORDS }] }), []);
  assert.ok(problems({ exceptions: [{ category: "pii.email", match: PH }] }).some((m) => /placeholder a data-socket read shows/.test(m)));
  assert.ok(problems({ exceptions: [{ category: "pii.email", match: PH, patternHidden: true }] }).some((m) => /unknown key 'patternHidden'/.test(m)));
});
