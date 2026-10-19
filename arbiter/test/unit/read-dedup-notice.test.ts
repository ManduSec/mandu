/**
 * read-dedup-notice.test.ts — confidentiality.md §7.1, "The Read dedup
 * notice" (tour item 5). Claude Code answers a re-Read of an unchanged file
 * with its own fixed sentence instead of the file. The confidentiality
 * derivation masked it at the file's path-derived level, so the model got a
 * symbol standing for the harness's words and quoted it as the file. The
 * notice holds no file byte: a result that is EXACTLY a dedup shape is
 * public; anything else a Read of a secret path returns keeps the mask.
 *
 * Unit level: the predicate (`isReadDedupNotice`) and the engine's classify
 * verdict. The real-proxy half: tests/stack/read-dedup-notice.test.ts.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { isReadDedupNotice } from "../../policy/claude-code-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const WASTED = "Wasted call — file unchanged since your last Read. Refer to that earlier tool_result instead.";
const UNCHANGED =
  "File unchanged since last read. The content from the earlier Read tool_result in this conversation is still current — refer to that instead of re-reading.";
const seeded = (p: string) =>
  `<system-reminder>This file is already in your context (see "Contents of ${p}" above) and has not changed on disk. Use that content instead of re-reading.</system-reminder>`;
const EMPTY_FILE = "<system-reminder>Warning: the file exists but the contents are empty.</system-reminder>";
const SHORT_FILE =
  "<system-reminder>Warning: the file exists but is shorter than the provided offset (40). The file has 12 lines.</system-reminder>";
const BUDGET = "<system-reminder>\n<total_tokens>14000 tokens left</total_tokens>\n</system-reminder>";
const SECRET = "/ws/.env"; // a catalog secret path: no-model by the path alone
const FILE_READ = "     1\tSTRIPE_KEY=sk_live_FakeDedup0123456789abcdef\n";

const policy = () => createEngineBackedPolicy({ policyFileOverride: {}, confidentiality: true, integrity: false });
const readOf = (p: ReturnType<typeof policy>, value: string, file_path = SECRET) =>
  p.classify({ tool: "Read", value, boundary: "model_context", origin: file_path, params: { file_path } });

test("isReadDedupNotice: the two 'file unchanged' sentences and the seeded form naming the call's own path, exactly", () => {
  for (const v of [WASTED, UNCHANGED, `${WASTED}\n`, `\n${UNCHANGED}\n\n`]) {
    assert.equal(isReadDedupNotice(v, "Read", { file_path: SECRET }), true, JSON.stringify(v));
  }
  assert.equal(isReadDedupNotice(WASTED, "Read", undefined), true, "the sentences need no params");
  assert.equal(isReadDedupNotice(seeded(SECRET), "Read", { file_path: SECRET }), true);
});

test("isReadDedupNotice: anything appended, a lookalike, another tool, another path, a length warning → false", () => {
  const no: Array<[string, string, Record<string, unknown> | undefined]> = [
    [`${WASTED}\n${FILE_READ}`, "Read", { file_path: SECRET }],
    [`${FILE_READ}${WASTED}`, "Read", { file_path: SECRET }],
    [`${WASTED} sk_live_FakeDedup0123456789abcdef`, "Read", { file_path: SECRET }],
    [WASTED.replace("—", "-"), "Read", { file_path: SECRET }],
    [WASTED.toLowerCase(), "Read", { file_path: SECRET }],
    [`     1\t${WASTED}`, "Read", { file_path: SECRET }],
    [`${WASTED}\n\n${BUDGET}`, "Read", { file_path: SECRET }],
    [`${seeded(SECRET)}\n\n${BUDGET}`, "Read", { file_path: SECRET }],
    [seeded("/ws/other.env"), "Read", { file_path: SECRET }],
    [seeded(SECRET), "Read", undefined],
    [seeded(""), "Read", { file_path: "" }],
    [EMPTY_FILE, "Read", { file_path: SECRET }],
    [SHORT_FILE, "Read", { file_path: SECRET }],
    [WASTED, "Bash", { command: `cat ${SECRET}` }],
    [WASTED, "read", { filePath: SECRET }],
    [WASTED, "mcp__fs__Read", { file_path: SECRET }],
    ["", "Read", { file_path: SECRET }],
  ];
  for (const [v, tool, params] of no) assert.equal(isReadDedupNotice(v, tool, params), false, `${tool}: ${JSON.stringify(v)}`);
});

test("classify (secrets): a Read of a secret path is masked; its dedup notice is public", () => {
  const p = policy();
  const file = readOf(p, FILE_READ);
  assert.equal(file.confidentiality, "no-model", "the file itself: the path-derived level");
  for (const v of [WASTED, UNCHANGED, seeded(SECRET)]) {
    const r = readOf(p, v);
    assert.equal(r.confidentiality, "public", JSON.stringify(v));
    assert.match(r.reason, /read dedup notice/);
  }
});

test("classify (secrets): every near-notice Read of a secret path keeps the path-derived mask (fail-closed)", () => {
  const p = policy();
  for (const v of [
    `${WASTED}\n${FILE_READ}`,
    `${FILE_READ}${WASTED}`,
    WASTED.replace("—", "-"),
    `     1\t${WASTED}`,
    `${WASTED}\n\n${BUDGET}`,
    seeded("/ws/other.env"),
    EMPTY_FILE,
    SHORT_FILE,
  ]) {
    assert.equal(readOf(p, v).confidentiality, "no-model", JSON.stringify(v));
  }
  // the same sentence from a tool that is not Claude Code's Read
  const bash = p.classify({ tool: "Bash", value: WASTED, boundary: "model_context", params: { command: `cat ${SECRET}` } });
  assert.equal(bash.confidentiality, "no-model", "a Bash result naming the secret path stays masked");
  // a field-addressed request is never the whole result
  const field = p.classify({ tool: "Read", value: WASTED, field: "content", boundary: "model_context", origin: SECRET, params: { file_path: SECRET } });
  assert.equal(field.confidentiality, "no-model", "field-addressed: no release");
});
