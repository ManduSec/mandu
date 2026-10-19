/**
 * retired-level-names.test — the level names retired on 2026-09-27 are
 * refused in policy.yaml, with no translation (confidentiality.md
 * §5), and a lock spelled with one can never compile to nothing.
 *
 * Pure policy-document logic: no protection axis is exercised.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LEVELS, loadPolicyFileStrict, PolicyFileError, RETIRED_LEVELS, validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { loadPolicyFile } from "../../policy/load-policy.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is exercised

const OLD_STRICT = ["secret", "strict"].join("-");
const OLD_MODEL_OK = ["secret", "model-ok"].join("-");
const SILENT = { info: () => {}, warn: () => {} };

test("the four levels are the whole enum; the old names are not in it", () => {
  assert.deepEqual([...LEVELS], ["public", "any-model", "local-model", "no-model"]);
  assert.ok(!LEVELS.has(OLD_STRICT) && !LEVELS.has(OLD_MODEL_OK));
});

test("the validator refuses an old name, naming the entry and the levels it accepts", () => {
  for (const old of [OLD_STRICT, OLD_MODEL_OK]) {
    const doc = { version: 1, paths: [{ path: "/h/contract.md", level: old }] };
    const problems = validatePolicyDocument(doc);
    assert.equal(problems.length, 1, problems.join("\n"));
    assert.match(problems[0]!, /^paths\[0\]\.level/);
    assert.match(problems[0]!, /no-model/);
    assert.equal(doc.paths[0]!.level, old, "the document is not rewritten");
  }
});

test("the refusal names the replacement for each retired name, and only for those", () => {
  const problem = (level: unknown) => validatePolicyDocument({ version: 1, paths: [{ path: "/h/c.md", level }] })[0]!;
  assert.match(problem(OLD_STRICT), /retired on 2026-09-27, write no-model\)$/);
  assert.match(problem(OLD_MODEL_OK), /retired on 2026-09-27, write any-model\)$/);
  assert.deepEqual([...RETIRED_LEVELS.values()].filter((v) => !LEVELS.has(v)), [], "every replacement is a current level");
  assert.ok([...RETIRED_LEVELS.keys()].every((k) => !LEVELS.has(k)), "a retired name is never accepted");
  assert.doesNotMatch(problem("secret"), /retired/);
  assert.doesNotMatch(problem(7), /retired/);
});

test("the strict loader (the daemon's start) refuses a file with an old name", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-retired-levels-"));
  try {
    const file = join(dir, "policy.yaml");
    writeFileSync(file, `version: 1\npaths:\n  - path: /h/contract.md\n    level: ${OLD_STRICT}\n`);
    assert.throws(
      () => loadPolicyFileStrict(file),
      (e: unknown) => e instanceof PolicyFileError && e.problems.some((p) => /write no-model\)$/.test(p)),
      "the daemon's refusal carries the replacement name to its log",
    );
    writeFileSync(file, `version: 1\npaths:\n  - path: /h/contract.md\n    level: no-model\n`);
    assert.deepEqual(loadPolicyFileStrict(file).config?.paths?.map((p) => p.level), ["no-model"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a loader that skips the validator still locks: an unknown or missing level compiles to no-model, never to nothing", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-retired-levels-"));
  try {
    const file = join(dir, "policy.yaml");
    writeFileSync(
      file,
      `version: 1\npaths:\n  - path: /h/contract.md\n    level: ${OLD_STRICT}\n  - { path: /h/deal.md, level: ${OLD_MODEL_OK} }\n  - { path: /h/bare.md }\n  - { path: /h/ok.md, level: local-model }\n`,
    );
    const lenient = loadPolicyFile(file, dir, SILENT);
    assert.deepEqual(lenient?.paths?.map((p) => p.level), [OLD_STRICT, OLD_MODEL_OK, undefined, "local-model"], "not translated");
    const c = compilePolicy({ specId: "claude-code", document: lenient, log: SILENT });
    const level = (p: string) => c.pathLabels.get(p)?.confidentiality;
    assert.equal(level("/h/contract.md"), "no-model");
    assert.equal(level("/h/deal.md"), "no-model", "the lenient reading is the strictest, not the old meaning");
    assert.equal(level("/h/bare.md"), "no-model");
    assert.equal(level("/h/ok.md"), "local-model");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
