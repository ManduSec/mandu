/**
 * dev-count-words.test — dashboard.md §4.32 *Counts*: a count agrees with
 * its noun ("1 run", "2 runs"), never a hedge such as "run(s)" or
 * "match(es)".
 *
 * Pins, over the shipped text:
 *   1. THE INSPECTOR'S SCRIPTS. No string or template text in dev/js/*.js
 *      carries the hedge. The scripts are parsed (TypeScript's own parser,
 *      as JavaScript), so a call such as `push(s)` is code, not words.
 *   2. THE SERVER'S WORDS. The same over src/view-model/: the view models
 *      compose sentences both front-ends show (the Approvals detail's
 *      "requesting session: s1").
 *   3. THE PRODUCT PAGE. The same over public/js/*.js, which already says
 *      it right everywhere; this keeps it so.
 *
 * Each module's own suite renders its count of one in a real DOM (ci-js,
 * matrix-js, run-views-js, prompt-filters-js, secrets-js, egress-js-panel,
 * drills-js, control-js-boot, app-js-*); the stack e2e
 * inspector-counts-at-one renders the served pages over real recorded runs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

import { devPagesDir, NO_DEV_PAGES } from "./dev-pages.js";

const PKG = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..");
const HEDGE = /[A-Za-z]\((?:s|es)\)/;

/** Every piece of string or template text in `src` (comments and code left out). */
function words(file: string, src: string): string[] {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, file.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS);
  const out: string[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n)) out.push(n.text);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

/** The hedges in the files of `dir` with `ext`: "file: text". */
function hedges(dir: string, ext: string, root = PKG): { files: number; found: string[] } {
  const files = readdirSync(join(root, dir)).filter((f) => f.endsWith(ext));
  const found: string[] = [];
  for (const f of files) {
    for (const w of words(f, readFileSync(join(root, dir, f), "utf8"))) if (HEDGE.test(w)) found.push(`${dir}/${f}: ${JSON.stringify(w)}`);
  }
  return { files: files.length, found };
}

test("the parser reads string and template text, not code or comments", () => {
  const got = words("x.js", "/* a run(s) */ push(s); const a = 'one run(s)'; const b = `${n} file(s) ${m} match(es)`; // x(s)\n");
  assert.deepEqual(got, ["one run(s)", "", " file(s) ", " match(es)"]);
  assert.deepEqual(got.filter((w) => HEDGE.test(w)), ["one run(s)", " file(s) ", " match(es)"]);
});

test("1. the inspector's scripts: no \"(s)\" or \"(es)\" hedge in any string", { skip: NO_DEV_PAGES }, () => {
  const { files, found } = hedges("js", ".js", devPagesDir()!);
  assert.ok(files >= 20, `the inspector's scripts are read (${files})`);
  assert.deepEqual(found, []);
});

test("2. the view models: no \"(s)\" or \"(es)\" hedge in any string", () => {
  const { files, found } = hedges(join("src", "view-model"), ".ts");
  assert.ok(files >= 10, `the view models are read (${files})`);
  assert.deepEqual(found, []);
});

test("3. the product page's scripts: no \"(s)\" or \"(es)\" hedge in any string", () => {
  const { files, found } = hedges(join("public", "js"), ".js");
  assert.ok(files >= 1, `the product page's scripts are read (${files})`);
  assert.deepEqual(found, []);
});
