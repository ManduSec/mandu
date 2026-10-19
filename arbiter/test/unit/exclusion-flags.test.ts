/**
 * exclusion-flags.test.ts — a search that excludes a labelled folder
 * (docs/design/confidentiality/exclusion-flags.md): the pure blanking of
 * `--exclude-dir=NAME` words of one plain grep (X1, X2), and the classify's
 * path rules reading demo-c2's command with it (`labelForClassify`).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { grepExclusionSpans, withoutGrepExclusions } from "../../policy/exclusion-flags.js";
import { labelForClassify, type LabelLookup } from "../../policy/secret-catalog.js";
import type { LabelDecision } from "../../policy/path-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const DEMO = "grep -rIl -i park . --exclude-dir=bank";

test("blanked: each whole --exclude-dir=NAME word of one plain grep, same length", () => {
  assert.equal(withoutGrepExclusions(DEMO), `grep -rIl -i park . ${" ".repeat("--exclude-dir=bank".length)}`);
  assert.equal(withoutGrepExclusions(DEMO).length, DEMO.length);
  for (const c of [
    "grep -r park . --exclude-dir=bank --exclude-dir=.git",
    "egrep -rl 'a b' . --exclude-dir=bank/",
    "fgrep -r x --exclude-dir=bank.old .",
    "grep -e --exclude-dir=bank -r .", // as -e's pattern it is text, never a path
  ]) {
    const spans = grepExclusionSpans(c);
    assert.ok(spans && spans.length > 0, c);
    assert.ok(!/--exclude-dir=/.test(withoutGrepExclusions(c)), c);
  }
});

test("unchanged: every refusal of X1 and X2", () => {
  for (const c of [
    "grep -r park . --exclude-dir bank",           // the two-word form
    "grep -r park . --exclude=bank",               // a file glob
    "grep -r park . --exclude-dir=./bank",         // a path
    "grep -r park . --exclude-dir=/ws/bank",
    "grep -r park . --exclude-dir=..",
    "grep -r park . --exclude-dir='bank'",         // a quote in the word
    "grep -r park . '--exclude-dir=bank'",
    "grep -r park . --exclude-dir=bank*",          // a glob
    "grep -r park . --exclude-dir={bank,.git}",
    "grep -r park . --exclude-dir=^bank",
    "grep -r park . --exclude-dir=%bank",
    "grep -r 'park --exclude-dir=bank' .",         // inside a quoted pattern
    "grep -r park . --exclude-dir=bank 2>/dev/null",
    "grep -r park . --exclude-dir=bank | head",
    "cd ws && grep -r park . --exclude-dir=bank",
    "/usr/bin/grep -r park . --exclude-dir=bank",
    "rg -g '!bank' park",
    "'grep' -r park . --exclude-dir=bank",
    "grep -r 'park . --exclude-dir=bank",          // unterminated
    "bash -lc 'grep -r park . --exclude-dir=bank'",
    // implementation review round 1: a file literally named so
    "grep -v zzz -- --exclude-dir=server.key",
    "grep -f --exclude-dir=bank -r .",
    "grep -rf --exclude-dir=bank .",
    "grep --file --exclude-dir=bank -r .",
    "grep --exclude-from --exclude-dir=bank -r .",
    // implementation review round 2: a quoted `--`, a long option's file
    'grep -v zzz "--" --exclude-dir=server.key',
    "grep -v zzz '--' --exclude-dir=server.key",
    "grep --from --exclude-dir=server.key x",
    "grep --include-from --exclude-dir=x -r .",
    "grep --exclude-f --exclude-dir=x -r .",
  ]) assert.equal(withoutGrepExclusions(c), c, c);
});

const BANK = "/proj/bank";
const ENV = "/proj/.env";
const lookup: LabelLookup = Object.assign(
  (p: string): LabelDecision | null => p === BANK || p.startsWith(`${BANK}/`) ? { level: "no-model", bindings: [], via: BANK }
    : p === ENV ? { level: "public", bindings: [], via: ENV } : null,
  { roots: () => [{ path: BANK, level: "no-model" as const }] },
);
const classify = (command: string, extra: Record<string, unknown> = {}) =>
  labelForClassify({ tool: "Bash", origin: command, params: { command, ...extra }, callStartDir: "/proj" }, "/home/u", lookup);

test("the classify: demo-c2's command is public; an operand or statement naming the folder stays secret", () => {
  assert.equal(classify("grep -rIl -i park .").level, "public", "the search with no exclusion: public today");
  assert.equal(classify(DEMO).level, "public", "the exclusion is not read as a path");
  assert.equal(classify("grep -rIl -i park . --exclude-dir bank").level, "no-model", "the two-word form: as before");
  assert.equal(classify("grep -r park bank --exclude-dir=x").level, "no-model", "an operand naming the folder");
  assert.equal(classify("grep -r park . --exclude-dir=bank bank/statement.md").level, "no-model", "a statement named beside it");
  assert.equal(classify("grep -r park . --exclude=bank").level, "no-model", "--exclude=: as before");
});

test("the classify: whole-text heuristics lose the blanked word (grep never changes directory)", () => {
  // `.env` labelled public: read with the exact base once no word reads as a change of directory
  assert.equal(classify("grep KEY .env --exclude-dir=chdir").level, "public");
  assert.equal(classify("grep KEY .env --exclude-dir=cd").level, "public");
});

test("the classify: a typed path field holding the command's text is never blanked", () => {
  // a file labelled no-model whose NAME is the command's text, read through a
  // typed relative path field equal to the command (implementation review round 1)
  const odd = "grep x --exclude-dir=q";
  const oddLookup: LabelLookup = Object.assign(
    (p: string): LabelDecision | null => p === `/proj/${odd}` ? { level: "no-model", bindings: [], via: p } : null,
    { roots: () => [{ path: `/proj/${odd}`, level: "no-model" as const }] },
  );
  const m = labelForClassify({ tool: "custom", params: { path: odd, command: odd }, pathBase: { dir: "/proj", fields: ["path"] } }, "/home/u", oddLookup);
  assert.equal(m.level, "no-model");
});

test("the classify: a catalog file literally named --exclude-dir=NAME keeps its reading after --", () => {
  assert.equal(classify("grep -v zzz -- --exclude-dir=server.key").level, "no-model");
});
