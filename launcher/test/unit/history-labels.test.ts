/**
 * Unit: history-labels — the launcher's mirror of the arbiter's label
 * precedence, deciding which paths a repository's history holds that a human
 * label puts above `public` (confidentiality-plan-14 §8.1). The parity with
 * the arbiter's own resolver is pinned in
 * tests/stack/git-history-locks-parity.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  compileHistoryGlob, compileHistoryLabels, historyGlobMatches, historyPathspecs, labelledAbovePublic,
  levelRank, resolveHistoryLevel, withRealSpellings, type HistoryLabel,
} from "../../src/history-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the labels are the confidentiality axis's

const L = (path: string, level: string, o: { recursive?: boolean; glob?: true } = {}): HistoryLabel =>
  ({ path, level, recursive: o.recursive ?? true, ...(o.glob ? { glob: true as const } : {}) });

test("precedence: an exact literal wins; else the longest literal prefix; a public carve-out under a secret folder stays public", () => {
  const c = compileHistoryLabels([
    L("/w/repo", "no-model"),
    L("/w/repo/README.md", "public"),
    L("/w/repo/docs", "public"),
    L("/w/repo/docs/keys.txt", "no-model"),
    L("/w/other", "no-model", { recursive: false }),
  ]);
  assert.equal(resolveHistoryLevel("/w/repo/deploy/id_rsa", c), "no-model");
  assert.equal(resolveHistoryLevel("/w/repo/README.md", c), "public");
  assert.equal(resolveHistoryLevel("/w/repo/docs/guide.md", c), "public");
  assert.equal(resolveHistoryLevel("/w/repo/docs/keys.txt", c), "no-model");
  assert.equal(resolveHistoryLevel("/w/repo-2/x", c), null, "segment-aware: /w/repo does not cover /w/repo-2");
  assert.equal(resolveHistoryLevel("/w/other", c), "no-model");
  assert.equal(resolveHistoryLevel("/w/other/x", c), null, "a non-recursive label covers itself only");
  assert.equal(labelledAbovePublic("/w/repo/deploy/id_rsa", c), true);
  assert.equal(labelledAbovePublic("/w/repo/README.md", c), false);
  assert.equal(labelledAbovePublic("/elsewhere", c), false);
});

test("patterns: a match covers what is below it when recursive; the literal prefix is the specificity; a tie goes to the pattern, then the stricter level", () => {
  const g = compileHistoryGlob("/w/**/*.pem")!;
  assert.equal(g.literalPrefix, "/w");
  assert.equal(historyGlobMatches(g, "/w/a/b/k.pem", false), true);
  assert.equal(historyGlobMatches(g, "/w/k.pem", false), true, "** matches zero segments");
  assert.equal(historyGlobMatches(g, "/x/k.pem", false), false);
  assert.equal(compileHistoryGlob("**/.env")!.literalPrefix, "", "an unrooted pattern has no literal prefix");
  assert.equal(compileHistoryGlob("/w/[z-a]"), null, "a pattern the arbiter would refuse matches nothing");
  assert.equal(compileHistoryGlob("/w/a**b"), null);

  const c = compileHistoryLabels([
    L("**/.env", "no-model", { glob: true }),
    L("/w/fixtures", "public"),
    L("/w/fixtures/*", "any-model", { glob: true }),
    L("/w/t/*", "public", { glob: true }),
    L("/w/t/*", "no-model", { glob: true, recursive: false }),
  ]);
  assert.equal(resolveHistoryLevel("/w/app/.env", c), "no-model");
  assert.equal(resolveHistoryLevel("/w/fixtures/.env", c), "any-model", "a pattern ties a literal ancestor at the same prefix and wins");
  assert.equal(resolveHistoryLevel("/w/t/x", c), "no-model", "two patterns at one prefix: the stricter wins");
  assert.equal(resolveHistoryLevel("/w/t/x/y", c), "public", "the non-recursive one does not cover below");
  assert.equal(levelRank("bogus"), 3, "an unknown level ranks as no-model");
});

test("historyPathspecs: the labels' literal prefixes inside the repository; the whole history when a label covers it or a pattern may match anywhere; none when no label above public reaches it", () => {
  const specs = (labels: HistoryLabel[]) => historyPathspecs("/w/repo", compileHistoryLabels(labels));
  assert.deepEqual(specs([L("/w/repo/deploy/id_rsa", "no-model"), L("/w/repo/secrets/**", "no-model", { glob: true })]), ["deploy/id_rsa", "secrets"]);
  assert.deepEqual(specs([L("/w/repo/README.md", "public"), L("/elsewhere/x", "no-model")]), [], "a public label alone, or a label outside, walks nothing");
  assert.equal(specs([L("/w", "no-model")]), null, "a recursive label above the root: the whole history");
  assert.deepEqual(specs([L("/w", "no-model", { recursive: false })]), [], "a non-recursive one reaches nothing inside");
  assert.equal(specs([L("**/*.pem", "no-model", { glob: true })]), null, "an unrooted pattern may match anywhere");
  assert.equal(specs([L("/w/*/deploy", "no-model", { glob: true })]), null, "a pattern whose literal prefix is above the root");
  assert.equal(specs([L("/w/repo", "any-model")]), null, "a label on the root itself");
});

test("withRealSpellings: a literal or a pattern's literal prefix written through a symlink also decides under the real spelling; carve-outs included", () => {
  const real = (p: string): string => p.replace(/^\/home\/u\/work/, "/mnt/data/work");
  const out = withRealSpellings([
    L("/home/u/work/repo/deploy/id_rsa", "no-model"),
    L("/home/u/work/repo/README.md", "public"),
    L("/home/u/work/**/*.pem", "no-model", { glob: true }),
    L("**/.env", "no-model", { glob: true }),
    L("/srv/x", "no-model"),
  ], real);
  const paths = out.map((l) => l.path);
  assert.ok(paths.includes("/mnt/data/work/repo/deploy/id_rsa"));
  assert.ok(paths.includes("/mnt/data/work/repo/README.md"), "the carve-out too, so it keeps winning");
  assert.ok(paths.includes("/mnt/data/work/**/*.pem"));
  assert.equal(out.filter((l) => l.path === "/srv/x").length, 1, "no duplicate when the spelling is already real");
  assert.equal(out.length, 8);
  const c = compileHistoryLabels(out);
  assert.equal(labelledAbovePublic("/mnt/data/work/repo/deploy/id_rsa", c), true);
  assert.equal(labelledAbovePublic("/mnt/data/work/repo/README.md", c), false);
});
