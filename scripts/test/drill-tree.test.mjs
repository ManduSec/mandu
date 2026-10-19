/**
 * drill-tree.test — scripts/drill-tree.mjs, the drill-tree resolver the shell
 * scripts and the script tests use (test-organization.md §5, "The drill
 * tree"): none for a checkout without a declared tree (the public tree), the
 * tree for one that declares it, MANDU_DRILL_TREE first; and its command line,
 * which nightly-stack.sh runs (the path on stdout and exit 0, or nothing and
 * exit 1). The dashboard's copy of the rule is held equal to this one by
 * dashboard/test/unit/drill-tree.test.ts.
 *
 * Run:  node --test scripts/test/drill-tree.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DRILL_TREE_ENV, declaredTree, drillTree } from "../drill-tree.mjs";
import { tmpDir } from "./lib/tmp-dir.mjs";

const SCRIPT = fileURLToPath(new URL("../drill-tree.mjs", import.meta.url));

function checkout(mandu, dirs = []) {
  const root = tmpDir("drill-tree-");
  mkdirSync(join(root, "tests"), { recursive: true });
  if (mandu !== undefined) writeFileSync(join(root, "tests", "package.json"), JSON.stringify({ name: "t", mandu }));
  for (const d of dirs) mkdirSync(join(root, d), { recursive: true });
  return root;
}

function cli(root, env = {}) {
  const clean = { ...process.env };
  delete clean[DRILL_TREE_ENV];
  return spawnSync(process.execPath, [SCRIPT, root], { encoding: "utf8", env: { ...clean, ...env } });
}

test("no tree: no package.json, no declaration (the public tests/package.json), a missing directory, a bad declaration", () => {
  assert.equal(drillTree(checkout(), {}), null);
  assert.equal(drillTree(checkout({ siblings: ["arbiter"] }), {}), null);
  assert.equal(drillTree(checkout({ drillTree: "gone" }), {}), null);
  for (const bad of ["/abs", "../up", "", 3]) {
    const root = checkout({ drillTree: bad }, ["up"]);
    assert.equal(declaredTree(join(root, "tests")), null, JSON.stringify(bad));
    assert.equal(drillTree(root, {}), null, JSON.stringify(bad));
  }
});

test("a declared tree, and MANDU_DRILL_TREE before it", () => {
  const root = checkout({ drillTree: "d" }, ["tests/d", "other"]);
  assert.deepEqual(drillTree(root, {}), { root: join(root, "tests", "d"), testsDir: join(root, "tests"), rel: "d" });
  assert.deepEqual(drillTree(root, { [DRILL_TREE_ENV]: "other" }), { root: join(root, "other"), testsDir: join(root, "tests"), rel: join("..", "other") });
  assert.equal(drillTree(root, { [DRILL_TREE_ENV]: join(root, "nope") }), null, "set but not a directory: none");
});

test("the command line: the tree's path and exit 0, or nothing and exit 1", () => {
  const root = checkout({ drillTree: "d" }, ["tests/d"]);
  const yes = cli(root);
  assert.equal(yes.status, 0, yes.stderr);
  assert.equal(yes.stdout, `${join(root, "tests", "d")}\n`);
  const no = cli(checkout({ siblings: [] }));
  assert.equal(no.status, 1);
  assert.equal(no.stdout, "");
  assert.equal(no.stderr, "", "none is an answer, not an error");
  assert.equal(cli(root, { [DRILL_TREE_ENV]: "/nonexistent-drill-tree" }).status, 1);
});
