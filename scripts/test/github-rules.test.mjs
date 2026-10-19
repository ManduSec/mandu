// github-rules.test.mjs — GitHub's filter-pattern semantics (scripts/ci/github-rules.mjs,
// docs/design/testing/continuous-integration.md §12, "When GitHub runs"), which
// suites-manifest.test.mjs uses to check ci.yml's docs filter. Pure node; no
// network, no privilege.

import { test } from "node:test";
import assert from "node:assert/strict";

import { filterMatch, globMatch, globRegex } from "../ci/github-rules.mjs";

test("globRegex: GitHub's filter patterns (* within a segment, ** across, a leading **/ also at the root)", () => {
  assert.ok(globMatch("launcher/src/*.ts", "launcher/src/run.ts"));
  assert.ok(!globMatch("launcher/src/*.ts", "launcher/src/platform/linux.ts"), "* stops at /");
  assert.ok(globMatch("launcher/src/**", "launcher/src/platform/linux.ts"));
  assert.ok(globMatch("**/*.md", "README.md"), "a leading **/ matches at the root");
  assert.ok(globMatch("**/*.md", "a/b/c.md"));
  assert.ok(globMatch("**/fixtures/**", "arbiter/test/fixtures/x.md"));
  assert.ok(globMatch("**/fixtures/**", "fixtures/x"));
  assert.ok(!globMatch("**/*.md", "a.mdx"));
  assert.ok(!globMatch("docs/**", "dashboard/docs.ts"));
  assert.ok(globMatch(".github/workflows/ci.yml", ".github/workflows/ci.yml"), "dots are literal");
  assert.ok(!globMatch(".github/workflows/ci.yml", ".github/workflows/ciXyml"));
  for (const bad of ["a?.ts", "a+", "[ab].ts", "!docs/**"]) assert.throws(() => globRegex(bad), /GitHub|ordered list/, bad);
});

test("filterMatch: the last matching pattern decides; ! deselects; nothing matched is not selected", () => {
  const pats = ["**", "!docs/**", "!**/*.md", "launcher/README.md", "**/fixtures/**"];
  assert.equal(filterMatch(pats, "arbiter/src/a.ts"), true);
  assert.equal(filterMatch(pats, "docs/a.svg"), false);
  assert.equal(filterMatch(pats, "README.md"), false);
  assert.equal(filterMatch(pats, "launcher/README.md"), true);
  assert.equal(filterMatch(pats, "docs/x/fixtures/a.md"), true);
  assert.equal(filterMatch(["docs/**"], "arbiter/a.ts"), false);
  assert.equal(filterMatch([], "a"), false);
});
