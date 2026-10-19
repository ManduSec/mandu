/**
 * Unit: fs-sync's own locations come from the path table
 * (fs-sync/src/generated/mandu-paths.ts; docs/design/architecture/on-disk-layout.md §5,
 * §7 phase 3b). Pure: explicit env and home, no file touched.
 */

import { strict as assert } from "node:assert";
import { join, posix } from "node:path";
import { test } from "node:test";

import { manduPath } from "../../src/generated/mandu-paths.js";
import { ALWAYS_DENIED_DIRS, CLOCK_IGNORED_DIRS, humanEditClockIgnores } from "../../src/ignored.js";
import { MANDU_HOME_DIR_NAME, ViewLayout, defaultStateBase } from "../../src/layout.js";

test("defaultStateBase is the table's view-state: $HOME/.mandu/state, only MANDU_HOME moves it, empty counts as unset", () => {
  assert.equal(defaultStateBase({}, "/home/u"), "/home/u/.mandu/state");
  assert.equal(defaultStateBase({}, "/home/u/"), "/home/u/.mandu/state");
  assert.equal(defaultStateBase({ MANDU_HOME: "/m" }, "/home/u"), "/m/state");
  // The retired per-path override (was MANDU_VIEW_STATE) moves nothing.
  assert.equal(defaultStateBase({ MANDU_VIEW_STATE: "/v/state/", MANDU_HOME: "/m" }, "/home/u"), "/m/state");
  assert.equal(defaultStateBase({ MANDU_HOME: "" }, "/home/u"), "/home/u/.mandu/state");
  assert.equal(defaultStateBase({ XDG_STATE_HOME: "/x" }, "/home/u"), "/home/u/.mandu/state", "XDG roots do not move it");
  for (const env of [{}, { MANDU_HOME: "/m" }]) {
    assert.equal(defaultStateBase(env, "/h"), manduPath("view-state", env, "/h"));
  }
});

test("ViewLayout without a state base lands under defaultStateBase(): ~/.mandu/state/workspaces", () => {
  const l = new ViewLayout("/tmp/some-ws");
  assert.equal(l.workspaceDir, join(defaultStateBase(), "workspaces", l.workspaceId));
  const home = new ViewLayout("/tmp/some-ws", defaultStateBase({}, "/home/u"));
  assert.equal(home.workspaceDir, join("/home/u/.mandu/state/workspaces", home.workspaceId));
});

test("ViewLayout without a state base lands under defaultStateBase()", () => {
  const l = new ViewLayout("/tmp/some-ws");
  assert.equal(l.workspaceDir, join(defaultStateBase(), "workspaces", l.workspaceId));
});

test("Mandu's own directory name comes from the table and is never walked", () => {
  assert.equal(MANDU_HOME_DIR_NAME, ".mandu");
  assert.equal(MANDU_HOME_DIR_NAME, posix.basename(manduPath("mandu-home", {}, "/home/u")));
  assert.ok(ALWAYS_DENIED_DIRS.includes(MANDU_HOME_DIR_NAME));
  assert.ok(ALWAYS_DENIED_DIRS.includes(".git"));
});

test("the human-edit clock ignores .git, Mandu's dir and node_modules at any depth, by whole segment", () => {
  assert.deepEqual([...CLOCK_IGNORED_DIRS], [".git", ".mandu", "node_modules"]);
  for (const hit of [".git", ".git/index", "a/.mandu/x", ".mandu", "pkg\\node_modules\\x.js", "a/b/node_modules"]) {
    assert.equal(humanEditClockIgnores(hit), true, hit);
  }
  for (const miss of ["src/a.ts", ".gitignore", "x.mandu", ".mandu-notes/a", "my_node_modules/x", "a/.github/w.yml"]) {
    assert.equal(humanEditClockIgnores(miss), false, miss);
  }
});
