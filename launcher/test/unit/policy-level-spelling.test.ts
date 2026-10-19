/**
 * policy-level-spelling.test — the policy.yaml line scans `mandu doctor` uses
 * (the policy path, `local-model` labels, the `models:` section).
 *
 * Pure text scan and rendering: no protection axis is exercised.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { hasModelsSection, localModelLevelLines, policyFilePath } from "../../src/policy-level-spelling.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is exercised

test("the policy path follows MANDU_POLICY_FILE, then MANDU_HOME, then HOME", () => {
  assert.equal(policyFilePath({ MANDU_POLICY_FILE: "/p.yaml", HOME: "/h" }), "/p.yaml");
  assert.equal(policyFilePath({ MANDU_HOME: "/m", HOME: "/h" }), "/m/policy.yaml");
  assert.equal(policyFilePath({ HOME: "/h" }), "/h/.mandu/policy.yaml");
  assert.equal(policyFilePath({}), null);
  // The path table's `policy` entry (on-disk-layout.md §5): an empty variable
  // counts as unset, MANDU_HOME alone is enough, and XDG_CONFIG_HOME no
  // longer places it (the one home, phase 3c).
  assert.equal(policyFilePath({ MANDU_POLICY_FILE: "", MANDU_HOME: "", HOME: "/h" }), "/h/.mandu/policy.yaml");
  assert.equal(policyFilePath({ MANDU_HOME: "/m" }), "/m/policy.yaml");
  assert.equal(policyFilePath({ XDG_CONFIG_HOME: "/x", HOME: "/h" }), "/h/.mandu/policy.yaml");
});

// ── confidentiality-plan-11 D6: local-model labels and the models: section ──

test("localModelLevelLines: block and flow style, quoted, not in a comment, not another level", () => {
  const text = [
    "paths:",
    "  - path: ~/notes/contract.md",
    "    level: local-model",
    "  - { path: ~/a, level: 'local-model' }",
    "  # level: local-model",
    "  - path: ~/b",
    "    level: local-models",
    "    level: no-model",
  ].join("\n");
  assert.deepEqual(localModelLevelLines(text), [3, 4]);
  assert.deepEqual(localModelLevelLines(""), []);
});

test("hasModelsSection: a top-level models: with a block or a non-empty flow list; not an empty inline value, a nested key or a comment", () => {
  assert.ok(hasModelsSection("paths: []\nmodels:\n  - name: ollama\n    url: http://127.0.0.1:11434\n"));
  assert.ok(hasModelsSection("models: [{name: o, url: 'http://h'}]\n"));
  assert.ok(!hasModelsSection("models: []\n"));
  assert.ok(!hasModelsSection("models: null # none yet\n"));
  assert.ok(!hasModelsSection("apps:\n  models: x\n"));
  assert.ok(!hasModelsSection("# models:\npaths: []\n"));
});
