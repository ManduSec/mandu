/**
 * session-tags.test.ts — the id-derived session annotation (event-source.ts).
 *
 * Mandu dashboard. e2e test runs mint a session id with the TEST_SESSION_PREFIX
 * so the sidebar can badge them as test traffic (not a real run). `sessionTags`
 * is the single derivation both EventSource impls call when building SessionRef.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { sessionTags, testNumber, TEST_SESSION_PREFIX } from "../../src/event-source.js";

test("flags a classed e2e session with its test class", () => {
  assert.deepEqual(sessionTags("claude-e2e-greeting-1781835632"), ["test", "claude-e2e"]);
  assert.deepEqual(sessionTags("codex-e2e-stored-ipi-1781835632"), ["test", "codex-e2e"]);
  assert.deepEqual(sessionTags("replay-e2e-ipi-text-1781835632"), ["test", "replay-e2e"]);
});

test("flags a legacy e2e- prefixed session as a test run (no class)", () => {
  assert.equal(TEST_SESSION_PREFIX, "e2e-");
  assert.deepEqual(sessionTags("e2e-helloworld-1781835632"), ["test"]);
  assert.deepEqual(sessionTags(TEST_SESSION_PREFIX + "x"), ["test"]);
});

test("assigns stable per-class badges: replay-e2e Re1–Re7, claude-e2e E1–E21, codex-e2e C1–C3", () => {
  assert.equal(testNumber("replay-e2e-ipi-text-1782006909017"), "Re1");
  assert.equal(testNumber("replay-e2e-chain-fetch-write-read-1782006909017"), "Re7");
  assert.equal(testNumber("claude-e2e-greeting-1782006909017"), "E1");
  assert.equal(testNumber("claude-e2e-chain-fetch-write-read-1782006909017"), "E10");
  // The trusted-path scenarios (the dual of the IPI ones) extend the sequence.
  assert.equal(testNumber("claude-e2e-trusted-glob-1782006909017"), "E11");
  assert.equal(testNumber("claude-e2e-trusted-grep-files-1782006909017"), "E12");
  assert.equal(testNumber("claude-e2e-trusted-and-untrusted-1782006909017"), "E13");
  // inspect-summarize (U-LLM path) was APPENDED, not slotted into its suite-array
  // position, so it trails at E14 and the numbers above stay stable.
  assert.equal(testNumber("claude-e2e-inspect-summarize-1782006909017"), "E14");
  // The exact-answer TIGHT-utility scenarios (2026-07-10) trail as E15/E16.
  assert.equal(testNumber("claude-e2e-count-security-1782006909017"), "E15");
  assert.equal(testNumber("claude-e2e-inspect-extract-1782006909017"), "E16");
  // untrusted-file-lookup (the UNTRUSTED dual of E12) is APPENDED as E17, not
  // slotted next to trusted-grep-files, so E13–E16 stay stable.
  assert.equal(testNumber("claude-e2e-untrusted-file-lookup-1782006909017"), "E17");
  // More tight-utility shapes appended as E18/E19.
  assert.equal(testNumber("claude-e2e-inspect-compare-1782006909017"), "E18");
  assert.equal(testNumber("claude-e2e-untrusted-writeback-1782006909017"), "E19");
  // The exec-routing scenarios (2026-07-10) trail as E20/E21 (append-only rule).
  assert.equal(testNumber("claude-e2e-exec-symbol-command-blocked-1783717388614"), "E20");
  assert.equal(testNumber("claude-e2e-exec-curl-run-blindspot-1783717388614"), "E21");
  // codex-e2e (the Codex CLI sibling) counts its own C-sequence.
  assert.equal(testNumber("codex-e2e-reasoning-1782006909017"), "C1");
  assert.equal(testNumber("codex-e2e-benign-exec-1782006909017"), "C2");
  assert.equal(testNumber("codex-e2e-stored-ipi-1782006909017"), "C3");
  // same scenario NAME across classes → different numbers (no collision).
  assert.notEqual(
    testNumber("replay-e2e-chain-fetch-write-read-1782006909017"),
    testNumber("claude-e2e-chain-fetch-write-read-1782006909017"),
  );
  assert.notEqual(
    testNumber("claude-e2e-reasoning-1782006909017"),
    testNumber("codex-e2e-reasoning-1782006909017"),
  );
});

test("returns undefined for an unregistered or non-test session id", () => {
  assert.equal(testNumber("claude-e2e-not-a-real-scenario-1782006909017"), undefined);
  assert.equal(testNumber("1781835632-239110"), undefined);
  assert.equal(testNumber("e2e-legacy-1781835632"), undefined); // legacy class-less id
});

test("returns undefined for a normal (non-test) session id", () => {
  assert.equal(sessionTags("1781835632-239110"), undefined); // launcher <ts>-<pid>
  assert.equal(sessionTags("mp_abc123"), undefined); // proxy per-process fallback
  assert.equal(sessionTags("verify-emptyfix-1781836281"), undefined);
});

test("the plan 11 local-model drill is its own class: tagged test, badged LM1/LM2", () => {
  assert.deepEqual(sessionTags("local-model-e2e-local-model-1790555000000"), ["test", "local-model-e2e"]);
  assert.equal(testNumber("local-model-e2e-local-model-1790555000000"), "LM1");
  assert.equal(testNumber("local-model-e2e-any-model-1790555100000"), "LM2");
  // The pre-2026-09-28 scope ids (`lm-local-<stamp>`) were never a class.
  assert.equal(sessionTags("lm-local-mg3xk1a2b3"), undefined);
});

test("the plan 11 phase 3 drill is its own class too: tagged test, badged LMM1 (test-organization.md §8.3)", () => {
  assert.deepEqual(sessionTags("local-main-model-e2e-main-model-1790555200000"), ["test", "local-main-model-e2e"]);
  assert.equal(testNumber("local-main-model-e2e-main-model-1790555200000"), "LMM1");
  // Its class is not mistaken for local-model-e2e's, nor theirs for it.
  assert.deepEqual(sessionTags("local-model-e2e-local-model-1790555000000"), ["test", "local-model-e2e"]);
  // Before 2026-09-29 the drill minted a scenario-less `local-main-model-e2e-<ms>`: tagged, never badged.
  assert.deepEqual(sessionTags("local-main-model-e2e-1790555200000"), ["test", "local-main-model-e2e"]);
  assert.equal(testNumber("local-main-model-e2e-1790555200000"), undefined);
});

test("the browser drill is its own class: tagged test, its four tasks badged BJ1-BJ4", () => {
  assert.deepEqual(sessionTags("browser-jev-e2e-settings-rename-1792330000000"), ["test", "browser-jev-e2e"]);
  assert.equal(testNumber("browser-jev-e2e-settings-rename-1792330000000"), "BJ1");
  assert.equal(testNumber("browser-jev-e2e-integration-paste-1792330000000"), "BJ2");
  assert.equal(testNumber("browser-jev-e2e-support-unbound-1792330000000"), "BJ3");
  assert.equal(testNumber("browser-jev-e2e-field-value-1792330000000"), "BJ4");
  assert.equal(testNumber("browser-jev-e2e-not-a-task-1792330000000"), undefined);
});

test("OpenClaw's inspect-extract is badged OCl6, like OpenCode's OCo6", () => {
  assert.equal(testNumber("openclaw-e2e-inspect-extract-1790555300000"), "OCl6");
  assert.equal(testNumber("opencode-e2e-inspect-extract-1790555300000"), "OCo6");
  assert.equal(testNumber("openclaw-e2e-net-exfil-blocked-1790555300000"), "OCl5", "earlier badges unchanged");
});
