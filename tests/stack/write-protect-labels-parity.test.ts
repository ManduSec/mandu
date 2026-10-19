/**
 * The labels the launcher writes on its write-protect list and the labels the
 * arbiter agrees to show in the Inbox are the same set
 * (sandbox-security-review-2026-09-28 finding 6; launcher/src/write-protect.ts,
 * arbiter/policy/write-protect.ts). A label on one side only is either never
 * shown (the arbiter says "a protected file") or shown for no entry.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PROTECTED_WRITE_LABELS } from "../../arbiter/policy/write-protect.js";
import { laterRunFiles, WRITE_PROTECT_LABELS } from "../../launcher/src/write-protect.js";

test("launcher WRITE_PROTECT_LABELS == arbiter PROTECTED_WRITE_LABELS, and every ask entry uses one", () => {
  assert.deepEqual([...WRITE_PROTECT_LABELS].sort(), [...PROTECTED_WRITE_LABELS].sort());
  for (const e of laterRunFiles({ HOME: "/h" })) assert.ok(PROTECTED_WRITE_LABELS.has(e.label), e.label);
  assert.ok(PROTECTED_WRITE_LABELS.has("a git hook"));
});
