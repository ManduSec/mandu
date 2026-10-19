/**
 * line-fingerprint.test — the value backstop's line matching
 * (egress-fingerprint.ts; confidentiality-plan-11 §8 row 1): a labeled
 * document reaches a diff or a partial print line by line, never verbatim.
 *
 * Pure matching: the confidentiality axis is what the backstop serves.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { lineFingerprints, MIN_LINE_FINGERPRINT_LEN, secretValueMatch } from "../../policy/egress-fingerprint.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const DOC = [
  "# Master Services Agreement",
  "",
  "Acme agrees to pay 4,200,000 USD on 2026-09-30.",
  "   Termination requires ninety days written notice.   ",
  "}",
  "Acme agrees to pay 4,200,000 USD on 2026-09-30.",
].join("\n");

test("only long lines of a multi-line value are fingerprints, trimmed and deduplicated", () => {
  assert.deepEqual(lineFingerprints(DOC), [
    "# Master Services Agreement",
    "Acme agrees to pay 4,200,000 USD on 2026-09-30.",
    "Termination requires ninety days written notice.",
  ]);
  assert.ok(lineFingerprints(DOC).every((l) => l.length >= MIN_LINE_FINGERPRINT_LEN));
  assert.deepEqual(lineFingerprints("sk-live-0123456789abcdef0123456789"), [], "a single-line value is its own fingerprint");
  assert.deepEqual(lineFingerprints("a\r\nshort\r\n"), []);
});

test("a diff, a partial print and the whole value match; unrelated text and short lines do not", () => {
  const lines = lineFingerprints(DOC);
  assert.equal(secretValueMatch(`before ${DOC} after`, DOC, lines), "value");
  assert.equal(secretValueMatch("-Acme agrees to pay 4,200,000 USD on 2026-09-30.\n+(gone)\n", DOC, lines), "line");
  assert.equal(secretValueMatch("  Termination requires ninety days written notice.", DOC, lines), "line");
  assert.equal(secretValueMatch("}\n\n# Notes\n", DOC, lines), null, "short lines never match on their own");
  assert.equal(secretValueMatch("Acme agrees to pay", DOC, lines), null, "a fragment shorter than a line is not a match");
  assert.equal(secretValueMatch("key=abc", "abc", []), null, "values under the floor are skipped");
});
