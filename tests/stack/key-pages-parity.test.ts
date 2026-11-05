/**
 * key-pages-parity — the Rules page's table of where each company's keys
 * are replaced (dashboard/src/view-model/key-pages.ts, dashboard.md §4.25r
 * *The advice says where to replace the key*) is keyed by the arbiter's
 * content-detector rule ids (`SHAPE_WORDS`, arbiter/policy/policy-suggestions.ts).
 *
 * The dashboard does not import the arbiter, so it names the ids itself. A
 * detector renamed or removed in the arbiter would silently lose its link:
 * this test fails instead. It also pins that each entry's company is the one
 * the arbiter's words for that rule name.
 *
 * Axes explicit: secrets (Keys Mandu found is a confidentiality surface; no
 * axis is read).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SHAPE_WORDS } from "../../arbiter/policy/policy-suggestions.js";
import { KEY_PAGES } from "../../dashboard/src/view-model/key-pages.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

test("every rule id in key-pages.ts is a key of the arbiter's SHAPE_WORDS", () => {
  const missing = Object.keys(KEY_PAGES).filter((rule) => !Object.prototype.hasOwnProperty.call(SHAPE_WORDS, rule));
  assert.deepEqual(missing, [], "rename these in dashboard/src/view-model/key-pages.ts to the arbiter's detector ids");
});

test("each entry's company is the one the arbiter's words for its rule name", () => {
  for (const [rule, p] of Object.entries(KEY_PAGES)) {
    const words = SHAPE_WORDS[rule]!;
    // "GitHub token", "OpenAI-style API key", "AWS access key"; Google Cloud's keys are "Google API key".
    const name = p.company === "Google Cloud" ? "Google" : p.company;
    assert.ok(words.startsWith(name), `${rule}: "${words}" does not name ${p.company}`);
  }
});
