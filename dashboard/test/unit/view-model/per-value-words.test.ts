/**
 * per-value-words.test — the Rules page's words for a file whose values are
 * bound one by one (confidentiality plan 13 §5.2, `values:`; the sentences in
 * §5.3's form; dashboard.md §4.25p "Per value").
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { perValueWords, TERMS } from "../../../src/view-model/rule-words.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import { fileLabel } from "../../../src/view-model/file-browser.js";
import type { PolicySnapshot } from "../../../src/policy-model.js";

const VALUES = [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }, { key: "AWS_*", bindings: ["amazonaws.com"] }];

test("perValueWords: plan 13 §5.3's sentence, each value then the whole file", () => {
  assert.equal(perValueWords(VALUES, [], []),
    "STRIPE_KEY may be sent only to api.stripe.com; AWS_* only to amazonaws.com; a program holding the whole file may send it nowhere without asking.");
  assert.equal(perValueWords([{ key: "A", bindings: [] }, { key: "B", bindings: ["b.example"] }], ["f.example", "b.example"], ["b.example"]),
    "A may be sent nowhere without asking; B only to b.example; any other value only to f.example, b.example; a program holding the whole file may send it only to b.example.");
});

const BASE = {
  available: true, verdictsKnown: true, verdicts: [], usage: { rules: [], sensitivePaths: [] }, egressPosture: "normal",
} as unknown as PolicySnapshot;

function rows(paths: unknown[]) {
  const document = { lists: {}, paths, rules: {}, userRules: [], destinations: [] };
  return toPolicyPanelViewModel({ ...BASE, document } as unknown as PolicySnapshot).yourRules ?? [];
}

test("a file rule with values: carries them, says where each may go, and its level words name no file host", () => {
  const r = rows([{ path: "/home/u/ws/app/.env", level: "no-model", bindings: [], recursive: false, values: VALUES, wholeBindings: [] }])
    .find((x) => x.id === "lock:/home/u/ws/app/.env")!;
  assert.deepEqual(r.values, VALUES);
  assert.equal(r.plain.effect, TERMS.hidden);
  assert.equal(r.plain.send, "STRIPE_KEY may be sent only to api.stripe.com; AWS_* only to amazonaws.com; a program holding the whole file may send it nowhere without asking.");
  assert.match(r.effect, /per value: STRIPE_KEY → api\.stripe\.com; AWS_\* → amazonaws\.com/, "the inspector's words list them too");
  assert.doesNotMatch(r.plain.send!, /placeholder|binding|symbol|policy\.yaml|twin|taint/i, "the product's own vocabulary");
  // Without values: nothing changes.
  const plain = rows([{ path: "/home/u/notes", level: "any-model", bindings: ["api.example.com"], recursive: true }]).find((x) => x.id === "lock:/home/u/notes")!;
  assert.equal(plain.values, undefined);
  assert.equal(plain.plain.send, undefined);
  assert.equal(plain.plain.effect, "Any AI, when it asks; may be sent to api.example.com");
  // Not secret: there is nothing to send per value.
  const pub = rows([{ path: "/home/u/pub.env", level: "public", bindings: [], recursive: false, values: VALUES }]).find((x) => x.id === "lock:/home/u/pub.env")!;
  assert.equal(pub.plain.send, undefined);
});

test("the file browser's label for a file under a rule with values: the same sentence, from the arbiter's whole-file answer", () => {
  const l = fileLabel({ path: "/home/u/ws/app/.env", level: "no-model", bindings: [], rule: "label:/home/u/ws/app/.env", store: "policy", values: VALUES, fileBindings: [] }, "/home/u");
  assert.deepEqual(l.values, VALUES);
  assert.equal(l.words, TERMS.hidden);
  assert.match(l.send ?? "", /^STRIPE_KEY may be sent only to api\.stripe\.com;/);
  const none = fileLabel({ path: "/home/u/x", level: "no-model", bindings: ["a.example"], rule: "label:/home/u/x", store: "policy" }, "/home/u");
  assert.equal(none.values, undefined);
  assert.equal(none.words, "No AI; may be sent to a.example");
});

test("a program holding a file with values: on the Approvals card: where the whole file may go, and no Always, with the reason in words", async () => {
  const { holderSourceWords } = await import("../../../src/view-model/ask-words.js");
  const [w] = holderSourceWords([{ path: "/home/u/ws/.env", level: "no-model", bindings: [], blocks: true, always: false, noAlways: "per-value" }] as never, "api.stripe.com", "/home/u");
  assert.equal(w!.mayGo, "may go nowhere");
  assert.equal(w!.always, undefined);
  assert.equal(w!.noAlways, "Each value in it has its own hosts, and the whole file may go only where every value may. Add the host to the values in your rules file.");
  assert.doesNotMatch(w!.noAlways!, /placeholder|binding|symbol|policy\.yaml|twin|taint/i);
});
