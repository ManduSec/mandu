/**
 * rules-hosts-parts.test — dashboard.md §4.25u *Rules names each host*: the
 * Rules page's own sentences that name hosts come as parts too, each host
 * (and each value's key) a code of its own, the text exactly the string
 * they replace, and a file whose values are bound one by one (plan 13
 * §5.2) says where each value may go in *What the rules say*, not only the
 * whole file's hosts.
 *
 *   P1  `perValueParts`: its text is `perValueWords`, byte for byte, in
 *       every shape (a value with no hosts, the file's own hosts, the whole
 *       file's); the keys and hosts are the codes, in order; no two text
 *       parts touch; two calls share no part;
 *   P2  `hostParts`: one code per host, ", " between;
 *   P3  `sendLine` / `whyWords`: *May be sent to* names each host as a
 *       code; "Nowhere without your OK." is words; a per-value file's line
 *       is the per-value sentence (it said "Nowhere without your OK."
 *       while its values had hosts), for a file and a folder alike;
 *   P4  the browser label (`fileLabel`) and the panel row (`plain`) carry
 *       `sendParts` beside `send`, and nothing without values.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { hostParts, perValueParts, perValueWords } from "../../../src/view-model/rule-words.js";
import { fileLabel, sendLine, whyWords, type PathLevelsEntryWire, type WhyPathWire } from "../../../src/view-model/file-browser.js";
import { toPolicyPanelViewModel } from "../../../src/view-model/policy-panel.js";
import type { PolicySnapshot } from "../../../src/policy-model.js";

type Part = { kind: string; text: string };
const text = (parts: readonly Part[]): string => parts.map((p) => p.text).join("");
const codes = (parts: readonly Part[]): string[] => parts.filter((p) => p.kind === "code").map((p) => p.text);
const noTouchingText = (parts: readonly Part[]): boolean => parts.every((p, i) => i === 0 || !(p.kind === "text" && parts[i - 1]!.kind === "text"));

const HOME = "/home/u";
const VALUES = [{ key: "STRIPE_KEY", bindings: ["api.stripe.com", "payments-eu.example.com"] }, { key: "AWS_*", bindings: ["s3.eu-central-1.amazonaws.com"] }];

test("P1: perValueParts reads exactly as perValueWords, each key and host its own code, in every shape", () => {
  const shapes: Array<[typeof VALUES, string[], string[], string]> = [
    [VALUES, [], [],
      "STRIPE_KEY may be sent only to api.stripe.com, payments-eu.example.com; AWS_* only to s3.eu-central-1.amazonaws.com; a program holding the whole file may send it nowhere without asking."],
    [[{ key: "A", bindings: [] }, { key: "B", bindings: ["b.example"] }], ["f.example", "b.example"], ["b.example"],
      "A may be sent nowhere without asking; B only to b.example; any other value only to f.example, b.example; a program holding the whole file may send it only to b.example."],
    [[{ key: "ONLY", bindings: [] }], [], [], "ONLY may be sent nowhere without asking; a program holding the whole file may send it nowhere without asking."],
    [[], ["f.example"], ["f.example"], "any other value only to f.example; a program holding the whole file may send it only to f.example."],
  ];
  for (const [values, file, whole, words] of shapes) {
    const parts = perValueParts(values, file, whole);
    assert.equal(perValueWords(values, file, whole), words, "the sentence is as it was");
    assert.equal(text(parts), words, "the parts read as the sentence");
    assert.deepEqual(codes(parts), [...values.flatMap((v) => [v.key, ...v.bindings]), ...file, ...whole], "each key and host a code, in order");
    assert.ok(noTouchingText(parts), JSON.stringify(parts));
  }
  const a = perValueParts(VALUES, [], []);
  const b = perValueParts(VALUES, [], []);
  assert.ok(a.every((p) => !b.includes(p)), "two calls share no part");
});

test("P2: hostParts gives each host its own code, a text ', ' between them", () => {
  assert.deepEqual(hostParts(["a.example", "db.internal:5432"]), [{ kind: "code", text: "a.example" }, { kind: "text", text: ", " }, { kind: "code", text: "db.internal:5432" }]);
  assert.deepEqual(hostParts([]), []);
});

const entry = (over: Partial<PathLevelsEntryWire> = {}): PathLevelsEntryWire =>
  ({ path: "/home/u/ws/.env", level: "no-model", bindings: [], rule: "label:/home/u/ws/.env", store: "policy", ...over });
const WHY: WhyPathWire = { path: "/home/u/ws/.env", axis: true, level: "no-model", rule: "label:/home/u/ws/.env", bindings: [], outranked: [], readers: [], others: null, consumers: [], twinShape: null, verdicts: [] };

test("P3: May be sent to names each host as code; nowhere is words; a per-value file says where each value may go, file and folder alike", () => {
  const hosts = ["api.stripe.com", "db.internal:5432", "deploy-hooks.example.com"];
  const listed = sendLine(entry({ bindings: hosts }));
  assert.equal(listed.text, hosts.join(", "), "the text as before");
  assert.equal(text(listed.parts), listed.text);
  assert.deepEqual(codes(listed.parts), hosts);
  const nowhere = sendLine(entry());
  assert.equal(nowhere.text, "Nowhere without your OK.");
  assert.deepEqual(nowhere.parts, [{ kind: "text", text: "Nowhere without your OK." }], "no host, no code");
  // Plan 13 §5.2: `bindings` is the whole file's; the values have their own.
  const perValue = entry({ bindings: [], values: VALUES, fileBindings: ["deploy-hooks.example.com"] });
  const line = sendLine(perValue);
  assert.equal(line.text, perValueWords(VALUES, ["deploy-hooks.example.com"], []), "the sentence the row's Per value shows");
  assert.notEqual(line.text, "Nowhere without your OK.", "it no longer says less than the rules let leave");
  assert.match(line.text, /^STRIPE_KEY may be sent only to api\.stripe\.com, payments-eu\.example\.com; .*a program holding the whole file may send it nowhere without asking\.$/);
  assert.equal(text(line.parts), line.text);
  assert.deepEqual(codes(line.parts), ["STRIPE_KEY", "api.stripe.com", "payments-eu.example.com", "AWS_*", "s3.eu-central-1.amazonaws.com", "deploy-hooks.example.com"]);
  // Not secret: there is nothing to send per value.
  assert.equal(sendLine({ ...perValue, level: "public" }).text, "Nowhere without your OK.");
  for (const folder of [false, true]) {
    const w = whyWords(WHY, perValue, [], HOME, folder);
    const got = w.lines.find((l) => l.term === "May be sent to")!;
    assert.equal(got.text, line.text, `${folder ? "a folder" : "a file"}: the per-value sentence`);
    assert.deepEqual(got.parts, line.parts);
    const other = w.lines.filter((l) => l.term !== "May be sent to");
    assert.ok(other.every((l) => l.parts === undefined), "the other lines are text only");
  }
  const plain = whyWords(WHY, entry({ bindings: hosts }), [], HOME).lines.find((l) => l.term === "May be sent to")!;
  assert.deepEqual(codes(plain.parts!), hosts);
});

const BASE = {
  available: true, verdictsKnown: true, verdicts: [], usage: { rules: [], sensitivePaths: [] }, egressPosture: "normal",
} as unknown as PolicySnapshot;

test("P4: the browser label and the panel row carry sendParts beside send; none without values", () => {
  const l = fileLabel(entry({ values: VALUES, fileBindings: [] }), HOME);
  assert.equal(text(l.sendParts!), l.send);
  assert.deepEqual(codes(l.sendParts!), ["STRIPE_KEY", "api.stripe.com", "payments-eu.example.com", "AWS_*", "s3.eu-central-1.amazonaws.com"]);
  assert.equal(fileLabel(entry({ bindings: ["a.example"] }), HOME).sendParts, undefined);
  const document = { lists: {}, paths: [
    { path: "/home/u/ws/app/.env", level: "no-model", bindings: [], recursive: false, values: VALUES, wholeBindings: [] },
    { path: "/home/u/notes", level: "any-model", bindings: ["api.example.com"], recursive: true },
  ], rules: {}, userRules: [], destinations: [] };
  const rows = toPolicyPanelViewModel({ ...BASE, document } as unknown as PolicySnapshot).yourRules ?? [];
  const r = rows.find((x) => x.id === "lock:/home/u/ws/app/.env")!;
  assert.equal(text(r.plain.sendParts!), r.plain.send);
  assert.deepEqual(codes(r.plain.sendParts!), ["STRIPE_KEY", "api.stripe.com", "payments-eu.example.com", "AWS_*", "s3.eu-central-1.amazonaws.com"]);
  assert.equal(rows.find((x) => x.id === "lock:/home/u/notes")!.plain.sendParts, undefined);
});
