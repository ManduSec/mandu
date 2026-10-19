/**
 * policy-edit-blobs.test — `lock-blob` / `unlock-blob` and policy.yaml
 * `blobs:` end to end through the policy machinery
 * (confidentiality-plan-14-policy-suggestions.md §8.2;
 * policy-surface.md §8.3.2, §8.4.1): the validator's id grammar, the
 * compiled `blobLocks`, the `blob-lock` facet of `policyDelta` (add or raise
 * = tighten; remove, lower or add at public = relax), `relaxationsOf`, the
 * agent's op list, and Undo itemizing by id.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy, relaxationsOf } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { policyDelta } from "../../policy/policy-delta.js";
import {
  AGENT_EDIT_OPS, applyEdits, diffItems, evaluateEdits, revertConflicts, revertItems, type PolicyEdit,
} from "../../policy/policy-edit.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // blob locks are the confidentiality axis's; nothing here reads an axis

const A = `sha1:${"a1".repeat(20)}`;
const B = `sha1:${"b2".repeat(20)}`;
const S256 = `sha256:${"c3".repeat(32)}`;

const law = (doc: PolicyFileConfig | null) => compilePolicy({ specId: "claude-code", document: doc });
const ok = (doc: PolicyFileConfig | null, edits: PolicyEdit[]): PolicyFileConfig => {
  const r = applyEdits(doc, edits);
  assert.ok(r.ok, r.ok ? "" : r.problems.join("\n"));
  return r.document;
};
const deltaOf = (before: PolicyFileConfig | null, edits: PolicyEdit[]) => {
  const ev = evaluateEdits({ specId: "claude-code", document: before }, edits, { now: 0 });
  assert.ok(ev.ok, ev.ok ? "" : ev.problems.join("\n"));
  return ev;
};

test("lock-blob adds an entry; a second lock-blob on the id replaces the level and keeps the note; unlock-blob removes it", () => {
  const one = ok(null, [{ op: "lock-blob", blob: A, level: "no-model", note: "found in history: deploy/config.py" }]);
  assert.deepEqual(one.blobs, [{ id: A, level: "no-model", note: "found in history: deploy/config.py" }]);
  const two = ok(one, [{ op: "lock-blob", blob: A, level: "any-model" }, { op: "lock-blob", blob: S256, level: "no-model" }]);
  assert.deepEqual(two.blobs, [
    { id: A, level: "any-model", note: "found in history: deploy/config.py" },
    { id: S256, level: "no-model" },
  ]);
  const three = ok(two, [{ op: "unlock-blob", blob: A }, { op: "unlock-blob", blob: S256 }]);
  assert.equal("blobs" in three, false, "the emptied section is dropped");
  const r = applyEdits(one, [{ op: "unlock-blob", blob: B }]);
  assert.equal(r.ok, false);
  assert.match(r.ok ? "" : r.problems[0]!, /no lock on sha1:b2/);
});

test("the validator: the id grammar (format prefix, full name, lowercase), the level, one entry per id, a one-line note", () => {
  const bad = (blobs: unknown): string[] => validatePolicyDocument({ version: 1, blobs } as never);
  assert.deepEqual(bad([{ id: A, level: "no-model" }, { id: S256, level: "public", note: "n" }]), []);
  assert.match(bad([{ id: A.toUpperCase().replace("SHA1", "sha1"), level: "no-model" }]).join("\n"), /blobs\[0\]\.id: must be sha1:<40 hex digits> or sha256:<64 hex digits>, lowercase/);
  assert.match(bad([{ id: A.slice(5), level: "no-model" }]).join("\n"), /blobs\[0\]\.id/, "the format prefix is required");
  assert.match(bad([{ id: `sha1:${"a".repeat(39)}`, level: "no-model" }]).join("\n"), /blobs\[0\]\.id/, "a short name is not an id");
  assert.match(bad([{ id: `sha256:${"a".repeat(40)}`, level: "no-model" }]).join("\n"), /blobs\[0\]\.id/, "a sha1 name under sha256");
  assert.match(bad([{ id: A, level: "no-model" }, { id: A, level: "any-model" }]).join("\n"), /blobs\[1\]\.id: .* listed twice/);
  assert.match(bad([{ id: A, level: "top-secret" }]).join("\n"), /blobs\[0\]\.level: must be public \| any-model \| local-model \| no-model/);
  assert.match(bad([{ id: A, level: "no-model", note: "a\nb" }]).join("\n"), /blobs\[0\]\.note: must be one line/);
  assert.match(bad([{ id: A, level: "no-model", note: "x".repeat(201) }]).join("\n"), /blobs\[0\]\.note/);
  assert.match(bad([{ id: A, level: "no-model", path: "/x" }]).join("\n"), /blobs\[0\]: unknown key 'path'/);
  assert.match(bad({ id: A }).join("\n"), /^blobs: must be a list/);
});

test("compiled: blobLocks by id; an unknown level (a loader that skipped the validator) locks at no-model, a malformed id locks nothing", () => {
  const c = law({ version: 1, blobs: [{ id: A, level: "any-model", note: "n" }, { id: B, level: "bogus" }, { id: "sha1:nope", level: "no-model" }] });
  assert.deepEqual([...c.blobLocks.values()], [{ id: A, level: "any-model", note: "n" }, { id: B, level: "no-model" }]);
  assert.equal(law(null).blobLocks.size, 0, "the built-ins lock no object");
});

test("policyDelta blob-lock: add above public or raise = tighten; remove, lower, or add at public = relax; a note alone is no change", () => {
  const base: PolicyFileConfig = { version: 1, blobs: [{ id: A, level: "any-model" }] };
  const add = deltaOf(base, [{ op: "lock-blob", blob: B, level: "no-model" }]);
  assert.equal(add.tightening, true);
  assert.deepEqual(add.delta.tightenings.map((c) => [c.facet, c.subject]), [["blob-lock", B]]);
  for (const level of ["any-model", "local-model"] as const) {
    assert.equal(deltaOf(base, [{ op: "lock-blob", blob: B, level }]).tightening, true, `a new lock at ${level} hides the object: a tightening`);
  }
  const raise = deltaOf(base, [{ op: "lock-blob", blob: A, level: "no-model" }]);
  assert.equal(raise.tightening, true);
  assert.match(raise.delta.tightenings[0]!.detail, /raised from any-model to no-model/);

  const pub = deltaOf(base, [{ op: "lock-blob", blob: B, level: "public" }]);
  assert.equal(pub.tightening, false, "a public blob lock is a declaration a human makes");
  assert.deepEqual(pub.delta.relaxations.map((c) => [c.facet, c.subject]), [["blob-lock", B]]);
  const lower = deltaOf({ version: 1, blobs: [{ id: A, level: "no-model" }] }, [{ op: "lock-blob", blob: A, level: "any-model" }]);
  assert.equal(lower.tightening, false);
  assert.match(lower.delta.relaxations[0]!.detail, /lowered from no-model to any-model/);
  const remove = deltaOf(base, [{ op: "unlock-blob", blob: A }]);
  assert.equal(remove.tightening, false);
  assert.match(remove.delta.relaxations[0]!.detail, /is removed/);

  const noted = deltaOf(base, [{ op: "lock-blob", blob: A, level: "any-model", note: "changed words" }]);
  assert.deepEqual(noted.delta, { relaxations: [], tightenings: [] }, "the note is words only");
  // `blobs` is a known document key: a law holding one never turns an
  // unrelated tightening into a proposal ("unknown document key").
  const unrelated = deltaOf(base, [{ op: "lock-path", path: "/srv/x", level: "no-model" }]);
  assert.equal(unrelated.tightening, true);
  assert.deepEqual(policyDelta(law(base), law(base)), { relaxations: [], tightenings: [] });
});

test("relaxationsOf: a public blob lock is listed; a lock above public is not", () => {
  const r = relaxationsOf(law({ version: 1, blobs: [{ id: A, level: "public" }, { id: B, level: "no-model" }] }));
  assert.deepEqual(r.filter((x) => x.kind === "public-blob").map((x) => x.subject), [A]);
  assert.equal(r.some((x) => x.subject === B), false);
});

test("the agent may send both blob ops (lock-blob tightens at once; unlock-blob waits for a human)", () => {
  assert.ok(AGENT_EDIT_OPS.includes("lock-blob"));
  assert.ok(AGENT_EDIT_OPS.includes("unlock-blob"));
});

test("Undo itemizes blobs by id: reverting one lock keeps a later lock on another; a lock changed since is a conflict", () => {
  const v0: PolicyFileConfig = { version: 1 };
  const v1 = ok(v0, [{ op: "lock-blob", blob: A, level: "no-model" }]);
  const change1 = diffItems(v0, v1);
  assert.deepEqual(change1.map((i) => [i.section, i.key, i.before]), [["blobs", A, null]]);
  const v2 = ok(v1, [{ op: "lock-blob", blob: B, level: "no-model" }]);
  const undone = revertItems(v2, change1);
  assert.ok(undone.ok);
  assert.deepEqual(undone.ok ? undone.document.blobs : null, [{ id: B, level: "no-model" }], "B survives the undo of A");
  assert.deepEqual(revertConflicts(v2, change1), []);
  const v3 = ok(v2, [{ op: "lock-blob", blob: A, level: "any-model" }]);
  assert.deepEqual(revertConflicts(v3, change1), [`blobs ${A}`], "A changed again since: Undo names it and changes nothing");
  // Undoing the only lock drops the section.
  const back = revertItems(v1, change1);
  assert.ok(back.ok && !("blobs" in back.document));
});
