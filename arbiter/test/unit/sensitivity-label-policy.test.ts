/**
 * sensitivity-label-policy.test — the `sensitivity_labels:` section of the law
 * (confidentiality plan 14 §14.1, 4a): the validator, the edit ops
 * (`map-sensitivity-label` / `unmap-sensitivity-label`), their schema and
 * item-level undo, the delta's `sensitivity-labels` facet (the monotonic
 * split), and the administrator's layer (`/etc/mandu/policy.d`, here a
 * temp directory).
 *
 * No privilege; the protection axes are not read by this code.
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AdminLayerError, adminLayerView, NO_ADMIN_LAYER, setAdminLayer } from "../../policy/admin-layer.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { policyDelta } from "../../policy/policy-delta.js";
import { AGENT_EDIT_OPS, applyEdits, diffItems, evaluateEdits, revertItems } from "../../policy/policy-edit.js";
import { policyEditSchema } from "../../policy/policy-edit-schema.js";
import { installAdminLayer, validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { effectiveLabelMapping } from "../../policy/sensitivity-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f7c2a-3b5d-4e6f-8a9b-0c1d2e3f4a5b";
const TENANT = "5b3c2d4e-1111-4222-8333-444455556666";

const dirs: string[] = [];
afterEach(() => { setAdminLayer(NO_ADMIN_LAYER); });
process.on("exit", () => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function layerDir(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "mandu-labels-policy-d-"));
  dirs.push(d);
  for (const [n, text] of Object.entries(files)) writeFileSync(join(d, n), text);
  return d;
}

test("the validator: a good section; a malformed GUID, a duplicate (per site), an unknown level, a long name are refused", () => {
  const good: PolicyFileConfig = {
    sensitivity_labels: [
      { id: HC, site: TENANT, name: "Highly Confidential", level: "no-model" },
      { id: HC, name: "Highly Confidential (any tenant)", level: "no-model" },
      { id: `{${GEN.toUpperCase()}}`, name: "General", level: "public" },
    ],
  };
  assert.deepEqual(validatePolicyDocument(good), []);
  const problems = validatePolicyDocument({
    sensitivity_labels: [
      { id: "9fbde396", name: "x", level: "no-model" },
      { id: HC, site: "tenant", name: "x", level: "no-model" },
      { id: HC, site: TENANT, name: "a", level: "no-model" },
      { id: HC.toUpperCase(), site: `{${TENANT}}`, name: "b", level: "no-model" },
      { id: GEN, name: "c", level: "secret" },
      { id: "6a6a6a6a-1111-4222-8333-444455556666", name: "c", level: ["secret", "strict"].join("-") },
      { id: "2a2a2a2a-1111-4222-8333-444455556666", name: "n".repeat(65), level: "public" },
      { id: "3a3a3a3a-1111-4222-8333-444455556666", name: "two\nlines", level: "public" },
      { id: "4a4a4a4a-1111-4222-8333-444455556666", name: "", level: "public" },
      { id: "5a5a5a5a-1111-4222-8333-444455556666", name: "x", level: "public", color: "red" },
    ],
  } as unknown as PolicyFileConfig).join("\n");
  assert.match(problems, /sensitivity_labels\[0\]\.id: must be a label GUID/);
  assert.match(problems, /sensitivity_labels\[1\]\.site: must be a tenant GUID/);
  assert.match(problems, /sensitivity_labels\[3\]\.id: .* is listed twice/);
  assert.match(problems, /sensitivity_labels\[4\]\.level: must be public \| any-model \| local-model \| no-model/);
  assert.match(problems, /sensitivity_labels\[5\]\.level: .*retired on 2026-09-27/);
  assert.match(problems, /sensitivity_labels\[6\]\.name: must be one line of 1 to 64 characters/);
  assert.match(problems, /sensitivity_labels\[7\]\.name/);
  assert.match(problems, /sensitivity_labels\[8\]\.name/);
  assert.match(problems, /sensitivity_labels\[9\]: unknown key/);
  assert.match(validatePolicyDocument({ sensitivity_labels: "all" } as unknown as PolicyFileConfig).join("\n"), /sensitivity_labels: must be a list/);
});

test("the edit ops: map adds or replaces by (id, site), unmap removes; the result validates; not offered to a model", () => {
  const doc = applyEdits(null, [
    { op: "map-sensitivity-label", id: HC, site: TENANT, name: "Highly Confidential", level: "any-model" },
    { op: "map-sensitivity-label", id: GEN, name: "General", level: "public" },
  ]);
  assert.ok(doc.ok);
  assert.deepEqual(doc.document.sensitivity_labels, [
    { id: HC, site: TENANT, name: "Highly Confidential", level: "any-model" },
    { id: GEN, name: "General", level: "public" },
  ]);
  const raised = applyEdits(doc.document, [{ op: "map-sensitivity-label", id: `{${HC.toUpperCase()}}`, site: TENANT, name: "HC", level: "no-model" }]);
  assert.ok(raised.ok);
  assert.equal(raised.document.sensitivity_labels!.length, 2, "the same (id, site) is replaced, whatever its spelling");
  const gone = applyEdits(raised.document, [{ op: "unmap-sensitivity-label", id: GEN }, { op: "unmap-sensitivity-label", id: HC, site: TENANT }]);
  assert.ok(gone.ok);
  assert.equal(gone.document.sensitivity_labels, undefined, "an emptied section is removed");
  const missing = applyEdits(null, [{ op: "unmap-sensitivity-label", id: HC }]);
  assert.ok(!missing.ok && /no mapping for the label/.test(missing.problems.join()));
  const invalid = applyEdits(null, [{ op: "map-sensitivity-label", id: "nope", name: "x", level: "no-model" }]);
  assert.ok(!invalid.ok && /must be a label GUID/.test(invalid.problems.join()));
  const extra = applyEdits(null, [{ op: "map-sensitivity-label", id: HC, name: "x", level: "no-model", note: "hi" }]);
  assert.ok(!extra.ok && /unknown key 'note'/.test(extra.problems.join()));
  assert.ok(!AGENT_EDIT_OPS.includes("map-sensitivity-label") && !AGENT_EDIT_OPS.includes("unmap-sensitivity-label"));
  const schema = JSON.stringify(policyEditSchema());
  assert.match(schema, /"map-sensitivity-label"/);
});

test("undo: each mapping is its own item (by id and site), so undoing one keeps a later change to another; a change recorded as the whole section still reverts whole", () => {
  const before: PolicyFileConfig = { sensitivity_labels: [{ id: HC, name: "HC", level: "no-model" }] };
  const after = applyEdits(before, [{ op: "map-sensitivity-label", id: GEN, name: "General", level: "any-model" }]);
  assert.ok(after.ok);
  const items = diffItems(before, after.document);
  assert.deepEqual(items.map((i) => [i.section, i.key]), [["sensitivity-labels", `${GEN}|`]], "the one mapping the change made (policy-surface.md §8.4.6)");
  const back = revertItems(after.document, items);
  assert.ok(back.ok);
  assert.deepEqual(back.document.sensitivity_labels, before.sensitivity_labels);
  // A later change to HC survives undoing GEN's.
  const later = applyEdits(after.document, [{ op: "map-sensitivity-label", id: `{${HC.toUpperCase()}}`, name: "HC", level: "local-model" }]);
  assert.ok(later.ok);
  const undone = revertItems(later.document, items);
  assert.ok(undone.ok);
  assert.deepEqual(undone.document.sensitivity_labels, [{ id: `{${HC.toUpperCase()}}`, name: "HC", level: "local-model" }], "HC's later change kept (the same mapping however its id is written), GEN gone");
  // The last mapping undone leaves no empty section.
  const only = revertItems(after.document, diffItems({}, after.document));
  assert.ok(only.ok);
  assert.equal("sensitivity_labels" in only.document, false);
  // A change recorded before the section was itemized: one whole-key item.
  const legacy = [{ section: "key" as const, key: "sensitivity_labels", before: structuredClone(before.sensitivity_labels), after: structuredClone(after.document.sensitivity_labels) }];
  const whole = revertItems(after.document, legacy);
  assert.ok(whole.ok);
  assert.deepEqual(whole.document.sensitivity_labels, before.sensitivity_labels);
});

test("the delta facet: a new mapping above public or a raise tightens; removing, lowering, a new public mapping and a rename relax", () => {
  const law = (labels: PolicyFileConfig["sensitivity_labels"]) => compilePolicy({ specId: "claude-code", document: labels ? { sensitivity_labels: labels } : null });
  const facet = (a: ReturnType<typeof law>, b: ReturnType<typeof law>) => {
    const d = policyDelta(a, b);
    return {
      tighten: d.tightenings.filter((c) => c.facet === "sensitivity-labels").length,
      relax: d.relaxations.filter((c) => c.facet === "sensitivity-labels").length,
      other: d.relaxations.filter((c) => c.facet !== "sensitivity-labels").length,
    };
  };
  const none = law(undefined);
  const hc = law([{ id: HC, name: "HC", level: "any-model" }]);
  const hcUp = law([{ id: HC, name: "HC", level: "no-model" }]);
  const hcRenamed = law([{ id: HC, name: "Public now", level: "any-model" }]);
  const pub = law([{ id: GEN, name: "General", level: "public" }]);
  assert.deepEqual(facet(none, hc), { tighten: 1, relax: 0, other: 0 }, "a new mapping above public");
  assert.deepEqual(facet(hc, hcUp), { tighten: 1, relax: 0, other: 0 }, "a raise");
  assert.deepEqual(facet(hcUp, hc), { tighten: 0, relax: 1, other: 0 }, "a lowering");
  assert.deepEqual(facet(hc, none), { tighten: 0, relax: 1, other: 0 }, "a removal above public");
  assert.deepEqual(facet(none, pub), { tighten: 0, relax: 1, other: 0 }, "a new public mapping silences the label");
  assert.deepEqual(facet(pub, none), { tighten: 0, relax: 0, other: 0 }, "removing a public mapping changes nothing");
  assert.deepEqual(facet(hc, hcRenamed), { tighten: 0, relax: 1, other: 0 }, "a rename changes what the review shows");
  assert.deepEqual(facet(hc, hc), { tighten: 0, relax: 0, other: 0 });
  // The data plane's verdict follows: a new mapping above public is a pure tightening.
  const ev = evaluateEdits({ specId: "claude-code", document: null }, [{ op: "map-sensitivity-label", id: HC, name: "HC", level: "no-model" }]);
  assert.ok(ev.ok && ev.tightening && ev.delta.tightenings.length === 1);
  const lower = evaluateEdits({ specId: "claude-code", document: { sensitivity_labels: [{ id: HC, name: "HC", level: "no-model" }] } }, [{ op: "unmap-sensitivity-label", id: HC }]);
  assert.ok(lower.ok && !lower.tightening);
});

test("the administrator's layer: sensitivity_labels allowed, merged stricter-wins, shown in the view; a duplicate across files refuses", () => {
  const d = layerDir({
    "10-org.yaml": `sensitivity_labels:\n  - id: ${HC}\n    name: Highly Confidential\n    level: no-model\n  - id: ${GEN}\n    site: ${TENANT}\n    name: General\n    level: public\n`,
  });
  const l = installAdminLayer(d);
  assert.deepEqual(l.sensitivityLabels?.map((e) => [e.entry.id, e.file.endsWith("10-org.yaml")]), [[HC, true], [GEN, true]]);
  // A user file cannot lower the organization's mapping; the validator does not refuse it (it merges).
  assert.deepEqual(validatePolicyDocument({ sensitivity_labels: [{ id: HC, name: "Mine", level: "public" }] }), []);
  const m = effectiveLabelMapping([{ id: HC, name: "Mine", level: "public" }], l);
  assert.deepEqual(m.map((e) => [e.id, e.level, e.name]), [[HC, "no-model", "Highly Confidential"], [GEN, "public", "General"]]);
  const view = adminLayerView(l);
  assert.equal(view.admin?.sensitivityLabels.length, 2);
  assert.equal(view.admin?.sensitivityLabels[0]!["name"], "Highly Confidential");

  const dup = layerDir({
    "10-a.yaml": `sensitivity_labels:\n  - id: ${HC}\n    name: A\n    level: no-model\n`,
    "20-b.yaml": `sensitivity_labels:\n  - id: "{${HC.toUpperCase()}}"\n    name: B\n    level: any-model\n  - id: nope\n    name: C\n    level: no-model\n`,
  });
  assert.throws(() => installAdminLayer(dup), (e: unknown) => {
    assert.ok(e instanceof AdminLayerError);
    const all = e.problems.join("\n");
    assert.match(all, /20-b\.yaml: sensitivity_labels: .* is already mapped in .*10-a\.yaml/);
    assert.match(all, /20-b\.yaml: sensitivity_labels\[1\]\.id: must be a label GUID/);
    return true;
  });
  // Still refused: any other key in an administrator's file.
  assert.throws(() => installAdminLayer(layerDir({ "a.yaml": "paths:\n  - path: /x\n    level: public\n" })), /'paths' cannot be set here \(an administrator's file sets models, perimeter, models_locked, sensitivity_labels, prompt_filters and bwrap_path/);
});
