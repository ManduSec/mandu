/**
 * prompt-filter-policy.test — `prompt_filters:` in policy.yaml
 * (confidentiality-plan-15-prompt-filter.md §6, phase 2). Mandu-new.
 *
 * Proves: the validator's grammar (on/off, on_error, actions, exceptions,
 * signed_only; `ask` accepted since phase 3 (ranked between mask and block),
 * `endpoint` a model's name since the classifier plugins, its typed edit a
 * relaxation whichever way it moves; `locked` only in
 * the administrator's layer); the effective configuration (built-in
 * defaults, the administrator's rows as defaults, a LOCKED row holding
 * against a weaker one of the person's, longest-prefix resolution with the
 * `redact` fallback); the lock problems the validator reports; the
 * monotonic split of `policyDelta`'s `prompt-filters` facet through the
 * typed edits (turning on and raising an action apply as tightenings;
 * turning off, lowering, an exception, signed_only are relaxations); the
 * administrator's layer admits `prompt_filters:` and refuses a duplicate.
 *
 * Axes: secrets (stated; nothing here reads the axes).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  checkPromptFilters,
  comparePromptFilters,
  coversCategory,
  effectivePromptConfig,
  globRegExp,
  promptConfigDigest,
  promptLockProblems,
  resolveAction,
  type AdminPromptFilters,
} from "../../prompt-filter/policy.js";
import { evaluateEdits } from "../../policy/policy-edit.js";
import { validatePolicyDocument, installAdminLayer } from "../../policy/policy-file-validate.js";
import { AdminLayerError, NO_ADMIN_LAYER, adminLayerView, setAdminLayer } from "../../policy/admin-layer.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const problems = (v: unknown, admin = false): string[] => {
  const out: string[] = [];
  checkPromptFilters(v, "prompt_filters", out, { admin });
  return out;
};

test("the validator: the grammar of §6; a user's locked is refused; ask is accepted; endpoint (phase 3) is a model's name", () => {
  assert.deepEqual(problems({
    filters: { "registered-value": "on", "key-shapes": true, "acme-dlp": { on: true, on_error: "pass" }, off1: "off" },
    actions: { "secret.registered": "mask", "secret.shape": "redact", "pii.payment-card": "block", pii: { action: "log" } },
    exceptions: [{ category: "pii.email", match: "*@example.com" }],
    signed_only: false,
  }), []);
  assert.deepEqual(problems({ actions: { "acme.codename": "ask", pii: { action: "ask" } } }), [], "ask is a policy action since phase 3");
  assert.deepEqual(problems({ filters: { cls: { on: true, endpoint: "ollama-local" } } }), [], "phase 3: endpoint names a models: entry");
  assert.match(problems({ filters: { cls: { on: true, endpoint: 7 } } }).join("\n"), /endpoint: must name a models: entry/);
  assert.match(problems({ filters: { x: { on: true, locked: true } } }).join("\n"), /only your administrator's files can lock a filter/);
  assert.match(problems({ actions: { pii: { action: "block", locked: true } } }).join("\n"), /only your administrator's files can lock an action/);
  assert.deepEqual(problems({ filters: { x: { on: true, locked: true } }, actions: { pii: { action: "block", locked: true } } }, true), []);
  assert.match(problems({ signed_only: true }, true).join("\n"), /signed_only: unknown key/, "signed_only is the person's");
  assert.match(problems({ filters: { "Bad Id": "on" } }).join("\n"), /a filter id is lowercase/);
  assert.match(problems({ actions: { "PII.Email": "redact" } }).join("\n"), /dotted lowercase/);
  assert.match(problems({ actions: { pii: "hide" } }).join("\n"), /must be one of pass, log, redact, mask, ask, block/);
  assert.match(problems({ exceptions: [{ category: "pii.email", match: "*" }] }).join("\n"), /would let every finding/);
  assert.match(problems({ exceptions: [{ category: "pii.email" }] }).join("\n"), /match: must be a one-line pattern/);
  assert.match(problems({ nope: 1 }).join("\n"), /prompt_filters\.nope: unknown key/);
  // Through the whole-document validator.
  assert.deepEqual(validatePolicyDocument({ prompt_filters: { filters: { "key-shapes": "on" } } }), []);
  assert.match(validatePolicyDocument({ prompt_filters: [] }).join("\n"), /prompt_filters: must be a mapping/);
});

test("the effective configuration: built-in defaults, longest prefix wins, the fallback is redact", () => {
  const d = effectivePromptConfig(null);
  assert.deepEqual([...d.filters.values()].map((f) => [f.id, f.on, f.setBy]), [["registered-value", true, "default"], ["key-shapes", false, "default"]]);
  assert.equal(resolveAction(d, "secret.registered"), "mask");
  assert.equal(resolveAction(d, "pii.email"), "redact", "decision 3: a non-registered finding is redacted by default");
  const c = effectivePromptConfig({ actions: { pii: "log", "pii.payment-card": "block", "secret.shape": "mask" }, filters: { "registered-value": "off" } });
  assert.equal(resolveAction(c, "pii.email"), "log");
  assert.equal(resolveAction(c, "pii.payment-card"), "block");
  assert.equal(resolveAction(c, "pii.payment-card.amex"), "block");
  assert.equal(resolveAction(c, "piiz"), "redact", "a prefix covers only dotted children");
  assert.equal(resolveAction(c, "secret.shape.github-token"), "mask");
  assert.equal(c.filters.get("registered-value")!.on, false);
  assert.equal(c.filters.get("registered-value")!.setBy, "you");
  assert.ok(coversCategory("pii", "pii.email") && !coversCategory("pii.email", "pii"));
  assert.ok(globRegExp("*@example.com").test("Bob@Example.com"));
  assert.ok(!globRegExp("*@example.com").test("bob@example.com.evil"));
  assert.notEqual(promptConfigDigest(d), promptConfigDigest(c), "the digest moves with the policy");
});

test("the administrator's layer: rows are defaults; a LOCKED row holds against a weaker one, and the validator names it", () => {
  const admin: AdminPromptFilters[] = [{
    file: "/etc/mandu/policy.d/10-org.yaml",
    config: {
      filters: { "acme-dlp": { on: true, locked: true }, "key-shapes": "on" },
      actions: { "pii.payment-card": { action: "block", locked: true }, pii: "redact" },
      exceptions: [{ category: "pii.email", match: "*@acme.example" }],
    },
  }];
  const user = {
    filters: { "acme-dlp": "off", "key-shapes": "off" },
    actions: { "pii.payment-card": "log", "pii.payment-card.test": "pass", pii: "log" },
    exceptions: [{ category: "pii.payment-card", match: "4111*" }, { category: "pii.phone", match: "555-*" }],
  };
  const c = effectivePromptConfig(user, admin);
  assert.equal(c.filters.get("acme-dlp")!.on, true, "a locked filter stays on");
  assert.equal(c.filters.get("acme-dlp")!.setBy, "administrator");
  assert.equal(c.filters.get("key-shapes")!.on, false, "an unlocked administrator's switch is a default the person may change");
  assert.equal(resolveAction(c, "pii.payment-card"), "block");
  assert.equal(resolveAction(c, "pii.payment-card.test"), "block", "a person's sub-row cannot weaken a locked prefix");
  assert.equal(resolveAction(c, "pii.email"), "log", "an unlocked administrator's row is overridden");
  const exc = c.exceptions.map((e) => [e.category, e.setBy, e.inForce]);
  assert.deepEqual(exc, [["pii.email", "administrator", true], ["pii.payment-card", "you", false], ["pii.phone", "you", true]]);
  const lp = promptLockProblems(user, admin).join("\n");
  assert.match(lp, /filters\.acme-dlp: set by your administrator \(\/etc\/mandu\/policy\.d\/10-org\.yaml\)/);
  assert.match(lp, /actions\.pii\.payment-card: pii\.payment-card is set by your administrator .* log would relax it/);
  assert.match(lp, /actions\.pii\.payment-card\.test: /);
  assert.match(lp, /exceptions\[0\]: pii\.payment-card is set by your administrator/);
  assert.doesNotMatch(lp, /key-shapes|actions\.pii:|exceptions\[1\]/, "unlocked rows are the person's to change");
});

test("policyDelta's prompt-filters facet: on and up tighten; off, down, an exception and signed_only relax", () => {
  const before = { specId: "claude-code" as const, document: { version: 1, prompt_filters: { actions: { pii: "redact" as const } } } };
  const ev = (edits: unknown[]) => {
    const r = evaluateEdits(before, edits);
    assert.ok(r.ok, JSON.stringify(r));
    return r;
  };
  const on = ev([{ op: "set-prompt-filter", filter: "key-shapes", on: true }]);
  assert.equal(on.tightening, true);
  assert.equal(on.document.prompt_filters?.filters?.["key-shapes"], "on");
  assert.equal(ev([{ op: "set-prompt-action", category: "pii", action: "block" }]).tightening, true);
  assert.equal(ev([{ op: "set-prompt-action", category: "pii.payment-card", action: "mask" }]).tightening, true);
  assert.equal(ev([{ op: "set-prompt-filter", filter: "acme", on: true, on_error: "block" }]).tightening, true);
  for (const [edits, why] of [
    [[{ op: "set-prompt-filter", filter: "registered-value", on: false }], /registered-value is turned off/],
    [[{ op: "set-prompt-action", category: "pii", action: "log" }], /findings of pii: redact → log/],
    [[{ op: "set-prompt-action", category: "pii.email", action: "pass" }], /findings of pii\.email: redact → pass/],
    [[{ op: "remove-prompt-action", category: "pii" }, { op: "set-prompt-action", category: "secret.registered", action: "redact" }], /secret\.registered: mask → redact/],
    [[{ op: "add-prompt-exception", category: "pii.email", match: "*@example.com" }], /matching \*@example\.com are let through/],
    [[{ op: "set-prompt-filter", filter: "acme", on: true, on_error: "pass" }], /on_error of the prompt filter acme: default → pass/],
  ] as const) {
    const r = ev(edits as unknown as unknown[]);
    assert.equal(r.tightening, false, JSON.stringify(edits));
    assert.match(r.delta.relaxations.map((x) => x.detail).join("\n"), why);
    assert.ok(r.delta.relaxations.every((x) => x.facet === "prompt-filters"));
  }
  // signed_only and removing an exception (hand edits through the comparison).
  assert.equal(comparePromptFilters({ signed_only: false }, { signed_only: true })[0]!.direction, "relax");
  assert.equal(comparePromptFilters({ exceptions: [{ category: "pii.email", match: "*@x.example" }] }, {})[0]!.direction, "tighten");
  assert.equal(comparePromptFilters({}, "nonsense")[0]!.direction, "relax", "an unreadable value is a relaxation (fail closed)");
  assert.deepEqual(comparePromptFilters({ actions: { pii: "log" } }, { actions: { pii: "log" } }), []);
  // remove-prompt-exception on a missing one is a problem, not a silent no-op.
  const bad = evaluateEdits(before, [{ op: "remove-prompt-exception", category: "pii.email", match: "x" }]);
  assert.equal(bad.ok, false);
  // Phase 3: ask ranks between mask and block, so raising a category to ask
  // is a tightening (the human alone answers the hold) and ask → mask relaxes.
  const ask = ev([{ op: "set-prompt-action", category: "pii", action: "ask" }]);
  assert.equal(ask.tightening, true);
  assert.equal(ask.document.prompt_filters?.actions?.["pii"], "ask");
  assert.equal(comparePromptFilters({ actions: { pii: "ask" } }, { actions: { pii: "mask" } })[0]!.direction, "relax");
  assert.equal(comparePromptFilters({ actions: { pii: "ask" } }, { actions: { pii: "block" } })[0]!.direction, "tighten");
  // The validator still runs on the result: an unknown action cannot be written.
  const bogus = evaluateEdits(before, [{ op: "set-prompt-action", category: "pii", action: "hide" }]);
  assert.equal(bogus.ok, false);
});

test("set-prompt-filter's endpoint (phase 3): any change relaxes; on_error is kept; null removes it; a model that is not local: true is refused", () => {
  const models = [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat" as const, model: "qwen2.5:7b", local: true },
    { name: "gpu", url: "http://127.0.0.1:8000", wire: "openai-chat" as const, local: true },
    { name: "cloud", url: "https://api.example.com", wire: "openai-chat" as const, model: "x" },
  ];
  const before = { specId: "claude-code" as const, document: { version: 1, models, prompt_filters: { filters: { cls: { on: true, on_error: "pass" as const } } } } };
  const set = evaluateEdits(before, [{ op: "set-prompt-filter", filter: "cls", on: true, endpoint: "ollama" }]);
  assert.ok(set.ok, JSON.stringify(set));
  assert.deepEqual(set.document.prompt_filters?.filters?.["cls"], { on: true, on_error: "pass", endpoint: "ollama" }, "on_error kept");
  assert.equal(set.tightening, false);
  assert.match(set.delta.relaxations.map((x) => x.detail).join("\n"), /sends your prompts to the model ollama/);
  const moved = evaluateEdits({ ...before, document: set.document }, [{ op: "set-prompt-filter", filter: "cls", on: true, endpoint: "gpu" }]);
  assert.ok(moved.ok);
  assert.equal(moved.tightening, false, "another local model is still a relaxation");
  const cleared = evaluateEdits({ ...before, document: set.document }, [{ op: "set-prompt-filter", filter: "cls", on: true, endpoint: null }]);
  assert.ok(cleared.ok);
  assert.deepEqual(cleared.document.prompt_filters?.filters?.["cls"], { on: true, on_error: "pass" });
  assert.equal(cleared.tightening, false);
  const kept = evaluateEdits({ ...before, document: set.document }, [{ op: "set-prompt-filter", filter: "cls", on: false }]);
  assert.ok(kept.ok);
  assert.deepEqual(kept.document.prompt_filters?.filters?.["cls"], { on: false, on_error: "pass", endpoint: "ollama" }, "an edit without endpoint keeps it");
  const remote = evaluateEdits(before, [{ op: "set-prompt-filter", filter: "cls", on: true, endpoint: "cloud" }]);
  assert.equal(remote.ok, false);
  assert.match((remote as { problems: string[] }).problems.join("\n"), /'cloud' is not declared local: true/);
  assert.equal(evaluateEdits(before, [{ op: "set-prompt-filter", filter: "cls", on: true, endpoint: 7 }]).ok, false);
});

function layerDir(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "mdu-prompt-admin-"));
  dirs.push(d);
  for (const [n, t] of Object.entries(files)) writeFileSync(join(d, n), t);
  return d;
}

test("the administrator's layer admits prompt_filters (with locked), shows it, and refuses a duplicate across files", () => {
  const d = layerDir({ "10-org.yaml": "prompt_filters:\n  filters:\n    key-shapes: { on: true, locked: true }\n  actions:\n    secret.shape: { action: block, locked: true }\n" });
  const l = installAdminLayer(d);
  try {
    assert.equal(l.promptFilters?.length, 1);
    assert.equal(adminLayerView(l).admin?.promptFilters[0]!.file, join(d, "10-org.yaml"));
    // The person's file cannot ADD a conflict with the lock.
    assert.match(validatePolicyDocument({ prompt_filters: { filters: { "key-shapes": "off" } } }).join("\n"), /set by your administrator/);
    assert.deepEqual(validatePolicyDocument({ prompt_filters: { actions: { "secret.shape": "block", pii: "log" } } }), []);
    // A relaxation under the lock does not even change the law in force.
    const c = effectivePromptConfig({ actions: { "secret.shape.github-token": "log" } }, l.promptFilters);
    assert.equal(resolveAction(c, "secret.shape.github-token"), "block");
  } finally {
    setAdminLayer(NO_ADMIN_LAYER);
  }
  const dup = layerDir({
    "10-a.yaml": "prompt_filters:\n  actions:\n    pii: block\n",
    "20-b.yaml": "prompt_filters:\n  actions:\n    pii: log\n  signed_only: true\n",
  });
  assert.throws(() => installAdminLayer(dup), (e: unknown) => {
    assert.ok(e instanceof AdminLayerError);
    const all = e.problems.join("\n");
    assert.match(all, /20-b\.yaml: prompt_filters\.signed_only: unknown key/);
    return true;
  });
  const dup2 = layerDir({ "10-a.yaml": "prompt_filters:\n  actions:\n    pii: block\n", "20-b.yaml": "prompt_filters:\n  actions:\n    pii: log\n" });
  assert.throws(() => installAdminLayer(dup2), /20-b\.yaml: prompt_filters\.actions\.pii is already set in .*10-a\.yaml/);
  setAdminLayer(NO_ADMIN_LAYER);
});
