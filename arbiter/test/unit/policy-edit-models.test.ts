/**
 * policy-edit-models.test — the model ops of the edit grammar
 * (policy-surface.md §8.4.1, confidentiality-plan-11 §7.3).
 *
 * Pins:
 *   - add-model / update-model / remove-model apply onto an empty and a
 *     populated document; update replaces the entry whole; the input is never
 *     modified;
 *   - the validator's own `checkModels` rules refuse a bad entry (url with
 *     credentials, a cloud-backed model at `local: true`, a token VALUE in
 *     token_env, a duplicate name), so the grammar adds no second copy;
 *   - the delta classifies EVERY models change as a relaxation (add local, add
 *     outside, edit, remove, rename), and an unchanged `models:` section no
 *     longer turns an unrelated tightening into a proposal;
 *   - Undo reverts a model change item by item, keeps a later change to
 *     another model, refuses when the same model changed again, and still
 *     reverts a change recorded when `models:` was one whole-key item.
 *
 * Pure: no arbiter, no DB, no privilege; no protection axis is read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { policyDelta } from "../../policy/policy-delta.js";
import { applyEdits, canonicalJson, diffItems, evaluateEdits, revertConflicts, revertItems, type PolicyEdit } from "../../policy/policy-edit.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";

const NOW = Date.parse("2026-09-28T00:00:00Z");
const SPEC = "claude-code" as const;

const OLLAMA = { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat" as const, model: "llama3.2", local: true };
const WITH_MODELS: PolicyFileConfig = {
  version: 1,
  paths: [{ path: "/home/u/notes", level: "local-model" }],
  models: [OLLAMA, { name: "gateway", url: "https://llm.example.com" }],
};

function ok(doc: PolicyFileConfig | null, edits: PolicyEdit[]): PolicyFileConfig {
  const r = applyEdits(doc, edits, { now: NOW });
  assert.ok(r.ok, `expected the edits to apply: ${r.ok ? "" : r.problems.join("; ")}`);
  assert.deepEqual(validatePolicyDocument(r.document), []);
  return r.document;
}

function refused(doc: PolicyFileConfig | null, edits: unknown, pattern: RegExp): void {
  const r = applyEdits(doc, edits, { now: NOW });
  assert.equal(r.ok, false, `expected a refusal for ${JSON.stringify(edits)}`);
  if (!r.ok) assert.match(r.problems.join("\n"), pattern);
}

test("add-model onto an empty document writes the entry as given; the input is never modified", () => {
  const doc = ok(null, [{ op: "add-model", ...OLLAMA, token_env: "OLLAMA_TOKEN" }]);
  assert.deepEqual(doc.models, [{ ...OLLAMA, token_env: "OLLAMA_TOKEN" }]);
  const input = structuredClone(WITH_MODELS);
  const more = ok(input, [{ op: "add-model", name: "lab", url: "http://10.0.0.5:8000" }]);
  assert.deepEqual(input, WITH_MODELS, "applyEdits works on a copy");
  assert.deepEqual(more.models?.map((m) => m.name), ["ollama", "gateway", "lab"]);
});

test("update-model replaces the named entry whole, in place; remove-model drops it and an emptied section", () => {
  const doc = ok(WITH_MODELS, [{ op: "update-model", name: "ollama", url: "http://127.0.0.1:11434" }]);
  assert.deepEqual(doc.models?.[0], { name: "ollama", url: "http://127.0.0.1:11434" }, "a field left out is removed (wire, model, local)");
  assert.equal(doc.models?.[1]?.name, "gateway", "the order is kept");
  const gone = ok(WITH_MODELS, [{ op: "remove-model", name: "gateway" }, { op: "remove-model", name: "ollama" }]);
  assert.equal(gone.models, undefined, "an empty models: section is not left behind");
});

test("the validator's checkModels rules refuse a bad entry; missing and duplicate names are refused", () => {
  refused(WITH_MODELS, [{ op: "add-model", name: "ollama", url: "http://127.0.0.1:1" }], /already declared/);
  refused(WITH_MODELS, [{ op: "update-model", name: "nope", url: "http://127.0.0.1:1" }], /no model named "nope"/);
  refused(WITH_MODELS, [{ op: "remove-model", name: "nope" }], /no model named "nope"/);
  refused(null, [{ op: "add-model", name: "x", url: "http://user:pw@127.0.0.1:1" }], /no credentials/);
  refused(null, [{ op: "add-model", name: "x", url: "ftp://127.0.0.1" }], /http\(s\) URL/);
  refused(null, [{ op: "add-model", name: "x", url: "http://127.0.0.1:11434", model: "gpt-oss:120b-cloud", local: true }], /cloud model/);
  refused(null, [{ op: "add-model", name: "x", url: "http://127.0.0.1:1", token_env: "sk-live-abc123" }], /environment variable NAME/);
  refused(null, [{ op: "add-model", name: "bad name", url: "http://127.0.0.1:1" }], /letters, digits/);
  refused(null, [{ op: "add-model", name: "x", url: "http://127.0.0.1:1", local: "yes" }], /local: must be true or false/);
  refused(null, [{ op: "add-model", name: "x", url: "http://127.0.0.1:1", token: "sk-123" }], /unknown key 'token'/);
  refused(WITH_MODELS, [{ op: "add-model", name: "lab", url: "https://10.0.0.5:8443", helper: true }], /helper: 'lab' is not local: true/);
  refused({ ...WITH_MODELS, models: [{ ...OLLAMA, helper: true }] },
    [{ op: "add-model", name: "lab", url: "https://10.0.0.5:8443", local: true, helper: true }], /only one model can be the helper's/);
  // A non-local entry may name a cloud model: it is an outside model either way.
  ok(null, [{ op: "add-model", name: "x", url: "http://127.0.0.1:11434", model: "gpt-oss:120b-cloud" }]);
});

test("the delta: EVERY models change is a relaxation (add local, add outside, edit, remove, rename)", () => {
  const before = { specId: SPEC, document: WITH_MODELS };
  const cases: Array<[string, PolicyEdit[], string[]]> = [
    ["add local", [{ op: "add-model", name: "lab", url: "https://10.0.0.5:8443", local: true }], ["lab"]],
    ["add outside", [{ op: "add-model", name: "lab", url: "http://10.0.0.5:8000" }], ["lab"]],
    ["edit the url", [{ op: "update-model", ...OLLAMA, url: "http://127.0.0.1:11435" }], ["ollama"]],
    ["drop local", [{ op: "update-model", ...OLLAMA, local: false }], ["ollama"]],
    ["only the token variable", [{ op: "update-model", ...OLLAMA, token_env: "T" }], ["ollama"]],
    ["make it the helper", [{ op: "update-model", ...OLLAMA, helper: true }], ["ollama"]],
    ["remove", [{ op: "remove-model", name: "gateway" }], ["gateway"]],
    ["rename", [{ op: "remove-model", name: "gateway" }, { op: "add-model", name: "gw", url: "https://llm.example.com" }], ["gw", "gateway"]],
  ];
  for (const [what, edits, subjects] of cases) {
    const ev = evaluateEdits(before, edits, { now: NOW });
    assert.ok(ev.ok, `${what}: ${ev.ok ? "" : ev.problems.join("; ")}`);
    assert.equal(ev.tightening, false, `${what} is a relaxation`);
    assert.deepEqual(ev.delta.relaxations.map((r) => r.facet), subjects.map(() => "models"), what);
    assert.deepEqual(ev.delta.relaxations.map((r) => r.subject).sort(), [...subjects].sort(), what);
    assert.deepEqual(ev.delta.tightenings, [], `${what}: a models change has no tightening form`);
  }
  const local = evaluateEdits(before, [{ op: "add-model", name: "lab", url: "https://10.0.0.5:8443", local: true }], { now: NOW });
  assert.ok(local.ok);
  assert.match(local.delta.relaxations[0]!.detail, /files labeled local-model may be sent to it/);
  assert.doesNotMatch(local.delta.relaxations[0]!.detail, /unencrypted/);
  // Plan 12 D2: the opt-out is spelled out in the delta the human reads.
  const plain = evaluateEdits(before, [{ op: "add-model", name: "lab", url: "http://10.0.0.5:8000", local: true, allow_plain_http: true }], { now: NOW });
  assert.ok(plain.ok, plain.ok ? "" : plain.problems.join("; "));
  assert.match(plain.delta.relaxations[0]!.detail, /files labeled local-model may be sent to it unencrypted \(allow_plain_http\)/);
  const flip = evaluateEdits({ specId: SPEC, document: { ...WITH_MODELS, models: [...WITH_MODELS.models!, { name: "lab", url: "http://10.0.0.5:8000", local: true, allow_plain_http: true }] } },
    [{ op: "update-model", name: "lab", url: "https://10.0.0.5:8443", local: true }], { now: NOW });
  assert.ok(flip.ok, flip.ok ? "" : flip.problems.join("; "));
  assert.match(flip.delta.relaxations[0]!.detail, /model lab changes \(url, allowPlainHttp\)/);
  const gone = evaluateEdits(before, [{ op: "remove-model", name: "gateway" }], { now: NOW });
  assert.ok(gone.ok);
  assert.match(gone.delta.relaxations[0]!.detail, /would skip the model proxy/);
});

test("helper moves between two local entries in one edit list; the compiled list marks only the helper", () => {
  const lab = { name: "lab", url: "https://10.0.0.5:8443", local: true };
  const doc: PolicyFileConfig = { version: 1, models: [{ ...OLLAMA, helper: true }, lab] };
  const moved = ok(doc, [{ op: "update-model", ...OLLAMA }, { op: "update-model", ...lab, helper: true }]);
  assert.deepEqual(moved.models?.map((m) => [m.name, m.helper ?? false]), [["ollama", false], ["lab", true]]);
  const compiled = compilePolicy({ specId: SPEC, document: moved }).models;
  assert.equal(compiled.find((m) => m.name === "lab")?.helper, true);
  assert.equal("helper" in compiled.find((m) => m.name === "ollama")!, false, "absent unless true: the wire list is unchanged for a file without it");
  const ev = evaluateEdits({ specId: SPEC, document: doc }, [{ op: "update-model", ...OLLAMA }, { op: "update-model", ...lab, helper: true }], { now: NOW });
  assert.ok(ev.ok);
  assert.match(ev.delta.relaxations.map((r) => r.detail).join("\n"), /model lab changes \(helper\)/);
  // Moving it in two SEPARATE lists would pass through a file with two helpers: refused.
  refused(doc, [{ op: "update-model", ...lab, helper: true }], /only one model can be the helper's/);
});

test("the delta compares the COMPILED list: a spelling with the same meaning is no change", () => {
  const b = compilePolicy({ specId: SPEC, document: { version: 1, models: [{ name: "g", url: "https://llm.example.com" }] } });
  const a = compilePolicy({ specId: SPEC, document: { version: 1, models: [{ name: "g", url: "https://llm.example.com", wire: "anthropic", local: false }] } });
  assert.deepEqual(policyDelta(b, a), { relaxations: [], tightenings: [] });
});

test("the delta: removing the whole models: section is a relaxation too", () => {
  const b = compilePolicy({ specId: SPEC, document: WITH_MODELS });
  const a = compilePolicy({ specId: SPEC, document: { version: 1, paths: WITH_MODELS.paths } });
  const d = policyDelta(b, a);
  assert.deepEqual(d.relaxations.map((r) => `${r.facet} ${r.subject}`).sort(), ["models gateway", "models ollama"]);
});

test("an unchanged models: section no longer makes an unrelated tightening a proposal", () => {
  const ev = evaluateEdits({ specId: SPEC, document: WITH_MODELS }, [{ op: "lock-path", path: "/home/u/repo/.env", level: "no-model" }], { now: NOW });
  assert.ok(ev.ok);
  assert.equal(ev.tightening, true, "models: is a known key with its own comparison, so it adds nothing when it is unchanged");
  assert.deepEqual(ev.delta.relaxations, []);
});

test("Undo: a model change reverts item by item, keeps a later change to another model, refuses a model changed again", () => {
  for (const e of [
    { op: "add-model", name: "lab", url: "https://10.0.0.5:8443", local: true },
    { op: "update-model", ...OLLAMA, model: "qwen2.5" },
    { op: "remove-model", name: "gateway" },
  ] as PolicyEdit[]) {
    const after = ok(WITH_MODELS, [e]);
    const items = diffItems(WITH_MODELS, after);
    assert.deepEqual(items.map((i) => i.section), ["models"], `${e.op}: one models item`);
    assert.deepEqual(revertConflicts(after, items), []);
    const back = revertItems(after, items);
    assert.ok(back.ok, back.ok ? "" : back.problems.join("; "));
    const byName = (d: PolicyFileConfig) => canonicalJson([...(d.models ?? [])].sort((x, y) => x.name.localeCompare(y.name)));
    assert.equal(byName(back.document), byName(WITH_MODELS), `${e.op} reverts`);
  }
  const added = ok(WITH_MODELS, [{ op: "add-model", name: "lab", url: "http://10.0.0.5:8000" }]);
  const items = diffItems(WITH_MODELS, added);
  const later = ok(added, [{ op: "update-model", ...OLLAMA, model: "qwen2.5" }]);
  const back = revertItems(later, items);
  assert.ok(back.ok);
  assert.deepEqual(back.document.models?.map((m) => m.name), ["ollama", "gateway"]);
  assert.equal(back.document.models?.[0]?.model, "qwen2.5", "the later edit of another model survives");
  const again = ok(added, [{ op: "update-model", name: "lab", url: "http://10.0.0.6:8000" }]);
  assert.deepEqual(revertConflicts(again, items), ["models lab"]);
});

test("Undo still reverts a change recorded while models: was one whole-key item", () => {
  const after = ok(WITH_MODELS, [{ op: "add-model", name: "lab", url: "http://10.0.0.5:8000" }]);
  const legacy = [{ section: "key" as const, key: "models", before: structuredClone(WITH_MODELS.models), after: structuredClone(after.models) }];
  assert.deepEqual(revertConflicts(after, legacy), []);
  const back = revertItems(after, legacy);
  assert.ok(back.ok);
  assert.equal(canonicalJson(back.document.models), canonicalJson(WITH_MODELS.models));
});
