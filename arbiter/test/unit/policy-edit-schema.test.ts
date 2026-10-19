/**
 * policy-edit-schema.test — the schema the agent is told is the schema the
 * arbiter enforces (policy-surface.md §8.4.3).
 *
 * Pins:
 *   - the checked-in policy-edit.schema.json equals policyAgentEditSchema()
 *     (drift: regenerate with `npx tsx scripts/gen-policy-schema.ts`);
 *   - the agent schema (what a model is offered) is the whole grammar minus
 *     the model-endpoint ops (§4.3a);
 *   - every op has exactly one schema branch, and the enums come from the
 *     validator's tables;
 *   - a corpus of edit shapes: the schema accepts exactly the ones applyEdits
 *     accepts on a document where every target exists (both directions).
 * A minimal validator for the subset of JSON Schema the generator emits lives
 * here (type, const, enum, required, properties, additionalProperties,
 * items, minItems, oneOf, anyOf, minLength, maxLength, pattern, minimum, maximum).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { policyAgentEditSchema, policyEditSchema } from "../../policy/policy-edit-schema.js";
import { AGENT_EDIT_OPS, applyEdits, LABEL_EDIT_OPS, MODEL_EDIT_OPS, modelEditProblems, POLICY_EDIT_OPS, PROMPT_EDIT_OPS } from "../../policy/policy-edit.js";
import { dispositionableRuleIds, LEVELS } from "../../policy/policy-file-validate.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4); none is read

type S = Record<string, unknown>;

function valid(schema: S, v: unknown): boolean {
  if ("const" in schema && v !== schema.const) return false;
  if (Array.isArray(schema.enum) && !(schema.enum as unknown[]).includes(v)) return false;
  if (Array.isArray(schema.oneOf) && (schema.oneOf as S[]).filter((s) => valid(s, v)).length !== 1) return false;
  if (Array.isArray(schema.anyOf) && !(schema.anyOf as S[]).some((s) => valid(s, v))) return false;
  switch (schema.type) {
    case "string":
      if (typeof v !== "string") return false;
      if (typeof schema.minLength === "number" && v.length < schema.minLength) return false;
      if (typeof schema.maxLength === "number" && v.length > schema.maxLength) return false;
      if (typeof schema.pattern === "string" && !new RegExp(schema.pattern).test(v)) return false;
      break;
    case "integer":
      if (!Number.isInteger(v)) return false;
      if (typeof schema.minimum === "number" && (v as number) < schema.minimum) return false;
      if (typeof schema.maximum === "number" && (v as number) > schema.maximum) return false;
      break;
    case "boolean": if (typeof v !== "boolean") return false; break;
    case "null": if (v !== null) return false; break;
    case "array":
      if (!Array.isArray(v)) return false;
      if (typeof schema.minItems === "number" && v.length < schema.minItems) return false;
      if (schema.items && !v.every((x) => valid(schema.items as S, x))) return false;
      break;
    case "object": {
      if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
      const o = v as S;
      const props = (schema.properties ?? {}) as Record<string, S>;
      for (const r of (schema.required ?? []) as string[]) if (!(r in o)) return false;
      for (const [k, x] of Object.entries(o)) {
        if (!(k in props)) { if (schema.additionalProperties === false) return false; continue; }
        if (!valid(props[k]!, x)) return false;
      }
      break;
    }
  }
  return true;
}

const HERE = dirname(fileURLToPath(import.meta.url));

test("the checked-in schema is exactly what the generator produces", () => {
  const onDisk = JSON.parse(readFileSync(join(HERE, "..", "..", "policy", "policy-edit.schema.json"), "utf8"));
  assert.deepEqual(onDisk, policyAgentEditSchema(), "regenerate: cd arbiter && npx tsx scripts/gen-policy-schema.ts");
});

test("the agent schema is the whole grammar minus the model-endpoint, label-mapping and prompt-filter ops (§4.3a; plan 14 §14.1; plan 15 §6)", () => {
  const opsOf = (s: S) => ((s.items as S).oneOf as S[]).map((b) => ((b.properties as S).op as S).const);
  assert.deepEqual([...MODEL_EDIT_OPS], ["add-model", "update-model", "remove-model", "restore-model"]);
  assert.deepEqual(opsOf(policyAgentEditSchema() as S), [...AGENT_EDIT_OPS]);
  assert.deepEqual([...LABEL_EDIT_OPS], ["map-sensitivity-label", "unmap-sensitivity-label"]);
  assert.deepEqual([...PROMPT_EDIT_OPS], ["set-prompt-filter", "set-prompt-action", "remove-prompt-action", "add-prompt-exception", "remove-prompt-exception"]);
  assert.deepEqual([...AGENT_EDIT_OPS], POLICY_EDIT_OPS.filter((op) => !MODEL_EDIT_OPS.includes(op) && !LABEL_EDIT_OPS.includes(op) && !PROMPT_EDIT_OPS.includes(op)));
  for (const op of [...MODEL_EDIT_OPS, ...LABEL_EDIT_OPS, ...PROMPT_EDIT_OPS]) assert.doesNotMatch(JSON.stringify(policyAgentEditSchema()), new RegExp(`"${op}"`));
  // Each agent branch is the full grammar's branch, unchanged.
  const full = ((policyEditSchema() as S).items as S).oneOf as S[];
  for (const b of ((policyAgentEditSchema() as S).items as S).oneOf as S[]) assert.ok(full.some((f) => JSON.stringify(f) === JSON.stringify(b)));
});

test("modelEditProblems: one problem per model op, by index and op only; nothing for other ops or a non-list", () => {
  const edits = [
    { op: "lock-path", path: "/x", level: "no-model" },
    { op: "add-model", name: "sk-ant-canary", url: "http://sk-ant-canary@10.0.0.5" },
    { op: "remove-model", name: "gw" },
  ];
  const p = modelEditProblems(edits, "the policy agent");
  assert.equal(p.length, 2);
  assert.match(p[0]!, /^edits\[1\] \(add-model\): model endpoints cannot be changed from the policy agent; the user changes them in Settings › Models/);
  assert.match(p[1]!, /^edits\[2\] \(remove-model\)/);
  assert.doesNotMatch(p.join("\n"), /canary/, "no value the caller wrote is echoed");
  assert.deepEqual(modelEditProblems([{ op: "lock-path" }, null, "add-model"]), []);
  assert.deepEqual(modelEditProblems({ op: "add-model" }), []);
});

test("one branch per op; enums come from the validator's tables", () => {
  const s = policyEditSchema() as S;
  const branches = ((s.items as S).oneOf as S[]);
  assert.deepEqual(branches.map((b) => ((b.properties as S).op as S).const), [...POLICY_EDIT_OPS]);
  const lock = branches.find((b) => ((b.properties as S).op as S).const === "lock-path")!;
  assert.deepEqual(((lock.properties as S).level as S).enum, [...LEVELS]);
  const disp = branches.find((b) => ((b.properties as S).op as S).const === "set-disposition")!;
  assert.deepEqual(((disp.properties as S).rule as S).enum, dispositionableRuleIds());
});

const TARGETS: PolicyFileConfig = {
  version: 1,
  lists: { svc: ["api.example.com"] },
  paths: [{ path: "/srv/a", level: "no-model" }],
  blobs: [{ id: "sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad", level: "no-model" }],
  user_rules: [{ id: "r-0001", kind: "release", to: { host: "x.example" }, mode: "allow" }],
  destinations: [{ host: "db.internal", port: 5432, connect: "allow" }],
  models: [{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true }],
};

const CORPUS: unknown[] = [
  { op: "lock-path", path: "/srv/b", level: "no-model" },
  { op: "lock-path", path: "/srv/b", level: "any-model", bindings: ["a.example"], recursive: false },
  { op: "lock-path", path: "/srv/b", level: "top-secret" },
  { op: "lock-path", path: "/srv/b" },
  { op: "lock-path", path: "/srv/b", level: "no-model", reason: "extra key" },
  { op: "lock-path", path: "", level: "no-model" },
  { op: "lock-path", path: "/srv/b", level: "no-model", recursive: "yes" },
  { op: "unlock-path", path: "/srv/a" },
  { op: "lock-blob", blob: "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "no-model" },
  { op: "lock-blob", blob: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", level: "any-model", note: "found in history: deploy/config.py (a1b2c3d..e4f5a6b)" },
  { op: "lock-blob", blob: "sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad", level: "public" },
  { op: "lock-blob", blob: "sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", level: "no-model" },
  { op: "lock-blob", blob: "3b18e512dba79e4c8300dd08aeb37f8e728b8dad", level: "no-model" },
  { op: "lock-blob", blob: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "no-model" },
  { op: "lock-blob", blob: "md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "no-model" },
  { op: "lock-blob", blob: "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
  { op: "lock-blob", blob: "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "top-secret" },
  { op: "lock-blob", blob: "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "no-model", note: "two\nlines" },
  { op: "lock-blob", blob: "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "no-model", note: "x".repeat(201) },
  { op: "lock-blob", blob: "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "no-model", note: 7 },
  { op: "lock-blob", blob: "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", level: "no-model", path: "/srv/a" },
  { op: "unlock-blob", blob: "sha1:3b18e512dba79e4c8300dd08aeb37f8e728b8dad" },
  { op: "unlock-blob", blob: "not-an-id" },
  { op: "trust-origin", kind: "url", pattern: "https://pypi.org/" },
  { op: "trust-origin", kind: "file", pattern: "/x" },
  { op: "distrust-origin", kind: "dir", pattern: "/home/u/Downloads" },
  { op: "release", to: { host: "pastebin.com" }, mode: "block" },
  { op: "release", from: { host: "docs.python.org" }, to: { host: "@svc" }, mode: "allow", expires: "2026-12-01T00:00:00Z", reason: "r" },
  { op: "release", to: { host: "pastebin.com" }, mode: "off" },
  { op: "release", to: { host: "pastebin.com", port: 1 }, mode: "block" },
  { op: "release", to: { host: "pastebin.com" }, mode: "block", expires: null },
  { op: "retire-rule", id: "r-0001" },
  { op: "set-disposition", rule: dispositionableRuleIds()[0], mode: "block" },
  { op: "set-disposition", rule: "egress:not-a-rule", mode: "block" },
  { op: "set-disposition", rule: dispositionableRuleIds()[0], mode: "allow" },
  { op: "allow-connect", host: "registry.npmjs.org" },
  { op: "allow-connect", host: "db.internal", port: 5433 },
  { op: "allow-connect", host: "db.internal", port: "*" },
  { op: "allow-connect", host: "db.internal", port: 70000 },
  { op: "remove-connect", host: "db.internal", port: 5432 },
  { op: "trust-command", id: "git", trustHelp: true },
  { op: "trust-command", id: "git" },
  { op: "tool-inbound", tool: "my_tool", trust: "UNTRUSTED" },
  { op: "tool-inbound", tool: "my_tool", trust: "MAYBE" },
  { op: "list", name: "svc", add: ["b.example"] },
  { op: "list", name: "bad name", add: ["b.example"] },
  { op: "list", name: "svc", add: "b.example" },
  { op: "list", name: "svc", remove: [""] },
  { op: "allow-connect", host: "db.internal", port: "443" },
  { op: "release", to: { host: "x.example" }, mode: "allow", expires: 5 },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000" },
  { op: "add-model", name: "lab", url: "https://10.0.0.5:8443", wire: "openai-chat", model: "qwen2.5", local: true, token_env: "LAB_TOKEN" },
  { op: "add-model", name: "lab" },
  { op: "add-model", name: "bad name", url: "http://10.0.0.5:8000" },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", wire: "grpc" },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", local: "yes" },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", token_env: "sk-not a name" },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", token_env: "9_TOKEN" },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", token_env: "_lab_token2" },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", key: "sk-123" },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", local: true, allow_plain_http: true },
  { op: "add-model", name: "lab", url: "http://10.0.0.5:8000", local: true, allow_plain_http: "yes" },
  { op: "add-model", name: "lab", url: "https://10.0.0.5:8443", local: true, tls: "yes" },
  { op: "add-model", name: "lab", url: "https://10.0.0.5:8443", local: true, tls: { ca: "/etc/ssl/ca.pem" } },
  { op: "add-model", name: "lab", url: "https://10.0.0.5:8443", local: true, tls: { pin_sha256: ["short="] } },
  { op: "update-model", name: "ollama", url: "http://127.0.0.1:11434", local: true },
  { op: "update-model", name: "ollama" },
  { op: "remove-model", name: "ollama" },
  { op: "remove-model", name: "ollama", url: "http://127.0.0.1:11434" },
  { op: "explode" },
];

test("corpus: the schema accepts exactly the edits applyEdits accepts (both directions)", () => {
  const branchSchema = (policyEditSchema() as S).items as S;
  for (const e of CORPUS) {
    const bySchema = valid(branchSchema, e);
    const byArbiter = applyEdits(TARGETS, [e]).ok;
    assert.equal(bySchema, byArbiter, `${JSON.stringify(e)}: schema ${bySchema ? "accepts" : "refuses"}, arbiter ${byArbiter ? "accepts" : "refuses"}`);
  }
  assert.equal(valid(policyEditSchema() as S, []), false, "an empty list is refused by both");
  assert.equal(applyEdits(TARGETS, []).ok, false);
});
