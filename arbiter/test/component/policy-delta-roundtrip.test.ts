/**
 * policy-delta round trip e2e (policy-surface.md §8.3, §8.4.1, stage A0).
 *
 * The classifier is only as good as the law it is shown. This suite runs it
 * over a REAL `policy.yaml` on disk, through the same `PolicyDocumentStore`
 * and strict loader the arbiter boots from, rather than over literals:
 *   - a hand-written file (a list-referenced allow rule, a model-ok lock with
 *     readers, a strict lock) is loaded; edits are evaluated against the
 *     document the store holds;
 *   - a TIGHTENING list is written by the store and the file re-read from disk
 *     compiles to a law whose delta from the original is still tightening
 *     (the YAML dump → load round trip loses nothing the gate depends on);
 *   - a RELAXING list (a model-ok lock over catalog secrets; a list edit that
 *     widens the allow rule) is classified as such and, not being applied, the
 *     file on disk is byte-identical afterwards.
 * The ops that enact this over the data socket (`policyPropose`) arrive in
 * stage A1 with their own daemon-level e2e (§7).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { compilePolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { isTightening, policyDelta } from "../../policy/policy-delta.js";
import { PolicyDocumentStore } from "../../policy/policy-document-store.js";
import { evaluateEdits } from "../../policy/policy-edit.js";
import { loadPolicyFileStrict } from "../../policy/policy-file-validate.js";
import { stateAxes } from "../axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4)

const HAND_WRITTEN = `# my law
version: 1
lists:
  svc:
    - api.example.com
paths:
  - path: /home/u/.aws
    level: any-model
    bindings: [aws.amazon.com]
    readers: [aws]
    others: deny
  - path: /home/u/repo/.env
    level: no-model
user_rules:
  - id: r-0001
    kind: release
    from: { host: docs.python.org }
    to: { host: "@svc" }
    mode: allow
    expires: "2026-12-01T00:00:00Z"
`;

function withStore(fn: (store: PolicyDocumentStore, file: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-policy-delta-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, HAND_WRITTEN);
  const loaded = loadPolicyFileStrict(file);
  const store = new PolicyDocumentStore({ path: file, rebuild: () => {}, pollMs: 0 }, { document: loaded.config, found: loaded.found });
  try {
    fn(store, file);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

const NOW = Date.parse("2026-09-25T00:00:00Z");

test("a tightening list written through the store stays a tightening after the YAML round trip", () => {
  withStore((store, file) => {
    const original = store.document;
    const ev = evaluateEdits({ specId: "claude-code", document: original }, [
      { op: "lock-path", path: "/home/u/repo/secrets", level: "no-model" },
      { op: "release", to: { host: "pastebin.com" }, mode: "block" },
      { op: "release", id: "r-0001", from: { host: "docs.python.org" }, to: { host: "@svc" }, mode: "allow", expires: "2026-11-01T00:00:00Z" },
    ], { by: "agent:e2e", now: NOW });
    assert.ok(ev.ok, ev.ok ? "" : ev.problems.join("; "));
    assert.equal(ev.tightening, true, JSON.stringify(ev.delta.relaxations));

    store.apply(ev.document, { via: "apply", requestedBy: "agent:e2e" });
    const reread = loadPolicyFileStrict(file).config as PolicyFileConfig;
    const before = compilePolicy({ specId: "claude-code", document: original });
    const after = compilePolicy({ specId: "claude-code", document: reread });
    const d = policyDelta(before, after, { now: NOW });
    assert.equal(isTightening(d), true, `after the round trip: ${JSON.stringify(d.relaxations)}`);
    assert.deepEqual(d.tightenings.map((t) => t.facet).sort(), ["paths", "user-rules", "user-rules"]);
  });
});

test("relaxing lists are classified as relaxations and leave the file on disk byte-identical", () => {
  withStore((store, file) => {
    const bytes = readFileSync(file);
    for (const edits of [
      [{ op: "lock-path", path: "/home/u/.ssh", level: "any-model" }],
      [{ op: "list", name: "svc", add: ["pastebin.com"] }],
      [{ op: "lock-path", path: "/home/u/.aws/credentials", level: "no-model" }], // overlap hazard: ~/.aws has readers
      [{ op: "unlock-path", path: "/home/u/repo/.env" }],
    ]) {
      const ev = evaluateEdits({ specId: "claude-code", document: store.document }, edits, { now: NOW });
      assert.ok(ev.ok, ev.ok ? "" : ev.problems.join("; "));
      assert.equal(ev.tightening, false, `expected a relaxation for ${JSON.stringify(edits)}`);
    }
    assert.deepEqual(readFileSync(file), bytes, "classification never writes");
  });
});
