/**
 * rule-ref.test — decision provenance (docs/design/ui/policy-surface.md §9.3).
 *
 * The invariant: EVERY branch of the pure usage gates (decideFsPath,
 * decideDesymbolization) returns a `ruleRef` whose id is a key of the RULES
 * catalog and whose source matches the catalog row. The compiler already
 * forbids off-catalog ids (`ruleRef(id: RuleId)`); this test drives a
 * branch-covering request matrix so a NEW branch added without a ruleRef —
 * the optional field's failure mode — is caught at unit time, not in the
 * dashboard as an unlabeled decision.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { decideFsPath } from "../../policy/fs-outbound.js";
import {
  decideDesymbolization,
  type DesymSymbolEntry,
  type DesymbolizationRequest,
  wireSchemeRefusal,
  wirePositionRefusal,
} from "../../policy/policy-interface.js";
import { execGate } from "../../policy/exec-gate.js";
import { decideSessionEgress } from "../../policy/session-egress.js";
import {
  RULES,
  GATES,
  gateOf,
  listUsageRules,
  listUsageGates,
  ruleRef,
  verdictRef,
  type RuleRef,
} from "../../policy/rule-ref.js";

const HOME = "/home/u";

function assertCataloged(ref: RuleRef | undefined, expectId: keyof typeof RULES): void {
  assert.ok(ref, `decision must carry a ruleRef (expected ${expectId})`);
  assert.equal(ref.id, expectId);
  assert.equal(ref.source, RULES[expectId].source, "source must match the catalog row");
}

// ── decideFsPath: one probe per branch, in rule order ───────────────────────

test("decideFsPath: every branch carries its catalog ruleRef", () => {
  const base = { tool: "Read", mode: "read" as const, workspaceRoots: ["/ws"] };

  assertCataloged(decideFsPath({ ...base, path: "  " }, { home: HOME }).ruleRef, "fs:invalid-path");
  assertCataloged(decideFsPath({ ...base, path: "sub/rel.txt" }, { home: HOME }).ruleRef, "fs:relative-path");
  assertCataloged(decideFsPath({ ...base, path: "~/.ssh/id_rsa" }, { home: HOME }).ruleRef, "fs:sensitive-path");
  assertCataloged(decideFsPath({ ...base, path: "/ws/notes.md" }, { home: HOME }).ruleRef, "fs:workspace-root");
  assertCataloged(
    decideFsPath({ ...base, path: "/data/x" }, { home: HOME, isDirTrusted: (p) => p === "/data/x" }).ruleRef,
    "fs:dir-allowlist",
  );
  assertCataloged(decideFsPath({ ...base, path: "/opt/elsewhere" }, { home: HOME }).ruleRef, "fs:default-deny");
});

// ── decideDesymbolization: branch matrix ────────────────────────────────────

const ACTIVE: DesymSymbolEntry = { value: "v", origin: null, obsoleted_at: null };
const SECRET: DesymSymbolEntry = {
  ...ACTIVE, confidentiality: "any-model", bindings: ["api.example"],
};

function desym(
  req: Partial<DesymbolizationRequest> & { boundary: DesymbolizationRequest["boundary"] },
  entry: DesymSymbolEntry | undefined,
  opts?: { confidentiality?: boolean; destTrusted?: boolean },
) {
  return decideDesymbolization(
    { symbol: "$MDU:Read[aaaa].x", ...req },
    () => entry,
    () => opts?.destTrusted ?? false,
    { confidentiality: opts?.confidentiality ?? false },
  );
}

test("decideDesymbolization: integrity branches carry their catalog ruleRefs", () => {
  assertCataloged(
    decideDesymbolization({ symbol: "", boundary: "network" }, undefined, () => false).ruleRef,
    "egress:invalid-symbol",
  );
  assertCataloged(desym({ boundary: "network", destination: "x.test" }, undefined).ruleRef, "egress:unknown-symbol");
  assertCataloged(
    desym({ boundary: "network", destination: "x.test" }, { ...ACTIVE, obsoleted_at: 1 }).ruleRef,
    "egress:obsolete-symbol",
  );
  assertCataloged(desym({ boundary: "shell", asCommand: true }, ACTIVE).ruleRef, "egress:symbol-as-command");
  assertCataloged(desym({ boundary: "network" }, ACTIVE).ruleRef, "egress:unknown-destination");
  assertCataloged(
    desym({ boundary: "network", destination: "ok.test" }, ACTIVE, { destTrusted: true }).ruleRef,
    "egress:trusted-destination",
  );
  assertCataloged(
    desym({ boundary: "network", destination: "evil.test" }, ACTIVE).ruleRef,
    "egress:untrusted-destination",
  );
  assertCataloged(desym({ boundary: "shell" }, ACTIVE).ruleRef, "egress:shell-boundary");
  assertCataloged(desym({ boundary: "filesystem" }, ACTIVE).ruleRef, "egress:filesystem-humanview");
  assertCataloged(desym({ boundary: "model_context" }, ACTIVE).ruleRef, "egress:user-facing-output");
});

test("decideDesymbolization: confidentiality branches carry their catalog ruleRefs", () => {
  const conf = { confidentiality: true };
  assertCataloged(
    desym({ boundary: "model_context" }, SECRET, conf).ruleRef,
    "egress:secret-model-context",
  );
  assertCataloged(desym({ boundary: "filesystem" }, SECRET, conf).ruleRef, "egress:secret-filesystem");
  assertCataloged(desym({ boundary: "network" }, SECRET, conf).ruleRef, "egress:secret-unknown-destination");
  assertCataloged(
    desym({ boundary: "network", destination: "api.example" }, { ...SECRET, integrity: "trusted" }, conf).ruleRef,
    "egress:secret-bound-trusted",
  );
  assertCataloged(
    desym({ boundary: "network", destination: "api.example" }, SECRET, conf).ruleRef,
    "egress:secret-bound-approval",
  );
  assertCataloged(
    desym({ boundary: "network", destination: "elsewhere.test" }, SECRET, conf).ruleRef,
    "egress:secret-unbound",
  );
  // Plan 10 §11.13.1: the wire twin's https-only rule (server-composed).
  assertCataloged(wireSchemeRefusal({ boundary: "network", destination: "api.example", scheme: "http" }, "https")!.ruleRef, "egress:secret-https-only");
  // …and its position rule (2026-10-09, server-composed).
  assertCataloged(wirePositionRefusal({ boundary: "network", destination: "api.example", positions: ["body"] }, true)!.ruleRef, "egress:secret-wire-position");
});

// ── exec wire gate + session watermark gate ─────────────────────────────────

test("execGate: both branches carry their catalog ruleRefs", () => {
  const blocked = execGate({ command: "bash -c $MDU:Read[abcd].content" });
  assertCataloged(blocked.ruleRef, "exec:symbol-in-command");
  assertCataloged(execGate({ command: "echo hi" }).ruleRef, "exec:no-symbol-in-command");
});

test("decideSessionEgress: every branch carries its catalog ruleRef", () => {
  const high = {
    sessionLevel: "any-model" as const,
    sessionBindings: ["api.example"] as string[],
  };
  assertCataloged(
    decideSessionEgress({ ...high, sessionLevel: "public", boundary: "network" }).ruleRef,
    "session:not-high",
  );
  assertCataloged(decideSessionEgress({ ...high, boundary: "filesystem" }).ruleRef, "session:high-fs-labeled");
  assertCataloged(
    decideSessionEgress({ ...high, boundary: "shell", netEnabled: false }).ruleRef,
    "session:agentshell-no-net",
  );
  assertCataloged(
    decideSessionEgress({ ...high, boundary: "network", destination: "api.example", untrustedTainted: true }).ruleRef,
    "session:high-tainted-bound",
  );
  assertCataloged(
    decideSessionEgress({ ...high, boundary: "network", destination: "api.example" }).ruleRef,
    "session:high-bound-release",
  );
  assertCataloged(
    decideSessionEgress({ ...high, boundary: "network", destination: "evil.test" }).ruleRef,
    "session:high-unbound",
  );
});

// ── catalog + helpers ───────────────────────────────────────────────────────

test("listUsageRules mirrors the catalog exactly; helpers build well-formed refs", () => {
  const rules = listUsageRules();
  assert.equal(rules.length, Object.keys(RULES).length);
  for (const r of rules) {
    assert.ok(r.id in RULES);
    assert.equal(r.summary, RULES[r.id as keyof typeof RULES].summary);
  }
  assert.deepEqual(ruleRef("fs:default-deny"), { source: "fail-closed", id: "fs:default-deny" });
  assert.deepEqual(verdictRef("egr-7"), { source: "verdict", id: "verdict:egr-7" });
});

test("gate closure: every rule id's prefix is a GATES key and rides the row", () => {
  // The compiler enforces the prefix via the RULES key template; this asserts
  // the runtime derivation (listUsageRules stamps `gate` = the id prefix) so a
  // new gate family added without a GATES entry is caught here too.
  for (const r of listUsageRules()) {
    const prefix = r.id.slice(0, r.id.indexOf(":"));
    assert.ok(prefix in GATES, `rule ${r.id}: prefix '${prefix}' must be a GATES key`);
    assert.equal(r.gate, prefix, `rule ${r.id}: gate must be the id prefix`);
  }
  assert.equal(gateOf("fs:default-deny"), "fs");
  assert.equal(gateOf("session:not-high"), "session");
});

test("listUsageGates mirrors GATES; every gate owns at least one rule", () => {
  const gates = listUsageGates();
  assert.equal(gates.length, Object.keys(GATES).length);
  const owned = new Set(listUsageRules().map((r) => r.gate));
  for (const g of gates) {
    assert.ok(g.id in GATES);
    assert.equal(g.title, GATES[g.id as keyof typeof GATES].title);
    // No orphan gates: a gate with no rules is dead catalog weight (a rename
    // that left the old entry behind) — the panel would render an empty group.
    assert.ok(owned.has(g.id as keyof typeof GATES), `gate '${g.id}' owns no rules`);
    // The citation fields the panel detail shows must be non-empty (an empty
    // definedIn/doc renders as an invented-looking blank line).
    assert.ok(g.definedIn.length > 0 && g.doc.length > 0 && g.evaluation.length > 0);
  }
});
