/**
 * policy-snapshot.test.ts — unit tests for the arbiter policy SNAPSHOT builder.
 *
 * Mandu-new test (no reference origin). The snapshot serializes the ACTIVE
 * data-trust (inbound schema) + data-usage (outbound resolve/egress) policy into
 * a JSON-friendly, human-readable rule table the dashboard renders in its
 * per-tool-call policy modal (docs/design/ui/dashboard.md). It is OBSERVABILITY
 * ONLY — it never feeds a decision, so it must faithfully MIRROR the specs the
 * engine actually enforces (claude-code-inbound.ts / tool-outbound.ts) without
 * re-deciding anything.
 *
 * The builder `describePolicySnapshot` is PURE (explicit inputs → snapshot), so
 * these tests pin its shape deterministically; one integration test exercises
 * the engine-backed `policySnapshot()` method end-to-end.
 *
 * Run: npm run test:integrity
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import {
  describePolicySnapshot,
  type PolicySnapshotInputs,
} from "../../policy/policy-snapshot.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import {
  setActiveInboundSpec,
  getActiveInboundSpecId,
} from "../../policy/tool-inbound.js";
import {
  CLAUDE_CODE_INBOUND_SPEC,
  MANDU_INSPECT_TOOL,
} from "../../policy/claude-code-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

before(() => setActiveInboundSpec("claude-code"));
after(() => setActiveInboundSpec("claude-code"));

// A minimal, fully-controlled input set so the pure builder's output is
// deterministic and independent of the live spec maps.
function inputs(over: Partial<PolicySnapshotInputs> = {}): PolicySnapshotInputs {
  return {
    specId: "claude-code",
    inboundSpec: { Bash: { schema: "UNTRUSTED" } },
    mcpPrefix: "mcp__",
    mcpSpec: { schema: "UNTRUSTED" },
    outboundResolve: { Bash: true },
    outboundFieldPolicy: {},
    origins: [
      { id: "URL", mode: "allowlist", listSize: 2 },
      { id: "CHANNEL", mode: "blocklist", listSize: 0 },
      { id: "DIR", mode: "blocklist", listSize: 1 },
    ],
    ...over,
  };
}

// ── Origins ────────────────────────────────────────────────────────────────

test("origins carry mode, listSize and a derived defaultTrust", () => {
  const snap = describePolicySnapshot(inputs());
  const url = snap.origins.find((o) => o.id === "URL");
  const dir = snap.origins.find((o) => o.id === "DIR");
  assert.ok(url && dir);
  // allowlist → default UNTRUSTED; blocklist → default TRUSTED.
  assert.deepEqual(url, { id: "URL", mode: "allowlist", listSize: 2, defaultTrust: "UNTRUSTED" });
  assert.deepEqual(dir, { id: "DIR", mode: "blocklist", listSize: 1, defaultTrust: "TRUSTED" });
});

// ── Literal inbound tool ─────────────────────────────────────────────────────

test("a whole-result literal tool (Bash) renders one (result) field", () => {
  const snap = describePolicySnapshot(inputs());
  const bash = snap.tools.Bash;
  assert.equal(bash.inbound?.kind, "literal");
  assert.deepEqual(bash.inbound?.fields, [
    { field: "(result)", trust: "UNTRUSTED", category: null, detail: "UNTRUSTED (literal)" },
  ]);
  // Bash egress is HumanShell → resolve (HumanView).
  assert.equal(bash.outbound.toolResolve, true);
  assert.equal(bash.outbound.destination, "HumanView");
});

// ── Structured inbound tool ──────────────────────────────────────────────────

test("a structured tool (WebFetch) flattens leaves with key/data/literal markers", () => {
  const snap = describePolicySnapshot(
    inputs({
      inboundSpec: { WebFetch: CLAUDE_CODE_INBOUND_SPEC.WebFetch },
      outboundResolve: { WebFetch: true },
      outboundFieldPolicy: { WebFetch: { url: "resolve", prompt: "resolve" } },
    }),
  );
  const wf = snap.tools.WebFetch;
  assert.equal(wf.inbound?.kind, "structured");
  const byField = new Map(wf.inbound!.fields.map((f) => [f.field, f]));
  // DataSpec body field → conditional on the URL category.
  assert.equal(byField.get("content")?.trust, "conditional");
  assert.equal(byField.get("content")?.category, "URL");
  // KeySpec → raw TRUSTED key.
  assert.equal(byField.get("url")?.trust, "TRUSTED");
  assert.equal(byField.get("url")?.category, "URL");
  // Literal metadata.
  assert.equal(byField.get("status")?.trust, "TRUSTED");
  // Outbound: url resolves to HumanView; field override surfaced.
  assert.equal(wf.outbound.toolResolve, true);
  assert.ok(wf.outbound.fields.some((f) => f.field === "url" && f.policy === "resolve"));
});

test("a structured tool's explicit whole-result rule is mirrored as a (result) row", () => {
  // WebFetch carries `wholeResult` (URL-keyed) for the live field-less call
  // shape; the snapshot must show it or the modal would claim fail-closed for
  // a rule classify() actually resolves (observability must mirror enforcement).
  const snap = describePolicySnapshot(
    inputs({ inboundSpec: { WebFetch: CLAUDE_CODE_INBOUND_SPEC.WebFetch } }),
  );
  const row = snap.tools.WebFetch.inbound!.fields.find((f) => f.field === "(result)");
  assert.ok(row, "expected a (result) whole-result row for WebFetch");
  assert.equal(row!.trust, "conditional");
  assert.equal(row!.category, "URL");
  assert.match(row!.detail, /whole-result rule/);

  // A structured spec WITHOUT a wholeResult rule gets NO (result) row — its
  // field-less call shape is the fail-closed default (fallbackTrust).
  const read = describePolicySnapshot(
    inputs({ inboundSpec: { Read: CLAUDE_CODE_INBOUND_SPEC.Read } }),
  );
  assert.equal(
    read.tools.Read.inbound!.fields.find((f) => f.field === "(result)"),
    undefined,
    "Read must not render a whole-result grant it does not have",
  );
});

test("nested __items schema (WebSearch) flattens with [] segment", () => {
  const snap = describePolicySnapshot(
    inputs({ inboundSpec: { WebSearch: CLAUDE_CODE_INBOUND_SPEC.WebSearch } }),
  );
  const fields = snap.tools.WebSearch.inbound!.fields.map((f) => f.field);
  assert.ok(fields.includes("results[].title"), `got ${fields.join(", ")}`);
  assert.ok(fields.includes("query"));
});

// ── Action-dispatched inbound tool ───────────────────────────────────────────

test("an action tool (Grep) renders per-branch fields and a default branch", () => {
  const snap = describePolicySnapshot(
    inputs({ inboundSpec: { Grep: CLAUDE_CODE_INBOUND_SPEC.Grep } }),
  );
  const grep = snap.tools.Grep;
  assert.equal(grep.inbound?.kind, "action");
  const fields = grep.inbound!.fields.map((f) => f.field);
  // Branch keys are prefixed by the dispatch field=value.
  assert.ok(fields.some((f) => f.startsWith("output_mode=content")), fields.join(", "));
  assert.ok(fields.some((f) => f.startsWith("output_mode=files_with_matches")), fields.join(", "));
  // The fail-closed default branch is surfaced explicitly.
  assert.ok(fields.some((f) => f.startsWith("output_mode=*")), fields.join(", "));
  const def = grep.inbound!.fields.find((f) => f.field.startsWith("output_mode=*"));
  assert.equal(def?.trust, "UNTRUSTED");
});

// ── MCP synthetic entry + fail-closed fallback ───────────────────────────────

test("a synthetic mcp__* entry mirrors the prefix rule (UNTRUSTED)", () => {
  const snap = describePolicySnapshot(inputs());
  const mcp = snap.tools["mcp__*"];
  assert.ok(mcp, "expected a synthetic mcp__* tool rule");
  assert.equal(mcp.inbound?.kind, "literal");
  assert.equal(mcp.inbound?.fields[0]?.trust, "UNTRUSTED");
});

test("the mandu-inspect hybrid rule is surfaced as a synthetic conditional entry", () => {
  // classify() enforces the hybrid exact-name + pure-symbolic-shape rule for
  // the Mandu inspect tool OUTSIDE the spec map; the snapshot must mirror it
  // so the dashboard modal doesn't show the generic mcp__* rule for a call
  // classify() actually trusted.
  const snap = describePolicySnapshot(inputs());
  const rule = snap.tools[MANDU_INSPECT_TOOL];
  assert.ok(rule, "expected a synthetic mandu-inspect tool rule");
  assert.equal(rule.inbound?.fields[0]?.trust, "conditional");
  assert.match(rule.inbound?.fields[0]?.detail ?? "", /\$MDU:/);
});

test("an explicit mandu-inspect spec entry suppresses the synthetic hybrid rule", () => {
  // Mirrors enforcement precedence: an explicit exact-name entry (YAML
  // override) wins, so the snapshot renders THAT entry, not the hybrid rule.
  const snap = describePolicySnapshot(
    inputs({ inboundSpec: { [MANDU_INSPECT_TOOL]: { schema: "UNTRUSTED" } } }),
  );
  const rule = snap.tools[MANDU_INSPECT_TOOL];
  assert.equal(rule.inbound?.kind, "literal");
  assert.equal(rule.inbound?.fields[0]?.trust, "UNTRUSTED");
});

test("the synthetic hybrid rule is claude-code-spec-only", () => {
  const snap = describePolicySnapshot(inputs({ specId: "openclaw" }));
  assert.equal(snap.tools[MANDU_INSPECT_TOOL], undefined);
});

test("snapshot records the fail-closed fallback + mcp prefix", () => {
  const snap = describePolicySnapshot(inputs());
  assert.equal(snap.fallbackTrust, "UNTRUSTED");
  assert.equal(snap.mcpPrefix, "mcp__");
  assert.equal(snap.specId, "claude-code");
});

// ── Tools with no outbound entry default to AgentView (not_resolve) ──────────

test("a tool absent from the outbound maps defaults to AgentView", () => {
  const snap = describePolicySnapshot(
    inputs({ inboundSpec: { Task: { schema: "UNTRUSTED" } }, outboundResolve: {}, outboundFieldPolicy: {} }),
  );
  assert.equal(snap.tools.Task.outbound.toolResolve, false);
  assert.equal(snap.tools.Task.outbound.destination, "AgentView");
});

// ── Engine integration ───────────────────────────────────────────────────────

test("createEngineBackedPolicy().policySnapshot() reflects the live spec + origins", () => {
  const policy = createEngineBackedPolicy({
    policyFileOverride: {
      inbound: { url: { default: "UNTRUSTED", trustedList: ["internal.example"] } },
    },
  });
  const snap = policy.policySnapshot();
  assert.equal(snap.specId, "claude-code");
  assert.equal(getActiveInboundSpecId(), "claude-code");
  // The URL allowlist from the override is reflected in origins.
  const url = snap.origins.find((o) => o.id === "URL");
  assert.equal(url?.mode, "allowlist");
  assert.equal(url?.listSize, 1);
  assert.equal(url?.defaultTrust, "UNTRUSTED");
  // Live tools are present.
  assert.ok(snap.tools.Bash, "expected Bash in the live snapshot");
  assert.ok(snap.tools.WebFetch, "expected WebFetch in the live snapshot");
  assert.equal(snap.tools.Bash.inbound?.kind, "literal");
});
