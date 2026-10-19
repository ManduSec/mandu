/**
 * policy.test.ts — unit tests for the lifted data-trust classification engine.
 *
 * Mandu-new test. Adapted from adfi-openclaw/test/unit/unit_policy.ts (the
 * reference category + summarizeToolTrust suite) and extended to cover the
 * arbiter's `classify()` contract end to end:
 *   - schema-based field classification (TRUSTED + UNTRUSTED fields in one tool)
 *   - origin rules (URL allowlist/blocklist, sibling vs params key)
 *   - fail-closed default for unknown tools / unknown fields / unmatched actions
 *   - fail-closed when the ruleset is empty / no policy file
 *
 * Run: npm run test:integrity
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";

import {
  createEngineBackedPolicy,
  createDefaultPolicyEngine,
} from "../../policy/policy-interface.js";
import { PolicyEngine, createPolicyEngine } from "../../policy/policy-engine.js";
import {
  createUrlTrustCategory,
  createChannelTrustCategory,
  createDirTrustCategory,
} from "../../policy/trust-category.js";
import { summarizeToolTrust } from "../../policy/resolve-schema.js";
import {
  getToolInboundSpec,
  setActiveInboundSpec,
} from "../../policy/tool-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

// This suite is adapted from the reference OpenClaw policy suite and exercises
// the lifted OpenClaw tool names (web_fetch, web_search, exec, write, process).
// Mandu's ACTIVE DEFAULT spec is now Claude Code, so select the OpenClaw spec
// for this suite and restore the default afterward. (Claude Code's own spec is
// covered by claude-code-policy.test.ts.)
before(() => setActiveInboundSpec("openclaw"));
after(() => setActiveInboundSpec("claude-code"));

// ── Trust categories (ported from unit_policy.ts) ───────────────────────────

test("URL allowlist: default UNTRUSTED, listed → TRUSTED", () => {
  const cat = createUrlTrustCategory({ mode: "allowlist", list: ["internal.company.com"] });
  assert.equal(cat.classify("https://internal.company.com/data"), "TRUSTED");
  assert.equal(cat.classify("https://evil.com/x"), "UNTRUSTED");
  assert.equal(cat.classify(null), "UNTRUSTED");
  assert.equal(cat.classify(""), "UNTRUSTED");
});

test("URL patterns written with a scheme name their host (they never matched before 2026-09-25): allowlist AND blocklist", () => {
  const trust = createUrlTrustCategory({ mode: "allowlist", list: ["https://pypi.org/", "HTTPS://docs.python.org/3", "https://*.corp.net"] });
  assert.equal(trust.classify("https://pypi.org/project/requests/"), "TRUSTED");
  assert.equal(trust.classify("https://docs.python.org/3/library/os.html"), "TRUSTED");
  assert.equal(trust.classify("https://docs.python.org/2/"), "UNTRUSTED", "the path prefix still applies");
  assert.equal(trust.classify("https://api.corp.net/x"), "TRUSTED");
  assert.equal(trust.classify("https://pypi.org.evil.example/"), "UNTRUSTED");
  // The fail-OPEN half: a scheme'd UNTRUSTED entry in blocklist mode used to be
  // ignored, so the site it names stayed trusted.
  const block = createUrlTrustCategory({ mode: "blocklist", list: ["https://paste.example/"] });
  assert.equal(block.classify("https://paste.example/raw/abc"), "UNTRUSTED");
  assert.equal(block.classify("https://docs.python.org/"), "TRUSTED");
});

test("URL wildcard subdomain + path prefix", () => {
  const wild = createUrlTrustCategory({ mode: "allowlist", list: ["*.corp.net"] });
  assert.equal(wild.classify("https://api.corp.net/x"), "TRUSTED");
  assert.equal(wild.classify("https://evil.corp.net.attacker.com"), "UNTRUSTED");
  const pathp = createUrlTrustCategory({ mode: "allowlist", list: ["api.github.com/repos"] });
  assert.equal(pathp.classify("https://api.github.com/repos/org/x"), "TRUSTED");
  assert.equal(pathp.classify("https://api.github.com/users/x"), "UNTRUSTED");
});

test("CHANNEL blocklist: exact + platform wildcard", () => {
  const cat = createChannelTrustCategory({ mode: "blocklist", list: ["discord:123456", "telegram:*"] });
  assert.equal(cat.classify("agent:bot:discord:123456"), "UNTRUSTED");
  assert.equal(cat.classify("agent:bot:telegram:chat1"), "UNTRUSTED");
  assert.equal(cat.classify("agent:bot:discord:999999"), "TRUSTED");
  assert.equal(cat.classify(null), "TRUSTED");
});

test("DIR blocklist: containment + prefix-collision safety", () => {
  const cat = createDirTrustCategory({ mode: "blocklist", list: ["/ws/downloads"] });
  assert.equal(cat.classify("/ws/downloads/external.txt"), "UNTRUSTED");
  assert.equal(cat.classify("/ws/downloads/nested/deep.json"), "UNTRUSTED");
  assert.equal(cat.classify("/ws/downloads2/file.txt"), "TRUSTED");
  assert.equal(cat.classify("/ws/notes.txt"), "TRUSTED");
});

// ── DIR: cwd-independence (the eval-time process.cwd() TODO, resolved
//    2026-07-16 — trust-category.ts header has the full rationale) ───────────

test("DIR: a RELATIVE key fails closed UNTRUSTED in BOTH modes (no cwd resolution)", () => {
  // The reference resolved relative keys against process.cwd() at eval time —
  // nondeterministic in the arbiter daemon, and unsafe in both directions
  // (allowlist: false trust when the daemon's cwd sits inside a trusted dir;
  // blocklist: a listed dir dodged because the key resolves elsewhere).
  const block = createDirTrustCategory({ mode: "blocklist", list: ["/ws/downloads"] });
  assert.equal(block.classify("downloads/external.txt"), "UNTRUSTED");
  assert.equal(block.classify("notes.txt"), "UNTRUSTED", "over-symbolize an unanchorable key");

  const allow = createDirTrustCategory({ mode: "allowlist", list: [process.cwd()] });
  // The daemon's OWN cwd is allowlisted — the exact false-trust shape the old
  // eval-time resolve produced. A relative key must NOT ride it.
  assert.equal(allow.classify("notes.txt"), "UNTRUSTED");
  assert.equal(allow.classify(process.cwd() + "/notes.txt"), "TRUSTED", "absolute keys unchanged");

  // Null/empty keys keep the category-default semantics (unchanged).
  assert.equal(block.classify(null), "TRUSTED");
  assert.equal(allow.classify(""), "UNTRUSTED");
});

test("DIR: absolute keys with dot-segments cannot dodge a blocklist entry", () => {
  const cat = createDirTrustCategory({ mode: "blocklist", list: ["/ws/downloads"] });
  assert.equal(cat.classify("/ws/src/../downloads/evil.txt"), "UNTRUSTED");
  assert.equal(cat.classify("/ws/downloads/../src/main.ts"), "TRUSTED", "normalized OUT of the listed dir");
});

// ── PolicyEngine registry + summarizeToolTrust (ported) ─────────────────────

test("PolicyEngine registry: register/get/has", () => {
  const engine = new PolicyEngine();
  assert.equal(engine.get("URL"), undefined);
  engine.register(createUrlTrustCategory({ mode: "allowlist", list: ["a.com"] }));
  assert.ok(engine.has("URL"));
  assert.equal(engine.get("URL")?.id, "URL");
});

test("summarizeToolTrust: web_fetch trusted vs untrusted URL", () => {
  const engine = new PolicyEngine();
  engine.register(createUrlTrustCategory({ mode: "allowlist", list: ["internal.company.com"] }));
  const spec = getToolInboundSpec("web_fetch")!;
  assert.equal(summarizeToolTrust(spec, { url: "https://internal.company.com/x" }, engine), "TRUSTED");
  assert.equal(summarizeToolTrust(spec, { url: "https://evil.com/x" }, engine), "UNTRUSTED");
});

test("summarizeToolTrust: process unknown action fails closed", () => {
  const engine = new PolicyEngine();
  const spec = getToolInboundSpec("process")!;
  assert.equal(summarizeToolTrust(spec, { action: "nonexistent" }, engine), "UNTRUSTED");
  assert.equal(summarizeToolTrust(spec, { action: "list" }, engine), "TRUSTED");
});

test("createPolicyEngine: built-in defaults registered with no policy file", () => {
  const eng = createPolicyEngine(undefined, process.cwd(), { info() {}, warn() {} }, null);
  // URL default = allowlist-empty → unknown URL UNTRUSTED.
  assert.equal(eng.get("URL")?.classify("https://anything.example"), "UNTRUSTED");
  // CHANNEL/DIR default = blocklist-empty → unknown TRUSTED.
  assert.equal(eng.get("CHANNEL")?.classify("slack:x"), "TRUSTED");
  assert.equal(eng.get("DIR")?.classify("/ws/x"), "TRUSTED");
});

// ── classify(): schema-based field classification ───────────────────────────

test("classify: a single tool result with both TRUSTED and UNTRUSTED fields", () => {
  // web_fetch with an allowlist that does NOT cover the fetched URL: the
  // metadata fields (status) are literal TRUSTED, while the body fields
  // (text/title) are URL-data keyed off params.url → UNTRUSTED.
  const policy = createEngineBackedPolicy({
    policyFileOverride: { inbound: { url: { default: "UNTRUSTED", trustedList: ["internal.example"] } } },
  });
  const params = { url: "https://attacker.example/post" };

  const status = policy.classify({ tool: "web_fetch", field: "status", value: "200", boundary: "model_context", params });
  assert.equal(status.trust, "TRUSTED", "metadata field is literal TRUSTED");

  const text = policy.classify({ tool: "web_fetch", field: "text", value: "evil body", boundary: "model_context", params });
  assert.equal(text.trust, "UNTRUSTED", "body keyed off untrusted URL → UNTRUSTED");
  assert.equal(text.category, "URL");

  const url = policy.classify({ tool: "web_fetch", field: "url", value: params.url, boundary: "model_context", params });
  assert.equal(url.trust, "TRUSTED", "the URL key field itself is raw TRUSTED");
});

test("classify: same body becomes TRUSTED once its origin is allowlisted (origin rule)", () => {
  const policy = createEngineBackedPolicy({
    policyFileOverride: { inbound: { url: { default: "UNTRUSTED", trustedList: ["internal.example"] } } },
  });
  const trusted = policy.classify({
    tool: "web_fetch", field: "text", value: "internal body",
    boundary: "model_context", params: { url: "https://internal.example/wiki" },
  });
  assert.equal(trusted.trust, "TRUSTED");
  assert.equal(trusted.category, "URL");
});

test("classify: per-item array fields key off the item's sibling URL", () => {
  const policy = createEngineBackedPolicy({
    policyFileOverride: { inbound: { url: { default: "UNTRUSTED", trustedList: ["good.example"] } } },
  });
  // web_search result item title keyField "url" resolves against params here
  // (the proxy supplies the per-item url as a param/sibling).
  const evil = policy.classify({
    tool: "web_search", field: "results[0].title", value: "t",
    boundary: "model_context", params: { url: "https://evil.example" },
  });
  assert.equal(evil.trust, "UNTRUSTED");
  const good = policy.classify({
    tool: "web_search", field: "results[0].title", value: "t",
    boundary: "model_context", params: { url: "https://good.example" },
  });
  assert.equal(good.trust, "TRUSTED");
});

test("classify: whole-result literal tools (exec UNTRUSTED, write TRUSTED)", () => {
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  assert.equal(policy.classify({ tool: "exec", value: "stdout", boundary: "shell" }).trust, "UNTRUSTED");
  assert.equal(policy.classify({ tool: "write", value: "ok", boundary: "filesystem" }).trust, "TRUSTED");
});

test("classify: action-dispatched tool (process poll vs list)", () => {
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  assert.equal(
    policy.classify({ tool: "process", value: "out", boundary: "shell", params: { action: "poll" } }).trust,
    "UNTRUSTED",
  );
  assert.equal(
    policy.classify({ tool: "process", value: "out", boundary: "shell", params: { action: "list" } }).trust,
    "TRUSTED",
  );
});

// ── classify(): fail-closed defaults (the security invariant) ───────────────

test("classify: unknown tool fails closed (UNTRUSTED) — e.g. un-remapped Claude Code tool", () => {
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  for (const tool of ["Bash", "Glob", "mcp__server__tool", "totally_unknown"]) {
    const r = policy.classify({ tool, value: "x", boundary: "model_context" });
    assert.equal(r.trust, "UNTRUSTED", `tool ${tool} must fail closed`);
    assert.match(r.reason, /fail-closed/);
  }
});

test("classify: field absent from schema fails closed", () => {
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  const r = policy.classify({ tool: "web_fetch", field: "not_a_field", value: "x", boundary: "model_context" });
  assert.equal(r.trust, "UNTRUSTED");
  assert.match(r.reason, /not in tool/);
});

test("classify: action-dispatched tool with unmatched action + no default fails closed", () => {
  // process has a defaultSchema=UNTRUSTED, so unknown actions are UNTRUSTED via
  // that default. Verify the explicit fail-closed for an action tool whose
  // branch is genuinely unselectable is also UNTRUSTED.
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  const r = policy.classify({ tool: "process", value: "x", boundary: "shell", params: { action: "bogus" } });
  assert.equal(r.trust, "UNTRUSTED");
});

test("classify: structured-schema tool with no field given fails closed", () => {
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  // web_fetch is an object schema; without a field we cannot classify a single
  // value, so fail closed rather than guess.
  const r = policy.classify({ tool: "web_fetch", value: "whole body", boundary: "model_context", params: { url: "https://x.example" } });
  assert.equal(r.trust, "UNTRUSTED");
  assert.match(r.reason, /structured schema but no field/);
});

test("classify: empty/missing ruleset is fail-closed for data fields", () => {
  // No policy file → URL category is allowlist-empty (intrinsic default), so a
  // body keyed off ANY url is UNTRUSTED. This is the empty-ruleset guard.
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  const r = policy.classify({
    tool: "web_fetch", field: "text", value: "body",
    boundary: "model_context", params: { url: "https://anything.example" },
  });
  assert.equal(r.trust, "UNTRUSTED");
});

// ── default (stub) engine still safe ────────────────────────────────────────

test("createDefaultPolicyEngine: origin-allowlist only, else UNTRUSTED", () => {
  const policy = createDefaultPolicyEngine({ trustedOrigins: ["https://docs.internal"] });
  assert.equal(policy.classify({ tool: "x", value: "v", boundary: "network", origin: "https://docs.internal" }).trust, "TRUSTED");
  assert.equal(policy.classify({ tool: "x", value: "v", boundary: "network", origin: "https://evil" }).trust, "UNTRUSTED");
  assert.equal(policy.classify({ tool: "x", value: "v", boundary: "network" }).trust, "UNTRUSTED");
});

test("desymbolizationDecision: unknown symbol is a no-op (allow), known stays gated", () => {
  // With no symbolLookup wired, every symbol is unknown → resolving is a no-op
  // (nothing to leak), so the gate allows it. The real gating is exercised by
  // egress-gate.test.ts with a live symbol table.
  const policy = createEngineBackedPolicy({ policyFileOverride: null });
  const d = policy.desymbolizationDecision({ symbol: "$MDU:exec[abcd]", boundary: "network" });
  assert.equal(d.allow, true);
  // Empty symbol always fails closed.
  const e = policy.desymbolizationDecision({ symbol: "", boundary: "network" });
  assert.equal(e.allow, false);
});
