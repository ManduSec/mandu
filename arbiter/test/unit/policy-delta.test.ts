/**
 * policy-delta.test — the monotonic split's gate (policy-surface.md §8.3).
 *
 * Pins, one before/after pair per §3.2 row in both directions:
 *   - the two §3.3 declassifications a naive "adding a lock tightens" rule lets
 *     through (a model-ok lock over catalog secrets; a model-ok lock under a
 *     strict ancestor) are RELAXATIONS, and so is `recursive` on a model-ok dir;
 *   - raising a lock to strict is a TIGHTENING (the set-difference bug);
 *   - extending an allow rule's expiry or widening its `from` is a RELAXATION
 *     (the same-id bug), shortening / narrowing is a tightening;
 *   - a list edit relaxes through the rule that references it;
 *   - the overlap hazard: a new strict lock that may take over from a label
 *     with readers is a relaxation;
 *   - fail closed: an unknown document key is a relaxation.
 *
 * Pure: no arbiter, no DB, no privilege; no protection axis is read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { hostPatternCovers, isTightening, policyDelta, type PolicyDelta } from "../../policy/policy-delta.js";

const SILENT = { info: () => {}, warn: () => {} };
const NOW = Date.parse("2026-09-25T00:00:00Z");

function delta(before: PolicyFileConfig | null, after: PolicyFileConfig | null): PolicyDelta {
  const b = compilePolicy({ specId: "claude-code", document: before, log: SILENT });
  const a = compilePolicy({ specId: "claude-code", document: after, log: SILENT });
  return policyDelta(b, a, { now: NOW });
}

function assertRelaxes(before: PolicyFileConfig | null, after: PolicyFileConfig | null, facet: string, why: string): void {
  const d = delta(before, after);
  assert.equal(isTightening(d), false, `${why}: expected a relaxation, got none`);
  assert.ok(d.relaxations.some((r) => r.facet === facet), `${why}: expected a ${facet} relaxation, got ${JSON.stringify(d.relaxations)}`);
}

function assertTightens(before: PolicyFileConfig | null, after: PolicyFileConfig | null, why: string): void {
  const d = delta(before, after);
  assert.deepEqual(d.relaxations, [], `${why}: expected a tightening`);
  assert.ok(d.tightenings.length > 0, `${why}: expected at least one tightening row`);
}

// ── identity ─────────────────────────────────────────────────────────────────

test("an unchanged law (built-ins, or the same document compiled twice) has no delta", () => {
  assert.deepEqual(delta(null, null), { relaxations: [], tightenings: [] });
  const doc: PolicyFileConfig = {
    lists: { svc: ["api.example.com"] },
    paths: [{ path: "/srv/app/.env", level: "any-model", bindings: ["api.example.com"] }],
    user_rules: [{ id: "r-1", kind: "release", to: { host: "@svc" }, mode: "allow", expires: "2026-12-01T00:00:00Z" }],
    tools: { my_tool: { inbound: { summary: "TRUSTED" }, outbound: "resolve" } },
    inbound: { url: { trustedList: ["https://docs.python.org/"] }, command: [{ id: "git", trustHelp: true }] },
    destinations: [{ host: "api.example.com", connect: "allow" }],
    env: { exempt: ["MY_TOKEN"] },
  };
  assert.deepEqual(delta(doc, structuredClone(doc)), { relaxations: [], tightenings: [] });
});

// ── paths (§3.3) ─────────────────────────────────────────────────────────────

test("paths: a model-ok lock over catalog secrets is a RELAXATION (declassifies ~/.ssh keys)", () => {
  assertRelaxes(null, { paths: [{ path: "/home/u/.ssh", level: "any-model" }] }, "paths", "model-ok lock on ~/.ssh");
});

test("paths: a model-ok lock under a strict ancestor is a RELAXATION", () => {
  const before: PolicyFileConfig = { paths: [{ path: "/home/u/private", level: "no-model" }] };
  const after: PolicyFileConfig = { paths: [...before.paths!, { path: "/home/u/private/notes", level: "any-model" }] };
  assertRelaxes(before, after, "paths", "model-ok under strict");
});

test("paths: a public lock, a new lock with bindings, and a new lock with readers are RELAXATIONS", () => {
  assertRelaxes(null, { paths: [{ path: "/srv/fixtures/.env", level: "public" }] }, "paths", "public lock");
  assertRelaxes(null, { paths: [{ path: "/home/u/.aws", level: "no-model", bindings: ["aws.amazon.com"] }] }, "paths", "strict with bindings");
  assertRelaxes(null, { paths: [{ path: "/home/u/.aws", level: "no-model", readers: ["aws"] }] }, "paths", "strict with readers");
});

test("paths: setting recursive on a model-ok directory lock is a RELAXATION; on a plain strict lock it TIGHTENS", () => {
  assertRelaxes(
    { paths: [{ path: "/home/u/proj", level: "any-model", recursive: false }] },
    { paths: [{ path: "/home/u/proj", level: "any-model" }] },
    "paths",
    "recursive on model-ok",
  );
  assertTightens(
    { paths: [{ path: "/home/u/proj", level: "no-model", recursive: false }] },
    { paths: [{ path: "/home/u/proj", level: "no-model" }] },
    "recursive on plain strict",
  );
  assertRelaxes(
    { paths: [{ path: "/home/u/proj", level: "no-model" }] },
    { paths: [{ path: "/home/u/proj", level: "no-model", recursive: false }] },
    "paths",
    "recursive true → false",
  );
});

test("paths: a new plain strict lock TIGHTENS; removing a lock RELAXES", () => {
  assertTightens(null, { paths: [{ path: "/srv/app/.env", level: "no-model" }] }, "plain strict on .env");
  assertTightens(null, { paths: [{ path: "/srv/app/**/*.pem", level: "no-model" }] }, "plain strict pattern");
  assertRelaxes({ paths: [{ path: "/srv/app/.env", level: "no-model" }] }, null, "paths", "unlock");
});

test("paths: RAISING a lock to strict is a TIGHTENING (the set-difference bug), lowering one RELAXES", () => {
  const modelOk: PolicyFileConfig = { paths: [{ path: "/srv/app/.env", level: "any-model", bindings: ["api.example.com"] }] };
  const strict: PolicyFileConfig = { paths: [{ path: "/srv/app/.env", level: "no-model" }] };
  assertTightens(modelOk, strict, "model-ok → strict");
  assertRelaxes(strict, modelOk, "paths", "strict → model-ok");
});

test("paths: dropping a binding TIGHTENS; adding one RELAXES", () => {
  const two: PolicyFileConfig = { paths: [{ path: "/srv/app/.env", level: "any-model", bindings: ["a.example.com", "b.example.com"] }] };
  const one: PolicyFileConfig = { paths: [{ path: "/srv/app/.env", level: "any-model", bindings: ["a.example.com"] }] };
  assertTightens(two, one, "drop a binding");
  assertRelaxes(one, two, "paths", "add a binding");
});

test("paths: the overlap hazard — a new strict lock that may take over from a label with readers RELAXES", () => {
  const before: PolicyFileConfig = { paths: [{ path: "/home/u/.aws", level: "no-model", readers: ["aws"], others: "deny" }] };
  const after: PolicyFileConfig = { paths: [...before.paths!, { path: "/home/u/.aws/credentials", level: "no-model" }] };
  const d = delta(before, after);
  assert.equal(isTightening(d), false);
  assert.match(d.relaxations[0]!.detail, /may take over from \/home\/u\/\.aws/);
  // A lock elsewhere in the tree does not overlap and tightens.
  assertTightens(before, { paths: [...before.paths!, { path: "/srv/app/.env", level: "no-model" }] }, "no overlap");
  // A `**` pattern overlaps everything.
  assertRelaxes(before, { paths: [...before.paths!, { path: "**/.env", level: "no-model" }] }, "paths", "** overlaps");
});

test("paths: making a label with readers plain strict RELAXES (non-readers go from denied to the twin)", () => {
  assertRelaxes(
    { paths: [{ path: "/home/u/.aws", level: "no-model", readers: ["aws"], others: "deny" }] },
    { paths: [{ path: "/home/u/.aws", level: "no-model" }] },
    "paths",
    "drop readers",
  );
});

// ── origins ──────────────────────────────────────────────────────────────────

test("origins: trusting an origin RELAXES, un-trusting TIGHTENS; untrustedList the reverse; list refs expand", () => {
  assertRelaxes(null, { inbound: { url: { trustedList: ["https://pastebin.com/"] } } }, "origins", "trust origin");
  assertTightens({ inbound: { url: { trustedList: ["https://pastebin.com/"] } } }, { inbound: { url: { trustedList: [] } } }, "untrust origin");
  assertTightens(null, { inbound: { dir: { untrustedList: ["/home/u/Downloads"] } } }, "distrust dir");
  assertRelaxes({ inbound: { dir: { untrustedList: ["/home/u/Downloads"] } } }, null, "origins", "drop untrusted dir");
  // Through a list: the document text of inbound is unchanged; the list grew.
  const b: PolicyFileConfig = { lists: { docs: ["https://docs.python.org/"] }, inbound: { url: { trustedList: ["@docs"] } } };
  const a: PolicyFileConfig = { lists: { docs: ["https://docs.python.org/", "https://evil.example/"] }, inbound: { url: { trustedList: ["@docs"] } } };
  assertRelaxes(b, a, "origins", "list grows under a trustedList ref");
  assertTightens(a, b, "list shrinks under a trustedList ref");
});

test("origins: default UNTRUSTED TIGHTENS, default TRUSTED RELAXES", () => {
  assertTightens({ inbound: { dir: { default: "TRUSTED" } } }, { inbound: { dir: { default: "UNTRUSTED" } } }, "default untrusted");
  assertRelaxes({ inbound: { dir: { default: "UNTRUSTED" } } }, { inbound: { dir: { default: "TRUSTED" } } }, "origins", "default trusted");
});

// ── command output + tools ───────────────────────────────────────────────────

test("command output: trustHelp on RELAXES, off TIGHTENS; a new id trusting nothing is neutral-to-tight", () => {
  assertRelaxes(null, { inbound: { command: [{ id: "git", trustHelp: true }] } }, "command-output", "trustHelp on");
  assertTightens({ inbound: { command: [{ id: "git", trustHelp: true }] } }, { inbound: { command: [{ id: "git", trustHelp: false }] } }, "trustHelp off");
  assertRelaxes(
    { inbound: { command: [{ id: "git", trustHelp: true }] } },
    { inbound: { command: [{ id: "git", trustHelp: true, aliases: ["g"] }] } },
    "command-output",
    "a new alias carries the trust to another name",
  );
});

test("tools: a TRUSTED field or whole result RELAXES, UNTRUSTED TIGHTENS; outbound resolve on RELAXES", () => {
  assertRelaxes(null, { tools: { WebFetch: { inbound: "TRUSTED" } } }, "tools", "WebFetch trusted");
  assertRelaxes(null, { tools: { my_tool: { inbound: { summary: "TRUSTED" } } } }, "tools", "field trusted");
  assertTightens({ tools: { my_tool: { inbound: { summary: "TRUSTED" } } } }, { tools: { my_tool: { inbound: "UNTRUSTED" } } }, "field untrusted");
  assertRelaxes(null, { tools: { my_tool: { outbound: "resolve" } } }, "tools", "resolve on");
  assertTightens({ tools: { my_tool: { outbound: "resolve" } } }, { tools: { my_tool: { outbound: "not_resolve" } } }, "resolve off");
  assertRelaxes(null, { tools: { my_tool: { outbound: { body: "resolve" } } } }, "tools", "field resolve");
});

// ── dispositions ─────────────────────────────────────────────────────────────

test("dispositions: ask → block TIGHTENS, block → ask RELAXES (absent = ask)", () => {
  const id = "egress:untrusted-to-untrusted-destination";
  const blocked: PolicyFileConfig = { rules: { [id]: { mode: "block" } } };
  const d = delta(null, blocked);
  // The rule id must exist for the validator; this pins the classifier only.
  assert.deepEqual(d.relaxations, []);
  assert.equal(d.tightenings[0]?.facet, "dispositions");
  assertRelaxes(blocked, null, "dispositions", "back to ask");
});

// ── user rules (§3.4) ────────────────────────────────────────────────────────

const allowRule = (over: Partial<NonNullable<PolicyFileConfig["user_rules"]>[number]> = {}): PolicyFileConfig => ({
  user_rules: [{ id: "r-1", kind: "release", from: { host: "docs.python.org" }, to: { host: "api.example.com" }, mode: "allow", expires: "2026-10-01T00:00:00Z", ...over }],
});

test("user rules: EXTENDING an allow's expiry or WIDENING its from RELAXES (the same-id bug); the reverse TIGHTENS", () => {
  assertRelaxes(allowRule(), allowRule({ expires: "2027-01-01T00:00:00Z" }), "user-rules", "extend expiry");
  assertRelaxes(allowRule(), allowRule({ expires: null }), "user-rules", "expiry → never");
  assertTightens(allowRule(), allowRule({ expires: "2026-09-30T00:00:00Z" }), "shorten expiry");
  assertRelaxes(allowRule(), allowRule({ from: undefined }), "user-rules", "from → any origin");
  assertRelaxes(allowRule(), allowRule({ to: { host: "*.example.com" } }), "user-rules", "to widened");
  assertTightens(allowRule({ to: { host: "*.example.com" } }), allowRule(), "to narrowed");
});

test("user rules: adding an allow RELAXES, a block TIGHTENS; retiring a block, or setting it off/audit, RELAXES", () => {
  const block: PolicyFileConfig = { user_rules: [{ id: "b-1", kind: "release", to: { host: "pastebin.com" }, mode: "block" }] };
  assertRelaxes(null, allowRule(), "user-rules", "new allow");
  assertTightens(null, block, "new block");
  assertRelaxes(block, null, "user-rules", "retire block");
  assertRelaxes(block, { user_rules: [{ ...block.user_rules![0]!, mode: "off" }] }, "user-rules", "block off");
  assertRelaxes(block, { user_rules: [{ ...block.user_rules![0]!, mode: "audit" }] }, "user-rules", "block → audit");
  // off on an ALLOW rule tightens; audit rules are neutral either way.
  assertTightens(allowRule(), allowRule({ mode: "off" }), "allow off");
  const audit: PolicyFileConfig = { user_rules: [{ id: "a-1", kind: "release", to: { host: "*" }, mode: "audit" }] };
  assert.deepEqual(delta(null, audit), { relaxations: [], tightenings: [] });
  assert.deepEqual(delta(audit, null), { relaxations: [], tightenings: [] });
});

test("user rules: a list edit relaxes through the rule that references it", () => {
  const b: PolicyFileConfig = { lists: { svc: ["api.example.com"] }, user_rules: [{ id: "r-1", kind: "release", to: { host: "@svc" }, mode: "allow" }] };
  const a: PolicyFileConfig = { ...b, lists: { svc: ["api.example.com", "pastebin.com"] } };
  const d = delta(b, a);
  assert.equal(isTightening(d), false);
  assert.equal(d.relaxations[0]!.subject, "r-1");
});

test("user rules: an allow already expired at comparison time is ignored on both sides", () => {
  const expired = allowRule({ expires: "2026-01-01T00:00:00Z" });
  assert.deepEqual(delta(null, expired).relaxations, []);
});

test("hostPatternCovers follows hostMatches: * ⊇ *.x ⊇ x and *.sub.x; a literal covers only itself", () => {
  assert.ok(hostPatternCovers("*", "*.example.com"));
  assert.ok(hostPatternCovers("*.example.com", "example.com"));
  assert.ok(hostPatternCovers("*.example.com", "api.example.com"));
  assert.ok(hostPatternCovers("*.example.com", "*.api.example.com"));
  assert.ok(!hostPatternCovers("*.api.example.com", "*.example.com"));
  assert.ok(!hostPatternCovers("api.example.com", "*.api.example.com"));
  assert.ok(!hostPatternCovers("example.com", "*"));
  assert.ok(hostPatternCovers("API.example.com", "api.example.com"));
});

// ── destinations, apps, env ──────────────────────────────────────────────────

test("destinations: a connect allow RELAXES, removing one TIGHTENS", () => {
  const d: PolicyFileConfig = { destinations: [{ host: "db.internal", port: 5432, connect: "allow" }] };
  assertRelaxes(null, d, "destinations", "connect allow");
  assertTightens(d, null, "remove connect allow");
});

test("apps: output clear / mask RELAXES, back to secret TIGHTENS", () => {
  const clear: PolicyFileConfig = { apps: [{ app: "jq", output: "clear" }] };
  assertRelaxes(null, clear, "apps", "clear");
  assertTightens(clear, null, "remove clear");
  assertTightens(clear, { apps: [{ app: "jq", output: "secret" }] }, "clear → secret");
});

test("paths: a reader's output (plan 13 D3) raised above secret RELAXES; lowered back, nothing else changed, TIGHTENS", () => {
  const at = (readers: unknown[]): PolicyFileConfig => ({ paths: [{ path: "/home/u/.pgpass", level: "no-model", readers: readers as never }] });
  const base = at(["psql", "pg_dump"]);
  const clear = at([{ app: "psql", output: "clear" }, "pg_dump"]);
  const mask = at([{ app: "psql", output: "mask", mask: ["pw=\\S+"] }, "pg_dump"]);
  assertRelaxes(base, clear, "paths", "secret → clear on a reader entry");
  assert.match(delta(base, clear).relaxations[0]!.detail, /psql's output .*\/home\/u\/\.pgpass.* clear/);
  assertRelaxes(base, mask, "paths", "secret → mask on a reader entry");
  assertRelaxes(mask, clear, "paths", "mask → clear");
  assertTightens(clear, base, "clear → secret (the bare name)");
  assertTightens(clear, at([{ app: "psql", output: "secret" }, "pg_dump"]), "clear → explicit secret");
  assertTightens(clear, mask, "clear → mask");
  assertTightens(mask, at([{ app: "psql", output: "mask", mask: ["pw=\\S+", "AKIA.*"] }, "pg_dump"]), "mask with more spans");
  assertRelaxes(mask, at([{ app: "psql", output: "mask", mask: ["AKIA.*"] }, "pg_dump"]), "paths", "mask with other spans");
  // the output change rides with another reader change: not a proven form
  assertRelaxes(clear, at(["psql", "pg_dump", "psql2"]), "paths", "output lowered and a reader added");
});

test("env: an exemption RELAXES, a new secret name TIGHTENS", () => {
  assertRelaxes(null, { env: { exempt: ["GITHUB_TOKEN"] } }, "env", "exempt");
  assertTightens({ env: { exempt: ["GITHUB_TOKEN"] } }, null, "unexempt");
  assertTightens(null, { env: { secrets: ["MY_CORP_*"] } }, "add secret");
  assertRelaxes({ env: { secrets: ["MY_CORP_*"] } }, null, "env", "drop secret");
});

// ── fail closed ──────────────────────────────────────────────────────────────

test("fail closed: an unknown document key is a relaxation; different boot specs are not comparable", () => {
  const d = delta(null, { future_key: { anything: true } } as unknown as PolicyFileConfig);
  assert.equal(isTightening(d), false);
  assert.equal(d.relaxations[0]!.facet, "law");
  const b = compilePolicy({ specId: "claude-code", document: null, log: SILENT });
  const o = compilePolicy({ specId: "opencode", document: null, log: SILENT });
  assert.equal(isTightening(policyDelta(b, o)), false);
});

test("a mixed change is a relaxation even when most of it tightens (one list, one verdict)", () => {
  const d = delta(null, {
    paths: [{ path: "/srv/app/.env", level: "no-model" }],
    inbound: { url: { trustedList: ["https://pastebin.com/"] } },
  });
  assert.equal(isTightening(d), false);
  assert.equal(d.tightenings.length, 1);
  assert.equal(d.relaxations.length, 1);
});

test("env.sources: a new source masks (tightening); its bindings release (relaxation); relaxationsOf lists them", async () => {
  const { relaxationsOf } = await import("../../policy/compiled-policy.js");
  const before = compilePolicy({ specId: "claude-code", document: { version: 1 } as PolicyFileConfig });
  const noBind = compilePolicy({ specId: "claude-code", document: { version: 1, env: { sources: [{ name: "GH_TOKEN", source: "cmd:gh auth token" }] } } as PolicyFileConfig });
  const bound = compilePolicy({ specId: "claude-code", document: { version: 1, env: { sources: [{ name: "GH_TOKEN", source: "cmd:gh auth token", bindings: ["api.github.com"] }] } } as PolicyFileConfig });
  assert.equal(isTightening(policyDelta(before, noBind)), true, "a sourced variable without bindings only masks");
  const d = policyDelta(noBind, bound);
  assert.equal(isTightening(d), false);
  assert.ok(d.relaxations.some((r) => r.facet === "env" && /GH_TOKEN may be sent to api\.github\.com/.test(r.detail)), JSON.stringify(d.relaxations));
  assert.ok(relaxationsOf(bound).some((r) => r.kind === "env-binding" && r.subject === "GH_TOKEN"));
  assert.deepEqual(bound.envSources.map((e) => [e.name, e.source, [...e.bindings]]), [["GH_TOKEN", "cmd:gh auth token", ["api.github.com"]]]);
});

test("ssh_agent: gating the agent socket is a tightening, lifting it a relaxation", () => {
  const none = compilePolicy({ specId: "claude-code", document: { version: 1 } as PolicyFileConfig });
  const gated = compilePolicy({ specId: "claude-code", document: { version: 1, ssh_agent: { readers: [{ app: "ssh", from: "git" }] } } as PolicyFileConfig });
  assert.equal(isTightening(policyDelta(none, gated)), true);
  assert.equal(isTightening(policyDelta(gated, none)), false);
  assert.deepEqual(gated.sshAgentReaders, [{ app: "ssh", from: "git" }]);
  assert.equal(none.sshAgentReaders, null);
});

test("protect: adding a path is a tightening, removing it a relaxation", () => {
  const a = compilePolicy({ specId: "claude-code", document: { version: 1 } as PolicyFileConfig });
  const b = compilePolicy({ specId: "claude-code", document: { version: 1, protect: ["~/Documents"] } as PolicyFileConfig });
  assert.equal(isTightening(policyDelta(a, b)), true);
  assert.equal(isTightening(policyDelta(b, a)), false);
  assert.deepEqual([...b.protect], ["~/Documents"]);
});
