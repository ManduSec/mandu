/**
 * compiled-policy.test — compile, don't mutate (policy-surface.md
 * §2.2, stage 3).
 *
 * Pins:
 *   - GOLDEN: compiling the built-ins with no document yields tables that are
 *     deep-equal to the pristine built-in constants for EVERY spec id, and the
 *     snapshot the dashboard reads is unchanged;
 *   - IMMUTABILITY: the compiled tables are frozen; compiling a document with
 *     overrides changes NOTHING in the built-in constants (the regression the
 *     old in-place merge made impossible to test);
 *   - overrides land only on the boot spec's copy; a session bound to another
 *     spec sees its own pristine table;
 *   - relaxationsOf(built-ins) is EMPTY for every spec; a document that trusts
 *     an origin, a tool field, an outbound resolve and a command's help output
 *     lists exactly those;
 *   - setActiveInboundSpec swaps the law in force (getToolInboundSpec follows);
 *     the exec classifier reads the compiled index and resets with it.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";

import {
  compilePolicy,
  getCurrentPolicy,
  relaxationsOf,
  resetCurrentPolicyForTests,
  swapCurrentPolicy,
} from "../../policy/compiled-policy.js";
import {
  BUILTIN_INBOUND_SPECS,
  INBOUND_SPEC_IDS,
  bindSessionSpec,
  clearSessionSpecs,
  getActiveInboundSpec,
  getActiveInboundSpecId,
  getToolInboundSpec,
  setActiveInboundSpec,
} from "../../policy/tool-inbound.js";
import {
  BUILTIN_OUTBOUND_FIELD_POLICY,
  BUILTIN_OUTBOUND_RESOLVE,
  destinationKind,
  getActiveOutboundResolve,
} from "../../policy/tool-outbound.js";
import { classifyExecOutput, _execResultTrustIndexForTests } from "../../policy/exec-inbound.js";
import { snapshotActivePolicy } from "../../policy/policy-snapshot.js";
import { createPolicyEngine } from "../../policy/policy-engine.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";

const SILENT = { info: () => {}, warn: () => {} };

after(() => {
  clearSessionSpecs();
  resetCurrentPolicyForTests("claude-code");
});

test("golden: the built-in compile equals the pristine constants for every spec; the snapshot is unchanged", () => {
  const before = snapshotActivePolicy(createPolicyEngine(undefined, process.cwd(), SILENT, null));
  for (const id of INBOUND_SPEC_IDS) {
    const c = compilePolicy({ specId: id, document: null });
    assert.deepEqual(c.inbound[id], BUILTIN_INBOUND_SPECS[id], `${id}: inbound`);
    assert.deepEqual(c.outboundResolve[id], BUILTIN_OUTBOUND_RESOLVE[id], `${id}: outbound resolve`);
    assert.deepEqual(c.outboundFieldPolicy[id], BUILTIN_OUTBOUND_FIELD_POLICY[id], `${id}: outbound fields`);
    assert.deepEqual(c.lawSource, { kind: "builtin" });
    assert.deepEqual(relaxationsOf(c), [], `${id}: the built-ins relax nothing`);
  }
  swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: null }));
  const after = snapshotActivePolicy(createPolicyEngine(undefined, process.cwd(), SILENT, null));
  assert.deepEqual(after, before, "the dashboard's snapshot of the law is byte-identical through the refactor");
});

const DOC: PolicyFileConfig = {
  inbound: {
    url: { default: "UNTRUSTED", trustedList: ["https://docs.python.org/"] },
    command: [{ id: "git", trustHelp: true, subcommands: { status: { schema: { stdout: "TRUSTED" } } } }],
  },
  tools: {
    WebFetch: { inbound: { url: "TRUSTED", text: "UNTRUSTED" }, outbound: { url: "resolve" } },
    my_tool: { inbound: { summary: "TRUSTED" }, outbound: "resolve" },
    Read: { outbound: "not_resolve" },
  },
};

test("immutability: compiling a document never touches the built-ins; the compiled tables are frozen", () => {
  const pristineWebFetch = BUILTIN_INBOUND_SPECS["claude-code"].WebFetch;
  const pristineResolve = { ...BUILTIN_OUTBOUND_RESOLVE["claude-code"] };
  const c = compilePolicy({ specId: "claude-code", document: DOC, log: SILENT });
  assert.equal(BUILTIN_INBOUND_SPECS["claude-code"].WebFetch, pristineWebFetch, "the built-in object is the same reference");
  assert.equal(BUILTIN_INBOUND_SPECS["claude-code"].my_tool, undefined, "no new tool leaked into the built-ins");
  assert.deepEqual(BUILTIN_OUTBOUND_RESOLVE["claude-code"], pristineResolve);
  assert.ok(Object.isFrozen(c.inbound["claude-code"]));
  assert.ok(Object.isFrozen(c.outboundResolve["claude-code"]));
  assert.ok(Object.isFrozen(c.execIndex));
  assert.throws(() => {
    (c.inbound["claude-code"] as Record<string, unknown>).Bash = "TRUSTED";
  }, /read only|not extensible|Cannot add property|Cannot assign/);
  // The override REPLACED WebFetch's schema and dropped its wholeResult grant.
  const wf = c.inbound["claude-code"].WebFetch as { schema: unknown; wholeResult?: unknown };
  assert.deepEqual(wf.schema, { url: "TRUSTED", text: "UNTRUSTED" });
  assert.equal(wf.wholeResult, undefined, "an operator override never inherits a built-in whole-result grant");
  assert.equal(c.outboundResolve["claude-code"].my_tool, true);
  assert.equal(c.outboundResolve["claude-code"].Read, false);
  assert.equal(c.execIndex.git?.trustHelp, true);
  // Overrides land on the boot spec ONLY — another spec's table is pristine.
  assert.deepEqual(c.inbound.opencode, BUILTIN_INBOUND_SPECS.opencode);
});

test("relaxationsOf: exactly the places the document is more permissive than the built-ins", () => {
  const c = compilePolicy({ specId: "claude-code", document: DOC, log: SILENT });
  const rel = relaxationsOf(c).map((r) => `${r.kind} ${r.subject}`).sort();
  assert.deepEqual(rel, [
    "exec-output-trust git status.stdout",
    "exec-output-trust git:trustHelp",
    "inbound-trust WebFetch.url",
    "inbound-trust my_tool.summary",
    "outbound-resolve my_tool",
    "trusted-origin URL:https://docs.python.org/",
  ]);
  // A pure TIGHTENING document relaxes nothing.
  const tight = compilePolicy({
    specId: "claude-code",
    document: { inbound: { dir: { default: "TRUSTED", untrustedList: ["~/Downloads"] } }, tools: { Glob: { inbound: "UNTRUSTED" } } },
    log: SILENT,
  });
  assert.deepEqual(relaxationsOf(tight), []);
});

test("the law in force: setActiveInboundSpec swaps it and every accessor follows; sessions resolve against their own spec", () => {
  resetCurrentPolicyForTests("claude-code");
  swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: DOC, log: SILENT }));
  assert.equal(getActiveInboundSpecId(), "claude-code");
  assert.deepEqual((getToolInboundSpec("WebFetch") as { schema: unknown }).schema, { url: "TRUSTED", text: "UNTRUSTED" });
  assert.equal(getActiveOutboundResolve().my_tool, true);
  assert.equal(destinationKind("WebFetch", "url"), "resolve"); // (also the built-in field policy — no relaxation)
  // A session bound to opencode sees the PRISTINE opencode table, not the override.
  bindSessionSpec("s-oc", "opencode");
  assert.equal(getToolInboundSpec("WebFetch", "s-oc"), undefined, "opencode has no WebFetch; the override is claude-code's");
  assert.equal(destinationKind("my_tool", undefined, "s-oc"), "not_resolve");
  // Switching the boot spec recompiles the SAME document under the new id.
  setActiveInboundSpec("opencode");
  assert.equal(getActiveInboundSpecId(), "opencode");
  assert.equal(getCurrentPolicy().document, DOC, "the document survives a spec switch");
  assert.equal((getActiveInboundSpec().my_tool as { schema: unknown } | undefined)?.schema !== undefined, true, "the override now rides opencode's copy");
  assert.deepEqual(getCurrentPolicy().inbound["claude-code"], BUILTIN_INBOUND_SPECS["claude-code"], "and claude-code's copy is pristine again");
  setActiveInboundSpec("claude-code");
});

test("exec classifier reads the compiled index; reset restores the built-ins", () => {
  resetCurrentPolicyForTests("claude-code");
  assert.equal(classifyExecOutput("git --help", {}).trustHelp, false, "built-ins trust no help output");
  swapCurrentPolicy(compilePolicy({ specId: "claude-code", document: DOC, log: SILENT }));
  assert.equal(classifyExecOutput("git --help", {}).trustHelp, true);
  assert.ok(_execResultTrustIndexForTests().git, "the test accessor reads the law in force");
  resetCurrentPolicyForTests();
  assert.equal(classifyExecOutput("git --help", {}).trustHelp, false);
  assert.equal(_execResultTrustIndexForTests().git, undefined);
});

// ── stage 4: lists, labels, dispositions, user rules ──────────────────────────

import { expandListsInDocument, hostMatches, matchUserRules, originHostOf } from "../../policy/compiled-policy.js";

const DOC4: PolicyFileConfig = {
  version: 1,
  lists: { "my-services": ["api.github.com", "*.internal.example"], docs: ["https://docs.python.org/"] },
  inbound: { url: { default: "UNTRUSTED", trustedList: ["@docs", "https://nodejs.org/api/"] } },
  paths: [{ path: "~/.ssh", level: "no-model" }, { path: "/srv/public", level: "public", recursive: false }],
  rules: { "egress:untrusted-destination": { mode: "block" } },
  user_rules: [
    { id: "allow-docs-to-api", kind: "release", from: { host: "docs.python.org" }, to: { host: "@my-services" }, mode: "allow" },
    { id: "block-paste", kind: "release", to: { host: "*.pastebin.com" }, mode: "block" },
    { id: "allow-paste-from-docs", kind: "release", from: { host: "docs.python.org" }, to: { host: "pastebin.com" }, mode: "allow" },
    { id: "audit-all", kind: "release", to: { host: "*" }, mode: "audit" },
    { id: "off-rule", kind: "release", to: { host: "*" }, mode: "off" },
    { id: "expired", kind: "release", to: { host: "*" }, mode: "allow", expires: "2000-01-01T00:00:00Z" },
  ],
};

test("paths: patterns — an entry with an unescaped * ? [ compiles to a pattern label (keyed apart from the literals); an escaped one stays a literal path; a public pattern is a listed relaxation", () => {
  const doc: PolicyFileConfig = {
    paths: [
      { path: "**/*.pem", level: "no-model" },
      { path: "~/work/*/contracts", level: "any-model", bindings: ["example.com"] },
      { path: "/srv/fixtures/**/.env", level: "public", recursive: false },
      { path: "/srv/odd/a\\*b.txt", level: "no-model" },
    ],
  };
  const c = compilePolicy({ specId: "claude-code", document: doc, log: SILENT });
  const pem = c.pathLabels.get("glob:**/*.pem");
  assert.equal(pem?.glob, true);
  assert.equal(pem?.path, "**/*.pem", "shown as the law wrote it");
  assert.equal(pem?.source, "policy-file");
  const work = [...c.pathLabels.values()].find((l) => l.path.endsWith("/work/*/contracts"));
  assert.equal(work?.glob, true);
  assert.ok(work!.path.startsWith("/"), "~ is expanded in a pattern too");
  assert.deepEqual(work?.bindings, ["example.com"]);
  assert.equal(c.pathLabels.get("glob:/srv/fixtures/**/.env")?.recursive, false);
  const lit = c.pathLabels.get("/srv/odd/a*b.txt");
  assert.equal(lit?.glob, undefined, "an escaped star is a real file name: a LITERAL label on it");
  assert.ok(relaxationsOf(c).some((r) => r.kind === "public-path" && r.subject === "/srv/fixtures/**/.env"), "a public pattern never hides from Relaxations");
});

test("stage 4 compile: @lists expand into the origin lists, labels/dispositions/user rules ride the compiled law", () => {
  const c = compilePolicy({ specId: "claude-code", document: DOC4, log: SILENT });
  assert.equal(c.document, DOC4, "the compiled law keeps the document as written (same reference)");
  assert.deepEqual(expandListsInDocument(DOC4)?.inbound?.url?.trustedList, ["https://docs.python.org/", "https://nodejs.org/api/"], "the @docs reference expands for the classifier registry");
  assert.deepEqual(DOC4.inbound?.url?.trustedList, ["@docs", "https://nodejs.org/api/"], "the input document is not modified");
  assert.deepEqual(Object.keys(c.lists).sort(), ["docs", "my-services"]);
  const ssh = [...c.pathLabels.values()].find((l) => l.path.endsWith("/.ssh"));
  assert.equal(ssh?.confidentiality, "no-model");
  assert.equal(ssh?.source, "policy-file");
  assert.equal(ssh?.recursive, true);
  assert.equal(c.pathLabels.get("/srv/public")?.recursive, false);
  assert.deepEqual(c.dispositions, { "egress:untrusted-destination": "block" });
  const byId = new Map(c.userRules.map((r) => [r.id, r]));
  assert.deepEqual(byId.get("allow-docs-to-api")?.to, ["api.github.com", "*.internal.example"], "@my-services expanded");
  assert.deepEqual(byId.get("allow-docs-to-api")?.from, ["docs.python.org"]);
  assert.equal(byId.get("block-paste")?.from, null, "no from = any origin");
  assert.equal(byId.get("expired")?.expiresAt, Date.parse("2000-01-01T00:00:00Z"));
  assert.ok(Object.isFrozen(c.userRules));
  const rel = relaxationsOf(c).map((r) => `${r.kind} ${r.subject}`).sort();
  assert.deepEqual(rel, [
    "public-path /srv/public",
    "trusted-origin URL:https://docs.python.org/",
    "trusted-origin URL:https://nodejs.org/api/",
    "user-rule-allow allow-docs-to-api",
    "user-rule-allow allow-paste-from-docs",
    "user-rule-allow expired",
  ]);
});

test("matchUserRules: Block beats Allow, audit only counts, off/expired are ignored, a narrowed rule needs a KNOWN origin", () => {
  const c = compilePolicy({ specId: "claude-code", document: DOC4, log: SILENT });
  const now = Date.parse("2026-09-05T00:00:00Z");
  // docs → my api: the allow rule decides; the audit rule is counted.
  let v = matchUserRules(c, { originHost: "docs.python.org", destinationHost: "api.github.com", now });
  assert.equal(v.decision?.mode, "allow");
  assert.equal(v.decision?.rule.id, "allow-docs-to-api");
  assert.deepEqual(v.audited.map((r) => r.id), ["audit-all"]);
  // suffix list entry matches a subdomain
  v = matchUserRules(c, { originHost: "docs.python.org", destinationHost: "db.internal.example", now });
  assert.equal(v.decision?.rule.id, "allow-docs-to-api");
  // pastebin: the block rule (any origin) beats the narrower allow for docs.
  v = matchUserRules(c, { originHost: "docs.python.org", destinationHost: "pastebin.com", now });
  assert.equal(v.decision?.mode, "block");
  assert.equal(v.decision?.rule.id, "block-paste");
  // unknown origin: the narrowed allow cannot match; the block still does.
  v = matchUserRules(c, { originHost: null, destinationHost: "api.github.com", now });
  assert.equal(v.decision, null, "no unnarrowed rule decides for api.github.com (expired and off are ignored)");
  assert.deepEqual(v.audited.map((r) => r.id), ["audit-all"]);
  v = matchUserRules(c, { originHost: null, destinationHost: "x.pastebin.com", now });
  assert.equal(v.decision?.rule.id, "block-paste");
  // the expired allow would have matched everything — before its expiry.
  v = matchUserRules(c, { originHost: null, destinationHost: "anything.example", now: Date.parse("1999-06-01T00:00:00Z") });
  assert.equal(v.decision?.rule.id, "expired");
});

test("hostMatches / originHostOf: case-insensitive, `*.x` suffix covers x itself, URLs yield hosts, paths yield null", () => {
  assert.ok(hostMatches("*", "anything"));
  assert.ok(hostMatches("API.GitHub.com", "api.github.com"));
  assert.ok(hostMatches("*.pastebin.com", "pastebin.com"));
  assert.ok(hostMatches("*.pastebin.com", "a.b.pastebin.com"));
  assert.ok(!hostMatches("*.pastebin.com", "notpastebin.com"));
  assert.ok(!hostMatches("api.github.com", "github.com"));
  assert.equal(originHostOf("https://Docs.Python.org/3/library/os.html"), "docs.python.org");
  assert.equal(originHostOf("/home/u/notes/a.txt"), null);
  assert.equal(originHostOf(null), null);
  assert.equal(originHostOf("not a url"), null);
});

test("paths[].extract rides on the compiled policy-file label (plan 10 §2.4)", () => {
  const doc = { version: 1, paths: [{ path: "/srv/app/custom.conf", level: "no-model", extract: "oauth: (\\S+)" }] };
  const c = compilePolicy({ specId: "claude-code", document: doc, log: SILENT });
  assert.equal(c.pathLabels.get("/srv/app/custom.conf")?.extract, "oauth: (\\S+)");
});


test("readers / others ride on the compiled label; apps compile into a table keyed by program (plan 10)", () => {
  const doc = {
    version: 1,
    paths: [{ path: "/h/.pgpass", level: "no-model", readers: ["psql"], others: "twin" as const }],
    apps: [{ app: "psql", output: "clear" as const }, { app: "aws", output: "mask" as const, mask: ["AKIA[0-9A-Z]{16}"] }],
  };
  const c = compilePolicy({ specId: "claude-code", document: doc, log: SILENT });
  const l = c.pathLabels.get("/h/.pgpass");
  assert.deepEqual(l?.readers, ["psql"]);
  assert.equal(l?.others, "twin");
  assert.equal(c.apps.get("psql")?.output, "clear");
  assert.deepEqual(c.apps.get("aws")?.mask, ["AKIA[0-9A-Z]{16}"]);
  assert.equal(c.apps.size, 2);
});

test("env: compiles onto the law as envSecrets (names kept as written, a bare '*' and non-strings dropped); absent ⇒ empty lists (plan 10 §11.4)", () => {
  const c = compilePolicy({ specId: "claude-code", document: { version: 1, env: { secrets: ["MYCO_*", "*", 7 as never], exempt: ["GH_TOKEN"] } }, log: SILENT });
  assert.deepEqual(c.envSecrets, { secrets: ["MYCO_*"], exempt: ["GH_TOKEN"] });
  assert.ok(Object.isFrozen(c.envSecrets) && Object.isFrozen(c.envSecrets.secrets));
  const none = compilePolicy({ specId: "claude-code", document: { version: 1 }, log: SILENT });
  assert.deepEqual(none.envSecrets, { secrets: [], exempt: [] });
  assert.deepEqual(compilePolicy({ specId: "claude-code", document: null, log: SILENT }).envSecrets, { secrets: [], exempt: [] });
});

test("relaxationsOf: bindings, env exemptions and non-secret app output are relaxations too (policy-surface.md §8.1 gap)", () => {
  const c = compilePolicy({
    specId: "claude-code",
    document: {
      paths: [
        { path: "/srv/app/.env", level: "any-model", bindings: ["api.example.com"] },
        { path: "/srv/app/key.pem", level: "no-model", readers: [{ app: "jq", output: "clear" }, { app: "cat", output: "secret" }, "head"] },
      ],
      env: { exempt: ["GITHUB_TOKEN"], secrets: ["MY_CORP_*"] },
      // Plan 13 D3: the program-wide rule is deprecated and clears nothing,
      // so it is no relaxation; the reader entry's output is one.
      apps: [{ app: "jq", output: "clear" }, { app: "cat", output: "secret" }],
    },
    log: SILENT,
  });
  const rel = relaxationsOf(c).map((r) => `${r.kind} ${r.subject}`).sort();
  assert.deepEqual(rel, ["app-output jq on /srv/app/key.pem", "env-exempt GITHUB_TOKEN", "path-binding /srv/app/.env"]);
});
