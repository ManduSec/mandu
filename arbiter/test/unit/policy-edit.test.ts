/**
 * policy-edit.test — typed edits to the law (policy-surface.md §8.4.1).
 *
 * Pins:
 *   - every PolicyEdit op onto an empty and a populated document; the result
 *     validates; the input is never modified; re-applying is idempotent where
 *     the op is (locks, origins, connects, lists);
 *   - one list, one verdict: a bad op anywhere refuses the whole list, and an
 *     op naming something that does not exist is refused;
 *   - `lock-path` on an existing label replaces level / bindings / recursive
 *     and keeps the expert-only readers / others / extract;
 *   - evaluateEdits: the §5.1 user story — lock `.env` at strict applies,
 *     trusting a registry or allowing an API is a proposal, a model-ok lock is
 *     a proposal (§3.3).
 *
 * Pure: no arbiter, no DB, no privilege; no protection axis is read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { applyEdits, canonicalJson, diffItems, evaluateEdits, layerItems, POLICY_EDIT_OPS, revertConflicts, revertItems, type PolicyEdit } from "../../policy/policy-edit.js";
import { dispositionableRuleIds, validatePolicyDocument } from "../../policy/policy-file-validate.js";

const NOW = Date.parse("2026-09-25T00:00:00Z");

const POPULATED: PolicyFileConfig = {
  version: 1,
  lists: { svc: ["api.example.com"] },
  paths: [{ path: "/home/u/.aws", level: "any-model", bindings: ["aws.amazon.com"], readers: ["aws"], others: "deny" }],
  user_rules: [{ id: "r-0001", kind: "release", to: { host: "@svc" }, mode: "allow" }],
  destinations: [{ host: "db.internal", port: 5432, connect: "allow" }],
  inbound: { url: { trustedList: ["https://docs.python.org/"] } },
};

function ok(doc: PolicyFileConfig | null, edits: PolicyEdit[]): PolicyFileConfig {
  const r = applyEdits(doc, edits, { by: "agent:s1", now: NOW });
  assert.ok(r.ok, `expected the edits to apply: ${r.ok ? "" : r.problems.join("; ")}`);
  assert.deepEqual(validatePolicyDocument(r.document), []);
  return r.document;
}

const ONE_OF_EACH: PolicyEdit[] = [
  { op: "lock-path", path: "/srv/app/.env", level: "no-model" },
  { op: "trust-origin", kind: "url", pattern: "https://pypi.org/" },
  { op: "distrust-origin", kind: "dir", pattern: "/home/u/Downloads" },
  { op: "release", to: { host: "pastebin.com" }, mode: "block", reason: "never paste" },
  { op: "set-disposition", rule: dispositionableRuleIds()[0]!, mode: "block" },
  { op: "allow-connect", host: "registry.npmjs.org" },
  { op: "trust-command", id: "git", trustHelp: true },
  { op: "tool-inbound", tool: "my_tool", trust: "UNTRUSTED" },
  { op: "list", name: "mine", add: ["a.example.com"] },
];

test("every op kind is exercised by this suite", () => {
  // The model ops (plan 11 D2) have their own suite: policy-edit-models.test.ts
  // (restore-model, plan 12 D5: admin-layer.test.ts); the blob locks (plan 14
  // §8.2): policy-edit-blobs.test.ts; the label mapping (plan 14 §14.1):
  // sensitivity-label-policy.test.ts; the prompt filter's switches (plan 15
  // §6): prompt-filter-policy.test.ts.
  const covered = new Set([...ONE_OF_EACH.map((e) => e.op), "unlock-path", "retire-rule", "remove-connect", "add-model", "update-model", "remove-model", "restore-model", "lock-blob", "unlock-blob", "map-sensitivity-label", "unmap-sensitivity-label",
    "set-prompt-filter", "set-prompt-action", "remove-prompt-action", "add-prompt-exception", "remove-prompt-exception"]);
  assert.deepEqual([...covered].sort(), [...POLICY_EDIT_OPS].sort());
});

test("every op applies onto an EMPTY document and the result validates", () => {
  const doc = ok(null, ONE_OF_EACH);
  assert.equal(doc.version, 1);
  assert.deepEqual(doc.paths, [{ path: "/srv/app/.env", level: "no-model" }]);
  assert.deepEqual(doc.inbound?.url?.trustedList, ["pypi.org"], "the scheme is stripped (the URL category never matches one)");
  assert.deepEqual(doc.inbound?.dir?.untrustedList, ["/home/u/Downloads"]);
  assert.equal(doc.user_rules?.[0]?.id, "r-0001");
  assert.equal(doc.user_rules?.[0]?.by, "agent:s1");
  assert.equal(doc.user_rules?.[0]?.added, new Date(NOW).toISOString());
  assert.deepEqual(doc.destinations, [{ host: "registry.npmjs.org", connect: "allow" }]);
  assert.deepEqual(doc.inbound?.command, [{ id: "git", trustHelp: true }]);
  assert.deepEqual(doc.tools, { my_tool: { inbound: "UNTRUSTED" } });
  assert.deepEqual(doc.lists, { mine: ["a.example.com"] });
});

test("every op applies onto a POPULATED document; the input is never modified", () => {
  const input = structuredClone(POPULATED);
  const doc = ok(input, [
    ...ONE_OF_EACH,
    { op: "retire-rule", id: "r-0001" },
    { op: "remove-connect", host: "db.internal", port: 5432 },
    { op: "unlock-path", path: "/home/u/.aws" },
  ]);
  assert.deepEqual(input, POPULATED, "applyEdits works on a copy");
  assert.equal(doc.user_rules?.length, 1);
  assert.equal(doc.user_rules?.[0]?.to.host, "pastebin.com");
  assert.notEqual(doc.user_rules?.[0]?.id, "r-0001");
  assert.equal(doc.paths?.some((p) => p.path === "/home/u/.aws"), false);
  assert.deepEqual(doc.destinations, [{ host: "registry.npmjs.org", connect: "allow" }]);
});

test("idempotent ops: applying the same lock / origin / connect / list edit twice changes nothing more", () => {
  const edits: PolicyEdit[] = [
    { op: "lock-path", path: "/srv/app/.env", level: "no-model" },
    { op: "trust-origin", kind: "url", pattern: "https://pypi.org/" },
    { op: "allow-connect", host: "registry.npmjs.org" },
    { op: "list", name: "svc", add: ["api.example.com"] },
  ];
  const once = ok(POPULATED, edits);
  assert.deepEqual(ok(once, edits), once);
});

test("trust-origin / distrust-origin write only the list the category's mode reads (a URL default is UNTRUSTED, a DIR default TRUSTED)", () => {
  const trusted = ok(null, [{ op: "trust-origin", kind: "url", pattern: "x.example" }]);
  assert.deepEqual(trusted.inbound?.url, { default: "UNTRUSTED", trustedList: ["x.example"] }, "the default is pinned in the file");
  const distrusted = ok(trusted, [{ op: "distrust-origin", kind: "url", pattern: "x.example" }]);
  assert.deepEqual(distrusted.inbound?.url, { default: "UNTRUSTED" }, "distrusting under an allowlist removes the allow entry");
  assert.equal(ok(null, [{ op: "distrust-origin", kind: "url", pattern: "y.example" }]).inbound, undefined, "an unlisted URL is already untrusted: nothing to write");
  const dir = ok(null, [{ op: "distrust-origin", kind: "dir", pattern: "/home/u/Downloads" }]);
  assert.deepEqual(dir.inbound?.dir, { default: "TRUSTED", untrustedList: ["/home/u/Downloads"] });
  assert.deepEqual(ok(dir, [{ op: "trust-origin", kind: "dir", pattern: "/home/u/Downloads" }]).inbound?.dir, { default: "TRUSTED" });
});

test("lock-path on an existing label replaces level/bindings/recursive and KEEPS readers/others/extract", () => {
  const doc = ok(POPULATED, [{ op: "lock-path", path: "/home/u/.aws", level: "no-model" }]);
  assert.deepEqual(doc.paths, [{ path: "/home/u/.aws", level: "no-model", readers: ["aws"], others: "deny" }]);
});

test("release with an existing id replaces that rule, keeping its added stamp", () => {
  const doc = ok(POPULATED, [{ op: "release", id: "r-0001", to: { host: "@svc" }, mode: "block" }]);
  assert.equal(doc.user_rules?.length, 1);
  assert.equal(doc.user_rules?.[0]?.mode, "block");
  assert.equal(doc.user_rules?.[0]?.added, new Date(NOW).toISOString(), "the populated rule had no added stamp; one is set");
});

test("one list, one verdict: a bad op anywhere refuses the whole list; missing targets are refused", () => {
  for (const [edits, pattern] of [
    [[{ op: "lock-path", path: "/srv/app/.env", level: "no-model" }, { op: "explode" }], /unknown op/],
    [[{ op: "unlock-path", path: "/nowhere" }], /no lock on \/nowhere/],
    [[{ op: "retire-rule", id: "r-9999" }], /no user rule/],
    [[{ op: "remove-connect", host: "nowhere.example" }], /no destination rule/],
    [[{ op: "list", name: "nope", remove: ["x"] }], /no list named nope/],
    [[{ op: "release", to: { host: "" }, mode: "allow" }], /to\.host/],
    [[{ op: "trust-origin", kind: "file", pattern: "/x" }], /kind/],
    [[{ op: "set-disposition", rule: "egress:not-a-rule", mode: "block" }], /rules/],
    [[{ op: "lock-path", path: "relative/path", level: "no-model" }], /absolute path/],
    [[], /non-empty list/],
    ["not a list", /non-empty list/],
  ] as Array<[unknown, RegExp]>) {
    const r = applyEdits(POPULATED, edits, { now: NOW });
    assert.equal(r.ok, false, `expected refusal for ${JSON.stringify(edits)}`);
    if (!r.ok) assert.match(r.problems.join("\n"), pattern);
  }
});

test("evaluateEdits: the 'set up Mandu for this repo' story — strict locks apply, trust and reach are proposals", () => {
  const before = { specId: "claude-code" as const, document: null };
  const locks = evaluateEdits(before, [
    { op: "lock-path", path: "/home/u/repo/.env", level: "no-model" },
    { op: "lock-path", path: "/home/u/repo/**/*.pem", level: "no-model" },
    { op: "release", to: { host: "pastebin.com" }, mode: "block" },
  ], { now: NOW });
  assert.ok(locks.ok && locks.tightening, "plain strict locks and a block rule apply at once");

  const trust = evaluateEdits(before, [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }], { now: NOW });
  assert.ok(trust.ok && !trust.tightening && trust.delta.relaxations[0]!.facet === "origins");

  const reach = evaluateEdits(before, [{ op: "allow-connect", host: "api.myproject.dev" }], { now: NOW });
  assert.ok(reach.ok && !reach.tightening);

  const declassify = evaluateEdits(before, [{ op: "lock-path", path: "/home/u/.ssh", level: "any-model" }], { now: NOW });
  assert.ok(declassify.ok && !declassify.tightening, "a model-ok lock is a declassification: a proposal (§3.3)");
});

test("evaluateEdits: an invalid list is refused before any classification", () => {
  const r = evaluateEdits({ specId: "claude-code", document: null }, [{ op: "unlock-path", path: "/x" }]);
  assert.equal(r.ok, false);
});

test("diffItems + revertItems: every op's change reverts exactly, onto an empty and a populated document", () => {
  for (const start of [null, POPULATED]) {
    for (const e of [...ONE_OF_EACH, { op: "retire-rule", id: "r-0001" }, { op: "unlock-path", path: "/home/u/.aws" }] as PolicyEdit[]) {
      if (start === null && (e.op === "retire-rule" || e.op === "unlock-path")) continue;
      const after = ok(start, [e]);
      const items = diffItems(start, after);
      assert.ok(items.length > 0, `${e.op}: the change touched something`);
      assert.deepEqual(revertConflicts(after, items), [], `${e.op}: nothing changed since`);
      const back = revertItems(after, items);
      assert.ok(back.ok, back.ok ? "" : back.problems.join("; "));
      const want = start ? { ...structuredClone(start), version: 1 } : { version: 1 };
      assert.equal(canonicalJson(back.document), canonicalJson(want), `${e.op} on ${start ? "populated" : "empty"}`);
    }
  }
});

test("revertItems keeps later changes to OTHER items; revertConflicts names an item changed again", () => {
  const a = ok(POPULATED, [{ op: "lock-path", path: "/srv/app/.env", level: "no-model" }]);
  const items = diffItems(POPULATED, a);
  const later = ok(a, [{ op: "allow-connect", host: "registry.npmjs.org" }]);
  const back = revertItems(later, items);
  assert.ok(back.ok);
  assert.deepEqual(back.document.destinations?.map((d) => d.host), ["db.internal", "registry.npmjs.org"]);
  assert.equal(back.document.paths?.some((p) => p.path === "/srv/app/.env"), false);
  const changedAgain = ok(a, [{ op: "lock-path", path: "/srv/app/.env", level: "no-model", recursive: false }]);
  assert.deepEqual(revertConflicts(changedAgain, items), ["paths /srv/app/.env"]);
});

test("layerItems: every op's change made to another document gives what the same edit gives there, other items kept", () => {
  // The other document: POPULATED with an unrelated hand change (a second
  // destination), as a held hand edit of policy.yaml would be (§8.4.6).
  const other = ok(POPULATED, [{ op: "allow-connect", host: "registry.example.org" }]);
  for (const e of [...ONE_OF_EACH, { op: "retire-rule", id: "r-0001" }, { op: "unlock-path", path: "/home/u/.aws" }] as PolicyEdit[]) {
    const after = ok(POPULATED, [e]);
    const r = layerItems(other, POPULATED, after);
    assert.ok(r.ok, `${e.op}: ${r.ok ? "" : [...r.conflicts, ...r.problems].join("; ")}`);
    assert.equal(canonicalJson(r.document), canonicalJson(ok(other, [e])), `${e.op}: the same change as the edit itself`);
  }
});

test("layerItems refuses an item the other document changed too, naming it; it never writes over it", () => {
  const after = ok(POPULATED, [{ op: "lock-path", path: "/home/u/.aws", level: "no-model" }]);
  const held = ok(POPULATED, [{ op: "lock-path", path: "/home/u/.aws", level: "any-model", bindings: ["evil.example"] }]);
  const r = layerItems(held, POPULATED, after);
  assert.equal(r.ok, false);
  assert.deepEqual(r.ok ? [] : r.conflicts, ["paths /home/u/.aws"]);
  // No change at all: the other document as it is.
  const same = layerItems(held, POPULATED, POPULATED);
  assert.ok(same.ok);
  assert.equal(canonicalJson(same.document), canonicalJson(held));
});

test("fail closed: a key diffItems does not itemize (protect:, env.sources) still reverts, as one whole value", () => {
  const before: PolicyFileConfig = { version: 1, protect: ["/home/u/Documents"] } as PolicyFileConfig;
  const after: PolicyFileConfig = { version: 1, protect: ["/home/u/Documents", "/home/u/repo"], env: { sources: [{ name: "GH_TOKEN", source: "cmd:gh auth token" }] } } as PolicyFileConfig;
  const items = diffItems(before, after);
  assert.deepEqual(items.map((i) => `${i.section} ${i.key}`).sort(), ["env-key sources", "key protect"]);
  const back = revertItems(after, items);
  assert.ok(back.ok, back.ok ? "" : back.problems.join("; "));
  assert.equal(canonicalJson(back.document), canonicalJson(before));
});

test("URL trust patterns lose their scheme (the URL category never matches one), keep a path, and refuse an empty host", () => {
  const doc = ok(null, [
    { op: "trust-origin", kind: "url", pattern: "https://pypi.org/" },
    { op: "trust-origin", kind: "url", pattern: "HTTP://github.com/myorg" },
    { op: "distrust-origin", kind: "url", pattern: "https://paste.example/" },
    { op: "distrust-origin", kind: "dir", pattern: "/home/u/untrusted/" },
  ]);
  assert.deepEqual(doc.inbound?.url?.trustedList, ["pypi.org", "github.com/myorg"]);
  assert.equal(doc.inbound?.url?.untrustedList, undefined, "an unlisted URL is already untrusted under the URL allowlist");
  assert.deepEqual(doc.inbound?.dir?.untrustedList, ["/home/u/untrusted/"], "only URL patterns are rewritten");
  const r = applyEdits(null, [{ op: "trust-origin", kind: "url", pattern: "https://" }]);
  assert.ok(!r.ok && /needs a host/.test(r.problems.join()));
});
