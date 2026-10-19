/**
 * policy-delta-engine-oracle — the tighten/relax verdict checked against the
 * REAL classifier (policy-surface.md §8.3; 2026-09-25).
 *
 * Why this exists: policyDelta compared the DOCUMENT, and one fact about the
 * engine was not in it: an origin section with no `default` meant "trust
 * everything" (blocklist) for every category. A `distrust-origin` edit
 * created `url: { untrustedList: [...] }`, the delta called it a tightening,
 * the data plane applied it without asking, and every URL became TRUSTED.
 * So this suite does not trust the delta's model of the engine: for many
 * (starting law, edit list) pairs it builds the engine before and after and
 * asserts that whenever the delta says TIGHTENING, no probe goes from
 * UNTRUSTED to TRUSTED. It also pins the engine rule the fix made: an absent
 * `default` is the category's built-in one.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { BUILTIN_ORIGIN_DEFAULT } from "../../policy/policy-engine.js";
import { evaluateEdits, type PolicyEdit } from "../../policy/policy-edit.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("full"); // this suite states its axes (protection-modes.md §4); the engines below pin integrity ON

const URLS = ["https://evil.example/page", "https://pypi.org/project/x/", "https://docs.python.org/3/", "https://paste.example/raw", "https://api.corp.net/v1"];
const DIRS = ["/home/u/Downloads/a.txt", "/home/u/repo/src/main.py", "/tmp/drop/x.md"];

function probes(doc: PolicyFileConfig | null): Record<string, string> {
  const engine = createEngineBackedPolicy({ policyFileOverride: doc, integrity: true, confidentiality: true });
  const out: Record<string, string> = {};
  for (const url of URLS) out[`url ${url}`] = engine.classify({ tool: "WebFetch", value: "x", boundary: "model_context", params: { url }, origin: url }).trust;
  for (const p of DIRS) out[`dir ${p}`] = engine.classify({ tool: "Read", value: "x", boundary: "model_context", params: { file_path: p }, origin: p }).trust;
  return out;
}

const STARTS: Array<[string, PolicyFileConfig | null]> = [
  ["built-ins", null],
  ["url allowlist", { version: 1, inbound: { url: { default: "UNTRUSTED", trustedList: ["docs.python.org", "*.corp.net"] } } }],
  ["url blocklist", { version: 1, inbound: { url: { default: "TRUSTED", untrustedList: ["paste.example"] } } }],
  ["dir blocklist", { version: 1, inbound: { dir: { default: "TRUSTED", untrustedList: ["/home/u/Downloads"] } } }],
  ["dir allowlist", { version: 1, inbound: { dir: { default: "UNTRUSTED", trustedList: ["/home/u/repo"] } } }],
];

const EDIT_LISTS: PolicyEdit[][] = [
  [{ op: "distrust-origin", kind: "url", pattern: "paste.example" }],
  [{ op: "distrust-origin", kind: "url", pattern: "docs.python.org" }],
  [{ op: "distrust-origin", kind: "url", pattern: "https://evil.example/" }],
  [{ op: "trust-origin", kind: "url", pattern: "pypi.org" }],
  [{ op: "trust-origin", kind: "url", pattern: "paste.example" }],
  [{ op: "distrust-origin", kind: "dir", pattern: "/tmp/drop" }],
  [{ op: "distrust-origin", kind: "dir", pattern: "/home/u/repo" }],
  [{ op: "trust-origin", kind: "dir", pattern: "/home/u/Downloads" }],
  [{ op: "distrust-origin", kind: "channel", pattern: "C123" }],
  [{ op: "lock-path", path: "/home/u/repo/.env", level: "no-model" }],
  [{ op: "release", to: { host: "paste.example" }, mode: "block" }],
  [{ op: "tool-inbound", tool: "WebFetch", trust: "UNTRUSTED" }],
  [{ op: "tool-inbound", tool: "WebFetch", trust: "TRUSTED" }],
  [{ op: "distrust-origin", kind: "url", pattern: "paste.example" }, { op: "distrust-origin", kind: "dir", pattern: "/tmp/drop" }],
];

test("oracle: whenever the delta says TIGHTENING, the real classifier trusts nothing it did not trust before", () => {
  let tightenings = 0;
  try {
    for (const [name, start] of STARTS) {
      const before = probes(start);
      for (const edits of EDIT_LISTS) {
        const ev = evaluateEdits({ specId: "claude-code", document: start }, edits);
        if (!ev.ok) continue; // a list the arbiter refuses is never applied
        const after = probes(ev.document);
        const newlyTrusted = Object.keys(before).filter((k) => before[k] === "UNTRUSTED" && after[k] === "TRUSTED");
        if (ev.tightening) {
          tightenings++;
          assert.deepEqual(newlyTrusted, [], `[${name}] ${JSON.stringify(edits)} was rated a tightening but newly trusts ${newlyTrusted.join(", ")}`);
        } else if (newlyTrusted.length > 0) {
          assert.ok(ev.delta.relaxations.length > 0, `[${name}] ${JSON.stringify(edits)} trusts more and says so`);
        }
      }
    }
  } finally {
    resetCurrentPolicyForTests("claude-code");
  }
  assert.ok(tightenings >= 20, `the corpus exercises the tightening path (${tightenings})`);
});

test("the engine rule the fix made: an absent `default` is the category's built-in one, never 'trust everything'", () => {
  try {
    assert.deepEqual(BUILTIN_ORIGIN_DEFAULT, { url: "UNTRUSTED", channel: "TRUSTED", dir: "TRUSTED" });
    const p = probes({ version: 1, inbound: { url: { trustedList: ["pypi.org"] } } });
    assert.equal(p["url https://pypi.org/project/x/"], "TRUSTED");
    assert.equal(p["url https://evil.example/page"], "UNTRUSTED", "a url section without default is an allowlist, as the built-in is");
  } finally {
    resetCurrentPolicyForTests("claude-code");
  }
});
