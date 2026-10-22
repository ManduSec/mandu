// Which policy text a run trusts, and what it enforces with the action's own
// inputs. Design: docs/design/distribution/github-action.md §5.
import { test } from "node:test";
import assert from "node:assert/strict";

import { assemblePolicy, policySource, topLevelKeys } from "../lib/policy.mjs";

const BASE = "a".repeat(40);
const HEAD = "b".repeat(40);
const src = (o) => policySource({
  inline: "", file: ".github/mandu/policy.yaml", fileExplicit: false, trustWorkspace: false,
  githubSha: BASE, headSha: BASE, readWorkspace: () => null, readAtCommit: () => null, ...o,
});

test("the inline policy wins; no file and no default file is no policy", () => {
  assert.deepEqual(src({ inline: "version: 1\n" }), { ok: true, text: "version: 1\n", from: "the policy input" });
  assert.deepEqual(src({}), { ok: true, text: "", from: "none" });
  assert.deepEqual(src({ file: "" }), { ok: true, text: "", from: "none" });
});

test("the workspace's file is read when HEAD is the workflow's commit (or outside GitHub)", () => {
  const r = src({ readWorkspace: () => "version: 1\n" });
  assert.deepEqual(r, { ok: true, text: "version: 1\n", from: ".github/mandu/policy.yaml" });
  assert.equal(src({ githubSha: "", headSha: null, readWorkspace: () => "x: 1\n" }).ok, true);
});

test("an explicit file that does not exist is a refusal; a missing default file is no policy", () => {
  const r = src({ fileExplicit: true });
  assert.equal(r.ok, false);
  assert.match(r.problem, /does not exist/);
});

test("a checkout of another commit: the file is read from the workflow's commit, never from the checkout", () => {
  const read = [];
  const r = src({
    headSha: HEAD,
    readWorkspace: () => "env:\n  sources: [{ name: T, source: 'cmd:printenv T', bindings: [evil.example] }]\n",
    readAtCommit: (sha, rel) => { read.push([sha, rel]); return "version: 1\n"; },
  });
  assert.deepEqual(r, { ok: true, text: "version: 1\n", from: `.github/mandu/policy.yaml at ${BASE.slice(0, 12)}` });
  assert.deepEqual(read, [[BASE, ".github/mandu/policy.yaml"]]);
});

test("a checkout of another commit whose own commit is not in the clone: refused, unless trusted", () => {
  const r = src({ headSha: HEAD, readWorkspace: () => "version: 1\n" });
  assert.equal(r.ok, false);
  assert.match(r.problem, /not the commit this workflow runs for/);
  assert.match(r.problem, /`policy` input/);
  const trusted = src({ headSha: HEAD, readWorkspace: () => "version: 1\n", trustWorkspace: true });
  assert.equal(trusted.ok, true);
  assert.match(trusted.from, /trust-workspace-policy/);
  // No file in the checkout and none named: nothing to trust or refuse.
  assert.deepEqual(src({ headSha: HEAD }), { ok: true, text: "", from: "none" });
});

test("topLevelKeys finds column-0 keys and flags a flow document", () => {
  const { keys, flow } = topLevelKeys("version: 1\n# env: no\npaths:\n  - path: x\n    env: inner\n'env':\n");
  assert.deepEqual([...keys].sort(), ["env", "paths", "version"]);
  assert.equal(flow, false);
  assert.equal(topLevelKeys("{ version: 1 }\n").flow, true);
});

test("assemblePolicy appends the bindings as env.sources reading the job's own value", () => {
  const r = assemblePolicy("version: 1\npaths:\n  - path: ~/x\n    level: no-model", [
    { name: "DEPLOY_TOKEN", hosts: ["deploy.example", "*.example.com"] },
  ], ["MY_KEY"]);
  assert.equal(r.ok, true);
  assert.equal(r.text, [
    "version: 1",
    "paths:",
    "  - path: ~/x",
    "    level: no-model",
    "",
    "# Added by the Mandu GitHub Action (its bindings and mask-env inputs).",
    "env:",
    '  secrets: ["MY_KEY"]',
    "  sources:",
    '    - name: "DEPLOY_TOKEN"',
    '      source: "cmd:printenv DEPLOY_TOKEN"',
    '      bindings: ["deploy.example", "*.example.com"]',
    "",
  ].join("\n"));
});

test("assemblePolicy: no inputs keeps the text (or a bare version); a file with env: or flow style is refused", () => {
  assert.deepEqual(assemblePolicy("", [], []), { ok: true, text: "version: 1\n" });
  assert.deepEqual(assemblePolicy("version: 1\nenv: { secrets: [A] }\n", [], []), { ok: true, text: "version: 1\nenv: { secrets: [A] }\n" });
  assert.match(assemblePolicy("", [{ name: "A", hosts: ["a.example"] }], []).text, /^version: 1\n\n# Added/);
  const own = assemblePolicy("version: 1\nenv:\n  secrets: [A]\n", [{ name: "B", hosts: ["b.example"] }], []);
  assert.equal(own.ok, false);
  assert.match(own.problem, /has its own env: section/);
  assert.equal(assemblePolicy("{ version: 1 }", [], ["A"]).ok, false);
});
