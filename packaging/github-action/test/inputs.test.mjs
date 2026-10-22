// The action's inputs: every one read, every bad one a problem (never a guess).
// Design: docs/design/distribution/github-action.md §4.
import { test } from "node:test";
import assert from "node:assert/strict";

import { DEFAULT_POLICY_FILE, parseBindings, parseInputs, parseNameList, splitArgs } from "../lib/inputs.mjs";

const noFile = () => null;
const inputs = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [`MANDU_ACTION_${k}`, v]));

test("the defaults: claude, the default policy file (used if present), confinement required, fail on a blocked send", () => {
  const { config, problems } = parseInputs(inputs({ PROMPT: "fix the build" }), noFile);
  assert.deepEqual(problems, []);
  assert.equal(config.agent, "claude");
  assert.equal(config.prompt, "fix the build");
  assert.deepEqual(config.agentArgs, []);
  assert.equal(config.policyFile, DEFAULT_POLICY_FILE);
  assert.equal(config.policyFileExplicit, false);
  assert.equal(config.requireConfinement, true);
  assert.equal(config.failOnBlocked, true);
  assert.equal(config.trustWorkspacePolicy, false);
  assert.equal(config.allowPersistedCredentials, false);
  assert.equal(config.setup, "auto");
  assert.equal(config.summary, true);
  assert.equal(config.workingDirectory, ".");
});

test("a prompt is required, from the input or a file, never both", () => {
  assert.match(parseInputs(inputs({}), noFile).problems.join("\n"), /prompt: required/);
  assert.match(parseInputs(inputs({ PROMPT: "a", PROMPT_FILE: "p.md" }), noFile).problems.join("\n"), /give one, not both/);
  assert.match(parseInputs(inputs({ PROMPT_FILE: "p.md" }), noFile).problems.join("\n"), /cannot read p\.md/);
  const r = parseInputs(inputs({ PROMPT_FILE: "p.md" }), (p) => (p === "p.md" ? "from the file" : null));
  assert.deepEqual(r.problems, []);
  assert.equal(r.config.prompt, "from the file");
});

test("bad values are problems: agent, booleans, setup, both policy forms", () => {
  const { problems } = parseInputs(inputs({
    PROMPT: "x", AGENT: "goose", FAIL_ON_BLOCKED: "maybe", SETUP: "always", POLICY: "version: 1", POLICY_FILE: "p.yaml",
  }), noFile);
  const all = problems.join("\n");
  assert.match(all, /agent: must be claude or codex/);
  assert.match(all, /fail-on-blocked: must be true or false/);
  assert.match(all, /setup: must be auto, true or false/);
  assert.match(all, /policy and policy-file: give one, not both/);
});

test("an inline policy replaces the policy file; an explicit file is marked explicit", () => {
  assert.equal(parseInputs(inputs({ PROMPT: "x", POLICY: "version: 1\n" }), noFile).config.policyFile, "");
  const r = parseInputs(inputs({ PROMPT: "x", POLICY_FILE: "ci/mandu.yaml" }), noFile).config;
  assert.equal(r.policyFile, "ci/mandu.yaml");
  assert.equal(r.policyFileExplicit, true);
});

test("splitArgs splits like a shell and expands nothing; a JSON array is taken as is", () => {
  assert.deepEqual(splitArgs(""), []);
  assert.deepEqual(splitArgs("--allowedTools Bash,Read --model 'claude x'"), ["--allowedTools", "Bash,Read", "--model", "claude x"]);
  assert.deepEqual(splitArgs('--a "b \\"c\\" d" e\\ f'), ["--a", 'b "c" d', "e f"]);
  assert.deepEqual(splitArgs("$HOME ~ *"), ["$HOME", "~", "*"], "no expansion");
  assert.deepEqual(splitArgs('["--x", "y z"]'), ["--x", "y z"]);
  assert.deepEqual(splitArgs("''"), [""]);
  assert.equal(splitArgs("'open"), null);
  assert.equal(splitArgs('"open'), null);
  assert.equal(splitArgs("[1, 2]"), null);
});

test("bindings: one variable per line, hosts checked, comments and blank lines skipped", () => {
  const problems = [];
  const b = parseBindings("# deploys\nDEPLOY_TOKEN: deploy.example.com, api.example.com:443\n\nNPM_TOKEN=registry.npmjs.org\nAWS_X: *.amazonaws.com\n", problems);
  assert.deepEqual(problems, []);
  assert.deepEqual(b, [
    { name: "DEPLOY_TOKEN", hosts: ["deploy.example.com", "api.example.com:443"] },
    { name: "NPM_TOKEN", hosts: ["registry.npmjs.org"] },
    { name: "AWS_X", hosts: ["*.amazonaws.com"] },
  ]);
});

test("bindings: a bad name, a missing or bad host, a name twice are each a problem", () => {
  const problems = [];
  const b = parseBindings("1BAD: a.example\nNOHOST:\nURL: https://a.example/x\nTWICE: a.example\nTWICE: b.example\nnot a line\n", problems);
  assert.deepEqual(b.map((x) => x.name), ["TWICE"]);
  const all = problems.join("\n");
  assert.match(all, /line 1: "1BAD" is not a variable name/);
  assert.match(all, /line 2: NOHOST names no host/);
  assert.match(all, /line 3: not a host name: "https:\/\/a\.example\/x"/);
  assert.match(all, /line 5: TWICE is bound twice/);
  assert.match(all, /line 6: write NAME: host, host/);
});

test("mask-env: names only, deduplicated", () => {
  const problems = [];
  assert.deepEqual(parseNameList("A_KEY, B_KEY\nA_KEY bad-name", "mask-env", problems), ["A_KEY", "B_KEY"]);
  assert.match(problems.join("\n"), /mask-env: "bad-name" is not a variable name/);
});
