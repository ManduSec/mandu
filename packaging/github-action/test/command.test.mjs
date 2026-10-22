// The launch a CI run makes, its fixed environment, the setup decision and
// the step's status. Design: docs/design/distribution/github-action.md §4.
import { test } from "node:test";
import assert from "node:assert/strict";

import { mkdtempSync, rmSync, statSync } from "node:fs";

import { launchArgv, launchEnv, RUNTIME_DIR_MAX, runtimeDirProblem, runtimeDirTemplate, setupDecision, stepStatus } from "../lib/command.mjs";

const cfg = (o = {}) => ({ agent: "claude", prompt: "fix it", agentArgs: [], requireConfinement: true, verbose: false, ...o });

test("claude runs as `claude -p <prompt> <args>`, codex as `codex exec <args> <prompt>`, the reply filter off", () => {
  assert.deepEqual(launchArgv(cfg({ agentArgs: ["--allowedTools", "Bash"] })), ["--no-reply-filter", "--require-confinement", "claude", "-p", "fix it", "--allowedTools", "Bash"]);
  assert.deepEqual(launchArgv(cfg({ agent: "codex", agentArgs: ["--full-auto"], requireConfinement: false, verbose: true })), ["--no-reply-filter", "--verbose", "codex", "exec", "--full-auto", "fix it"]);
});

test("a prompt that looks like a flag stays the prompt's argument", () => {
  assert.deepEqual(launchArgv(cfg({ prompt: "--dangerously-skip-permissions" })).slice(-2), ["-p", "--dangerously-skip-permissions"]);
});

test("launchEnv: the job's env, the run's fixed settings over it, the inputs and empty logins left out", () => {
  const env = launchEnv({
    PATH: "/bin", DEPLOY_TOKEN: "t", MANDU_MODE: "off", MANDU_EGRESS_HOLD_MS: "60000", MANDU_REPLY_FILTER: "1",
    MANDU_HOME: "/elsewhere", MANDU_ACTION_PROMPT: "p", ANTHROPIC_API_KEY: "", OPENAI_API_KEY: "sk-x", CI: "false",
  }, { manduHome: "/rt/mandu-1/home", runtimeDir: "/tmp/mdu-gha-x1y2z3" });
  assert.equal(env.PATH, "/bin");
  assert.equal(env.DEPLOY_TOKEN, "t", "the job's secrets reach the launch, which masks them");
  assert.equal(env.MANDU_MODE, "secrets");
  assert.equal(env.MANDU_EGRESS_HOLD_MS, "0", "nobody answers a hold in CI");
  assert.equal(env.MANDU_SECRETS_ASK_TIMEOUT, "1");
  assert.equal(env.MANDU_REPLY_FILTER, "0", "the log keeps placeholders");
  assert.equal(env.MANDU_HOME, "/rt/mandu-1/home");
  assert.equal(env.MANDU_POLICY_FILE, "/rt/mandu-1/home/policy.yaml");
  assert.equal(env.MANDU_RUNTIME_DIR, "/tmp/mdu-gha-x1y2z3", "the services' sockets go to the short dir");
  assert.ok(!("XDG_RUNTIME_DIR" in env), "the job's own XDG_RUNTIME_DIR is left as it was (here: unset)");
  assert.equal(env.CI, "true");
  assert.equal(env.OPENAI_API_KEY, "sk-x");
  assert.ok(!("ANTHROPIC_API_KEY" in env), "an empty login variable is no login");
  assert.ok(!Object.keys(env).some((k) => k.startsWith("MANDU_ACTION_")), "the inputs stay with the action");
});

test("setupDecision: auto is for Codex on Linux with sudo; true needs both; false never", () => {
  const linux = { platform: "linux", sudo: true };
  assert.deepEqual(setupDecision("auto", { ...linux, agent: "claude" }), { run: false });
  assert.deepEqual(setupDecision("auto", { ...linux, agent: "codex" }), { run: true });
  assert.deepEqual(setupDecision("true", { ...linux, agent: "claude" }), { run: true });
  assert.deepEqual(setupDecision("false", { ...linux, agent: "codex" }), { run: false });
  assert.match(setupDecision("auto", { platform: "linux", sudo: false, agent: "codex" }).note, /no passwordless sudo/);
  assert.match(setupDecision("true", { platform: "linux", sudo: false, agent: "codex" }).problem, /passwordless sudo/);
  assert.match(setupDecision("true", { platform: "darwin", sudo: true, agent: "codex" }).problem, /Linux/);
  assert.deepEqual(setupDecision("auto", { platform: "darwin", sudo: true, agent: "codex" }), { run: false });
});

test("stepStatus: the agent's failure first, then a blocked send under fail-on-blocked", () => {
  assert.equal(stepStatus(0, 0, true), 0);
  assert.equal(stepStatus(0, 2, true), 1);
  assert.equal(stepStatus(0, 2, false), 0);
  assert.equal(stepStatus(3, 2, true), 3);
  assert.equal(stepStatus(2, 0, false), 2);
});

test("the runtime dir stays within the launcher's 44-byte bound however long RUNNER_TEMP and TMPDIR are", () => {
  assert.equal(RUNTIME_DIR_MAX, 44, "launcher/src/runtime-base.ts: 107 usable sun_path bytes less INSTANCE_SOCK_SUFFIX_MAX (63)");
  const deep = `/home/runner/work/${"a-very-long-repository-name/".repeat(4)}_temp`;
  const template = runtimeDirTemplate({ RUNNER_TEMP: deep, TMPDIR: `${deep}/tmp` });
  assert.ok(!template.includes("runner"), `not under RUNNER_TEMP or TMPDIR: ${template}`);
  // mkdtemp appends six characters.
  const dir = mkdtempSync(template);
  try {
    assert.equal(Buffer.byteLength(dir), Buffer.byteLength(template) + 6);
    assert.ok(Buffer.byteLength(dir) <= RUNTIME_DIR_MAX, `${dir} is ${Buffer.byteLength(dir)} bytes`);
    assert.equal(runtimeDirProblem(dir), null);
    assert.equal(statSync(dir).mode & 0o777, 0o700, "made private");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  assert.match(runtimeDirProblem(`${deep}/mandu-x/run`), /bytes; Mandu's sockets need one of at most 44 bytes/);
  assert.equal(runtimeDirProblem("/" + "x".repeat(43)), null, "44 bytes fit");
  assert.notEqual(runtimeDirProblem("/" + "x".repeat(44)), null, "45 do not");
});
