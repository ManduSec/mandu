// Unit tests for scripts/secrets-to-env.mjs: the stderr load line names each
// key's kind and length, never its tail (the line lands in the watch runner's
// shared .cast recordings). Run: node --test <this file>.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, chmodSync, existsSync, symlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";
import { applySecretsEnv, secretsEnv } from "../secrets-to-env.mjs";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "secrets-to-env.mjs");
const KEY = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtailXYZ9";

// The checkout's own secrets.local.json comes first in discovery; a test that
// plants its file in a temp home skips when one exists.
const REPO_LOCAL = join(dirname(SCRIPT), "..", "secrets.local.json");
const skipRepoLocal = existsSync(REPO_LOCAL) ? "the checkout has a secrets.local.json" : false;

function run(secrets) {
  const dir = tmpDir("mandu-secrets-");
  const file = join(dir, "secrets.json");
  writeFileSync(file, JSON.stringify(secrets));
  chmodSync(file, 0o600);
  const env = { PATH: process.env.PATH, HOME: dir, MANDU_HOME: dir };
  return spawnSync(process.execPath, [SCRIPT], { env, encoding: "utf8" });
}

test("the load line shows the key's prefix and length, not its tail", { skip: skipRepoLocal }, () => {
  const r = run({ openai_api_key: KEY });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /export OPENAI_API_KEY=/, "the export itself still carries the key");
  assert.match(r.stderr, new RegExp(`OPENAI_API_KEY=sk-… \\(${KEY.length} chars\\)`));
  assert.ok(!r.stderr.includes("XYZ9"), "no suffix of the key on stderr");
  assert.ok(!r.stderr.includes("sk-pro"), "no more than the 3-char kind prefix");
});

test("a short value shows only that it is set", { skip: skipRepoLocal }, () => {
  const r = run({ ullm_model: "haiku" });
  assert.match(r.stderr, /MANDU_ULLM_MODEL=\(set, 5 chars\)/);
  assert.ok(!r.stderr.includes("ha…"));
});

test("the model services' keys a program calls itself: typesafe_api_key and openrouter_api_key (agent-sign-in.md §3.12)", { skip: skipRepoLocal }, () => {
  const r = run({ typesafe_api_key: "ts-AAAAAAAAAAAAAAAAtail1", openrouter_api_key: "sk-or-v1-BBBBBBBBBBBBtail2" });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /export TYPESAFE_API_KEY='ts-AAAAAAAAAAAAAAAAtail1'/);
  assert.match(r.stdout, /export OPENROUTER_API_KEY='sk-or-v1-BBBBBBBBBBBBtail2'/);
  assert.ok(!r.stderr.includes("tail1") && !r.stderr.includes("tail2"), "never a tail on stderr");
});

// Discovery falls to the path table's `secrets-json`
// (docs/design/architecture/on-disk-layout.md §5): $MANDU_HOME/secrets.json, else
// ~/.mandu/secrets.json. No per-file override exists.

function discover(env, file) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify({ ullm_model: "found-it" }));
  chmodSync(file, 0o600);
  return spawnSync(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
}

test("the file is found under $MANDU_HOME", { skip: skipRepoLocal }, () => {
  const dir = tmpDir("mandu-secrets-");
  const r = discover({ HOME: join(dir, "home"), MANDU_HOME: join(dir, "mh") }, join(dir, "mh", "secrets.json"));
  assert.match(r.stdout, /export MANDU_ULLM_MODEL='found-it'/);
});

test("no MANDU_HOME: the file is found under ~/.mandu (XDG_CONFIG_HOME does not move it)", { skip: skipRepoLocal }, () => {
  const dir = tmpDir("mandu-secrets-");
  const r = discover({ HOME: dir, XDG_CONFIG_HOME: join(dir, "xdg") }, join(dir, ".mandu", "secrets.json"));
  assert.match(r.stdout, /export MANDU_ULLM_MODEL='found-it'/);
});

test("the retired MANDU_SECRETS names no file", { skip: skipRepoLocal }, () => {
  const dir = tmpDir("mandu-secrets-");
  const r = discover({ HOME: dir, MANDU_HOME: join(dir, "mh"), MANDU_SECRETS: join(dir, "elsewhere.json") }, join(dir, "elsewhere.json"));
  assert.equal(r.status, 0);
  assert.doesNotMatch(r.stdout, /found-it/);
  assert.match(r.stderr, /no secrets file found/);
});

test("an unset-up /dev/null home reads as no secrets file", { skip: skipRepoLocal }, () => {
  const r = spawnSync(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, HOME: "/nonexistent", MANDU_HOME: "/dev/null/mandu-test-home" }, encoding: "utf8" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "");
});

test("MANDU_SECRETS_QUIET=1 (the launcher shim, not verbose): no informational lines; the exports and the warnings stay", { skip: skipRepoLocal }, () => {
  const dir = tmpDir("mandu-secrets-");
  const file = join(dir, "secrets.json");
  writeFileSync(file, JSON.stringify({ openai_api_key: KEY }));
  chmodSync(file, 0o644);
  const r = spawnSync(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, HOME: dir, MANDU_HOME: dir, MANDU_SECRETS_QUIET: "1" }, encoding: "utf8" });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /export OPENAI_API_KEY=/);
  assert.doesNotMatch(r.stderr, /loaded |  set  /, r.stderr);
  assert.match(r.stderr, /WARNING: .* is group\/other-readable/, "a warning still prints");
  const none = spawnSync(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, HOME: "/nonexistent", MANDU_HOME: "/dev/null/mandu-test-home", MANDU_SECRETS_QUIET: "1" }, encoding: "utf8" });
  assert.equal(none.status, 0);
  assert.equal(none.stderr, "", "no file found is not news");
});

test("MANDU_SECRETS_FILE=0: the file is not read; the environment alone counts (both formats)", () => {
  // no skip: with the switch, even the checkout's own secrets.local.json is not read
  const dir = tmpDir("mandu-secrets-");
  const file = join(dir, "secrets.json");
  writeFileSync(file, JSON.stringify({ anthropic_api_key: KEY, ullm_model: "found-it" }));
  chmodSync(file, 0o600);
  const env = { PATH: process.env.PATH, HOME: dir, MANDU_HOME: dir, MANDU_SECRETS_FILE: "0" };
  const r = spawnSync(process.execPath, [SCRIPT], { env, encoding: "utf8" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "", "no export from the file");
  assert.match(r.stderr, /MANDU_SECRETS_FILE=0: the secrets file is not read/);
  const ef = spawnSync(process.execPath, [SCRIPT, "--format=env-file"], { env: { ...env, OPENAI_API_KEY: KEY }, encoding: "utf8" });
  assert.equal(ef.status, 0);
  assert.equal(ef.stdout, `OPENAI_API_KEY=${KEY}\n`, "env-file: the environment's key only, nothing from the file");
  // any other value reads the file as before
  const on = spawnSync(process.execPath, [SCRIPT], { env: { ...env, MANDU_SECRETS_FILE: "1" }, encoding: "utf8" });
  assert.equal(on.status, 0);
  if (!skipRepoLocal) assert.match(on.stdout, /export ANTHROPIC_API_KEY=/);
});

// The launcher's in-process load (packaging.md §5.1): `applySecretsEnv` sets
// what the CLI's export lines set, in the env object it is given. The whole
// launch path is tests/stack/shim-secrets-env.test.ts.

function homeWith(secrets, mode = 0o600) {
  const dir = tmpDir("mandu-secrets-");
  const file = join(dir, "secrets.json");
  writeFileSync(file, JSON.stringify(secrets));
  chmodSync(file, mode);
  return dir;
}

test("importing the module runs no CLI (prints nothing)", () => {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", `await import(${JSON.stringify(SCRIPT)});`], {
    env: { PATH: process.env.PATH, HOME: "/nonexistent", MANDU_HOME: "/dev/null/mandu-test-home" }, encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, "");
  assert.equal(r.stderr, "");
});

test("the CLI still runs when reached through a symlinked directory (argv[1] keeps the typed spelling)", { skip: skipRepoLocal }, () => {
  const dir = homeWith({ ullm_model: "via-link" });
  const link = join(dir, "scripts-link");
  symlinkSync(dirname(SCRIPT), link);
  const r = spawnSync(process.execPath, [join(link, "secrets-to-env.mjs")], { env: { PATH: process.env.PATH, HOME: dir, MANDU_HOME: dir }, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /export MANDU_ULLM_MODEL='via-link'/);
});

test("applySecretsEnv: the CLI's exports, applied in place: unset filled, set kept, set-empty filled; the returned names", { skip: skipRepoLocal }, () => {
  const dir = homeWith({ anthropic_api_key: KEY, openai_api_key: "file-openai", ullm_model: "m", env: { A_TOKEN: "a", KEEP: "file", EMPTY: "file" } });
  const env = { HOME: dir, MANDU_HOME: dir, OPENAI_API_KEY: "env-openai", KEEP: "env", EMPTY: "" };
  const cli = spawnSync(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
  const exported = [...cli.stdout.matchAll(/^export ([A-Za-z_][A-Za-z0-9_]*)=/gm)].map((m) => m[1]);
  const lines = [];
  const set = applySecretsEnv(env, { quiet: true, log: (m) => lines.push(m) });
  assert.deepEqual(set, exported, "the same variables as the CLI's export lines, in order");
  assert.equal(env.ANTHROPIC_API_KEY, KEY);
  assert.equal(env.MANDU_ULLM_API_KEY, KEY, "the U-LLM key falls back to the Anthropic key");
  assert.equal(env.OPENAI_API_KEY, "env-openai", "an already-set variable is never overridden");
  assert.equal(env.KEEP, "env");
  assert.equal(env.EMPTY, "file", "a set-but-empty variable is filled, as the shell's export did");
  assert.equal(env.A_TOKEN, "a");
  assert.deepEqual(lines, [], "quiet: no informational lines");
});

test("applySecretsEnv: verbose lines go to `log`, unprefixed and masked; quiet keeps the warnings", { skip: skipRepoLocal }, () => {
  const dir = homeWith({ openai_api_key: KEY }, 0o644);
  const loud = [];
  applySecretsEnv({ HOME: dir, MANDU_HOME: dir }, { quiet: false, log: (m) => loud.push(m) });
  assert.ok(loud.some((l) => /^loaded /.test(l)), loud.join("\n"));
  assert.ok(loud.includes(`  set  OPENAI_API_KEY=sk-… (${KEY.length} chars)`), loud.join("\n"));
  assert.ok(!loud.join("\n").includes("XYZ9"));
  const quiet = [];
  applySecretsEnv({ HOME: dir, MANDU_HOME: dir }, { quiet: true, log: (m) => quiet.push(m) });
  assert.equal(quiet.length, 1, quiet.join("\n"));
  assert.match(quiet[0], /^WARNING: .* is group\/other-readable/);
});

test("applySecretsEnv: a name the shell's export refuses is skipped (and said); a NUL byte is dropped, as command substitution drops it", { skip: skipRepoLocal }, () => {
  const dir = homeWith({ env: { "bad-name": "x", "A B": "y", GOOD: "a\u0000b" } });
  const env = { HOME: dir, MANDU_HOME: dir };
  const lines = [];
  assert.deepEqual(applySecretsEnv(env, { quiet: true, log: (m) => lines.push(m) }), ["GOOD"]);
  assert.equal(env.GOOD, "ab");
  assert.equal(env["bad-name"], undefined);
  assert.equal(lines.filter((l) => /not a valid environment variable name/.test(l)).length, 2, lines.join("\n"));
});

test("applySecretsEnv: MANDU_SECRETS_FILE=0 sets nothing and never throws", () => {
  // no skip: with the switch, even the checkout's own secrets.local.json is not read
  const env = { HOME: "/nonexistent", MANDU_HOME: "/dev/null/mandu-test-home", MANDU_SECRETS_FILE: "0" };
  assert.deepEqual(applySecretsEnv(env, { quiet: true, log: () => {} }), []);
  assert.deepEqual(Object.keys(env).sort(), ["HOME", "MANDU_HOME", "MANDU_SECRETS_FILE"]);
});

test("secretsEnv env-file format: the effective value of each key, the environment first", { skip: skipRepoLocal }, () => {
  const dir = homeWith({ anthropic_api_key: "file-a", openai_api_key: "file-o" });
  const pairs = secretsEnv({ env: { HOME: dir, MANDU_HOME: dir, OPENAI_API_KEY: "env-o" }, format: "env-file", quiet: true, log: () => {} });
  assert.deepEqual(pairs, [["ANTHROPIC_API_KEY", "file-a"], ["OPENAI_API_KEY", "env-o"], ["MANDU_ULLM_API_KEY", "file-a"]]);
});
