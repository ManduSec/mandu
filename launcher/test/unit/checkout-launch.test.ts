/**
 * checkout-launch — the checkout prelude bin/mandu.mjs runs in the launcher's
 * own node (packaging.md §5.1; launcher/scripts/checkout-launch.mjs): the
 * verbose rule for the secrets lines (the shim's own), the best-effort
 * secrets load, and the freshness check that reads any error as stale. The
 * launch through the real shim is test/component/bundle-freshness.test.ts
 * and tests/stack/shim-secrets-env.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { bundleFresh, loadCheckoutSecrets, secretsQuiet } from "../../scripts/checkout-launch.mjs";
import { tmpDir } from "../lib/tmp-dir.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // what the launch's node does before the launcher; no arbiter decides anything here

test("secretsQuiet: quiet unless MANDU_VERBOSE is set to something other than \"\", 0 or false, or --verbose comes before the first --", () => {
  assert.equal(secretsQuiet(["claude"], {}), true);
  for (const v of ["", "0", "false", "FALSE", "False"]) assert.equal(secretsQuiet(["claude"], { MANDU_VERBOSE: v }), true, v);
  for (const v of ["1", "true", "yes"]) assert.equal(secretsQuiet(["claude"], { MANDU_VERBOSE: v }), false, v);
  assert.equal(secretsQuiet(["--verbose", "claude"], {}), false);
  assert.equal(secretsQuiet(["claude", "--verbose"], {}), false);
  assert.equal(secretsQuiet(["claude", "--", "--verbose"], {}), true, "after -- it is the agent's flag");
  assert.equal(secretsQuiet(["claude", "--verbose=1"], {}), true, "only the bare flag, as the shim matched it");
});

test("loadCheckoutSecrets: no scripts/mandu-env.sh → nothing loaded, the loader not even imported", async () => {
  const root = tmpDir("mandu-prelude-");
  mkdirSync(join(root, "scripts"));
  writeFileSync(join(root, "scripts", "secrets-to-env.mjs"), "throw new Error('must not be imported');\n");
  const env: Record<string, string | undefined> = {};
  assert.deepEqual(await loadCheckoutSecrets(root, ["claude"], env), []);
  assert.deepEqual(env, {});
});

test("loadCheckoutSecrets: a loader that fails to load is one warning line, never a thrown error (best effort, as the shell's `|| true`)", async () => {
  const root = tmpDir("mandu-prelude-");
  mkdirSync(join(root, "scripts"));
  writeFileSync(join(root, "scripts", "mandu-env.sh"), "");
  writeFileSync(join(root, "scripts", "secrets-to-env.mjs"), "throw new Error('broken loader');\n");
  const writes: string[] = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((s: string | Uint8Array) => { writes.push(String(s)); return true; }) as typeof process.stderr.write;
  let set: string[];
  try {
    set = await loadCheckoutSecrets(root, ["claude"], {});
  } finally {
    process.stderr.write = orig;
  }
  assert.deepEqual(set, []);
  assert.equal(writes.length, 1, writes.join(""));
  assert.match(writes[0]!, /^\[mandu-secrets\] could not load the secrets file: broken loader — nothing loaded\n$/);
});

test("loadCheckoutSecrets: hands the loader the env and the launch's quiet rule", async () => {
  const root = tmpDir("mandu-prelude-");
  mkdirSync(join(root, "scripts"));
  writeFileSync(join(root, "scripts", "mandu-env.sh"), "");
  writeFileSync(join(root, "scripts", "secrets-to-env.mjs"),
    "export function applySecretsEnv(env, opts) { env.SEEN_QUIET = String(opts.quiet); return ['SEEN_QUIET']; }\n");
  const env: Record<string, string | undefined> = {};
  assert.deepEqual(await loadCheckoutSecrets(root, ["claude"], env), ["SEEN_QUIET"]);
  assert.equal(env["SEEN_QUIET"], "true");
  const loud: Record<string, string | undefined> = {};
  await loadCheckoutSecrets(root, ["--verbose", "claude"], loud);
  assert.equal(loud["SEEN_QUIET"], "false");
});

test("bundleFresh: a dist with no build record, or none at all, is stale", () => {
  const root = tmpDir("mandu-prelude-");
  assert.equal(bundleFresh(join(root, "launcher", "dist"), root), false);
  mkdirSync(join(root, "dist"));
  writeFileSync(join(root, "dist", ".bundle-stamp.json"), "{not json");
  assert.equal(bundleFresh(join(root, "dist"), root), false);
});
