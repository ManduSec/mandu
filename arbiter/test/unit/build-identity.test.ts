/**
 * build-identity.test.ts — `hello` reports WHICH build of a release the
 * arbiter runs (runtime-instances.md §4.1): the hash of its bundle, and the
 * checkout rev it came from, so two commits of one version are told apart.
 *
 * Mandu-new test (no reference origin). Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { arbiterBuild, buildIdentityOf, bundleDigest, isCheckoutBuildDir } from "../../ipc/build-identity.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // the handshake is axis-independent

const sha16 = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 16);

test("bundleDigest: the first 16 hex digits of the file's SHA-256", () => {
  assert.equal(bundleDigest(Buffer.from("x")), sha16("x"));
  assert.match(bundleDigest(Buffer.from("")), /^[0-9a-f]{16}$/);
});

test("from source: no bundle, the checkout's rev (none without git)", () => {
  assert.deepEqual(buildIdentityOf("/repo/arbiter/ipc/build-identity.ts", "abc1234"), { bundle: null, rev: "abc1234" });
  assert.deepEqual(buildIdentityOf("/repo/arbiter/ipc/build-identity.ts", "nogit"), { bundle: null, rev: null });
  // This test runs the arbiter from source.
  assert.deepEqual(arbiterBuild("abc1234"), { bundle: null, rev: "abc1234" });
  assert.deepEqual(arbiterBuild("nogit"), { bundle: null, rev: null });
});

test("from a bundle: its hash; the rev only for a checkout's own build", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-build-"));
  try {
    // An install: <pkg>/dist/arbiter.mjs, no src/ beside dist/.
    const installed = join(tmp, "pkg", "dist");
    mkdirSync(installed, { recursive: true });
    writeFileSync(join(installed, "arbiter.mjs"), "bundle A");
    assert.equal(isCheckoutBuildDir(installed), false);
    assert.deepEqual(buildIdentityOf(join(installed, "arbiter.mjs"), "def5678"), { bundle: sha16("bundle A"), rev: null },
      "an install's rev is the enclosing directory's, not this code's");
    // A checkout's build: launcher/dist beside launcher/src/run.ts.
    const checkout = join(tmp, "repo", "launcher");
    mkdirSync(join(checkout, "dist"), { recursive: true });
    mkdirSync(join(checkout, "src"), { recursive: true });
    writeFileSync(join(checkout, "src", "run.ts"), "");
    writeFileSync(join(checkout, "dist", "arbiter.mjs"), "bundle B");
    assert.equal(isCheckoutBuildDir(join(checkout, "dist")), true);
    assert.deepEqual(buildIdentityOf(join(checkout, "dist", "arbiter.mjs"), "def5678"), { bundle: sha16("bundle B"), rev: "def5678" });
    // A bundle that cannot be read reports no hash (never a made-up one).
    assert.deepEqual(buildIdentityOf(join(installed, "gone.mjs"), "nogit"), { bundle: null, rev: null });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

async function helloOf(identity?: ConstructorParameters<typeof ArbiterServer>[0]["identity"]): Promise<Record<string, unknown>> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-bid-"));
  const socketPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"), log: () => {},
    ...(identity ? { identity } : {}),
  });
  await server.listen();
  const client = new ArbiterClient(socketPath);
  try {
    await client.connect();
    return (await client.hello()) as unknown as Record<string, unknown>;
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("hello reports the build beside the version", async () => {
  assert.deepEqual((await helloOf())["build"], { bundle: null, rev: null }, "an embedded server: no evidence");
  assert.deepEqual((await helloOf({ instanceId: null, gitRev: "abc1234", gitDirty: false }))["build"], { bundle: null, rev: "abc1234" },
    "absent = this code's own (from source: the rev)");
  const fake = { bundle: "f00df00df00df00d", rev: null };
  assert.deepEqual((await helloOf({ instanceId: null, gitRev: "abc1234", gitDirty: false, build: fake }))["build"], fake,
    "an identity can stand in for another build");
  const old = await helloOf({ instanceId: null, gitRev: "abc1234", gitDirty: false, build: null });
  assert.equal("build" in old, false, "an arbiter from before the build identity reports none");
  assert.equal(typeof old["version"], "string");
});
