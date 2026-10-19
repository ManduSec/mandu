/**
 * release-version.test.ts — `hello` reports the Mandu release the arbiter's
 * code belongs to (runtime-instances.md §4.1), which the launcher compares
 * with its own before it uses the arbiter.
 *
 * Mandu-new test (no reference origin). Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { releaseVersion } from "../../ipc/release-version.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // the handshake is axis-independent

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "package.json");
const OWN = (JSON.parse(readFileSync(PKG, "utf8")) as { version: string }).version;

async function helloOf(identity?: ConstructorParameters<typeof ArbiterServer>[0]["identity"]): Promise<Record<string, unknown>> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-relv-"));
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

test("releaseVersion is the arbiter package's version (one version for the product)", () => {
  assert.equal(releaseVersion(), OWN);
  assert.match(OWN, /^\d+\.\d+\.\d+/);
});

test("hello reports the release beside the code rev", async () => {
  const h = await helloOf();
  assert.equal(h["version"], OWN);
  assert.equal(h["protocolVersion"], 1, "every real arbiter's hello carries protocolVersion");
});

test("an identity can stand in for another release, or for one from before the check", async () => {
  assert.equal((await helloOf({ instanceId: null, gitRev: "nogit", gitDirty: false, version: "0.1.0" }))["version"], "0.1.0");
  const old = await helloOf({ instanceId: null, gitRev: "nogit", gitDirty: false, version: null });
  assert.equal("version" in old, false, "an arbiter from before the check reports no version");
  assert.equal(old["protocolVersion"], 1);
  assert.equal((await helloOf({ instanceId: null, gitRev: "abc1234", gitDirty: false }))["version"], OWN, "absent = this code's own");
});
