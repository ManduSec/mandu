/**
 * supervisor-release-stale.test — the STALE flag on an adopted arbiter by its
 * release and build, not by git rev only (runtime-instances.md §4, §4.1).
 *
 * The arbiter's `hello` reports `version` and `build` (the hash of the bundle
 * it runs, the checkout rev it came from; arbiter/ipc/build-identity.ts). The
 * supervisor compares them with what it would start itself
 * (own-arbiter-build.ts) before the scope-honest rev rule: an installation
 * has no rev to compare, and two builds of one version (the S8 miss,
 * reply-row-reservation.md §18.2) share their version.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { arbiterReleaseStaleness, type ArbiterIdentity, type OwnArbiterBuild } from "../../../src/supervisor/supervisor-defs.js";
import { bundleDigestOf, dashboardVersion, ownArbiterBuildOf } from "../../../src/supervisor/own-arbiter-build.js";
import { NEVER_READY_SCRIPT, tmpdir, nodeArgs, mkSup, registerTmpHooks } from "./supervisor-harness.js";

registerTmpHooks();

const V = "0.2.0-beta.6";
const IDENT = (over: Partial<ArbiterIdentity> = {}): ArbiterIdentity => ({
  pid: 4242, startedAt: "2026-10-17T00:00:00.000Z", instanceId: null,
  gitRev: "abc1234", gitDirty: false, sockPath: "/s", eventDir: "/e", symbolDb: "/db", protocolVersion: 1, ...over,
});
const OWN = (over: Partial<OwnArbiterBuild> = {}): OwnArbiterBuild => ({ version: V, bundle: "aaaaaaaaaaaaaaaa", installed: false, ...over });

test("another release is stale; a real arbiter without a version is an older one", () => {
  const v = arbiterReleaseStaleness(IDENT({ version: "0.1.0" }), OWN());
  assert.deepEqual(v, { stale: true, staleReason: `it runs Mandu 0.1.0; this dashboard is Mandu ${V}` });
  assert.match(arbiterReleaseStaleness(IDENT(), OWN())!.staleReason!, /an older Mandu release \(one that does not report its version\)/);
  const noProtocol = IDENT();
  delete noProtocol.protocolVersion;
  assert.equal(arbiterReleaseStaleness(noProtocol, OWN()), null, "no arbiter identity to judge: the rev rule decides");
  assert.equal(arbiterReleaseStaleness(IDENT({ version: "0.1.0" }), OWN({ version: null })), null, "our own version unknown");
});

test("this release, another bundle: stale, naming both builds", () => {
  const v = arbiterReleaseStaleness(IDENT({ version: V, build: { bundle: "bbbbbbbbbbbbbbbb", rev: "def5678" } }), OWN());
  assert.equal(v?.stale, true);
  assert.equal(v?.staleReason, `it runs another build of Mandu ${V} (bundle bbbbbbbbbbbbbbbb, rev def5678) than this dashboard starts (bundle aaaaaaaaaaaaaaaa)`);
});

test("the same bundle, or nothing to compare, leaves it to the rev rule", () => {
  assert.equal(arbiterReleaseStaleness(IDENT({ version: V, build: { bundle: "aaaaaaaaaaaaaaaa", rev: "fff0000" } }), OWN()), null,
    "one bundle from two commits");
  assert.equal(arbiterReleaseStaleness(IDENT({ version: V, build: { bundle: null, rev: "def5678" } }), OWN()), null,
    "a checkout's source: the scope-honest rev rule");
  assert.equal(arbiterReleaseStaleness(IDENT({ version: V }), OWN()), null, "an arbiter from before the build identity");
  assert.equal(arbiterReleaseStaleness(IDENT({ version: V, build: { bundle: "bbbbbbbbbbbbbbbb", rev: null } }), OWN({ bundle: null })), null,
    "no bundle of our own (a checkout that was never built)");
  assert.equal(arbiterReleaseStaleness(null, OWN()), null);
});

test("an installation over a checkout's source is stale (two places)", () => {
  const v = arbiterReleaseStaleness(IDENT({ version: V, build: { bundle: null, rev: "def5678" } }), OWN({ installed: true }));
  assert.equal(v?.stale, true);
  assert.match(v!.staleReason!, /a checkout's source \(rev def5678\), not this installation's build \(bundle aaaaaaaaaaaaaaaa\)/);
});

test("ownArbiterBuildOf: the dashboard's version and the digest the arbiter reports for the same file", () => {
  const pkg = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "package.json"), "utf8")) as { version: string };
  assert.equal(dashboardVersion(), pkg.version);
  const root = tmpdir();
  const dist = join(root, "launcher", "dist");
  mkdirSync(dist, { recursive: true });
  writeFileSync(join(dist, "arbiter.mjs"), "bundle one");
  const sha16 = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 16);
  assert.deepEqual(ownArbiterBuildOf({ repoRoot: root }), { version: pkg.version, bundle: sha16("bundle one"), installed: false });
  writeFileSync(join(dist, "arbiter.mjs"), "bundle two, longer");
  assert.equal(bundleDigestOf(join(dist, "arbiter.mjs")), sha16("bundle two, longer"), "a rebuild is re-hashed");
  const inst = join(root, "pkg");
  mkdirSync(join(inst, "dist"), { recursive: true });
  writeFileSync(join(inst, "dist", "arbiter.mjs"), "installed");
  assert.deepEqual(ownArbiterBuildOf({ repoRoot: inst, layout: { mode: "installed", pkgRoot: inst } }),
    { version: pkg.version, bundle: sha16("installed"), installed: true });
  assert.equal(ownArbiterBuildOf({ repoRoot: join(root, "none") }).bundle, null);
});

test("status(): an adopted arbiter of another build of this release is STALE, live, without a rev change", async () => {
  const dir = tmpdir();
  const sock = join(dir, "arbiter.sock");
  const build = { bundle: "aaaaaaaaaaaaaaaa", rev: "abc1234" };
  const fake = net.createServer((c) => {
    c.on("data", (b) => {
      if (b.toString().includes('"hello"')) {
        c.write(JSON.stringify({ id: 1, ok: true, result: { ...IDENT({ version: V, build }), sockPath: sock } }) + "\n");
      }
    });
  });
  await new Promise<void>((r) => fake.listen(sock, r));
  let own = OWN();
  const sup = mkSup(
    { arbiter: { label: "Arbiter", command: process.execPath, args: nodeArgs(NEVER_READY_SCRIPT),
      cwd: dir, env: {}, ready: { kind: "socket", path: sock }, endpoint: sock } },
    { arbiterSock: sock, gitRev: () => "abc1234", gitChangedInRange: () => [], ownArbiterBuild: () => own },
  );
  try {
    await sup.start("arbiter"); // endpoint already live → ADOPT, identity fetched
    const at = () => sup.status().find((s) => s.id === "arbiter")!;
    assert.equal(at().stale, false, "the build this dashboard starts");
    assert.equal(at().identity?.version, V);
    own = OWN({ bundle: "cccccccccccccccc" }); // the checkout's bundle was rebuilt; same rev, same version
    assert.equal(at().stale, true);
    assert.match(at().staleReason!, /another build of Mandu 0\.2\.0-beta\.6 \(bundle aaaaaaaaaaaaaaaa, rev abc1234\) than this dashboard starts \(bundle cccccccccccccccc\)/);
    own = OWN({ version: "0.3.0", bundle: "aaaaaaaaaaaaaaaa" });
    assert.match(at().staleReason!, /it runs Mandu 0\.2\.0-beta\.6; this dashboard is Mandu 0\.3\.0/);
  } finally {
    await sup.shutdownAll();
    await new Promise<void>((r) => fake.close(() => r()));
  }
});
