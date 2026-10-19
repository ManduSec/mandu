/**
 * stack-package-preflight.test.ts — every launch of the real stack refuses a
 * checkout whose service packages are not installed (tests/lib/stack-preflight.ts,
 * test-organization.md §8.12).
 *
 * The bug class: a service package without its node_modules does not stop
 * the launch; its service dies when first spawned, and a check graded on
 * what it did not do passes (the exec-wrap shim, 2026-10-04). The drill
 * replays and live runs refused it first; `withStack` (launcher-live.ts),
 * the harness every launching suite and the differential lanes go through,
 * now does too, before it creates anything.
 *
 * The checkout is a stub tree (the real bundle-manifest.json, a package.json
 * and an installed marker per service package), never the real tree: one
 * package's marker left out is the missing install.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { REPO_ROOT, withStack } from "../lib/launcher-live.js";
import {
  MissingStackPackagesError, assertStackPackages, manduServicePackages, markInstalled, missingManduPackages, writeStubCheckout,
} from "../lib/stack-preflight.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // withStack({ mode: "secrets" }) below; the preflight is axis-independent

const PACKAGES = manduServicePackages(REPO_ROOT);

/** A stub checkout in a temp dir (writeStubCheckout): the real manifest,
 *  every service package present, each installed except `missing`. */
function stubCheckout(missing: readonly string[]): string {
  return writeStubCheckout(mkdtempSync(join(tmpdir(), "mandu-stack-preflight-")), missing, REPO_ROOT);
}

test("unit: the service packages are the launcher's (bundle-manifest.json), and the checkout these suites run from has them all", () => {
  for (const p of ["arbiter", "fs-sync", "launcher", "interceptors/exec-wrap", "interceptors/anthropic-proxy", "interceptors/reply-filter"]) {
    assert.ok(PACKAGES.includes(p), `${p} is a service package (got ${PACKAGES.join(", ")})`);
  }
  assert.deepEqual(missingManduPackages(REPO_ROOT), [], "the suite's own checkout is installed (scripts/test-all.sh installs every package)");
});

test("unit: a missing package is a MissingStackPackagesError naming it, the lane and the install", (t) => {
  const root = stubCheckout(["interceptors/exec-wrap", "interceptors/net-proxy"]);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  assert.deepEqual(missingManduPackages(root), ["interceptors/exec-wrap", "interceptors/net-proxy"]);
  assert.throws(() => assertStackPackages(root, "some-lane"), (e: unknown) => {
    assert.ok(e instanceof MissingStackPackagesError);
    assert.equal(e.name, "MissingStackPackagesError");
    assert.deepEqual(e.missing, ["interceptors/exec-wrap", "interceptors/net-proxy"]);
    assert.match(e.message, /^some-lane: /);
    assert.match(e.message, /interceptors\/exec-wrap, interceptors\/net-proxy are not installed/);
    assert.match(e.message, /node scripts\/install-deps\.mjs interceptors\/exec-wrap && node scripts\/install-deps\.mjs interceptors\/net-proxy/);
    return true;
  });
  const complete = stubCheckout([]);
  t.after(() => rmSync(complete, { recursive: true, force: true }));
  assert.doesNotThrow(() => assertStackPackages(complete, "some-lane"));
});

test("e2e: withStack refuses a checkout without exec-wrap's install before it creates anything, and brings the stack up once it is installed", async (t) => {
  const root = stubCheckout(["interceptors/exec-wrap"]);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  // the stack's scratch would land in TMPDIR: an empty one of its own shows none was made
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "mandu-stack-preflight-tmp-")));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const saved = process.env["TMPDIR"];
  process.env["TMPDIR"] = scratch;
  let called = 0;
  try {
    await assert.rejects(
      withStack(async () => { called++; }, { mode: "secrets", packageRoot: root }),
      (e: unknown) => {
        assert.ok(e instanceof MissingStackPackagesError, `a MissingStackPackagesError, got ${String(e)}`);
        assert.match(e.message, /^withStack: the side under Mandu cannot run: interceptors\/exec-wrap is not installed/);
        assert.match(e.message, /node scripts\/install-deps\.mjs interceptors\/exec-wrap/);
        return true;
      },
    );
    assert.equal(called, 0, "the suite's body never ran");
    assert.deepEqual(readdirSync(scratch), [], "no stack scratch, no arbiter: the refusal is the whole failure");
    // the control: the same checkout installed, the stack comes up
    markInstalled(root, "interceptors/exec-wrap");
    await withStack(async ({ adminSock, workspace }) => {
      called++;
      assert.ok(workspace.startsWith(scratch), "the stack's workspace is in the TMPDIR it was given");
      assert.ok(adminSock.length > 0);
    }, { mode: "secrets", packageRoot: root });
    assert.equal(called, 1, "an installed checkout runs the body");
  } finally {
    if (saved === undefined) delete process.env["TMPDIR"];
    else process.env["TMPDIR"] = saved;
  }
});
