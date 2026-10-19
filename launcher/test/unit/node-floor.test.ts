/**
 * node-floor.test — the Node floor is ONE number stated in four places
 * ("do not merely check the major"). The
 * comparison is tested here; the three gates that cannot import the constant
 * (package.json `engines`, bin/mandu.mjs, scripts/bootstrap.sh) are read
 * as text and pinned to it so they cannot drift back to a major-only check.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { NODE_FLOOR, nodeMeetsFloor, parseNodeVersion } from "../../src/node-floor.js";

const here = dirname(fileURLToPath(import.meta.url));
const launcherRoot = join(here, "..", "..");
const repoRoot = join(launcherRoot, "..");

test("the floor is 22.13.0 — where node:sqlite lost its flag", () => {
  assert.equal(NODE_FLOOR, "22.13.0");
});

test("nodeMeetsFloor compares major.minor.patch, not the major alone", () => {
  assert.equal(nodeMeetsFloor("22.13.0"), true);
  assert.equal(nodeMeetsFloor("v22.13.0"), true);
  assert.equal(nodeMeetsFloor("22.14.1"), true);
  assert.equal(nodeMeetsFloor("23.0.0"), true);
  assert.equal(nodeMeetsFloor("24.2.0"), true);
  // The versions the old `>= 22` check wrongly admitted:
  assert.equal(nodeMeetsFloor("22.0.0"), false);
  assert.equal(nodeMeetsFloor("22.12.9"), false);
  assert.equal(nodeMeetsFloor("20.19.0"), false);
  // Unparseable fails closed.
  assert.equal(nodeMeetsFloor(""), false);
  assert.equal(nodeMeetsFloor("garbage"), false);
  assert.deepEqual(parseNodeVersion("22.13.0-nightly"), [22, 13, 0]);
});

test("package.json `engines.node` states the same floor", () => {
  const pkg = JSON.parse(readFileSync(join(launcherRoot, "package.json"), "utf8")) as { engines?: { node?: string } };
  assert.equal(pkg.engines?.node, `>=${NODE_FLOOR}`);
});

test("bin/mandu.mjs (runs before the bundle) duplicates the same floor", () => {
  const src = readFileSync(join(launcherRoot, "bin", "mandu.mjs"), "utf8");
  assert.match(src, new RegExp(`const NODE_FLOOR = "${NODE_FLOOR.replace(/\./g, "\\.")}"`));
  // and no major-only check survives
  assert.doesNotMatch(src, /nodeMajor\s*<\s*22/);
});

test("scripts/bootstrap.sh states the same floor and compares all three parts", () => {
  const src = readFileSync(join(repoRoot, "scripts", "bootstrap.sh"), "utf8");
  assert.match(src, new RegExp(`NODE_FLOOR="${NODE_FLOOR.replace(/\./g, "\\.")}"`));
  assert.match(src, /node_meets_floor/);
  assert.doesNotMatch(src, /NODE_MAJOR.*-lt 22/);
});

test("scripts/install.sh (the curl | sh installer) states the same floor, and its pinned Node meets it", () => {
  const src = readFileSync(join(repoRoot, "scripts", "install.sh"), "utf8");
  const floor = /^NODE_FLOOR="([0-9.]+)"$/m.exec(src)?.[1];
  const pin = /^NODE_PIN="([0-9.]+)"$/m.exec(src)?.[1];
  assert.equal(floor, NODE_FLOOR);
  assert.ok(pin && nodeMeetsFloor(pin), `the installer's pinned Node ${pin} meets the floor`);
});
