/**
 * node-env-proxy.test — the second Node floor (node-floor.ts
 * nodeEnvProxyGap; confidentiality-plan-13-reader-set-labels.md §10.2): a
 * Node program in a session uses Mandu's network proxy only when its Node
 * honours the launcher's NODE_USE_ENV_PROXY (fetch from 22.21 / 24.0,
 * http/https from 22.21 / 24.5, never 23.x). Below it `mandu doctor` warns
 * and the launch prints one notice line; no node on PATH, no warning; an
 * unreadable version is said so. Pure, plus one real PATH probe over a fake
 * `node` script.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  NODE_FLOOR, isNodeEnvProxyNotice, nodeEnvProxyFix, nodeEnvProxyGap, nodeEnvProxyNotice, nodeHonorsEnvProxy, nodeMeetsFloor,
} from "../../src/node-floor.js";
import { gatherFacts as gatherFactsIn, pathNodeRows, realPathNode, renderDoctor, type DoctorDeps, type DoctorFacts } from "../../src/doctor.js";
import { hermetic } from "../lib/test-runtime.js";
import { Layout } from "../../src/services/layout.js";

const gatherFacts = hermetic(gatherFactsIn, 0);

test("nodeHonorsEnvProxy: fetch from 22.21 and 24.0, http/https from 22.21 and 24.5, never 23.x", () => {
  const cases: Array<[string, boolean, boolean]> = [
    // version, fetch, https
    ["v22.13.0", false, false], // Mandu's own floor: runs Mandu, ignores the variable
    ["v22.20.9", false, false],
    ["v22.21.0", true, true],
    ["v22.22.1", true, true],
    ["v23.11.0", false, false],
    ["v24.0.0", true, false],
    ["v24.4.1", true, false],
    ["v24.5.0", true, true],
    ["v25.1.0", true, true],
    ["v20.19.0", false, false],
    ["garbage", false, false],
    ["", false, false],
  ];
  for (const [v, fetch, https] of cases) {
    assert.equal(nodeHonorsEnvProxy(v, "fetch"), fetch, `${v} fetch`);
    assert.equal(nodeHonorsEnvProxy(v, "https"), https, `${v} https`);
  }
  // The two floors are different numbers: Mandu runs where its programs' proxy does not.
  assert.equal(nodeMeetsFloor(NODE_FLOOR), true);
  assert.equal(nodeHonorsEnvProxy(NODE_FLOOR, "fetch"), false);
});

test("nodeEnvProxyGap: 22.13 warn, 22.21 ok, 23.x warn, 24.0 fetch ok / https warn, 24.5 ok, garbage unreadable, missing absent", () => {
  assert.deepEqual(nodeEnvProxyGap("v22.13.0\n"), { state: "bypass", version: "v22.13.0", apis: ["fetch", "https"] });
  assert.deepEqual(nodeEnvProxyGap("v22.21.0"), { state: "ok", version: "v22.21.0" });
  assert.deepEqual(nodeEnvProxyGap("v23.11.0"), { state: "bypass", version: "v23.11.0", apis: ["fetch", "https"] });
  assert.deepEqual(nodeEnvProxyGap("v24.0.0"), { state: "bypass", version: "v24.0.0", apis: ["https"] });
  assert.deepEqual(nodeEnvProxyGap("v24.5.0"), { state: "ok", version: "v24.5.0" });
  assert.deepEqual(nodeEnvProxyGap("not a version\nsecond line"), { state: "unreadable", text: "not a version" });
  assert.deepEqual(nodeEnvProxyGap(null), { state: "absent" });
  assert.deepEqual(nodeEnvProxyGap("  \n"), { state: "absent" });
});

test("the fix names the line the user is on", () => {
  assert.match(nodeEnvProxyFix("v24.2.0"), /Node 24\.5 or newer \(nvm install 24\)/);
  assert.match(nodeEnvProxyFix("v22.13.0"), /Node 22\.21 or newer, or 24\.5 or newer \(nvm install 22\)/);
  assert.match(nodeEnvProxyFix("v23.11.0"), /nvm install 22/);
});

test("launch notice: one plain line for a bypassing node only, recognized by the banner", () => {
  const old = nodeEnvProxyNotice(nodeEnvProxyGap("v22.13.0"))!;
  assert.equal(old, "mandu: ! Node v22.13.0 on your PATH is too old for Mandu: Node programs in this session won't have your secrets filled in on their web requests; see `mandu doctor`");
  assert.equal(isNodeEnvProxyNotice(old), true);
  assert.match(nodeEnvProxyNotice(nodeEnvProxyGap("v24.0.0"))!, /on web requests made with http\/https \(fetch works\); see `mandu doctor`$/);
  for (const v of ["v22.21.0", "v24.5.0", "garbage", null]) assert.equal(nodeEnvProxyNotice(nodeEnvProxyGap(v)), null, String(v));
  assert.equal(isNodeEnvProxyNotice("mandu: ! Claude Code 2.1.289 is newer than Mandu has tested"), false);
});

test("doctor rows: ✗ with the fix below the floor, ✓ above it, · for an unreadable version, nothing without a node", () => {
  const at = (gap: ReturnType<typeof nodeEnvProxyGap>): DoctorFacts["pathNode"] => ({ path: "/usr/bin/node", gap });
  const old = pathNodeRows(at(nodeEnvProxyGap("v22.13.0"))).join("\n");
  assert.match(old, /✗ node on your PATH is v22\.13\.0 \(\/usr\/bin\/node\): Node programs in a Mandu session won't have your secrets filled in on their web requests, so their logins fail \(nothing leaks\)/);
  assert.match(old, /fix: upgrade to Node 22\.21 or newer, or 24\.5 or newer/);
  const v24 = pathNodeRows(at(nodeEnvProxyGap("v24.0.0"))).join("\n");
  assert.match(v24, /✗ .*on web requests made with http\/https \(fetch works\)/);
  assert.match(v24, /fix: upgrade to Node 24\.5 or newer/);
  assert.match(pathNodeRows(at(nodeEnvProxyGap("v24.5.0"))).join("\n"), /✓ node on your PATH is v24\.5\.0 \(\/usr\/bin\/node\): Node programs in a Mandu session send their web requests through Mandu/);
  const odd = pathNodeRows(at(nodeEnvProxyGap("garbage"))).join("\n");
  assert.match(odd, /· could not read the version of the node on your PATH \(\/usr\/bin\/node: "garbage"\)/);
  assert.match(odd, /need Node 22\.21 or newer, or 24\.5 or newer/);
  assert.match(pathNodeRows(at({ state: "unreadable", text: "" })).join("\n"), /\(\/usr\/bin\/node: no answer\)/);
  assert.deepEqual(pathNodeRows(undefined), []);
  assert.deepEqual(pathNodeRows(at({ state: "absent" })), []);
});

const deps = (o: Partial<DoctorDeps>): DoctorDeps => ({
  nodeVersion: () => "22.22.1",
  gitVersion: () => null,
  commandExists: () => false,
  socketReachable: async () => false,
  fileExists: () => false,
  platform: () => "linux",
  usernsOk: () => false,
  readKnob: () => null,
  nativeBin: () => null,
  ...o,
});

test("gatherFacts → render: the PATH node row sits under the Node.js row; none without a node, no probe, or no answer read as missing", async () => {
  const facts = await gatherFacts({ PATH: "/fake" }, Layout.installed("/opt/mandu"), deps({
    pathNode: (env) => (env["PATH"] === "/fake" ? { path: "/fake/node", versionText: "v23.11.0\n" } : null),
  }));
  assert.deepEqual(facts.pathNode, { path: "/fake/node", gap: { state: "bypass", version: "v23.11.0", apis: ["fetch", "https"] } });
  const out = renderDoctor(facts);
  const needs = out.slice(out.indexOf("What Mandu needs"), out.indexOf("Installed"));
  assert.match(needs, /✓ Node\.js 22\.22\.1 \(22\.13\.0 or newer\)\n  ✗ node on your PATH is v23\.11\.0 \(\/fake\/node\)/);

  const none = await gatherFacts({}, Layout.installed("/opt/mandu"), deps({ pathNode: () => null }));
  assert.equal(none.pathNode, undefined);
  assert.doesNotMatch(renderDoctor(none), /node on your PATH/);
  const noProbe = await gatherFacts({}, Layout.installed("/opt/mandu"), deps({}));
  assert.equal(noProbe.pathNode, undefined, "a fixture without the probe never reads the host's node");
  const silent = await gatherFacts({}, Layout.installed("/opt/mandu"), deps({ pathNode: () => ({ path: "/x/node", versionText: null }) }));
  assert.deepEqual(silent.pathNode, { path: "/x/node", gap: { state: "unreadable", text: "" } });
});

test("realPathNode: the first executable node on PATH, its --version text; none when PATH has no node", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-path-node-"));
  try {
    const empty = join(dir, "empty");
    const a = join(dir, "a");
    const b = join(dir, "b");
    for (const d of [empty, a, b]) mkdirSync(d);
    // a non-executable `node` is skipped, as a shell would
    writeFileSync(join(empty, "node"), "#!/bin/sh\necho v1.0.0\n");
    writeFileSync(join(a, "node"), "#!/bin/sh\necho v22.13.0\n");
    chmodSync(join(a, "node"), 0o755);
    writeFileSync(join(b, "node"), "#!/bin/sh\necho v24.5.0\n");
    chmodSync(join(b, "node"), 0o755);
    assert.deepEqual(realPathNode({ PATH: `${empty}:relative:${a}:${b}` }), { path: join(a, "node"), versionText: "v22.13.0\n" });
    assert.equal(realPathNode({ PATH: empty }), null);
    assert.equal(realPathNode({}), null);
    writeFileSync(join(a, "node"), "#!/bin/sh\nexit 3\n");
    assert.deepEqual(realPathNode({ PATH: a }), { path: join(a, "node"), versionText: null }, "a node that fails is there, unread");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
