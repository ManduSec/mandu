/**
 * arbiter-classifier-args.test — the flags the dashboard supervisor starts
 * the live arbiter with so it can run the policy classifier
 * (confidentiality-plan-14 §14.3; supervisor-defs.ts `arbiterClassifierArgs`):
 * the classifier's argv as JSON (the bundle installed; in a checkout the
 * checkout's bundle behind the bundled arbiter, inspect-mcp's source through
 * its own tsx behind the source one), the Landlock applier when it is built,
 * nothing when the classifier's runtime is missing. No axis is read.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

import { arbiterClassifierArgs, arbiterPluginArgs, buildDefinitions } from "../../../src/supervisor/supervisor-defs.js";

test("a checkout: tsx + classify-main.ts, and the release applier", () => {
  const tsx = "/repo/interceptors/inspect-mcp/node_modules/tsx/dist/esm/index.mjs";
  const applier = "/repo/interceptors/target/release/mandu-landlock-apply";
  const have = new Set([tsx, applier]);
  const args = arbiterClassifierArgs({ repoRoot: "/repo", installedPkgRoot: null }, {}, (p) => have.has(p));
  assert.equal(args[0], "--classifier");
  assert.deepEqual(JSON.parse(args[1]!), [process.execPath, "--import", pathToFileURL(tsx).href, "/repo/interceptors/inspect-mcp/src/classify-main.ts"]);
  assert.deepEqual(args.slice(2), ["--landlock-apply", applier]);
});

test("a checkout's bundled arbiter: the build's classifier bundle (packaging.md §5.1); a build without it: the source", () => {
  const tsx = "/repo/interceptors/inspect-mcp/node_modules/tsx/dist/esm/index.mjs";
  const bundle = "/repo/launcher/dist/policy-classifier.mjs";
  const applier = "/repo/interceptors/target/release/mandu-landlock-apply";
  const o = { repoRoot: "/repo", installedPkgRoot: null, checkoutDist: "/repo/launcher/dist" };
  const args = arbiterClassifierArgs(o, {}, (p) => p === tsx || p === bundle || p === applier);
  assert.deepEqual(JSON.parse(args[1]!), [process.execPath, "--no-warnings=ExperimentalWarning", bundle], "no tsx: the bundle, as installed");
  assert.deepEqual(args.slice(2), ["--landlock-apply", applier], "the checkout's applier either way");
  const noBundle = arbiterClassifierArgs(o, {}, (p) => p === tsx);
  assert.deepEqual(JSON.parse(noBundle[1]!), [process.execPath, "--import", pathToFileURL(tsx).href, "/repo/interceptors/inspect-mcp/src/classify-main.ts"]);
  assert.deepEqual(arbiterClassifierArgs(o, {}, () => false), [], "neither: no flag");
});

test("buildDefinitions: the bundled arbiter's tail names the build's classifier, the source arbiter's the source one; the rest of the tail is the same", () => {
  const repo = mkdtempSync(join(tmpdir(), "mdu-classifier-defs-"));
  try {
    const tsx = join(repo, "interceptors", "inspect-mcp", "node_modules", "tsx", "dist", "esm", "index.mjs");
    const bundle = join(repo, "launcher", "dist", "policy-classifier.mjs");
    for (const f of [tsx, bundle]) { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, "\n"); }
    const d = buildDefinitions({
      repoRoot: repo, arbiterSock: "/s/arbiter.sock", modelProxyPort: 1, openaiProxyPort: 2, egressProxyPort: 3,
      proxyHost: "127.0.0.1", upstreamAnthropic: "", upstreamOpenai: "", logRingMax: 1, startTimeoutMs: 1, stopGraceMs: 1,
      autoStartArbiter: true, axisEnv: () => ({}), log: () => {}, gitRev: () => "nogit", gitChangedInRange: () => [],
      procCmdline: () => null, killPid: () => {}, discoverSocketOwner: () => null, symbolDb: "/s/db", eventDir: "/s/ev",
    } as unknown as Parameters<typeof buildDefinitions>[0], {});
    const classifierOf = (args: string[]): string[] => JSON.parse(args[args.indexOf("--classifier") + 1]!) as string[];
    assert.deepEqual(classifierOf(d.arbiter.args), [process.execPath, "--import", pathToFileURL(tsx).href, join(repo, "interceptors", "inspect-mcp", "src", "classify-main.ts")]);
    const b = d.arbiter.checkoutBundle!;
    assert.deepEqual(classifierOf(b.args), [process.execPath, "--no-warnings=ExperimentalWarning", bundle], "no tsx behind the bundled arbiter");
    const strip = (args: string[]): string[] => { const i = args.indexOf("--classifier"); return [...args.slice(0, i), ...args.slice(i + 2)]; };
    assert.deepEqual(strip(b.args).slice(2), strip(d.arbiter.args).slice(3), "the store flags and the rest of the tail are the same in both forms");
    assert.ok(!d["test-arbiter"].args.includes("--classifier") && !d["test-arbiter"].checkoutBundle!.args.includes("--classifier"), "the test tenant runs no classifier");
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("installed: the bundle and the packaged applier; MANDU_LANDLOCK_APPLY first when it exists", () => {
  const bundle = "/opt/mandu/dist/policy-classifier.mjs";
  const packaged = join("/opt/mandu/dist/native", `${process.platform}-${process.arch}`, "mandu-landlock-apply");
  const args = arbiterClassifierArgs({ repoRoot: "/x", installedPkgRoot: "/opt/mandu" }, {}, (p) => p === bundle || p === packaged);
  assert.deepEqual(JSON.parse(args[1]!), [process.execPath, "--no-warnings=ExperimentalWarning", bundle]);
  assert.deepEqual(args.slice(2), ["--landlock-apply", packaged]);
  const over = arbiterClassifierArgs({ repoRoot: "/x", installedPkgRoot: "/opt/mandu" }, { MANDU_LANDLOCK_APPLY: "/usr/local/bin/lla" }, (p) => p === bundle || p === "/usr/local/bin/lla");
  assert.deepEqual(over.slice(2), ["--landlock-apply", "/usr/local/bin/lla"]);
});

test("no classifier runtime: no flag (the arbiter says 'not available in this install'); no applier: no --landlock-apply", () => {
  assert.deepEqual(arbiterClassifierArgs({ repoRoot: "/repo", installedPkgRoot: null }, {}, () => false), []);
  const tsx = "/repo/interceptors/inspect-mcp/node_modules/tsx/dist/esm/index.mjs";
  assert.equal(arbiterClassifierArgs({ repoRoot: "/repo", installedPkgRoot: null }, {}, (p) => p === tsx).length, 2);
  // The live arbiter's definition carries none in a tree without inspect-mcp.
  const d = buildDefinitions({
    repoRoot: "/nonexistent-repo", arbiterSock: "/s/arbiter.sock", modelProxyPort: 1, openaiProxyPort: 2, egressProxyPort: 3,
    proxyHost: "127.0.0.1", upstreamAnthropic: "", upstreamOpenai: "", logRingMax: 1, startTimeoutMs: 1, stopGraceMs: 1,
    autoStartArbiter: true, axisEnv: () => ({}), log: () => {}, gitRev: () => "nogit", gitChangedInRange: () => [],
    procCmdline: () => null, killPid: () => {}, discoverSocketOwner: () => null,
  } as unknown as Parameters<typeof buildDefinitions>[0], {});
  assert.ok(!d.arbiter.args.includes("--classifier"));
});

test("the prompt filter plugins' flags (plan 15 §4.3): --net-guard when built, --landlock-apply unless the classifier's flags carry it", () => {
  const guard = "/repo/interceptors/target/release/mandu-net-guard";
  const applier = "/repo/interceptors/target/release/mandu-landlock-apply";
  const have = new Set([guard, applier]);
  const o = { repoRoot: "/repo", installedPkgRoot: null };
  assert.deepEqual(arbiterPluginArgs([], o, {}, (p) => have.has(p)), ["--net-guard", guard, "--landlock-apply", applier]);
  assert.deepEqual(arbiterPluginArgs(["--classifier", "[]", "--landlock-apply", applier], o, {}, (p) => have.has(p)), ["--net-guard", guard]);
  assert.deepEqual(arbiterPluginArgs([], o, {}, () => false), [], "not built: no flag (the arbiter runs no plugin)");
  const packaged = join("/opt/mandu/dist/native", `${process.platform}-${process.arch}`, "mandu-net-guard");
  assert.deepEqual(arbiterPluginArgs([], { repoRoot: "/x", installedPkgRoot: "/opt/mandu" }, {}, (p) => p === packaged), ["--net-guard", packaged]);
  assert.deepEqual(arbiterPluginArgs([], o, { MANDU_NET_GUARD: "/usr/local/bin/ng" }, (p) => p === "/usr/local/bin/ng"), ["--net-guard", "/usr/local/bin/ng"]);
});
